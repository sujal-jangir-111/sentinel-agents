"""Async LLM chat-completions client (OpenAI-compatible: Groq, Gemini or ASI:One) with a JSON-mode helper.

The provider comes from LLM_PROVIDER and its GROQ_* / GEMINI_* / ASI1_* settings (common.config).

Safety: every prompt is passed through `mask_secrets` before leaving the process, and
callers should truncate large inputs with `truncate` (CLAUDE.md §9.4, §14).
"""
import json
import re
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar

import httpx
from pydantic import ValidationError

from common.config import get_settings
from common.http_retry import MAX_ATTEMPTS, send_with_retry
from common.sast_rules import mask_secrets

TIMEOUT_SECONDS = 30.0
TEMPERATURE = 0.2
MAX_RATE_WAIT = 20.0        # a per-minute limit passes soon; a daily one won't, so that fails at once
PARSE_RETRY_WAIT = 0.5

T = TypeVar("T")


class LLMError(Exception):
    """The LLM could not be reached, rejected the request, or returned unusable output."""


class _ModelUnavailable(LLMError):
    """This model is overloaded, unreachable or retired; a different model may still answer."""


def truncate(text: str, limit: int, marker: str = "\n...[truncated]") -> str:
    """Cap text at `limit` characters (marker included)."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(marker))] + marker


_FENCE_RE = re.compile(r"^```[a-zA-Z0-9_-]*\s*\n?(.*?)\n?```$", re.DOTALL)


def parse_json_object(raw: str) -> Dict[str, Any]:
    """Strip ``` fences and parse a JSON object; falls back to the outermost {...} span."""
    text = raw.strip()
    fenced = _FENCE_RE.match(text)
    if fenced:
        text = fenced.group(1).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


def _masked(message: Dict[str, Any]) -> Dict[str, Any]:
    """Copy of a chat message with any text content passed through mask_secrets. A model's `reasoning` isn't part of the
    chat format, so it isn't sent back."""
    clean = {k: v for k, v in message.items() if k != "reasoning"}
    if isinstance(clean.get("content"), str):
        clean["content"] = mask_secrets(clean["content"])
    return clean


def _wait_hint(resp: httpx.Response) -> Optional[float]:
    """Seconds to wait for a failure that passes by itself: Groq sometimes can't parse its own model's output (a retry
    works), and its token limit is per minute. None means this isn't one of those."""
    if resp.status_code == 400 and "output_parse_failed" in resp.text:
        return PARSE_RETRY_WAIT
    if resp.status_code == 429:
        try:
            wait = float(resp.headers.get("retry-after", ""))
        except ValueError:
            return None
        return wait if 0 < wait <= MAX_RATE_WAIT else None
    return None


class LLMClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        fallback_model: Optional[str] = None,
        timeout: float = TIMEOUT_SECONDS,
    ) -> None:
        cfg = get_settings()
        self._client = client
        self._api_key = cfg.llm_api_key if api_key is None else api_key
        self.model = model or cfg.llm_model
        self._url = base_url or cfg.llm_base_url
        self._key_env = cfg.llm_key_env
        # A custom endpoint has no known fallback model unless one is passed explicitly
        self.fallback_model = fallback_model or ("" if base_url else cfg.llm_fallback_model)
        self._timeout = timeout

    async def complete(
        self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None, temperature: float = TEMPERATURE,
    ) -> Dict[str, Any]:
        """One chat completion over a full message list (optionally with function-calling tools).
        Returns the raw assistant message: {"content": ..., "tool_calls": [...]}. Text content is secret-masked."""
        if not self._api_key:
            raise LLMError(f"{self._key_env} is not configured")
        payload: Dict[str, Any] = {"temperature": temperature, "messages": [_masked(m) for m in messages]}
        if tools:
            payload["tools"] = tools
        try:   # with a fallback, trying the other model is the retry: waiting again on a stalled model only costs time
            return await self._post({**payload, "model": self.model}, attempts=1 if self._has_fallback else MAX_ATTEMPTS)
        except _ModelUnavailable as exc:
            if not self._has_fallback:
                raise LLMError(str(exc)) from exc
            return await self._post({**payload, "model": self.fallback_model})

    @property
    def _has_fallback(self) -> bool:
        return bool(self.fallback_model) and self.fallback_model != self.model

    async def _post(self, payload: Dict[str, Any], attempts: int = MAX_ATTEMPTS) -> Dict[str, Any]:
        """One model, with the shared retry policy. _ModelUnavailable means another model may still work."""
        resp = await send_with_retry(
            self._client, "POST", self._url, error_cls=_ModelUnavailable, label=f"LLM request ({payload['model']})",
            json=payload, headers={"Authorization": f"Bearer {self._api_key}"}, timeout=self._timeout, attempts=attempts,
            wait_hint=_wait_hint,
        )
        if resp.status_code == 404:   # models get retired: Google removed gemini-2.5-flash for new keys
            raise _ModelUnavailable(f"LLM model {payload['model']} is not available (HTTP 404)")
        if resp.status_code >= 400:
            raise LLMError(f"LLM request failed: HTTP {resp.status_code}")
        try:
            message = resp.json()["choices"][0]["message"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError("LLM returned an unexpected response shape") from exc
        if not isinstance(message, dict):
            raise LLMError("LLM returned an unexpected response shape")
        return message

    async def chat(self, system: str, user: str, temperature: float = TEMPERATURE) -> str:
        """One chat completion; returns the assistant text."""
        message = await self.complete(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], temperature=temperature)
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise LLMError("LLM returned an empty completion")
        return content

    async def _json_call(
        self, system: str, user: str, schema_hint: str, build: Callable[[Dict[str, Any]], T]
    ) -> T:
        """Ask for JSON only; on a parse/validation failure retry once with the error, then raise."""
        json_system = (
            f"{system}\n\nRespond with ONLY a single JSON object matching this shape. "
            f"No prose, no markdown fences.\n{schema_hint}"
        )
        prompt = user
        error = ""
        for attempt in range(2):
            raw = await self.chat(json_system, prompt)
            try:
                return build(parse_json_object(raw))
            except (ValueError, ValidationError) as exc:  # JSONDecodeError is a ValueError
                error = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
                prompt = f"{user}\n\nYour previous reply was invalid ({error}). Reply with ONLY valid JSON."
        raise LLMError(f"LLM did not return valid JSON after 2 attempts ({error})")

    async def chat_json(self, system: str, user: str, schema_hint: str) -> Dict[str, Any]:
        """JSON-object completion (fences stripped, one parse retry, then LLMError)."""
        return await self._json_call(system, user, schema_hint, lambda d: d)

    async def chat_model(
        self, model_cls: Type[T], system: str, user: str, schema_hint: Optional[str] = None
    ) -> T:
        """Like chat_json but validates into a pydantic/uagents Model (e.g. PatchDraftResult)."""
        if schema_hint is None:
            # uagents Models return the schema as a JSON string; plain pydantic returns a dict
            schema = model_cls.model_json_schema()  # type: ignore[attr-defined]
            schema = json.loads(schema) if isinstance(schema, str) else schema
            schema_hint = json.dumps(schema, separators=(",", ":"))
        hint = schema_hint
        return await self._json_call(system, user, hint, lambda d: model_cls.model_validate(d))  # type: ignore[attr-defined]


ASI1Client = LLMClient  # backwards-compatible name
