import json
import os
from typing import Callable, List

import json

import httpx
import pytest

from common.llm_client import ASI1Client, LLMClient, LLMError, parse_json_object, truncate
from common.models import PatchDraftResult

URL = "https://asi.test/v1/chat/completions"
KEY = "test-key-123"


def completion(text: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": text}}]})


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    sleeps: List[float] = []

    async def fake(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr("common.http_retry._sleep", fake)
    return sleeps


def make(handler: Callable[[httpx.Request], httpx.Response], key: str = KEY):
    seen: List[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(wrapped))
    return ASI1Client(http, api_key=key, model="asi1-mini", base_url=URL), seen, http


# ------------------------------------------------------------------ parsing helpers

def test_parse_json_object_variants():
    assert parse_json_object('{"a": 1}') == {"a": 1}
    assert parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('```\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('Sure! Here you go: {"a": {"b": 2}} hope it helps') == {"a": {"b": 2}}


@pytest.mark.parametrize("bad", ["not json", "[1, 2]", "", "{broken"])
def test_parse_json_object_rejects(bad):
    with pytest.raises(ValueError):
        parse_json_object(bad)


def test_truncate():
    assert truncate("short", 100) == "short"
    out = truncate("x" * 500, 100)
    assert len(out) == 100 and out.endswith("[truncated]")


# ------------------------------------------------------------------ chat

async def test_chat_request_shape_and_auth():
    client, seen, http = make(lambda r: completion("hello"))
    async with http:
        assert await client.chat("be brief", "hi") == "hello"
    req = seen[0]
    body = json.loads(req.content)
    assert str(req.url) == URL and req.headers["Authorization"] == f"Bearer {KEY}"
    assert body["model"] == "asi1-mini" and body["temperature"] == 0.2
    assert body["messages"] == [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]


async def test_secrets_are_masked_before_sending():
    client, seen, http = make(lambda r: completion("ok"))
    async with http:
        await client.chat("sys", 'STRIPE = "sk_test_51SENTINELDEMOxxxxxxxx" and AKIAIOSFODNN7EXAMPLE')
    sent = seen[0].content.decode()
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in sent and "AKIAIOSFODNN7EXAMPLE" not in sent
    assert "sk_tes****" in sent and "AKIAIO****" in sent


async def test_missing_api_key_never_sends():
    client, seen, http = make(lambda r: completion("x"), key="")
    async with http:
        with pytest.raises(LLMError, match="_API_KEY is not configured"):
            await client.chat("s", "u")
    assert seen == []


async def test_retries_5xx_with_backoff_then_succeeds(no_sleep):
    replies = iter([httpx.Response(503), httpx.Response(500), completion("finally")])
    client, seen, http = make(lambda r: next(replies))
    async with http:
        assert await client.chat("s", "u") == "finally"
    assert len(seen) == 3 and no_sleep == [0.5, 1.0]


async def test_timeout_exhausts_retries(no_sleep):
    def boom(request):
        raise httpx.ReadTimeout("slow", request=request)

    client, seen, http = make(boom)
    async with http:
        with pytest.raises(LLMError, match="3 attempts.*ReadTimeout"):
            await client.chat("s", "u")
    assert len(seen) == 3 and no_sleep == [0.5, 1.0]


async def test_4xx_not_retried_and_key_not_leaked():
    client, seen, http = make(lambda r: httpx.Response(401, json={"error": f"bad key {KEY}"}))
    async with http:
        with pytest.raises(LLMError) as exc:
            await client.chat("s", "u")
    assert "HTTP 401" in str(exc.value) and KEY not in str(exc.value) and len(seen) == 1


@pytest.mark.parametrize("payload", [{}, {"choices": []}, {"choices": [{"message": {}}]}, {"choices": [{"message": {"content": "  "}}]}])
async def test_malformed_completion_raises(payload):
    client, _, http = make(lambda r: httpx.Response(200, json=payload))
    async with http:
        with pytest.raises(LLMError):
            await client.chat("s", "u")


# ------------------------------------------------------------------ JSON mode

async def test_chat_json_strips_fences():
    client, seen, http = make(lambda r: completion('```json\n{"patched_code": "x = 1", "explanation": "e"}\n```'))
    async with http:
        out = await client.chat_json("sys", "user", '{"patched_code": str, "explanation": str}')
    assert out == {"patched_code": "x = 1", "explanation": "e"}
    system = json.loads(seen[0].content)["messages"][0]["content"]
    assert "ONLY a single JSON object" in system and '"patched_code"' in system


async def test_chat_json_retries_once_on_parse_failure():
    replies = iter([completion("I think the answer is..."), completion('{"ok": true}')])
    client, seen, http = make(lambda r: next(replies))
    async with http:
        assert await client.chat_json("s", "u", "{}") == {"ok": True}
    retry_prompt = json.loads(seen[1].content)["messages"][1]["content"]
    assert "previous reply was invalid" in retry_prompt


async def test_chat_json_gives_up_after_second_failure():
    client, seen, http = make(lambda r: completion("still not json"))
    async with http:
        with pytest.raises(LLMError, match="valid JSON after 2 attempts"):
            await client.chat_json("s", "u", "{}")
    assert len(seen) == 2


async def test_chat_model_validates_into_uagents_model():
    att = {
        "incident_id": "inc-1", "approved": True, "attestation_hash": "h", "target_file": "app.py",
        "patched_code_content": "x", "updated_requirements_txt": "y", "unified_diff": "z",
    }
    good = {"incident_id": "inc-1", "attestation": att, "rollback_available": True, "attempts": 2}
    client, _, http = make(lambda r: completion(json.dumps(good)))
    async with http:
        result = await client.chat_model(PatchDraftResult, "s", "u")
    assert isinstance(result, PatchDraftResult) and result.attempts == 2 and result.attestation.approved


async def test_chat_model_retries_on_validation_error_then_fails():
    client, seen, http = make(lambda r: completion('{"incident_id": "inc-1"}'))
    async with http:
        with pytest.raises(LLMError, match="2 attempts"):
            await client.chat_model(PatchDraftResult, "s", "u")
    assert len(seen) == 2


async def test_chat_model_default_schema_hint_lists_fields():
    client, seen, http = make(lambda r: completion("{}"))
    async with http:
        with pytest.raises(LLMError):
            await client.chat_model(PatchDraftResult, "s", "u")
    system = json.loads(seen[0].content)["messages"][0]["content"]
    assert "rollback_available" in system and "attempts" in system


# ------------------------------------------------------------------ live (opt-in)

@pytest.mark.integration
async def test_live_asi1_json_roundtrip():
    key = os.getenv("ASI1_API_KEY")
    if not key:
        pytest.skip("ASI1_API_KEY not set")
    async with httpx.AsyncClient() as http:
        out = await ASI1Client(http, api_key=key).chat_json("You are a test.", 'Return {"ok": true}', '{"ok": bool}')
    assert isinstance(out, dict)


# ------------------------------------------------------------------ provider selection

def test_gemini_is_the_default_provider_when_its_key_is_set(monkeypatch):
    from common.config import GEMINI_BASE_URL, get_settings
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    cfg = get_settings()
    assert (cfg.llm_provider, cfg.llm_api_key, cfg.llm_model, cfg.llm_base_url) == ("gemini", "g-key", "gemini-test", GEMINI_BASE_URL)


def test_asi1_provider_can_still_be_selected(monkeypatch):
    from common.config import ASI1_BASE_URL, get_settings
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    monkeypatch.setenv("LLM_PROVIDER", "asi1")
    monkeypatch.setenv("ASI1_API_KEY", "a-key")
    cfg = get_settings()
    assert (cfg.llm_provider, cfg.llm_api_key, cfg.llm_base_url, cfg.llm_key_env) == ("asi1", "a-key", ASI1_BASE_URL, "ASI1_API_KEY")


async def test_groq_failing_to_parse_its_own_output_is_retried(monkeypatch):
    """Live: Groq answered 400 output_parse_failed on 2 calls of 4 for a prompt that then worked."""
    waits = []

    async def sleep(seconds):
        waits.append(seconds)

    monkeypatch.setattr("common.http_retry._sleep", sleep)
    answers = iter([httpx.Response(400, json={"error": {"code": "output_parse_failed"}}), completion("ok")])
    client, seen, http = make(lambda r: next(answers))
    async with http:
        assert await client.chat("s", "u") == "ok"
    assert len(seen) == 2 and waits == [0.5]


async def test_a_short_rate_limit_is_waited_out_and_a_daily_one_is_not(monkeypatch):
    waits = []

    async def sleep(seconds):
        waits.append(seconds)

    monkeypatch.setattr("common.http_retry._sleep", sleep)
    short = iter([httpx.Response(429, headers={"retry-after": "7"}, json={}), completion("ok")])
    client, _, http = make(lambda r: next(short))
    async with http:
        assert await client.chat("s", "u") == "ok"
    assert waits == [7.0]
    waits.clear()
    client, _, http = make(lambda r: httpx.Response(429, headers={"retry-after": "53469"}, json={}))
    async with http:
        with pytest.raises(LLMError):
            await client.chat("s", "u")
    assert all(w < 20 for w in waits)


def test_the_code_budget_fits_the_providers_limit(monkeypatch):
    from common.config import get_settings
    monkeypatch.delenv("LLM_CONTEXT_CHARS", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    assert get_settings().llm_context_chars == 6_000
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_CONTEXT_CHARS", "9000")
    assert get_settings().llm_context_chars == 9000


def test_groq_provider_uses_the_chosen_model_for_everything(monkeypatch):
    from common.config import GROQ_BASE_URL, get_settings
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "g-key")
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    monkeypatch.delenv("GROQ_ASSISTANT_MODEL", raising=False)
    monkeypatch.delenv("GROQ_FALLBACK_MODEL", raising=False)
    cfg = get_settings()
    assert (cfg.llm_api_key, cfg.llm_base_url, cfg.llm_key_env) == ("g-key", GROQ_BASE_URL, "GROQ_API_KEY")
    assert cfg.llm_model == cfg.llm_assistant_model == "openai/gpt-oss-20b" and cfg.llm_fallback_model == ""


async def test_a_models_reasoning_is_not_sent_back():
    client, seen, http = make(lambda r: completion("ok"))
    async with http:
        await client.complete([{"role": "assistant", "content": "x", "reasoning": "private thoughts"}])
    assert "reasoning" not in json.loads(seen[0].content)["messages"][0]


async def test_missing_gemini_key_names_the_right_variable(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    async with httpx.AsyncClient() as http:
        with pytest.raises(LLMError, match="GEMINI_API_KEY is not configured"):
            await LLMClient(http).chat("s", "u")


# ------------------------------------------------------------------ fallback model

def _by_model(answers):
    """Client answering per requested model; records the order of models tried."""
    tried = []

    def handler(request):
        model = json.loads(request.content)["model"]
        tried.append(model)
        status = answers[model]
        return completion("ok") if status == 200 else httpx.Response(status, json={"error": "x"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), tried


def _client(http):
    return LLMClient(http, api_key="k", model="main", base_url=URL, fallback_model="lite")


async def test_overloaded_model_falls_back_once(no_sleep):
    http, tried = _by_model({"main": 503, "lite": 200})
    async with http:
        assert await _client(http).chat("s", "u") == "ok"
    assert tried == ["main", "lite"]                # no time wasted retrying the overloaded model


async def test_retired_model_falls_back_without_retrying(no_sleep):
    http, tried = _by_model({"main": 404, "lite": 200})
    async with http:
        await _client(http).chat("s", "u")
    assert tried == ["main", "lite"]


async def test_bad_key_does_not_fall_back(no_sleep):
    http, tried = _by_model({"main": 401, "lite": 200})
    async with http:
        with pytest.raises(LLMError, match="HTTP 401"):
            await _client(http).chat("s", "u")
    assert tried == ["main"]


async def test_both_models_down_raises_llm_error(no_sleep):
    http, tried = _by_model({"main": 503, "lite": 503})
    async with http:
        with pytest.raises(LLMError):
            await _client(http).chat("s", "u")
    assert tried == ["main"] + ["lite"] * 3         # the last resort still gets the full retry policy
