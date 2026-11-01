"""Shared HTTP retry policy (CLAUDE.md §14): 3 attempts, 0.5 s / 1 s / 2 s backoff.

Retries on 5xx, 429, timeouts and transport errors. Other 4xx responses are returned
to the caller untouched (they are not transient). `wait_hint` lets a caller turn a
response into an explicit wait (e.g. GitHub rate limits) or raise if waiting is pointless.
"""
import asyncio
from typing import Any, Callable, Optional, Type

import httpx

MAX_ATTEMPTS = 3
BACKOFF_SECONDS = 0.5


async def _sleep(seconds: float) -> None:
    """Indirection so tests can skip backoff without touching asyncio.sleep globally."""
    await asyncio.sleep(seconds)


async def send_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    error_cls: Type[Exception],
    label: str,
    wait_hint: Optional[Callable[[httpx.Response], Optional[float]]] = None,
    attempts: int = MAX_ATTEMPTS,
    **kwargs: Any,
) -> httpx.Response:
    delay = BACKOFF_SECONDS
    last = "unknown error"
    for attempt in range(attempts):
        wait = delay
        try:
            resp = await client.request(method, url, **kwargs)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last = type(exc).__name__
        else:
            hint = wait_hint(resp) if wait_hint else None
            if hint is not None:
                last = f"rate limited, HTTP {resp.status_code}"
                wait = hint
            elif resp.status_code >= 500 or resp.status_code == 429:
                last = f"HTTP {resp.status_code}"
            else:
                return resp
        if attempt < attempts - 1:
            await _sleep(wait)
            delay *= 2
    raise error_cls(f"{label} failed after {attempts} attempts ({last})")
