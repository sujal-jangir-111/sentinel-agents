"""Who may act on the console.

Viewing the dashboard is open. Anything that spends LLM quota or can lead to a GitHub write (assistant chat,
approve/reject) needs the operator password once CONSOLE_PASSWORD is set. Without a password the console is only
allowed on a loopback address: `exposure_error` makes the server refuse to start otherwise.
"""
import hashlib
import hmac
import ipaddress
import secrets
import time
from collections import deque
from typing import Callable, Deque, Mapping, Optional
from urllib.parse import urlsplit

COOKIE_NAME = "sentinel_operator"
SESSION_SECONDS = 12 * 60 * 60
MAX_FAILURES = 10          # failed logins allowed per FAILURE_WINDOW across all clients
FAILURE_WINDOW = 60.0
DEV_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}   # the Vite dev server


class OperatorAuth:
    def __init__(self, password: str, clock: Callable[[], float] = time.time) -> None:
        self._password = password
        self._key = secrets.token_bytes(32)     # sessions end when the server restarts
        self._clock = clock
        self._failures: Deque[float] = deque()

    @property
    def required(self) -> bool:
        return bool(self._password)

    @property
    def locked(self) -> bool:
        cutoff = self._clock() - FAILURE_WINDOW
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()
        return len(self._failures) >= MAX_FAILURES

    def login(self, password: str) -> Optional[str]:
        """A signed session token, or None for a wrong password (or while locked)."""
        if self.locked:
            return None
        if self._password and hmac.compare_digest(password.encode(), self._password.encode()):
            expires = str(int(self._clock()) + SESSION_SECONDS)
            return f"{expires}.{self._sign(expires)}"
        self._failures.append(self._clock())
        return None

    def is_operator(self, token: Optional[str]) -> bool:
        if not self.required:
            return True
        expires, _, signature = (token or "").partition(".")
        if not expires.isdigit() or not hmac.compare_digest(signature, self._sign(expires)):
            return False
        return int(expires) > self._clock()

    def _sign(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def exposure_error(host: str, password: str) -> Optional[str]:
    """Why this configuration must not start: never serve an open Approve button beyond this machine."""
    if password or is_loopback(host):
        return None
    return (f"Refusing to listen on {host} without a password: anyone who can reach this port could run incidents and "
            "approve changes. Set CONSOLE_PASSWORD, or use WEB_HOST=127.0.0.1.")


def same_origin(headers: Mapping[str, str]) -> bool:
    """False for a browser request sent by another website (CSRF, or a page hijacking the WebSocket).
    Requests with no Origin header are not from a browser page, so they carry no ambient cookie risk."""
    origin = headers.get("origin")
    if not origin or origin in DEV_ORIGINS:
        return True
    return urlsplit(origin).netloc in {headers.get("host"), headers.get("x-forwarded-host")}
