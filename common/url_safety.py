"""Is a service URL typed by a user safe for Sentinel to call?

Agents make requests from inside the deployment, so on a public host a user-supplied URL must never reach the
machine's own ports, the private network or a cloud metadata service (SSRF). Resolving DNS blocks, so call this
through asyncio.to_thread from async code.
"""
import ipaddress
import socket
from typing import Optional
from urllib.parse import urlsplit


def same_host(url: str, other: str) -> bool:
    a, b = urlsplit(url).hostname, urlsplit(other).hostname
    return bool(a and b) and a.lower() == b.lower()


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_global


def target_problem(url: str, allow_private: bool = False, known_safe_url: str = "") -> Optional[str]:
    """Why this URL must not be called, or None if it is fine."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return "that does not look like a valid URL"
    if parts.scheme not in ("http", "https") or not host:
        return "the service URL must start with http:// or https://"
    if parts.username or parts.password:
        return "the service URL must not contain a username or password"
    if allow_private or (known_safe_url and same_host(url, known_safe_url)):
        return None
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80))}
    except (OSError, UnicodeError):
        return f"I could not find a server at {host}"
    if not addresses or not all(_is_public(a) for a in addresses):
        return "that address is on a private network, so I can't reach it"
    return None
