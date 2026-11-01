"""Agent addresses, derived from the seeds in .env (or overridden by <NAME>_ADDRESS env vars)."""
import os
from typing import Dict, Optional

from uagents.crypto import Identity

from common.config import get_settings

AGENT_KEYS = ("orchestrator", "watchdog", "detective", "scanner", "executor")


def address_from_seed(seed: str) -> str:
    """The agent1q... address uagents assigns to this seed (wallet index 0)."""
    return Identity.from_seed(seed, 0).address


def agent_address(key: str) -> Optional[str]:
    """Address of an agent by key ('orchestrator', 'watchdog', ...); None if neither
    an explicit `<KEY>_ADDRESS` env var nor the agent's seed is configured."""
    if key not in AGENT_KEYS:
        raise KeyError(f"unknown agent key {key!r}")
    override = os.getenv(f"{key.upper()}_ADDRESS", "").strip()
    if override:
        return override
    seed = getattr(get_settings(), f"{key}_seed")
    return address_from_seed(seed) if seed else None


def all_addresses() -> Dict[str, Optional[str]]:
    return {key: agent_address(key) for key in AGENT_KEYS}


def gateway_seed() -> str:
    """Seed of the web gateway agent: GATEWAY_SEED, else derived from ORCHESTRATOR_SEED (stable, never printed)."""
    explicit = os.getenv("GATEWAY_SEED", "").strip()
    if explicit:
        return explicit
    base = get_settings().orchestrator_seed
    return f"{base}/web-gateway" if base else ""


def gateway_address() -> Optional[str]:
    seed = gateway_seed()
    return address_from_seed(seed) if seed else None
