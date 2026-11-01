"""Live "what is this agent doing" events for the web console.

Agents call `report()` at each real step of their work. It is best effort: progress reporting must never slow down
or break an incident. It is a no-op unless the web gateway can exist, which is only in local mode.
"""
from functools import lru_cache
from typing import Optional

from uagents import Context

from common.addresses import address_from_seed, gateway_seed
from common.agent_factory import local_mode
from common.models import AgentActivity

WORKING, DONE, FAILED = "working", "done", "failed"
MAX_TEXT = 220


@lru_cache(maxsize=4)
def _address_for(seed: str) -> str:
    return address_from_seed(seed)


def _gateway() -> Optional[str]:
    seed = gateway_seed()
    return _address_for(seed) if seed else None


async def report(ctx: Context, incident_id: str, agent: str, text: str, status: str = WORKING) -> None:
    """Tell the console what `agent` is doing right now. Never raises."""
    if not local_mode():
        return
    try:
        address = _gateway()
        if address:
            await ctx.send(address, AgentActivity(incident_id=incident_id, agent=agent, status=status, text=text[:MAX_TEXT]))
    except Exception as exc:
        ctx.logger.debug(f"[{incident_id}][{agent}][activity] not delivered: {exc}")
