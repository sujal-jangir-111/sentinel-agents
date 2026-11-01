"""The web gateway agent: the web console's identity on the agent network.

It sends Agent_1 structured requests and decisions, and receives incident updates from Agent_1 and live activity from
all five agents. It runs inside the web backend's event loop on port 8006 in local mode (no Agentverse mailbox), so the
agents must also run with AGENT_MAILBOX=false to reach it.
"""
import asyncio
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional, Set, Union

from uagents import Agent, Context, Model, Protocol
from uagents.resolver import RulesBasedResolver
from uagents_core.contrib.protocols.chat import ChatAcknowledgement, ChatMessage, TextContent, chat_protocol_spec

from common.addresses import agent_address, gateway_seed
from common.agent_factory import GATEWAY_PORT, NoRegistration, local_rules
from common.models import AgentActivity, IncidentRequest, IncidentUpdate

UpdateHandler = Callable[[IncidentUpdate], Awaitable[None]]
ActivityHandler = Callable[[AgentActivity], Awaitable[None]]
SEND_INTERVAL = 0.2
AGENT_KEYS = ("orchestrator", "watchdog", "detective", "scanner", "executor")


class Gateway:
    """Queue-based sender (uagents sends need a Context, which only handlers and intervals get) plus two inbound hooks."""

    def __init__(self, on_update: UpdateHandler, on_activity: ActivityHandler, seed: Optional[str] = None, port: int = GATEWAY_PORT,
                 orchestrator: Optional[str] = None, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        seed = seed or gateway_seed()
        if not seed:
            raise RuntimeError("Set GATEWAY_SEED or ORCHESTRATOR_SEED so the web gateway has a stable identity")
        self.orchestrator = orchestrator or agent_address("orchestrator")
        if not self.orchestrator:
            raise RuntimeError("Agent_1 address unknown: set ORCHESTRATOR_SEED (or ORCHESTRATOR_ADDRESS)")
        self._agents: Set[str] = {a for a in (agent_address(k) for k in AGENT_KEYS) if a}
        self._on_update, self._on_activity = on_update, on_activity
        self._outbox: "asyncio.Queue[Union[IncidentRequest, ChatMessage]]" = asyncio.Queue()
        self.agent = Agent(
            name="Sentinel-Web-Gateway", seed=seed, port=port, endpoint=[f"http://127.0.0.1:{port}/submit"],
            resolve=RulesBasedResolver(local_rules()), registration_policy=NoRegistration(), loop=loop,
            publish_agent_details=False, enable_agent_inspector=False, mark_inactive_on_shutdown=False,
            report_events=False,
        )
        self._wire()

    @property
    def address(self) -> str:
        return self.agent.address

    def send_request(self, request: IncidentRequest) -> None:
        self._outbox.put_nowait(request)

    def send_decision(self, action: str, incident_id: str) -> None:
        self._outbox.put_nowait(ChatMessage(timestamp=datetime.now(timezone.utc),
                                            content=[TextContent(text=f"{action} {incident_id}")]))

    def _wire(self) -> None:
        chat = Protocol(spec=chat_protocol_spec)

        @chat.on_message(ChatMessage)
        async def _on_chat(ctx: Context, sender: str, msg: ChatMessage) -> None:
            await ctx.send(sender, ChatAcknowledgement(timestamp=datetime.now(timezone.utc), acknowledged_msg_id=msg.msg_id))

        @chat.on_message(ChatAcknowledgement)
        async def _on_ack(ctx: Context, sender: str, msg: ChatAcknowledgement) -> None:
            return None

        self.agent.include(chat)

        @self.agent.on_message(IncidentUpdate)
        async def _on_incident(ctx: Context, sender: str, msg: IncidentUpdate) -> None:
            if sender == self.orchestrator:
                await self._on_update(msg)

        @self.agent.on_message(AgentActivity)
        async def _on_agent_activity(ctx: Context, sender: str, msg: AgentActivity) -> None:
            if sender in self._agents:
                await self._on_activity(msg)

        @self.agent.on_interval(period=SEND_INTERVAL)
        async def _flush(ctx: Context) -> None:
            while not self._outbox.empty():
                message: Model = self._outbox.get_nowait()
                await ctx.send(self.orchestrator, message)
