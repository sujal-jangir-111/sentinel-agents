"""Agent_2 agent (CLAUDE.md §5.2): burst probe, continuous polling, chaos, canary.

Run standalone:  python -m agents.Agent_2
All logic lives in the `Watchdog` class so it can be driven from pytest with a fake
context; `create_agent()` only wires it to a uagents Agent.
"""
import uuid
from typing import Any, Dict, List, Optional

import httpx
from uagents import Agent, Context

from common.activity import DONE, FAILED, report as activity
from common.addresses import agent_address
from common.agent_factory import build_agent
from common.config import get_settings
from common.logging import configure_console_utf8, log
from common.models import AgentErrorReport, HealthProbeReport, HealthProbeRequest
from common.probe import probe_service, summarize
from common.url_safety import same_host

AGENT_NAME = "Agent_2"
AGENT_LABEL = "Agent_2"  # display name on Agentverse and in uagents logs
PORT = 8002
DESCRIPTION = (
    "Agent_2 (Telemetry-Watchdog): burst-probes a service's endpoints (3 requests each), captures status, "
    "latency (p50/p95), error bodies and X-Error-File/X-Error-Line, injects chaos on demand and runs "
    "canary checks after a fix. Part of the Sentinel self-healing DevSecOps swarm (Fetch-A-Thon 3.0)."
)
DEFAULT_ENDPOINTS = ["/health", "/api/checkout"]


class Watchdog:
    def __init__(
        self,
        http: Optional[httpx.AsyncClient] = None,
        admin_token: Optional[str] = None,
        orchestrator_address: Optional[str] = None,
        targets: Optional[List[str]] = None,
        demo_url: Optional[str] = None,
    ) -> None:
        cfg = get_settings()
        self.http = http
        self.demo_url = cfg.demo_service_url if demo_url is None else demo_url
        self._owns_http = http is None
        self.admin_token = cfg.demo_admin_token if admin_token is None else admin_token
        self.orchestrator_address = orchestrator_address if orchestrator_address is not None else agent_address("orchestrator")
        self.targets = cfg.watchdog_targets if targets is None else targets

    # -- lifecycle ---------------------------------------------------------------

    async def startup(self, ctx: Context) -> None:
        if self.http is None:
            self.http = httpx.AsyncClient(timeout=10)
        ctx.logger.info(f"Address: {ctx.agent.address}")
        log(ctx.logger, "-", AGENT_NAME, "startup", f"✅ ready; {len(self.targets)} continuous target(s)")

    async def shutdown(self, ctx: Context) -> None:
        if self.http is not None and self._owns_http:
            await self.http.aclose()

    # -- A2A: HealthProbeRequest -> HealthProbeReport -------------------------------

    async def handle_probe_request(self, ctx: Context, sender: str, msg: HealthProbeRequest) -> None:
        stage = "canary" if msg.is_canary_check else "probe"
        try:
            assert self.http is not None, "http client not initialised"
            log(ctx.logger, msg.incident_id, AGENT_NAME, stage,
                f"🔍 Probing {len(msg.endpoints)} endpoint(s) on {msg.service_url}")
            await activity(ctx, msg.incident_id, AGENT_NAME, "Checking the service again to confirm the fix" if msg.is_canary_check
                           else f"Sending test requests to {', '.join(msg.endpoints[:3])}")
            # The admin token only ever goes to the configured demo service, never to a URL a user typed
            token = self.admin_token if same_host(msg.service_url, self.demo_url) else ""
            report, chaos_ok = await probe_service(self.http, msg, token)
            if msg.inject_chaos:
                log(ctx.logger, msg.incident_id, AGENT_NAME, "chaos",
                    "💥 fault injected" if chaos_ok else "chaos injection failed (continuing with probe)",
                    level="info" if chaos_ok else "warning")
            self._log_report(ctx, report)
            await activity(ctx, msg.incident_id, AGENT_NAME, self._outcome(report), DONE)
            await ctx.send(sender, report)
        except Exception as exc:  # handlers never raise
            log(ctx.logger, msg.incident_id, AGENT_NAME, stage, f"error: {type(exc).__name__}: {exc}", level="error")
            await activity(ctx, msg.incident_id, AGENT_NAME, "Could not check the service", FAILED)
            await self._send_error(ctx, sender, msg.incident_id, stage, exc)

    # -- continuous mode ---------------------------------------------------------------

    async def poll_targets(self, ctx: Context) -> None:
        """Probe every WATCHDOG_TARGETS URL; alert only on a healthy -> unhealthy transition."""
        for url in self.targets:
            try:
                await self._poll_one(ctx, url)
            except Exception as exc:
                log(ctx.logger, "-", AGENT_NAME, "poll", f"error polling {url}: {type(exc).__name__}: {exc}", level="error")

    async def _poll_one(self, ctx: Context, url: str) -> None:
        assert self.http is not None, "http client not initialised"
        request = HealthProbeRequest(incident_id=f"auto-{uuid.uuid4().hex[:8]}", service_url=url, endpoints=DEFAULT_ENDPOINTS)
        report, _ = await probe_service(self.http, request)
        key = f"health:{url}"
        previous = ctx.storage.get(key)  # None = never seen; treated as healthy so a down-at-start target alerts once
        ctx.storage.set(key, report.is_healthy)
        if report.is_healthy or previous is False:
            return
        log(ctx.logger, report.incident_id, AGENT_NAME, "poll", f"🚨 {url} turned unhealthy")
        self._log_report(ctx, report)
        if self.orchestrator_address:
            await ctx.send(self.orchestrator_address, report)
        else:
            log(ctx.logger, report.incident_id, AGENT_NAME, "poll", "ORCHESTRATOR_SEED not set; alert not delivered", level="warning")

    # -- helpers ------------------------------------------------------------------------

    @staticmethod
    def _outcome(report: HealthProbeReport) -> str:
        if report.is_healthy:
            return f"All {len(report.metrics)} test requests succeeded"
        bad = [m for m in report.metrics if not 200 <= m.status_code < 300]
        first = bad[0]
        what = "could not be reached" if first.status_code == 0 else f"returned error {first.status_code}"
        return f"{first.endpoint} {what} ({len(bad)} of {len(report.metrics)} requests failed)"

    def _log_report(self, ctx: Context, report: HealthProbeReport) -> None:
        s = summarize(report.metrics)
        by_ep: Dict[str, List[int]] = {}
        for m in report.metrics:
            by_ep.setdefault(m.endpoint, []).append(m.status_code)
        codes = ", ".join(f"{ep}→{'/'.join(map(str, c))}" for ep, c in by_ep.items())
        verdict = "healthy ✅" if report.is_healthy else "UNHEALTHY ❌"
        log(ctx.logger, report.incident_id, AGENT_NAME, "report",
            f"{verdict} | {codes} | p50={s['p50_ms']:.0f}ms p95={s['p95_ms']:.0f}ms "
            f"failing={int(s['failing'])}/{int(s['total'])}")

    async def _send_error(self, ctx: Context, sender: str, incident_id: str, stage: str, exc: Exception) -> None:
        try:
            await ctx.send(sender, AgentErrorReport(
                incident_id=incident_id, agent=AGENT_NAME, stage=stage, error=f"{type(exc).__name__}: {exc}"[:500],
            ))
        except Exception as send_exc:
            log(ctx.logger, incident_id, AGENT_NAME, stage, f"could not deliver error report: {send_exc}", level="error")


def create_agent(
    seed: Optional[str] = None,
    mailbox: bool = True,
    port: int = PORT,
    watchdog: Optional[Watchdog] = None,
    **agent_kwargs: Any,
) -> Agent:
    """Build the uagents Agent. Live runs use mailbox=True and the WATCHDOG_SEED from .env;
    tests pass mailbox=False and an explicit seed."""
    cfg = get_settings()
    wd = watchdog or Watchdog()
    agent = build_agent(
        name=AGENT_LABEL, seed=seed or cfg.watchdog_seed, seed_env="WATCHDOG_SEED", port=port,
        description=DESCRIPTION, mailbox=mailbox, **agent_kwargs,
    )

    @agent.on_event("startup")
    async def _startup(ctx: Context) -> None:
        await wd.startup(ctx)

    @agent.on_event("shutdown")
    async def _shutdown(ctx: Context) -> None:
        await wd.shutdown(ctx)

    @agent.on_message(HealthProbeRequest)
    async def _on_probe(ctx: Context, sender: str, msg: HealthProbeRequest) -> None:
        await wd.handle_probe_request(ctx, sender, msg)

    @agent.on_interval(period=float(cfg.watchdog_interval_seconds))
    async def _poll(ctx: Context) -> None:
        await wd.poll_targets(ctx)

    agent.watchdog = wd  # type: ignore[attr-defined]
    return agent


if __name__ == "__main__":
    configure_console_utf8()
    create_agent(mailbox=True).run()
