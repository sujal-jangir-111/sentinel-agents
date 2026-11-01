from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from agents.Agent_2 import Watchdog, create_agent
from common import probe
from common.addresses import address_from_seed, agent_address
from common.models import (
    AgentErrorReport, EndpointMetric, HealthProbeReport, HealthProbeRequest,
)
from demo_target_app import app as demo
from tests.bureau_harness import agent_test_kwargs, run_roundtrip

TOKEN = "wd-test-token"
ORCH = "agent1qorchestratoraddress"
DEMO_SRC = Path(demo.__file__).read_text(encoding="utf-8").splitlines()
FAULT_LINE = next(i for i, ln in enumerate(DEMO_SRC, 1) if 'PRICING["discount_rate"]' in ln)


@pytest.fixture(autouse=True)
def _demo_state(monkeypatch):
    monkeypatch.setenv("DEMO_ADMIN_TOKEN", TOKEN)
    demo.PATCHED = False
    yield
    demo.PATCHED = False


@pytest_asyncio.fixture
async def demo_http():
    """httpx client wired straight to the demo app (no sockets)."""
    transport = httpx.ASGITransport(app=demo.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://demo") as c:
        yield c


def make_watchdog(http, **kw) -> Watchdog:
    return Watchdog(http=http, admin_token=kw.pop("admin_token", TOKEN), demo_url=kw.pop("demo_url", req().service_url),
                    orchestrator_address=kw.pop("orchestrator_address", ORCH), targets=kw.pop("targets", []))


def req(**kw) -> HealthProbeRequest:
    return HealthProbeRequest(incident_id=kw.pop("incident_id", "inc-test"), service_url="http://demo", **kw)


def reports(ctx):
    return [m for _, m in ctx.sent if isinstance(m, HealthProbeReport)]


# ------------------------------------------------------------------ demo app: before / after hotfix

async def test_unhealthy_before_hotfix_reports_keyerror_at_fault_line(demo_http, ctx):
    wd = make_watchdog(demo_http)
    await wd.handle_probe_request(ctx, "agent1qsender", req())
    (dest, report), = ctx.sent
    assert dest == "agent1qsender" and isinstance(report, HealthProbeReport)
    assert report.is_healthy is False and report.is_canary_check is False
    health = [m for m in report.metrics if m.endpoint == "/health"]
    checkout = [m for m in report.metrics if m.endpoint == "/api/checkout"]
    assert len(health) == 3 and len(checkout) == 3  # burst of 3 per endpoint
    assert all(m.status_code == 200 and m.error_snippet is None for m in health)
    for m in checkout:
        assert m.status_code == 500 and m.latency_ms > 0 and m.timestamp_utc.endswith("+00:00")
        assert "KeyError" in m.error_snippet and "'discount_rate'" in m.error_snippet
        assert probe.parse_error_snippet(m.error_snippet) == ("app.py", FAULT_LINE)


async def test_healthy_after_hotfix_and_canary_flag_echoed(demo_http, ctx):
    wd = make_watchdog(demo_http)
    assert (await demo_http.post("/admin/apply-hotfix", headers={"X-Sentinel-Token": TOKEN})).status_code == 200
    await wd.handle_probe_request(ctx, "agent1qsender", req(is_canary_check=True))
    report, = reports(ctx)
    assert report.is_healthy is True and report.is_canary_check is True
    assert {m.status_code for m in report.metrics} == {200}
    assert all(m.error_snippet is None for m in report.metrics)


async def test_chaos_injection_breaks_a_patched_service(demo_http, ctx):
    wd = make_watchdog(demo_http)
    await demo_http.post("/admin/apply-hotfix", headers={"X-Sentinel-Token": TOKEN})
    await wd.handle_probe_request(ctx, "s", req(inject_chaos=True))
    report, = reports(ctx)
    assert report.is_healthy is False
    assert {m.status_code for m in report.metrics if m.endpoint == "/api/checkout"} == {500}


async def test_admin_token_is_never_sent_to_a_url_a_user_typed(demo_http, ctx):
    """Regression: the chaos call used to post the demo token to any service URL."""
    wd = make_watchdog(demo_http, demo_url="http://the-configured-demo.example")
    await demo_http.post("/admin/apply-hotfix", headers={"X-Sentinel-Token": TOKEN})
    await wd.handle_probe_request(ctx, "s", req(inject_chaos=True))
    report, = reports(ctx)
    assert report.is_healthy is True                                  # the token was withheld, so nothing was broken


async def test_chaos_with_wrong_token_does_not_break_probe(demo_http, ctx):
    wd = make_watchdog(demo_http, admin_token="wrong")
    await demo_http.post("/admin/apply-hotfix", headers={"X-Sentinel-Token": TOKEN})
    await wd.handle_probe_request(ctx, "s", req(inject_chaos=True))
    report, = reports(ctx)
    assert report.is_healthy is True  # chaos refused (401), service untouched, probe still ran


# ------------------------------------------------------------------ probe unit tests

def mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_network_errors_become_status_zero_without_raising():
    def boom(request):
        raise httpx.ConnectError("name resolution failed", request=request)

    async with mock_client(boom) as c:
        metrics = await probe.run_burst(c, "https://nowhere.invalid", ["/health"])
    assert len(metrics) == 3 and all(m.status_code == 0 for m in metrics)
    assert metrics[0].error_snippet.startswith("ConnectError")
    assert probe.is_healthy(metrics) is False


async def test_timeout_and_garbage_url_are_status_zero():
    def slow(request):
        raise httpx.ReadTimeout("too slow", request=request)

    async with mock_client(slow) as c:
        m = await probe.probe_once(c, "https://x.test", "/health")
        assert m.status_code == 0 and m.error_snippet.startswith("ReadTimeout")
        bad = await probe.probe_once(c, "not a url", "/health")
        assert bad.status_code == 0 and bad.error_snippet


async def test_snippet_truncated_to_1000_with_headers_kept_and_secrets_masked():
    body = "x" * 5000 + " sk_test_51SENTINELDEMOxxxxxxxx"

    def handler(request):
        return httpx.Response(500, text=body, headers={"X-Error-File": "app.py", "X-Error-Line": "42"})

    async with mock_client(handler) as c:
        m = await probe.probe_once(c, "https://x.test", "/api")
    assert len(m.error_snippet) <= 1000 and probe.parse_error_snippet(m.error_snippet) == ("app.py", 42)
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in m.error_snippet


async def test_redirects_followed_and_slow_latency_measured():
    def handler(request):
        if request.url.path == "/old":
            return httpx.Response(301, headers={"location": "/new"})
        return httpx.Response(200, json={"ok": True})

    async with mock_client(handler) as c:
        m = await probe.probe_once(c, "https://x.test/", "old")
    assert m.status_code == 200 and m.latency_ms >= 0


def test_percentiles_and_summary():
    assert probe.percentile([], 95) == 0.0
    assert probe.percentile([10, 20, 30, 40, 50, 60], 50) == 30
    assert probe.percentile([10, 20, 30, 40, 50, 60], 95) == 60
    ms = [EndpointMetric(endpoint="/a", status_code=c, latency_ms=l, timestamp_utc="t") for c, l in [(200, 10), (500, 30), (0, 20)]]
    s = probe.summarize(ms)
    assert s["failing"] == 2 and s["total"] == 3 and s["p50_ms"] == 20 and s["p95_ms"] == 30
    assert probe.is_healthy([]) is False


def test_parse_error_snippet_edge_cases():
    assert probe.parse_error_snippet(None) == (None, None)
    assert probe.parse_error_snippet("HTTP 500 boom") == (None, None)
    assert probe.parse_error_snippet("x\nX-Error-File: a/b.py\nX-Error-Line: 7") == ("a/b.py", 7)


# ------------------------------------------------------------------ handler error path

async def test_handler_never_raises_and_sends_agent_error_report(ctx):
    wd = make_watchdog(None)  # http client not initialised -> internal failure
    await wd.handle_probe_request(ctx, "agent1qsender", req(incident_id="inc-err"))
    (dest, err), = ctx.sent
    assert dest == "agent1qsender" and isinstance(err, AgentErrorReport)
    assert err.incident_id == "inc-err" and err.agent == "Agent_2" and err.stage == "probe"


# ------------------------------------------------------------------ continuous mode

async def test_poll_alerts_only_on_healthy_to_unhealthy_transition(demo_http, ctx):
    wd = make_watchdog(demo_http, targets=["http://demo"])
    await wd.poll_targets(ctx)  # first sighting, already broken -> alert once
    assert len(ctx.sent) == 1
    dest, alert = ctx.sent[0]
    assert dest == ORCH and alert.incident_id.startswith("auto-") and alert.is_healthy is False

    await wd.poll_targets(ctx)  # still broken -> no spam
    assert len(ctx.sent) == 1

    await demo_http.post("/admin/apply-hotfix", headers={"X-Sentinel-Token": TOKEN})
    await wd.poll_targets(ctx)  # recovered -> silent
    assert len(ctx.sent) == 1

    await demo_http.post("/admin/simulate-fault", headers={"X-Sentinel-Token": TOKEN})
    await wd.poll_targets(ctx)  # healthy -> unhealthy again -> alert
    assert len(ctx.sent) == 2 and ctx.sent[1][1].incident_id != alert.incident_id


async def test_poll_without_orchestrator_logs_and_does_not_raise(demo_http, ctx):
    wd = make_watchdog(demo_http, targets=["http://demo"], orchestrator_address="")
    await wd.poll_targets(ctx)
    assert ctx.sent == []


async def test_poll_survives_unreachable_target(ctx):
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    async with mock_client(boom) as c:
        wd = make_watchdog(c, targets=["https://down.invalid"])
        await wd.poll_targets(ctx)
    assert len(ctx.sent) == 1 and ctx.sent[0][1].metrics[0].status_code == 0


# ------------------------------------------------------------------ agent wiring + addresses

def test_create_agent_requires_seed(monkeypatch):
    monkeypatch.delenv("WATCHDOG_SEED", raising=False)
    with pytest.raises(RuntimeError, match="WATCHDOG_SEED"):
        create_agent(mailbox=False)


async def test_create_agent_wiring_and_mailbox_flag():
    agent = create_agent(seed="wiring test seed", mailbox=False, enable_agent_inspector=False)
    assert agent.name == "Agent_2" and agent.address == address_from_seed("wiring test seed")
    assert agent.mailbox_client is None
    live = create_agent(seed="wiring test seed", mailbox=True, enable_agent_inspector=False)
    assert live.mailbox_client is not None


def test_agent_address_env_override_and_seed(monkeypatch):
    monkeypatch.delenv("DETECTIVE_ADDRESS", raising=False)
    monkeypatch.setenv("DETECTIVE_SEED", "detective seed")
    assert agent_address("detective") == address_from_seed("detective seed")
    monkeypatch.setenv("DETECTIVE_ADDRESS", "agent1qexplicit")
    assert agent_address("detective") == "agent1qexplicit"
    monkeypatch.delenv("DETECTIVE_ADDRESS")
    monkeypatch.delenv("DETECTIVE_SEED")
    assert agent_address("detective") is None
    with pytest.raises(KeyError):
        agent_address("nobody")


# ------------------------------------------------------------------ real uagents round trip (local Bureau)

def test_round_trip_between_real_agents_in_a_local_bureau():
    """A requester agent sends HealthProbeRequest to the real Watchdog agent and gets the report back,
    exercising uagents message routing without any mailbox or network registration."""

    async def make_target(port: int):
        transport = httpx.ASGITransport(app=demo.app, raise_app_exceptions=False)
        http = httpx.AsyncClient(transport=transport, base_url="http://demo")
        return create_agent(seed="bureau watchdog seed", port=port, watchdog=make_watchdog(http), **agent_test_kwargs())

    target_addr, sender, report = run_roundtrip(
        make_target, lambda: HealthProbeRequest(incident_id="inc-bureau", service_url="http://demo"))
    assert sender == target_addr and report.incident_id == "inc-bureau"
    assert report.is_healthy is False
    assert {(m.endpoint, m.status_code) for m in report.metrics} == {("/health", 200), ("/api/checkout", 500)}
