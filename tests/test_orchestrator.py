import json
from dataclasses import replace
from typing import List, Optional

import pytest
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement, ChatMessage, EndSessionContent, StartSessionContent, TextContent, chat_protocol_spec,
)

from agents.Agent_1 import Orchestrator, create_agent, make_chat
from common.llm_client import ASI1Client
from common.config import Settings
from common.models import (
    AgentErrorReport, CommitCorrelationRequest, HealthProbeRequest, PatchDraftRequest, VulnerabilityScanRequest,
)
from tests.conftest import FakeContext
from tests.fakes import (
    ASI1_URL, ERROR_SNIPPET, FakeWeb, llm_reply, make_evidence, make_patch_result, make_probe_report, make_vuln_report,
)

USER = "agent1quserquserquserquserquserquserquserquserquser"
USER2 = "agent1qotheruserotheruserotheruserotheruserother"
ADDR = {"watchdog": "agent1qwatchdogwatchdogwatchdogwatchdogwatchdog", "detective": "agent1qdetectivedetectivedetectivedetectivedetec",
        "scanner": "agent1qscannerscannerscannerscannerscannerscanner", "executor": "agent1qexecutorexecutorexecutorexecutorexecutor"}
EMPTY = replace(Settings(), demo_repo_full_name="", demo_service_url="", skip_payment=False)
REPO = "acme/sentinel-target"
URL = "http://demo"
HEAL = f"Diagnose and heal the outage on {URL} for repo {REPO}"


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


def make_orch(settings: Settings = EMPTY, skip_payment: bool = True, llm: Optional[ASI1Client] = None, clock: Optional[Clock] = None, **kw):
    return Orchestrator(addresses=ADDR, llm=llm, skip_payment=skip_payment, settings=settings, clock=clock or Clock(), **kw)


def chat(text: str) -> ChatMessage:
    return ChatMessage(content=[TextContent(text=text)])


def texts(ctx: FakeContext, user: str = USER) -> List[str]:
    return [m.text() for d, m in ctx.sent if d == user and isinstance(m, ChatMessage)]


def sent(ctx: FakeContext, dest: str, kind: type) -> list:
    return [m for d, m in ctx.sent if d == dest and isinstance(m, kind)]


def incident_id(ctx: FakeContext) -> str:
    return sent(ctx, ADDR["watchdog"], HealthProbeRequest)[-1].incident_id


def stored(ctx: FakeContext, inc_id: str) -> dict:
    return json.loads(ctx.storage.get(f"inc:{inc_id}"))


async def start(orch, ctx, text=HEAL, user=USER) -> str:
    await orch.handle_chat(ctx, user, chat(text))
    return incident_id(ctx)


async def to_awaiting_approval(orch, ctx, **patch_kw) -> str:
    inc = await start(orch, ctx)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc))
    await orch.handle_evidence(ctx, ADDR["detective"], make_evidence(inc))
    await orch.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(inc))
    await orch.handle_patch_result(ctx, ADDR["executor"], make_patch_result(inc, **patch_kw))
    return inc


# ------------------------------------------------------------------ Sentinel's own fix must never be undone

MERGED_FIX = "Merge pull request #2 from me/sentinel/fix-inc-51626f69\n\nSentinel inc-51626f69: fix app.py"
MERGED_ROLLBACK = "Merge pull request #3 from me/sentinel/fix-inc-d5faec4b\n\nSentinel inc-d5faec4b: roll back app.py"


def blaming(inc: str, message: str):
    evidence = make_evidence(inc)
    return type(evidence).model_validate({**evidence.dict(), "commit_message": message})


async def test_merged_sentinel_fix_is_not_patched_or_rolled_back(ctx):
    """Regression (live): a chaos test after the fix was merged blamed the fix, and Sentinel offered to roll it back."""
    orch = make_orch()
    inc = await start(orch, ctx)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc))
    await orch.handle_evidence(ctx, ADDR["detective"], blaming(inc, MERGED_FIX))
    assert stored(ctx, inc)["state"] == "FAILED"
    assert sent(ctx, ADDR["scanner"], VulnerabilityScanRequest) == [] and sent(ctx, ADDR["executor"], PatchDraftRequest) == []
    last = texts(ctx)[-1]
    assert "Nothing to patch" in last and "Sentinel inc-51626f69: fix app.py" in last and "Redeploy" in last
    await orch.handle_chat(ctx, USER, chat("rollback"))                             # and no rollback can be authorized
    assert stored(ctx, inc)["state"] == "FAILED" and "Nothing is waiting" in texts(ctx)[-1]


async def test_a_merged_rollback_is_still_treated_as_a_real_cause(ctx):
    """A rollback really can bring a bug back, so it must go through the normal patch flow."""
    orch = make_orch()
    inc = await start(orch, ctx)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc))
    await orch.handle_evidence(ctx, ADDR["detective"], blaming(inc, MERGED_ROLLBACK))
    assert stored(ctx, inc)["state"] == "SCANNING" and len(sent(ctx, ADDR["scanner"], VulnerabilityScanRequest)) == 1


async def test_a_security_audit_still_runs_when_the_newest_commit_is_a_sentinel_fix(ctx):
    orch = make_orch()
    await orch.handle_chat(ctx, USER, chat(f"security audit of {REPO}"))
    inc = sent(ctx, ADDR["detective"], CommitCorrelationRequest)[0].incident_id
    await orch.handle_evidence(ctx, ADDR["detective"], blaming(inc, MERGED_FIX))
    assert stored(ctx, inc)["state"] == "SCANNING"


# ------------------------------------------------------------------ chat protocol basics

async def test_every_chat_message_is_acknowledged_first(ctx):
    msg = chat("hello there")
    await make_orch().handle_chat(ctx, USER, msg)
    (dest, ack) = ctx.sent[0]
    assert dest == USER and isinstance(ack, ChatAcknowledgement) and ack.acknowledged_msg_id == msg.msg_id
    assert "Sentinel" in texts(ctx)[0] and "approve" in texts(ctx)[0]            # then the help text


async def test_session_start_without_text_greets_and_end_session_flag_is_set_on_final_replies(ctx):
    await make_orch().handle_chat(ctx, USER, ChatMessage(content=[StartSessionContent()]))
    assert len(texts(ctx)) == 1 and "security audit" in texts(ctx)[0]
    final = make_chat("bye", end_session=True)
    assert isinstance(final.content[-1], EndSessionContent) and not any(isinstance(c, EndSessionContent) for c in make_chat("hi").content)


async def test_empty_message_is_acked_and_otherwise_ignored(ctx):
    await make_orch().handle_chat(ctx, USER, ChatMessage(content=[]))
    assert len(ctx.sent) == 1 and isinstance(ctx.sent[0][1], ChatAcknowledgement)


async def test_acknowledgements_from_the_user_are_ignored(ctx):
    await make_orch().handle_ack(ctx, USER, ChatAcknowledgement(acknowledged_msg_id=chat("x").msg_id))
    assert ctx.sent == []


# ------------------------------------------------------------------ starting incidents

async def test_heal_request_probes_the_service(ctx):
    orch = make_orch()
    inc = await start(orch, ctx)
    (req,) = sent(ctx, ADDR["watchdog"], HealthProbeRequest)
    assert req.service_url == URL and req.inject_chaos is False and inc.startswith("inc-") and len(inc) == 12
    assert "Probing" in texts(ctx)[-1] and inc in texts(ctx)[-1]
    s = stored(ctx, inc)
    assert (s["state"], s["mode"], s["repo"], s["user"]) == ("PROBING", "diagnose_and_heal", REPO, USER)


async def test_chaos_request_injects_the_fault(ctx):
    inc = await start(make_orch(), ctx, f"chaos test {URL} for repo {REPO}")
    assert sent(ctx, ADDR["watchdog"], HealthProbeRequest)[0].inject_chaos is True
    assert stored(ctx, inc)["mode"] == "chaos_test" and "Injecting the demo fault" in texts(ctx)[-1]


async def test_security_audit_skips_probing_and_goes_to_the_detective(ctx):
    await make_orch().handle_chat(ctx, USER, chat(f"run a security audit of {REPO}"))
    assert sent(ctx, ADDR["watchdog"], HealthProbeRequest) == []
    (req,) = sent(ctx, ADDR["detective"], CommitCorrelationRequest)
    assert req.repo_full_name == REPO and req.error_snippet is None
    assert stored(ctx, req.incident_id)["state"] == "CORRELATING"


async def test_missing_details_are_requested_unless_configured_defaults_exist(ctx):
    orch = make_orch()
    await orch.handle_chat(ctx, USER, chat("please heal my broken service"))
    assert "owner/repo" in texts(ctx)[-1] and sent(ctx, ADDR["watchdog"], HealthProbeRequest) == []
    defaults = replace(EMPTY, demo_repo_full_name="org/demo", demo_service_url="https://demo.example")
    ctx2 = FakeContext()
    await make_orch(defaults).handle_chat(ctx2, USER, chat("please heal my broken service"))
    (req,) = sent(ctx2, ADDR["watchdog"], HealthProbeRequest)
    assert req.service_url == "https://demo.example" and "configured" in texts(ctx2)[-1] and "org/demo" in texts(ctx2)[-1]


async def test_llm_intent_fallback_only_when_regex_finds_nothing(ctx):
    web = FakeWeb()
    web.llm = lambda r: llm_reply(json.dumps({"mode": "security_audit", "repo_full_name": REPO, "service_url": None}))
    llm = ASI1Client(web.client(), api_key="k", base_url=ASI1_URL)
    await make_orch(llm=llm).handle_chat(ctx, USER, chat(f"could you take a look at {REPO} please"))
    assert len(sent(ctx, ADDR["detective"], CommitCorrelationRequest)) == 1 and web.count("api.asi1.ai") == 1
    ctx2, web2 = FakeContext(), FakeWeb()
    web2.llm = lambda r: llm_reply(json.dumps({"mode": "diagnose_and_heal"}))
    await make_orch(llm=ASI1Client(web2.client(), api_key="k", base_url=ASI1_URL)).handle_chat(ctx2, USER, chat(HEAL))
    assert web2.count("api.asi1.ai") == 0                                         # regex succeeded: no LLM call


async def test_llm_failure_or_nonsense_falls_back_to_help(ctx):
    web = FakeWeb()                                                                # default fake LLM answers 401
    llm = ASI1Client(web.client(), api_key="k", base_url=ASI1_URL)
    await make_orch(llm=llm).handle_chat(ctx, USER, chat("what is the meaning of life"))
    assert "Try:" in texts(ctx)[-1]
    web.llm = lambda r: llm_reply(json.dumps({"mode": "launch_missiles"}))
    await make_orch(llm=llm).handle_chat(ctx, USER, chat("do something drastic"))
    assert "Try:" in texts(ctx)[-1]


# ------------------------------------------------------------------ the full lifecycle, step by step

async def test_full_lifecycle_to_approval(ctx):
    orch = make_orch()
    inc = await start(orch, ctx)

    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc))
    (corr,) = sent(ctx, ADDR["detective"], CommitCorrelationRequest)
    assert (corr.incident_id, corr.repo_full_name, corr.failing_endpoint, corr.error_snippet) == (inc, REPO, "/api/checkout", ERROR_SNIPPET)
    assert corr.failure_timestamp_utc == "2026-01-02T12:00:00+00:00" and stored(ctx, inc)["state"] == "CORRELATING"
    assert "HTTP 500" in texts(ctx)[-1] and "3/6" in texts(ctx)[-1]

    await orch.handle_evidence(ctx, ADDR["detective"], make_evidence(inc))
    (scan,) = sent(ctx, ADDR["scanner"], VulnerabilityScanRequest)
    assert (scan.modified_files, scan.suspect_commit_sha[:7]) == (["app.py"], "c0ffee1") and "yaml.load" in scan.active_ast_imports
    assert "Commit [`c0ffee1`]" in texts(ctx)[-1] and "@alice" in texts(ctx)[-1] and stored(ctx, inc)["state"] == "SCANNING"

    await orch.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(inc))
    (draft,) = sent(ctx, ADDR["executor"], PatchDraftRequest)
    assert draft.commit_evidence.offending_file == "app.py" and draft.vuln_report.total_reachable_critical == 1
    assert "3 CVE(s) (2 reachable, 1 reachable CRITICAL)" in texts(ctx)[-1] and stored(ctx, inc)["state"] == "PATCHING"

    await orch.handle_patch_result(ctx, ADDR["executor"], make_patch_result(inc, attempts=2))
    cardtext = texts(ctx)[-1]
    for needle in ("Sentinel Incident", "Blast score", "$4,320", "attempt 2/3", "ab12cd34ef567890…", "```diff", "Reply **approve**", "SKIP_PAYMENT"):
        assert needle in cardtext, needle
    assert stored(ctx, inc)["state"] == "AWAITING_APPROVAL" and stored(ctx, inc)["action_type"] == "OPEN_PR_AND_HOTFIX"

    await orch.handle_chat(ctx, USER, chat("approve"))
    assert "Change authorized" in texts(ctx)[-1] and "OPEN_PR_AND_HOTFIX" in texts(ctx)[-1]
    s = stored(ctx, inc)
    assert s["state"] == "EXECUTING" and s["authorized_by"] == USER and s["authorization"].startswith("skipped")


async def test_user_can_reject_and_the_session_ends(ctx):
    orch = make_orch()
    inc = await to_awaiting_approval(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("no thanks, reject it"))
    last = [m for d, m in ctx.sent if d == USER and isinstance(m, ChatMessage)][-1]
    assert "cancelled" in last.text() and isinstance(last.content[-1], EndSessionContent)
    assert stored(ctx, inc)["state"] == "CANCELLED"
    await orch.handle_chat(ctx, USER, chat("approve"))                              # too late: nothing is waiting
    assert "Nothing is waiting" in texts(ctx)[-1] and stored(ctx, inc)["state"] == "CANCELLED"


async def test_rejected_patch_offers_rollback_only(ctx):
    orch = make_orch()
    inc = await to_awaiting_approval(orch, ctx, approved=False, attempts=3)
    assert "No safe patch after 3 attempt(s)" in texts(ctx)[-1] and stored(ctx, inc)["action_type"] == "ROLLBACK_COMMIT"
    await orch.handle_chat(ctx, USER, chat("approve"))                              # approving a non-existent patch is refused
    assert "only option is a **rollback**" in texts(ctx)[-1] and stored(ctx, inc)["state"] == "AWAITING_APPROVAL"
    await orch.handle_chat(ctx, USER, chat("rollback"))
    assert "ROLLBACK_COMMIT" in texts(ctx)[-1] and stored(ctx, inc)["state"] == "EXECUTING"


async def test_rollback_is_refused_when_a_vetted_patch_exists(ctx):
    orch = make_orch()
    inc = await to_awaiting_approval(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("rollback"))
    assert "no rollback is needed" in texts(ctx)[-1] and stored(ctx, inc)["state"] == "AWAITING_APPROVAL"


async def test_no_patch_and_no_rollback_ends_the_incident(ctx):
    inc = await to_awaiting_approval(make_orch(), ctx, approved=False, rollback=False)
    assert stored(ctx, inc)["state"] == "FAILED" and "No rollback is available" in texts(ctx)[-1]


async def test_healthy_service_is_reported_and_an_audit_is_offered(ctx):
    orch = make_orch()
    inc = await start(orch, ctx)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc, healthy=True))
    assert "healthy" in texts(ctx)[-1] and f"security audit of {REPO}" in texts(ctx)[-1]
    assert stored(ctx, inc)["state"] == "RESOLVED" and sent(ctx, ADDR["detective"], CommitCorrelationRequest) == []


async def test_unreachable_service_is_explained_not_correlated(ctx):
    orch = make_orch()
    inc = await start(orch, ctx)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc, status=0))
    assert "unreachable" in texts(ctx)[-1] and "Recovery" in texts(ctx)[-1]
    assert stored(ctx, inc)["state"] == "FAILED" and sent(ctx, ADDR["detective"], CommitCorrelationRequest) == []


async def test_security_audit_lifecycle_ends_with_a_report(ctx):
    orch = make_orch()
    await orch.handle_chat(ctx, USER, chat(f"security audit of {REPO}"))
    inc = sent(ctx, ADDR["detective"], CommitCorrelationRequest)[0].incident_id
    await orch.handle_evidence(ctx, ADDR["detective"], make_evidence(inc))
    assert len(sent(ctx, ADDR["scanner"], VulnerabilityScanRequest)) == 1
    await orch.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(inc))
    last = [m for d, m in ctx.sent if d == USER and isinstance(m, ChatMessage)][-1]
    assert "Security Audit" in last.text() and isinstance(last.content[-1], EndSessionContent)
    assert sent(ctx, ADDR["executor"], PatchDraftRequest) == [] and stored(ctx, inc)["state"] == "RESOLVED"


# ------------------------------------------------------------------ guards, errors, never raising

async def test_messages_from_unexpected_senders_unknown_incidents_or_wrong_stage_are_ignored(ctx):
    orch = make_orch()
    inc = await start(orch, ctx)
    before = len(ctx.sent)
    await orch.handle_probe_report(ctx, "agent1qattacker", make_probe_report(inc))             # spoofed sender
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report("inc-deadbeef"))   # unknown incident
    await orch.handle_evidence(ctx, ADDR["detective"], make_evidence(inc))                     # wrong stage
    await orch.handle_vuln_report(ctx, ADDR["detective"], make_vuln_report(inc))               # wrong sender for this type
    assert len(ctx.sent) == before and stored(ctx, inc)["state"] == "PROBING"
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc))
    n = len(ctx.sent)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc))              # duplicate delivery
    assert len(ctx.sent) == n


@pytest.mark.parametrize("agent,stage_state,hint", [
    ("Agent_2", "PROBING", "service URL is reachable"),
    ("Agent_3", "CORRELATING", "GitHub token"),
    ("Agent_4", "SCANNING", "OSV.dev"),
    ("Agent_5", "PATCHING", "Nothing was merged"),
])
async def test_agent_error_reports_become_clear_recoverable_messages(ctx, agent, stage_state, hint):
    orch = make_orch()
    inc = await start(orch, ctx)
    s = stored(ctx, inc)
    s["state"] = stage_state
    ctx.storage.set(f"inc:{inc}", json.dumps(s))
    sender = ADDR[{"Agent_2": "watchdog", "Agent_3": "detective", "Agent_4": "scanner", "Agent_5": "executor"}[agent]]
    await orch.handle_agent_error(ctx, "agent1qstranger", AgentErrorReport(incident_id=inc, agent=agent, stage="x", error="boom"))
    assert stored(ctx, inc)["state"] == stage_state                                            # strangers cannot fail incidents
    await orch.handle_agent_error(ctx, sender, AgentErrorReport(incident_id=inc, agent=agent, stage="gatekeeper", error="OSVError: down"))
    last = [m for d, m in ctx.sent if d == USER and isinstance(m, ChatMessage)][-1]
    assert agent in last.text() and "OSVError: down" in last.text() and hint in last.text() and "Recovery" in last.text()
    assert isinstance(last.content[-1], EndSessionContent) and stored(ctx, inc)["state"] == "FAILED"
    n = len(ctx.sent)
    await orch.handle_agent_error(ctx, sender, AgentErrorReport(incident_id=inc, agent=agent, stage="x", error="again"))
    assert len(ctx.sent) == n                                                                  # already finished


class SendFails(FakeContext):
    """Delivery to chosen destinations fails, as when an agent is unreachable."""

    def __init__(self, bad: str) -> None:
        super().__init__()
        self.bad = bad

    async def send(self, destination, message):
        if destination == self.bad:
            raise ConnectionError("agent unreachable")
        await super().send(destination, message)


async def test_handlers_never_raise_and_the_user_hears_about_it():
    ctx = SendFails(ADDR["watchdog"])
    await make_orch().handle_chat(ctx, USER, chat(HEAL))                                         # watchdog unreachable
    assert "Something went wrong" in texts(ctx)[-1] and isinstance(ctx.sent[0][1], ChatAcknowledgement)

    ctx = SendFails(ADDR["detective"])
    orch = make_orch()
    inc = await start(orch, ctx)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc))                # pipeline step fails
    assert stored(ctx, inc)["state"] == "FAILED" and "Internal error" in texts(ctx)[-1]


async def test_unconfigured_agent_address_is_reported(ctx):
    orch = Orchestrator(addresses={**ADDR, "watchdog": None}, skip_payment=True, settings=EMPTY, clock=Clock())
    await orch.handle_chat(ctx, USER, chat(HEAL))
    assert "Something went wrong" in texts(ctx)[-1]


# ------------------------------------------------------------------ timeouts

async def test_stage_timeouts_fail_the_incident_with_a_recovery_hint(ctx):
    clock = Clock()
    orch = make_orch(clock=clock)
    inc = await start(orch, ctx)
    clock.t += 59
    await orch.sweep(ctx)
    assert stored(ctx, inc)["state"] == "PROBING"
    clock.t += 2
    await orch.sweep(ctx)
    assert stored(ctx, inc)["state"] == "FAILED"
    assert "Timed out after 60s" in texts(ctx)[-1] and "Agent_2" in texts(ctx)[-1] and "Recovery" in texts(ctx)[-1]


async def test_patching_gets_180_seconds(ctx):
    clock = Clock()
    orch = make_orch(clock=clock)
    inc = await start(orch, ctx)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(inc))
    await orch.handle_evidence(ctx, ADDR["detective"], make_evidence(inc))
    await orch.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(inc))
    clock.t += 170
    await orch.sweep(ctx)
    assert stored(ctx, inc)["state"] == "PATCHING"
    clock.t += 21
    await orch.sweep(ctx)
    assert stored(ctx, inc)["state"] == "FAILED" and "Agent_5" in texts(ctx)[-1]


async def test_unanswered_approval_expires_and_late_results_are_ignored(ctx):
    clock = Clock()
    orch = make_orch(clock=clock, approval_timeout=600)
    inc = await to_awaiting_approval(orch, ctx)
    clock.t += 601
    await orch.sweep(ctx)
    assert stored(ctx, inc)["state"] == "CANCELLED" and "expired" in texts(ctx)[-1]
    n = len(ctx.sent)
    await orch.handle_patch_result(ctx, ADDR["executor"], make_patch_result(inc))
    assert len(ctx.sent) == n
    await orch.handle_chat(ctx, USER, chat("approved"))                              # a late approval explains why and how to rerun
    late = texts(ctx)[-1]
    assert f"`{inc}`" in late and "expire after 10 min" in late and "Diagnose and heal" in late
    assert stored(ctx, inc)["state"] == "CANCELLED"


async def test_sweeper_never_raises(ctx):
    class Broken(Clock):
        def __call__(self):
            raise RuntimeError("clock exploded")

    orch = make_orch(clock=Clock())
    await start(orch, ctx)
    orch.clock = Broken()
    await orch.sweep(ctx)


# ------------------------------------------------------------------ Watchdog alerts

async def test_watchdog_alert_opens_an_incident_for_the_last_chatting_user(ctx):
    cfg = replace(EMPTY, demo_repo_full_name=REPO)
    orch = make_orch(cfg)
    await orch.handle_chat(ctx, USER, chat("hello"))                                              # user becomes "last_user"
    ctx.sent.clear()
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report("auto-1a2b3c4d"))
    assert "Agent_2 alert" in texts(ctx)[0] and "auto-1a2b3c4d" in texts(ctx)[0]
    (corr,) = sent(ctx, ADDR["detective"], CommitCorrelationRequest)
    assert corr.incident_id == "auto-1a2b3c4d" and corr.repo_full_name == REPO
    s = stored(ctx, "auto-1a2b3c4d")
    assert s["state"] == "CORRELATING" and s["user"] == USER and s["source"] == "watchdog-alert"
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report("auto-ffffffff"))     # same service: not handled twice
    assert len(sent(ctx, ADDR["detective"], CommitCorrelationRequest)) == 1


async def test_alert_guards(ctx):
    cfg = replace(EMPTY, demo_repo_full_name=REPO)
    orch = make_orch(cfg)
    await orch.handle_probe_report(ctx, "agent1qattacker", make_probe_report("auto-aaaaaaaa"))
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report("auto-bbbbbbbb", healthy=True))
    await make_orch(EMPTY).handle_probe_report(ctx, ADDR["watchdog"], make_probe_report("auto-cccccccc"))   # no DEMO repo configured
    assert ctx.sent == [] and ctx.storage.get("incidents") is None


async def test_headless_alert_incident_is_claimed_by_the_next_chat_message(ctx):
    cfg = replace(EMPTY, demo_repo_full_name=REPO)
    orch = make_orch(cfg)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report("auto-1a2b3c4d"))     # nobody has chatted yet
    assert stored(ctx, "auto-1a2b3c4d")["user"] == "" and texts(ctx) == []
    await orch.handle_evidence(ctx, ADDR["detective"], make_evidence("auto-1a2b3c4d"))
    await orch.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report("auto-1a2b3c4d"))
    await orch.handle_patch_result(ctx, ADDR["executor"], make_patch_result("auto-1a2b3c4d"))
    assert texts(ctx) == [] and stored(ctx, "auto-1a2b3c4d")["state"] == "AWAITING_APPROVAL"
    await orch.handle_chat(ctx, USER, chat("hi"))
    claimed = texts(ctx)
    assert "While you were away" in claimed[0] and "Sentinel Incident" in claimed[0] and "Reply **approve**" in claimed[0]
    await orch.handle_chat(ctx, USER, chat("approve"))
    assert stored(ctx, "auto-1a2b3c4d")["state"] == "EXECUTING"


# ------------------------------------------------------------------ status, multiple users, payment gate

async def test_status_queries(ctx):
    orch = make_orch()
    await orch.handle_chat(ctx, USER, chat("status"))
    assert "No incidents yet" in texts(ctx)[-1]
    inc = await start(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("status"))
    assert inc in texts(ctx)[-1] and "PROBING" in texts(ctx)[-1]
    await orch.handle_chat(ctx, USER, chat(f"status of {inc}"))
    assert inc in texts(ctx)[-1]
    await orch.handle_chat(ctx, USER2, chat("status"))                                              # other users see only their own
    assert "No incidents yet" in texts(ctx, USER2)[-1]


async def test_status_during_approval_repeats_the_card(ctx):
    orch = make_orch()
    await to_awaiting_approval(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("status"))
    assert "AWAITING_APPROVAL" in texts(ctx)[-1] and "Reply **approve**" in texts(ctx)[-1]


async def test_one_user_cannot_approve_another_users_incident(ctx):
    orch = make_orch()
    inc = await to_awaiting_approval(orch, ctx)
    await orch.handle_chat(ctx, USER2, chat(f"approve {inc}"))
    assert "Nothing is waiting" in texts(ctx, USER2)[-1] and stored(ctx, inc)["state"] == "AWAITING_APPROVAL"


async def test_approving_by_incident_id_among_several(ctx):
    orch = make_orch()
    first = await to_awaiting_approval(orch, ctx)
    second = await to_awaiting_approval(orch, ctx)
    await orch.handle_chat(ctx, USER, chat(f"approve {first}"))
    assert stored(ctx, first)["state"] == "EXECUTING" and stored(ctx, second)["state"] == "AWAITING_APPROVAL"


async def test_skip_payment_defaults_to_the_environment_setting(monkeypatch):
    monkeypatch.setenv("SKIP_PAYMENT", "true")
    assert Orchestrator(addresses=ADDR).skip_payment is True
    monkeypatch.setenv("SKIP_PAYMENT", "false")
    assert Orchestrator(addresses=ADDR).skip_payment is False


# ------------------------------------------------------------------ wiring

def test_create_agent_requires_seed(monkeypatch):
    monkeypatch.delenv("ORCHESTRATOR_SEED", raising=False)
    with pytest.raises(RuntimeError, match="ORCHESTRATOR_SEED"):
        create_agent(mailbox=False)


async def test_create_agent_exposes_the_chat_protocol_and_mailbox_by_default():
    agent = create_agent(seed="orchestrator wiring seed", enable_agent_inspector=False)
    assert agent.name == "Agent_1" and agent.mailbox_client is not None
    assert chat_protocol_spec.digest in agent.protocols
