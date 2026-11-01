"""Incidents started from the web console: any repository, an optional live URL, and no fallback to configured targets."""
import json
from dataclasses import replace
from typing import Any, Dict, Optional

from agents.Agent_1 import Orchestrator, make_chat
from agents.Agent_3 import CommitDetective
from common.addresses import address_from_seed
from common.config import Settings
from common.github_client import GitHubClient
from common.llm_client import LLMClient
from common.models import (
    CommitCorrelationRequest, CommitEvidenceReport, ExecuteRemediationCommand, HealthProbeRequest, IncidentRequest, IncidentUpdate,
    PatchDraftRequest, RemediationCompletionReport, VulnerabilityScanRequest,
)
from tests.fakes import ASI1_URL, FakeWeb, llm_reply, make_evidence, make_patch_result, make_probe_report, make_vuln_report

GATEWAY = "agent1qgatewaygatewaygatewaygatewaygatewaygateway"
ADDR = {"watchdog": "agent1qwatchdogwatchdogwatchdogwatchdogwatchdog", "detective": "agent1qdetectivedetectivedetectivedetectivedetec",
        "scanner": "agent1qscannerscannerscannerscannerscannerscanner", "executor": "agent1qexecutorexecutorexecutorexecutorexecutor"}
INC = "inc-1234abcd"
MINE = "me/sentinel-target"
STRANGER = "someone/their-shop"
CFG = replace(Settings(), demo_repo_full_name=MINE, demo_service_url="http://demo", github_write_allowlist=[], skip_payment=True)


def orch() -> Orchestrator:
    return Orchestrator(addresses=ADDR, skip_payment=True, settings=CFG, gateway=GATEWAY)


def request(repo: str = STRANGER, url: str = "", endpoints=(), mode: str = "diagnose_and_heal", branch: str = "develop") -> IncidentRequest:
    return IncidentRequest(incident_id=INC, mode=mode, repo_full_name=repo, branch=branch, problem="checkout crashes",
                           service_url=url, endpoints=list(endpoints))


def sent(ctx, dest: str, kind: type) -> list:
    return [m for d, m in ctx.sent if d == dest and isinstance(m, kind)]


def stored(ctx) -> Dict[str, Any]:
    return json.loads(ctx.storage.get(f"inc:{INC}"))


def updates(ctx) -> list:
    return [json.loads(m.record_json) for d, m in ctx.sent if d == GATEWAY and isinstance(m, IncidentUpdate)]


async def to_patched(o: Orchestrator, ctx, repo: str = STRANGER, **patch_kw) -> None:
    await o.handle_incident_request(ctx, GATEWAY, request(repo))
    await o.handle_evidence(ctx, ADDR["detective"], make_evidence(INC))
    await o.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(INC))
    await o.handle_patch_result(ctx, ADDR["executor"], make_patch_result(INC, **patch_kw))


async def test_only_the_gateway_can_start_a_web_incident(ctx):
    await orch().handle_incident_request(ctx, "agent1qsomeoneelse", request())
    assert ctx.sent == [] and ctx.storage.get(f"inc:{INC}") is None


async def test_without_a_live_url_the_detective_starts_at_once_on_the_users_repo_and_branch(ctx):
    await orch().handle_incident_request(ctx, GATEWAY, request())
    req, = sent(ctx, ADDR["detective"], CommitCorrelationRequest)
    assert req.repo_full_name == STRANGER and req.branch == "develop" and req.error_snippet == "checkout crashes"
    assert sent(ctx, ADDR["watchdog"], HealthProbeRequest) == []
    assert stored(ctx)["service_url"] == ""        # never filled in from DEMO_SERVICE_URL


async def test_a_live_url_is_probed_on_the_users_own_paths_first(ctx):
    await orch().handle_incident_request(ctx, GATEWAY, request(url="https://shop.example", endpoints=["/cart"]))
    probe, = sent(ctx, ADDR["watchdog"], HealthProbeRequest)
    assert probe.service_url == "https://shop.example" and probe.endpoints == ["/cart"] and not probe.inject_chaos


async def test_a_duplicate_request_is_ignored(ctx):
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request())
    n = len(ctx.sent)
    await o.handle_incident_request(ctx, GATEWAY, request())
    assert len(ctx.sent) == n


async def test_a_healthy_service_does_not_end_a_reported_problem(ctx):
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request(url="https://shop.example", endpoints=["/"]))
    await o.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(INC, healthy=True))
    assert stored(ctx)["state"] == "CORRELATING" and stored(ctx)["service_note"] == "healthy"


async def test_an_unreachable_service_does_not_end_a_reported_problem(ctx):
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request(url="https://shop.example", endpoints=["/"]))
    await o.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(INC, status=0))
    assert stored(ctx)["state"] == "CORRELATING" and stored(ctx)["service_note"] == "unreachable"


async def test_a_failing_probe_gives_the_detective_the_error_and_the_users_words(ctx):
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request(url="https://shop.example", endpoints=["/api/checkout"]))
    await o.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(INC))
    req, = sent(ctx, ADDR["detective"], CommitCorrelationRequest)
    assert req.failing_endpoint == "/api/checkout" and "X-Error-File" in req.error_snippet and "checkout crashes" in req.error_snippet


async def test_the_users_branch_reaches_the_scanner_and_the_fixer(ctx):
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request())
    await o.handle_evidence(ctx, ADDR["detective"], make_evidence(INC))
    scan, = sent(ctx, ADDR["scanner"], VulnerabilityScanRequest)
    await o.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(INC))
    draft, = sent(ctx, ADDR["executor"], PatchDraftRequest)
    assert scan.branch == "develop" and draft.branch == "develop" and draft.problem == "checkout crashes"


async def test_a_guessed_commit_is_not_held_against_the_fix(ctx):
    """With no error location the suspect is only a best guess, so the gatekeeper must not require removing its lines."""
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request())
    evidence = make_evidence(INC)
    guess = type(evidence).model_validate({**evidence.dict(), "confidence": "low"})
    await o.handle_evidence(ctx, ADDR["detective"], guess)
    scan, = sent(ctx, ADDR["scanner"], VulnerabilityScanRequest)
    assert scan.suspect_commit_sha == ""


async def test_a_security_audit_scans_the_whole_repository(ctx):
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request(mode="security_audit"))
    await o.handle_evidence(ctx, ADDR["detective"], make_evidence(INC))
    scan, = sent(ctx, ADDR["scanner"], VulnerabilityScanRequest)
    assert scan.modified_files == ["*"]


async def test_a_repo_sentinel_can_write_to_waits_for_approval(ctx):
    o = orch()
    await to_patched(o, ctx, repo=MINE)
    assert stored(ctx)["state"] == "AWAITING_APPROVAL" and "delivery" not in stored(ctx)


async def test_a_repo_sentinel_cannot_write_to_gets_the_fix_with_no_github_write(ctx):
    o = orch()
    await to_patched(o, ctx, repo=STRANGER)
    rec = stored(ctx)
    assert rec["state"] == "RESOLVED" and rec["delivery"] == "files"
    assert sent(ctx, ADDR["executor"], ExecuteRemediationCommand) == []


async def test_a_rejected_fix_stops_and_never_offers_a_rollback(ctx):
    o = orch()
    await to_patched(o, ctx, repo=MINE, approved=False)
    rec = stored(ctx)
    assert rec["state"] == "FAILED" and "safety" not in rec["last_note"] and "security check" in rec["last_note"]
    assert rec.get("action_type") is None


async def test_web_updates_are_structured_records_never_markdown_chat(ctx):
    await to_patched(orch(), ctx, repo=MINE)
    assert [u["state"] for u in updates(ctx)] == ["CORRELATING", "SCANNING", "PATCHING", "AWAITING_APPROVAL"]
    assert not [m for d, m in ctx.sent if d == GATEWAY and type(m).__name__ == "ChatMessage"]


async def test_approval_opens_the_pr_on_the_users_branch(ctx):
    o = orch()
    await to_patched(o, ctx, repo=MINE)
    await o.handle_chat(ctx, GATEWAY, make_chat(f"approve {INC}"))
    cmd, = sent(ctx, ADDR["executor"], ExecuteRemediationCommand)
    assert cmd.branch == "develop" and cmd.service_reload_webhook is None and stored(ctx)["state"] == "EXECUTING"
    assert updates(ctx)[-1]["state"] == "EXECUTING"


def report(redeployed: bool) -> RemediationCompletionReport:
    return RemediationCompletionReport(incident_id=INC, success=True, pr_url="https://github.com/me/sentinel-target/pull/9", sbom_file_url="s",
                                       dorado_tx_hash="", dorado_explorer_url="", redeploy_triggered=redeployed, summary_message="ok")


async def test_a_pr_without_a_redeploy_finishes_without_a_pointless_recheck(ctx):
    o = orch()
    await to_patched(o, ctx, repo=MINE)
    await o.handle_chat(ctx, GATEWAY, make_chat(f"approve {INC}"))
    await o.handle_remediation_report(ctx, ADDR["executor"], report(redeployed=False))
    assert stored(ctx)["state"] == "RESOLVED" and stored(ctx)["last_note"] == "pr-opened"
    assert sent(ctx, ADDR["watchdog"], HealthProbeRequest) == []


async def test_a_pr_with_a_redeploy_is_verified_on_the_same_paths(ctx):
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request(repo=MINE, url="http://demo", endpoints=["/api/checkout"]))
    await o.handle_probe_report(ctx, ADDR["watchdog"], make_probe_report(INC))
    await o.handle_evidence(ctx, ADDR["detective"], make_evidence(INC))
    await o.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(INC))
    await o.handle_patch_result(ctx, ADDR["executor"], make_patch_result(INC))
    await o.handle_chat(ctx, GATEWAY, make_chat(f"approve {INC}"))
    await o.handle_remediation_report(ctx, ADDR["executor"], report(redeployed=True))
    canary = [m for m in sent(ctx, ADDR["watchdog"], HealthProbeRequest) if m.is_canary_check]
    assert len(canary) == 1 and canary[0].endpoints == ["/api/checkout"]


# ------------------------------------------------------------------ Agent_3 from a description alone

def detective(web: FakeWeb) -> CommitDetective:
    http = web.client()
    return CommitDetective(gh=GitHubClient(http, token="t", write_allowlist=[]), llm=LLMClient(http, api_key="k", base_url=ASI1_URL))


def described(problem: str = "The checkout page shows an error about discounts") -> CommitCorrelationRequest:
    return CommitCorrelationRequest(incident_id=INC, repo_full_name="acme/sentinel-target", branch="main",
                                    failure_timestamp_utc="2026-03-01T12:00:00Z", failing_endpoint="", error_snippet=problem)


def answers(web: FakeWeb, located: Dict[str, str], explanation: str = "The discount lookup fails.") -> None:
    """First LLM call locates the bug, later ones write the explanation."""
    calls = {"n": 0}

    def reply(request):
        calls["n"] += 1
        return llm_reply(json.dumps(located) if calls["n"] == 1 else explanation)

    web.llm = reply


def only_report(ctx) -> CommitEvidenceReport:
    (_, msg), = ctx.sent
    assert isinstance(msg, CommitEvidenceReport), msg
    return msg


async def test_a_description_alone_finds_the_commit_and_marks_it_as_a_best_guess(ctx):
    web = FakeWeb()
    head = web.github.commits[0]["sha"] if hasattr(web.github, "commits") else ""
    answers(web, {"file": "", "sha": head})
    await detective(web).handle_request(ctx, "orch", described())
    report_ = only_report(ctx)
    assert report_.confidence == "low" and report_.offending_file and report_.root_cause_explanation


async def test_a_security_check_needs_no_bug_hunt_and_no_llm(ctx):
    web = FakeWeb()     # the default fake LLM answers 401, so any LLM call would be visible in the logs, not the report
    request_ = CommitCorrelationRequest(incident_id=INC, repo_full_name="acme/sentinel-target", branch="main",
                                        failure_timestamp_utc="2026-03-01T12:00:00Z", failing_endpoint="", error_snippet=None)
    await detective(web).handle_request(ctx, "orch", request_)
    report_ = only_report(ctx)
    assert report_.suspect_commit_sha == "" and report_.active_ast_imports and web.llm_prompts() == []


async def test_the_scanner_reports_how_much_it_really_scanned(ctx):
    from agents.Agent_4 import VulnScanner
    web = FakeWeb()
    http = web.client()
    scanner = VulnScanner(gh=GitHubClient(http, token="t", write_allowlist=[]), http=http)
    report_ = await scanner.scan(ctx, VulnerabilityScanRequest(
        incident_id=INC, repo_full_name="acme/sentinel-target", suspect_commit_sha="", modified_files=["app.py"], active_ast_imports=[]))
    assert report_.files_scanned >= 1 and report_.dependencies_scanned >= 1


async def test_a_web_security_check_finishes_without_a_fix_or_a_fixer(ctx):
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, request(mode="security_audit"))
    req, = sent(ctx, ADDR["detective"], CommitCorrelationRequest)
    assert req.failing_endpoint == "" and req.error_snippet is None
    evidence = make_evidence(INC)
    blank = {**evidence.dict(), "suspect_commit_sha": "", "suspect_commit_url": "", "author": "", "commit_message": "",
             "committed_at_utc": "", "offending_file": "", "offending_diff_snippet": "", "root_cause_explanation": ""}
    await o.handle_evidence(ctx, ADDR["detective"], type(evidence).model_validate(blank))
    await o.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(INC))
    assert stored(ctx)["state"] == "RESOLVED" and sent(ctx, ADDR["executor"], PatchDraftRequest) == []


async def test_a_bug_older_than_the_recent_commits_still_gets_a_file_and_no_commit(ctx):
    web = FakeWeb()
    answers(web, {"file": "not/in/the/tree.py", "sha": ""})
    await detective(web).handle_request(ctx, "orch", described())
    assert only_report(ctx).suspect_commit_sha == ""


async def test_an_error_location_is_still_decided_without_any_llm_guess(ctx):
    from tests.fakes import ERROR_SNIPPET
    web = FakeWeb()
    await detective(web).handle_request(ctx, "orch", described(ERROR_SNIPPET))
    assert only_report(ctx).confidence == "high"
