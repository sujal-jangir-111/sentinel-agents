import json
from typing import List

import pytest

from agents import Agent_4
from agents.Agent_5 import LOOP_TIMEOUT_SECONDS, RemediationExecutor, create_agent
from common.addresses import address_from_seed
from common.llm_client import ASI1Client
from common.gatekeeper import attestation_hash
from common.github_client import GitHubClient
from common.models import (
    AgentErrorReport, CommitEvidenceReport, CVEFinding, PatchDraftRequest, PatchDraftResult, PatchVettingRequest,
    SecurityApprovalAttestation, VulnerabilityReport,
)
from common.patching import make_unified_diff
from common.sast_rules import scan_text
from tests.bureau_harness import agent_test_kwargs, free_port, run_roundtrip
from tests.fakes import (
    draft_adding_a_new_finding,
    ASI1_URL, DEMO_FILES, HEAD_SHA, REPO, FakeWeb, checkout_patch, fully_fixed_app_source, llm_reply,
    runtime_fixed_app_source,
)

SCANNER = "agent1qscannerscannerscannerscannerscannerscannerscanner"
ORCH = "agent1qorchestratororchestratororchestratororchestr"
FULL_SECRET = "sk_test_51SENTINELDEMOxxxxxxxx"
INC = "inc-exec"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_):
        return None

    monkeypatch.setattr("common.http_retry._sleep", instant)


def make_executor(web: FakeWeb, scanner=SCANNER, max_attempts: int = 3) -> RemediationExecutor:
    http = web.client()
    return RemediationExecutor(
        gh=GitHubClient(http, token="t", write_allowlist=[]),
        llm=ASI1Client(http, api_key="test-key", base_url=ASI1_URL),
        scanner_address=scanner, max_attempts=max_attempts,
    )


def cve(pkg, installed, fixed, vuln, sev, reachable) -> CVEFinding:
    return CVEFinding(package_name=pkg, installed_version=installed, fixed_version=fixed, vuln_id=vuln,
                      severity=sev, is_reachable_in_ast=reachable, summary="s")


def draft_request(incident_id: str = INC) -> PatchDraftRequest:
    evidence = CommitEvidenceReport(
        incident_id=incident_id, repo_full_name=REPO, suspect_commit_sha=HEAD_SHA,
        suspect_commit_url=f"https://github.com/{REPO}/commit/{HEAD_SHA}", author="alice",
        commit_message="Require discount_rate in pricing config", committed_at_utc="2026-01-02T10:00:00+00:00",
        offending_file="app.py", offending_diff_snippet=checkout_patch(),
        root_cause_explanation="checkout reads PRICING['discount_rate'] directly, which the config lacks (KeyError).",
        active_ast_imports=["yaml", "yaml.load", "sqlite3"],
    )
    report = VulnerabilityReport(
        incident_id=incident_id, repo_full_name=REPO, total_reachable_critical=1,
        cve_findings=[
            cve("pyyaml", "5.3", "5.4", "GHSA-8q59-q68h-6hv4", "CRITICAL", True),
            cve("pyyaml", "5.3", "5.3.1", "GHSA-6757-jp84-gxfx", "HIGH", True),
            cve("urllib3", "1.24.1", "1.24.2", "GHSA-mh33-7rrq-662w", "HIGH", False),
        ],
        sast_findings=scan_text("app.py", DEMO_FILES["app.py"]),
    )
    return PatchDraftRequest(incident_id=incident_id, repo_full_name=REPO, commit_evidence=evidence, vuln_report=report)


def llm_answers(*codes: str):
    """Fake ASI:One that returns each code as a {"patched_code": ...} JSON answer, in order."""
    it = iter(codes)
    return lambda r: llm_reply(json.dumps({"patched_code": next(it), "explanation": "fix"}))


def vettings(ctx) -> List[PatchVettingRequest]:
    return [m for d, m in ctx.sent if isinstance(m, PatchVettingRequest)]


def approve(req: PatchVettingRequest) -> SecurityApprovalAttestation:
    return SecurityApprovalAttestation(
        incident_id=req.incident_id, approved=True,
        attestation_hash=attestation_hash(req.incident_id, req.target_file, req.unified_diff, req.updated_requirements_txt, SCANNER),
        target_file=req.target_file, patched_code_content=req.patched_code_content,
        updated_requirements_txt=req.updated_requirements_txt, unified_diff=req.unified_diff)


def reject(req: PatchVettingRequest, *reasons: str) -> SecurityApprovalAttestation:
    return SecurityApprovalAttestation(
        incident_id=req.incident_id, approved=False, attestation_hash="", rejection_reasons=list(reasons),
        target_file=req.target_file, patched_code_content=req.patched_code_content,
        updated_requirements_txt=req.updated_requirements_txt, unified_diff=req.unified_diff)


def results(ctx) -> List[PatchDraftResult]:
    return [m for _, m in ctx.sent if isinstance(m, PatchDraftResult)]


def errors(ctx) -> List[AgentErrorReport]:
    return [m for _, m in ctx.sent if isinstance(m, AgentErrorReport)]


# ------------------------------------------------------------------ drafting

async def test_first_draft_is_hardened_diffed_and_sent_to_the_scanner(ctx):
    web = FakeWeb()
    web.llm = llm_answers(runtime_fixed_app_source())  # the LLM only fixes the runtime bug
    ex = make_executor(web)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())

    (dest, req), = ctx.sent
    assert dest == SCANNER and isinstance(req, PatchVettingRequest)
    assert req.incident_id == INC and req.repo_full_name == REPO and req.target_file == "app.py"
    code = req.patched_code_content
    assert 'discount_rate = PRICING.get("discount_rate", 0.0)' in code              # LLM's runtime fix
    assert 'STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")' in code             # deterministic: secret -> env
    assert "yaml.safe_load(PRICING_YAML)" in code and "yaml.load(" not in code      # deterministic: safe yaml
    assert FULL_SECRET not in req.json()
    assert req.unified_diff == make_unified_diff(DEMO_FILES["app.py"], code, "app.py")
    assert "pyyaml==5.4" in req.updated_requirements_txt and "urllib3==1.24.1" in req.updated_requirements_txt
    assert "fastapi" in req.updated_requirements_txt
    # the display diff masks the removed key; nothing persisted by the executor holds the full secret either
    assert "sk_tes****" in req.unified_diff
    assert FULL_SECRET not in ctx.storage.get(f"loop:{INC}")


async def test_llm_prompt_is_grounded_and_never_contains_the_secret(ctx):
    web = FakeWeb()
    web.llm = llm_answers(runtime_fixed_app_source())
    await make_executor(web).handle_patch_draft_request(ctx, ORCH, draft_request())
    prompt = web.llm_prompts()[0]
    assert "KeyError" in prompt and "SQL_INJECTION" in prompt and "parameterized" in prompt
    assert 'PRICING["discount_rate"]' in prompt                         # the faulty line it must fix
    assert 'os.getenv("STRIPE_SECRET_KEY")' in prompt                    # baseline was hardened before prompting
    assert FULL_SECRET not in prompt and "sk_tes****" not in prompt      # not even a masked fragment is needed
    assert "REJECTED" not in prompt


async def test_missing_original_file_reports_error_instead_of_raising(ctx):
    web = FakeWeb()
    web.github.files = {"requirements.txt": "x==1\n"}
    await make_executor(web).handle_patch_draft_request(ctx, ORCH, draft_request())
    (dest, err), = ctx.sent
    assert dest == ORCH and isinstance(err, AgentErrorReport) and err.stage == "draft" and "app.py not found" in err.error


async def test_oversized_file_and_unreachable_scanner_report_errors(ctx):
    web = FakeWeb()
    web.github.files["app.py"] = "x = 1\n" * 10_000
    await make_executor(web).handle_patch_draft_request(ctx, ORCH, draft_request())
    assert "too large" in errors(ctx)[0].error
    ctx.sent.clear()
    web2 = FakeWeb()
    web2.llm = llm_answers(runtime_fixed_app_source())
    await make_executor(web2, scanner="").handle_patch_draft_request(ctx, ORCH, draft_request("inc-noscanner"))
    assert "SCANNER" in errors(ctx)[0].error


# ------------------------------------------------------------------ gatekeeper loop

async def test_approval_ends_the_loop_with_attestation_and_rollback_flag(ctx):
    web = FakeWeb()
    web.llm = llm_answers(fully_fixed_app_source())
    ex = make_executor(web)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    req, = vettings(ctx)
    assert ctx.storage.get(f"loop:{INC}")                              # state kept while waiting
    ctx.sent.clear()

    await ex.handle_attestation(ctx, SCANNER, approve(req))
    (dest, result), = ctx.sent
    assert dest == ORCH and isinstance(result, PatchDraftResult)
    assert result.attempts == 1 and result.rollback_available is True
    assert result.attestation.approved and result.attestation.attestation_hash
    assert result.attestation.unified_diff == req.unified_diff
    assert not ctx.storage.get(f"loop:{INC}")                          # state cleaned up

    ctx.sent.clear()
    await ex.handle_attestation(ctx, SCANNER, approve(req))             # late duplicate is ignored
    assert ctx.sent == []


async def test_rejection_feeds_reasons_back_and_second_attempt_is_approved(ctx):
    web = FakeWeb()
    web.llm = llm_answers(runtime_fixed_app_source(), fully_fixed_app_source())
    ex = make_executor(web)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    first, = vettings(ctx)
    ctx.sent.clear()

    reason = "SQL_INJECTION at line 83: row = db.execute(f\"SELECT ...\") -> Use parameterized queries"
    await ex.handle_attestation(ctx, SCANNER, reject(first, reason))
    second, = vettings(ctx)
    assert second.patched_code_content != first.patched_code_content and "?" in second.patched_code_content
    p1, p2 = web.llm_prompts()
    assert "REJECTED" not in p1 and "REJECTED" in p2 and reason in p2
    ctx.sent.clear()

    await ex.handle_attestation(ctx, SCANNER, approve(second))
    result, = results(ctx)
    assert result.attempts == 2 and result.attestation.approved


async def test_gives_up_after_max_attempts_and_offers_rollback_only(ctx):
    web = FakeWeb()
    web.llm = llm_answers(*[draft_adding_a_new_finding()] * 3)
    ex = make_executor(web, max_attempts=3)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    for n in range(1, 4):
        req = vettings(ctx)[-1]
        assert len(vettings(ctx)) == n
        await ex.handle_attestation(ctx, SCANNER, reject(req, f"SQL_INJECTION still present (round {n})"))
    assert len(vettings(ctx)) == 3                                    # no fourth submission
    result, = results(ctx)
    assert result.attempts == 3 and result.rollback_available is True
    att = result.attestation
    assert att.approved is False and att.attestation_hash == ""
    assert att.rejection_reasons == ["SQL_INJECTION still present (round 3)"]
    assert att.target_file == "app.py" and att.patched_code_content        # last draft kept for the report
    assert not ctx.storage.get(f"loop:{INC}")


async def test_rollback_unavailable_when_suspect_has_no_parent(ctx):
    web = FakeWeb()
    web.github.commits[0]["parents"] = []
    web.llm = llm_answers(fully_fixed_app_source())
    ex = make_executor(web, max_attempts=1)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    await ex.handle_attestation(ctx, SCANNER, reject(vettings(ctx)[0], "nope"))
    assert results(ctx)[0].rollback_available is False


# ------------------------------------------------------------------ fallbacks and local pre-checks

async def test_llm_unavailable_falls_back_to_reverting_the_offending_change(ctx):
    web = FakeWeb()  # default fake ASI:One answers 401
    await make_executor(web).handle_patch_draft_request(ctx, ORCH, draft_request())
    req, = vettings(ctx)
    lines = req.patched_code_content.splitlines()
    assert 'discount_rate = PRICING.get("discount_rate", 0.0)' in [ln.strip() for ln in lines]
    assert 'PRICING["discount_rate"]' not in req.patched_code_content
    assert "os.getenv(\"STRIPE_SECRET_KEY\")" in req.patched_code_content        # hardening still applied


async def test_unparseable_llm_output_also_falls_back(ctx):
    web = FakeWeb()
    web.llm = lambda r: llm_reply("Sure! I fixed it, no JSON here")
    await make_executor(web).handle_patch_draft_request(ctx, ORCH, draft_request())
    assert 'PRICING.get("discount_rate", 0.0)' in vettings(ctx)[0].patched_code_content
    assert len(web.llm_prompts()) == 2                                          # chat_json retried once first


async def test_patch_that_keeps_the_faulty_line_is_caught_locally_and_retried(ctx):
    web = FakeWeb()
    web.llm = llm_answers(DEMO_FILES["app.py"], fully_fixed_app_source())     # attempt 1 ignores the bug
    ex = make_executor(web)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    assert len(vettings(ctx)) == 1                       # the bad attempt never bothered the scanner
    assert vettings(ctx)[0].patched_code_content.count("PRICING.get(") >= 1
    p1, p2 = web.llm_prompts()
    assert "offending change from the suspect commit is still present" in p2
    await ex.handle_attestation(ctx, SCANNER, approve(vettings(ctx)[0]))
    assert results(ctx)[0].attempts == 2


async def test_syntax_error_from_llm_is_caught_locally(ctx):
    web = FakeWeb()
    web.llm = llm_answers("def broken(:\n", fully_fixed_app_source())
    await make_executor(web).handle_patch_draft_request(ctx, ORCH, draft_request())
    assert len(vettings(ctx)) == 1 and "does not parse" in web.llm_prompts()[1]


async def test_all_attempts_failing_locally_reports_failure_without_scanner(ctx):
    web = FakeWeb()
    web.llm = llm_answers(*[DEMO_FILES["app.py"]] * 2)
    await make_executor(web, max_attempts=2).handle_patch_draft_request(ctx, ORCH, draft_request())
    assert vettings(ctx) == []
    result, = results(ctx)
    assert result.attempts == 2 and result.attestation.approved is False and result.attestation.rejection_reasons


# ------------------------------------------------------------------ message guards

async def test_attestation_from_wrong_sender_or_unknown_incident_is_ignored(ctx):
    web = FakeWeb()
    web.llm = llm_answers(fully_fixed_app_source())
    ex = make_executor(web)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    req = vettings(ctx)[0]
    ctx.sent.clear()
    await ex.handle_attestation(ctx, "agent1qattacker", approve(req))           # forged approval
    unknown = approve(req)
    unknown.incident_id = "inc-unknown"
    await ex.handle_attestation(ctx, SCANNER, unknown)
    assert ctx.sent == [] and ctx.storage.get(f"loop:{INC}")


async def test_attestation_for_a_different_diff_is_an_error(ctx):
    web = FakeWeb()
    web.llm = llm_answers(fully_fixed_app_source())
    ex = make_executor(web)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    forged = approve(vettings(ctx)[0])
    forged.unified_diff = "--- a/app.py\n+++ b/app.py\n+evil"
    ctx.sent.clear()
    await ex.handle_attestation(ctx, SCANNER, forged)
    (dest, err), = ctx.sent
    assert dest == ORCH and isinstance(err, AgentErrorReport) and "does not match" in err.error
    assert not ctx.storage.get(f"loop:{INC}")


async def test_scanner_error_report_fails_the_incident(ctx):
    web = FakeWeb()
    web.llm = llm_answers(fully_fixed_app_source())
    ex = make_executor(web)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    ctx.sent.clear()
    stranger = AgentErrorReport(incident_id=INC, agent="x", stage="s", error="e")
    await ex.handle_agent_error(ctx, "agent1qstranger", stranger)
    assert ctx.sent == []
    await ex.handle_agent_error(ctx, SCANNER, AgentErrorReport(incident_id=INC, agent="Agent_4", stage="gatekeeper", error="OSVError: down"))
    (dest, err), = ctx.sent
    assert dest == ORCH and "OSVError: down" in err.error


async def test_sweeper_fails_loops_that_never_got_a_verdict(ctx):
    web = FakeWeb()
    web.llm = llm_answers(fully_fixed_app_source())
    ex = make_executor(web)
    await ex.handle_patch_draft_request(ctx, ORCH, draft_request())
    ctx.sent.clear()
    await ex.sweep(ctx)
    assert ctx.sent == []                                                       # still fresh
    st = json.loads(ctx.storage.get(f"loop:{INC}"))
    st["started_at"] -= LOOP_TIMEOUT_SECONDS + 5
    ctx.storage.set(f"loop:{INC}", json.dumps(st))
    await ex.sweep(ctx)
    (dest, err), = ctx.sent
    assert dest == ORCH and "timed out" in err.error and not ctx.storage.get(f"loop:{INC}")


# ------------------------------------------------------------------ wiring

def test_create_agent_requires_seed(monkeypatch):
    monkeypatch.delenv("EXECUTOR_SEED", raising=False)
    with pytest.raises(RuntimeError, match="EXECUTOR_SEED"):
        create_agent(mailbox=False)


async def test_create_agent_defaults():
    agent = create_agent(seed="executor wiring seed", enable_agent_inspector=False)
    assert agent.name == "Agent_5" and agent.mailbox_client is not None


# ------------------------------------------------------------------ Bureau: Executor <-> Scanner, for real

SCANNER_SEED = "bureau scanner seed (executor tests)"


def run_loop(web: FakeWeb) -> PatchDraftResult:
    async def make_target(port: int):
        scanner_http = web.client()
        scanner = Agent_4.VulnScanner(gh=GitHubClient(scanner_http, token="t", write_allowlist=[]), http=scanner_http)
        scanner_agent = Agent_4.create_agent(
            seed=SCANNER_SEED, port=free_port(), scanner=scanner, **agent_test_kwargs())
        executor = make_executor(web, scanner=address_from_seed(SCANNER_SEED))
        return create_agent(seed="bureau executor seed", port=port, executor=executor, **agent_test_kwargs()), [scanner_agent]

    target_addr, sender, result = run_roundtrip(make_target, lambda: draft_request("inc-bureau-exec"), timeout=60)
    assert sender == target_addr and isinstance(result, PatchDraftResult)
    return result


def test_bureau_patch_approved_on_first_attempt_by_the_real_scanner():
    web = FakeWeb()
    web.llm = llm_answers(fully_fixed_app_source())
    result = run_loop(web)
    att = result.attestation
    assert result.attempts == 1 and result.rollback_available is True
    assert att.approved is True and att.rejection_reasons == []
    assert att.attestation_hash == attestation_hash(
        "inc-bureau-exec", "app.py", att.unified_diff, att.updated_requirements_txt, address_from_seed(SCANNER_SEED))
    assert 'PRICING.get("discount_rate", 0.0)' in att.patched_code_content and FULL_SECRET not in att.json()
    assert "pyyaml==5.4" in att.updated_requirements_txt and att.unified_diff == make_unified_diff(
        DEMO_FILES["app.py"], att.patched_code_content, "app.py")


def test_bureau_rejected_then_fixed_across_executor_and_scanner():
    web = FakeWeb()
    web.llm = llm_answers(draft_adding_a_new_finding(), fully_fixed_app_source())  # 1st: introduces eval()
    result = run_loop(web)
    assert result.attempts == 2 and result.attestation.approved is True
    first_prompt, second_prompt = web.llm_prompts()
    assert "REJECTED" not in first_prompt and "REJECTED" in second_prompt
    assert "UNSAFE_EVAL" in second_prompt                        # the real scanner's reason, fed back verbatim
    assert "eval(" not in result.attestation.patched_code_content


def test_bureau_exhausted_attempts_returns_rejection_with_the_scanners_reasons():
    web = FakeWeb()
    web.llm = llm_answers(*[draft_adding_a_new_finding()] * 3)   # keeps adding eval()
    result = run_loop(web)
    assert result.attempts == 3 and result.attestation.approved is False and result.attestation.attestation_hash == ""
    assert any(r.startswith("UNSAFE_EVAL") for r in result.attestation.rejection_reasons)
    assert result.rollback_available is True
