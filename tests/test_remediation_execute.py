"""Step 10, Agent_5: ExecuteRemediationCommand -> branch + commits + SBOM + PR + hotfix webhook."""
import base64
import json
from dataclasses import replace
from typing import List

import httpx
import pytest

from agents.Agent_5 import RemediationExecutor
from common.config import Settings
from common.gatekeeper import attestation_hash
from common.github_client import GitHubClient
from common.models import (
    AgentErrorReport, ExecuteRemediationCommand, RemediationCompletionReport, SecurityApprovalAttestation,
)
from common.patching import make_unified_diff
from common.remediation import build_pr_body, remaining_findings, webhook_allowed
from tests.conftest import FakeContext
from tests.fakes import (
    draft_adding_a_new_finding,
    DEMO_FILES, HEAD_SHA, MAIN_SHA, OLD_SHA, PAYER, PRICE, README_SHA, REPO, TX_FAILED, TX_GOOD, TX_OTHER, TX_UNDER, WALLET,
    FakeChain, FakeWeb, fake_verifier, fully_fixed_app_source, make_vuln_report, runtime_fixed_app_source, standard_chain,
)

SCANNER = "agent1qscannerscannerscannerscannerscannerscannerscanner"
ORCH = "agent1qorchestratororchestratororchestratororchestr"
INC = "inc-exec0001"
TOKEN = "admin-token"
REQS = DEMO_FILES["requirements.txt"].replace("pyyaml==5.3", "pyyaml==5.4")


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_):
        return None

    monkeypatch.setattr("common.http_retry._sleep", instant)


class Hook:
    """The target service's /admin/apply-hotfix endpoint."""

    def __init__(self, status: int = 200) -> None:
        self.status, self.calls = status, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        return httpx.Response(self.status, json={"patched": self.status < 400})


def settings(skip_payment: bool = True, service_url: str = "http://demo") -> Settings:
    return replace(Settings(), skip_payment=skip_payment, orchestrator_wallet_address=WALLET, remediation_price_atestfet=PRICE,
                   demo_admin_token=TOKEN, demo_service_url=service_url, demo_repo_full_name=REPO,
                   dorado_explorer_base="https://explore-dorado.fetch.ai/transactions")


def build(web=None, hook=None, chain=None, skip_payment=True, service_url="http://demo"):
    web = web or FakeWeb()
    hook = hook or Hook()
    ex = RemediationExecutor(
        gh=GitHubClient(web.client(), token="t", write_allowlist=[REPO]), llm=None, scanner_address=SCANNER, orchestrator_address=ORCH,
        verifier=fake_verifier(chain or standard_chain()), settings=settings(skip_payment, service_url),
        webhook_http=httpx.AsyncClient(transport=httpx.MockTransport(hook)))
    return ex, web, hook


def seed(ctx, ex, approved_hash: str, rollback: bool = True) -> None:
    vuln = make_vuln_report(INC)
    ex._remember(ctx, {
        "incident_id": INC, "repo": REPO, "target_file": "app.py", "rollback_available": rollback,
        "evidence": {"sha": HEAD_SHA, "url": f"https://github.com/{REPO}/commit/{HEAD_SHA}", "author": "alice",
                     "explanation": "checkout reads PRICING['discount_rate'] directly."},
        "cves": [f.dict() for f in vuln.cve_findings], "sast_all": [f.dict() for f in vuln.sast_findings]}, approved_hash)


def attestation(patched=None, reqs=REQS, **over) -> SecurityApprovalAttestation:
    patched = patched or fully_fixed_app_source()
    diff = over.pop("unified_diff", None) or make_unified_diff(DEMO_FILES["app.py"], patched, "app.py")
    fields = dict(incident_id=INC, approved=True, attestation_hash=attestation_hash(INC, "app.py", diff, reqs, SCANNER),
                  target_file="app.py", patched_code_content=patched, updated_requirements_txt=reqs, unified_diff=diff)
    fields.update(over)
    return SecurityApprovalAttestation(**fields)


def command(att=None, action="OPEN_PR_AND_HOTFIX", tx="", payer="", hook="http://demo/admin/apply-hotfix") -> ExecuteRemediationCommand:
    return ExecuteRemediationCommand(incident_id=INC, repo_full_name=REPO, action_type=action, dorado_tx_hash=tx, payer_wallet=payer,
                                     attestation=att or attestation(), service_reload_webhook=hook)


def evolve(model, **update):
    return type(model)(**{**model.dict(), **update})


def replies(ctx: FakeContext, kind: type) -> List:
    return [m for d, m in ctx.sent if d == ORCH and isinstance(m, kind)]


async def run(ex, ctx, cmd, approved=True, rollback=True, sender=ORCH):
    seed(ctx, ex, cmd.attestation.attestation_hash if approved else "", rollback)
    await ex.handle_execute_command(ctx, sender, cmd)


def github_writes(web):
    return web.github.writes


# ------------------------------------------------------------------ the happy path

async def test_forward_fix_opens_branch_commits_files_pr_and_triggers_the_hotfix(ctx):
    ex, web, hook = build()
    await run(ex, ctx, command())
    (rep,) = replies(ctx, RemediationCompletionReport)
    assert rep.success and rep.redeploy_triggered and rep.pr_url == f"https://github.com/{REPO}/pull/1"
    assert rep.sbom_file_url == f"https://github.com/{REPO}/blob/sentinel/fix-{INC}/sbom.cdx.json" and rep.dorado_tx_hash == ""
    gh = web.github
    assert gh.branches[f"sentinel/fix-{INC}"] == MAIN_SHA                                  # branched from main head
    files = gh.branch_files[f"sentinel/fix-{INC}"]
    assert set(files) == {"app.py", "requirements.txt", "sbom.cdx.json"}
    assert files["app.py"] == fully_fixed_app_source() and "pyyaml==5.4" in files["requirements.txt"]
    (pull,) = gh.pulls
    assert pull["base"] == "main" and pull["head"] == f"sentinel/fix-{INC}"
    (call,) = hook.calls
    assert str(call.url) == "http://demo/admin/apply-hotfix" and call.headers["x-sentinel-token"] == TOKEN and call.method == "POST"


async def test_nothing_is_ever_written_to_main_and_the_pr_is_not_merged(ctx):
    ex, web, _ = build()
    await run(ex, ctx, command())
    for method, path, body in github_writes(web):
        assert not (method == "PUT" and body["branch"] == "main")
        assert not path.startswith("merge") and "merge" not in path
        if path == "git/refs":
            assert body["ref"] == f"refs/heads/sentinel/fix-{INC}"
    assert [m for m, p, _ in github_writes(web)].count("POST") == 2                         # one ref, one PR


async def test_sbom_is_cyclonedx_15_of_the_patched_dependencies_with_unresolved_findings(ctx):
    ex, web, _ = build()
    await run(ex, ctx, command())
    sbom = json.loads(web.github.branch_files[f"sentinel/fix-{INC}"]["sbom.cdx.json"])
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    purls = {c["purl"] for c in sbom["components"]}
    assert "pkg:pypi/pyyaml@5.4" in purls and "pkg:pypi/pyyaml@5.3" not in purls
    ids = {v["id"] for v in sbom["vulnerabilities"]}
    assert ids == {"GHSA-mh33-7rrq-662w"}                                                   # pyyaml fixed; latent urllib3 remains
    assert sbom["metadata"]["component"]["bom-ref"] == f"incident:{INC}"


async def test_pr_body_follows_the_template_and_holds_no_secret(ctx):
    ex, web, _ = build()
    await run(ex, ctx, command())
    body = web.github.pulls[0]["body"]
    for needle in ("Sentinel Auto-Remediation", INC, "### Root Cause", f"[{HEAD_SHA[:7]}]", "@alice", "`app.py`", "### Security Findings Fixed",
                   "GHSA-8q59-q68h-6hv4", "HARDCODED_SECRET", "### Change-Control Audit Trail", "payment skipped", "sbom.cdx.json",
                   "(CycloneDX v1.5)", "Generated by the Sentinel multi-agent swarm"):
        assert needle in body, needle
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in body and "sk_test_5" not in body.replace("sk_test_5****", "")


async def test_execution_is_idempotent_for_a_duplicate_command(ctx):
    ex, web, hook = build()
    cmd = command()
    await run(ex, ctx, cmd)
    writes = len(github_writes(web))
    await ex.handle_execute_command(ctx, ORCH, cmd)
    reps = replies(ctx, RemediationCompletionReport)
    assert len(reps) == 2 and reps[0] == reps[1] and len(github_writes(web)) == writes and len(hook.calls) == 1


async def test_a_retry_after_a_partial_run_reuses_the_branch_and_the_existing_pr(ctx):
    ex, web, _ = build()
    web.github.branches[f"sentinel/fix-{INC}"] = MAIN_SHA
    web.github.pulls.append({"head": f"sentinel/fix-{INC}", "base": "main", "number": 7, "html_url": f"https://github.com/{REPO}/pull/7"})
    await run(ex, ctx, command())
    (rep,) = replies(ctx, RemediationCompletionReport)
    assert rep.success and rep.pr_url.endswith("/pull/7")


# ------------------------------------------------------------------ hotfix webhook

async def test_failed_webhook_still_reports_the_pr_but_not_the_redeploy(ctx):
    ex, web, hook = build(hook=Hook(status=401))
    await run(ex, ctx, command())
    (rep,) = replies(ctx, RemediationCompletionReport)
    assert rep.success and not rep.redeploy_triggered and "NOT triggered" in rep.summary_message and "HTTP 401" in rep.summary_message


async def test_unreachable_webhook_is_contained(ctx):
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    ex, web, _ = build()
    ex.webhook_http = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    await run(ex, ctx, command())
    (rep,) = replies(ctx, RemediationCompletionReport)
    assert rep.success and not rep.redeploy_triggered and "ConnectError" in rep.summary_message


@pytest.mark.parametrize("url", ["http://evil.example/admin/apply-hotfix", "http://demo/other", "ftp://demo/admin/apply-hotfix",
                                 "http://user:pw@demo/admin/apply-hotfix", "not a url", "http://demo.evil.example/admin/apply-hotfix"])
async def test_webhook_url_must_be_the_demo_hotfix_endpoint_on_the_target_host(ctx, url):
    ex, web, hook = build(service_url="http://demo")
    await run(ex, ctx, command(hook=url))
    (rep,) = replies(ctx, RemediationCompletionReport)
    assert rep.success and not rep.redeploy_triggered and hook.calls == [] and "refused" in rep.summary_message


async def test_no_webhook_requested_means_no_call(ctx):
    ex, _, hook = build()
    await run(ex, ctx, command(hook=None))
    assert replies(ctx, RemediationCompletionReport)[0].redeploy_triggered is False and hook.calls == []


def test_webhook_allowed_unit():
    assert webhook_allowed("http://demo/admin/apply-hotfix") and webhook_allowed("https://x.onrender.com/admin/apply-hotfix/", "https://x.onrender.com")
    assert not webhook_allowed("https://y.onrender.com/admin/apply-hotfix", "https://x.onrender.com")


# ------------------------------------------------------------------ safety checks: refuse BEFORE any write

async def refused(ctx, ex, web, cmd, needle, **kw):
    await run(ex, ctx, cmd, **kw)
    assert replies(ctx, RemediationCompletionReport) == []
    (err,) = replies(ctx, AgentErrorReport)
    assert err.agent == "Agent_5" and err.stage == "execute" and needle in err.error, err.error
    assert github_writes(web) == []


async def test_tampered_diff_or_hash_is_refused(ctx):
    ex, web, hook = build()
    good = attestation()
    tampered = evolve(good, unified_diff=good.unified_diff + "\n+evil")
    await refused(ctx, ex, web, command(tampered), "attestation")
    assert hook.calls == []


async def test_forged_attestation_that_the_scanner_never_approved_is_refused(ctx):
    ex, web, _ = build()
    cmd = command()
    seed(ctx, ex, "0" * 64)                              # the Scanner approved a different hash
    await ex.handle_execute_command(ctx, ORCH, cmd)
    assert replies(ctx, AgentErrorReport) and github_writes(web) == []


async def test_unapproved_or_hashless_attestation_cannot_open_a_fix_pr(ctx):
    ex, web, _ = build()
    await refused(ctx, ex, web, command(attestation(approved=False)), "attestation")
    ctx2 = FakeContext()
    ex2, web2, _ = build()
    await refused(ctx2, ex2, web2, command(attestation(attestation_hash="")), "attestation")


async def test_patch_with_sast_findings_is_refused_even_if_hashed(ctx):
    ex, web, _ = build()
    await refused(ctx, ex, web, command(attestation(patched=draft_adding_a_new_finding())), "security findings")


async def test_attested_file_must_be_the_incident_file(ctx):
    ex, web, _ = build()
    await refused(ctx, ex, web, command(attestation(target_file="other.py")), "attest")


async def test_command_from_anyone_but_the_orchestrator_is_ignored(ctx):
    ex, web, _ = build()
    await run(ex, ctx, command(), sender="agent1qintruderintruderintruderintruderintruderintr")
    assert ctx.sent == [] and github_writes(web) == []


async def test_command_for_an_unknown_incident_or_wrong_repo_is_refused(ctx):
    ex, web, _ = build()
    await ex.handle_execute_command(ctx, ORCH, command())
    assert "no draft" in replies(ctx, AgentErrorReport)[0].error
    ctx2 = FakeContext()
    seed(ctx2, ex, command().attestation.attestation_hash)
    other = evolve(command(), repo_full_name="evil/repo")
    await ex.handle_execute_command(ctx2, ORCH, other)
    assert "does not match" in replies(ctx2, AgentErrorReport)[0].error and github_writes(web) == []


async def test_unknown_action_type_is_refused(ctx):
    ex, web, _ = build()
    await refused(ctx, ex, web, command(action="DELETE_EVERYTHING"), "unknown action_type")


async def test_writes_to_a_repo_outside_the_allowlist_are_refused_by_the_client(ctx):
    ex, web, _ = build()
    ex.gh = GitHubClient(web.client(), token="t", write_allowlist=["someone/else"])
    await run(ex, ctx, command())
    assert "allowlist" in replies(ctx, AgentErrorReport)[0].error and web.github.pulls == []


# ------------------------------------------------------------------ payment re-verification (SKIP_PAYMENT=false)

async def test_paid_execution_reverifies_the_transaction_and_records_it(ctx):
    chain = standard_chain()
    ex, web, _ = build(chain=chain, skip_payment=False)
    await run(ex, ctx, command(tx=TX_GOOD, payer=PAYER))
    (rep,) = replies(ctx, RemediationCompletionReport)
    assert rep.success and rep.dorado_tx_hash == TX_GOOD and rep.dorado_explorer_url.endswith(f"/{TX_GOOD}") and chain.lookups == [TX_GOOD]
    body = web.github.pulls[0]["body"]
    assert f"[`{TX_GOOD}`]" in body and f"`{PAYER}`" in body and "explore-dorado.fetch.ai" in body


@pytest.mark.parametrize("tx,needle", [("", "no transaction hash"), (TX_UNDER, "Underpaid"), (TX_OTHER, "different wallet"),
                                       (TX_FAILED, "failed on-chain"), ("F" * 64, "not found")])
async def test_unpaid_or_bad_payment_never_opens_a_pr(ctx, tx, needle):
    ex, web, hook = build(skip_payment=False)
    await refused(ctx, ex, web, command(tx=tx), needle)
    assert hook.calls == [] and web.github.pulls == []


async def test_payer_mismatch_is_refused(ctx):
    ex, web, _ = build(skip_payment=False)
    await refused(ctx, ex, web, command(tx=TX_GOOD, payer="fetch1someoneelse"), "payer wallet mismatch")


async def test_a_transaction_cannot_authorize_two_incidents_in_the_executor(ctx):
    ex, web, _ = build(skip_payment=False)
    await run(ex, ctx, command(tx=TX_GOOD, payer=PAYER))
    second = "inc-exec0002"
    att = attestation()
    att2 = evolve(att, incident_id=second, attestation_hash=attestation_hash(second, "app.py", att.unified_diff, REQS, SCANNER))
    ctx.storage.set(f"pr:{second}", ctx.storage.get(f"pr:{INC}").replace('"approved_hash": "%s"' % att.attestation_hash,
                                                                        '"approved_hash": "%s"' % att2.attestation_hash))
    await ex.handle_execute_command(ctx, ORCH, evolve(command(tx=TX_GOOD, payer=PAYER), incident_id=second, attestation=att2.dict()))
    errors = replies(ctx, AgentErrorReport)
    assert errors and "replay refused" in errors[-1].error
    assert len(web.github.pulls) == 1


async def test_github_failure_releases_the_payment_so_a_retry_can_use_it(ctx):
    web = FakeWeb()
    web.github.fail_write_status = 500
    ex, _, _ = build(web=web, skip_payment=False)
    await run(ex, ctx, command(tx=TX_GOOD, payer=PAYER))
    assert replies(ctx, AgentErrorReport) and not ctx.storage.get(f"used_tx:{TX_GOOD}")
    web.github.fail_write_status = None
    web.github.branches.pop(f"sentinel/fix-{INC}", None)
    await ex.handle_execute_command(ctx, ORCH, command(tx=TX_GOOD, payer=PAYER))
    assert replies(ctx, RemediationCompletionReport)[0].success


# ------------------------------------------------------------------ rollback

async def test_rollback_restores_the_parent_version_of_the_file_without_an_attestation(ctx):
    ex, web, hook = build()
    web.github.ref_files[(README_SHA, "app.py")] = runtime_fixed_app_source()      # file as it was before the suspect commit
    unvetted = attestation(approved=False, attestation_hash="")
    await run(ex, ctx, command(unvetted, action="ROLLBACK_COMMIT"), approved=False)
    (rep,) = replies(ctx, RemediationCompletionReport)
    assert rep.success and rep.redeploy_triggered
    files = web.github.branch_files[f"sentinel/fix-{INC}"]
    assert files["app.py"] == runtime_fixed_app_source() and set(files) == {"app.py", "sbom.cdx.json"}
    assert "pyyaml==5.3" in json.dumps(json.loads(files["sbom.cdx.json"])["components"]) or "pkg:pypi/pyyaml@5.3" in files["sbom.cdx.json"]
    assert "Rollback" in web.github.pulls[0]["title"] + web.github.pulls[0]["body"] and "rollback" in web.github.pulls[0]["body"].lower()
    assert len(hook.calls) == 1


async def test_rollback_without_an_available_parent_is_refused(ctx):
    ex, web, _ = build()
    await refused(ctx, ex, web, command(attestation(approved=False, attestation_hash=""), action="ROLLBACK_COMMIT"),
                  "no rollback is available", approved=False, rollback=False)


async def test_rollback_still_requires_the_payment_when_payment_is_on(ctx):
    ex, web, _ = build(skip_payment=False)
    await refused(ctx, ex, web, command(attestation(approved=False, attestation_hash=""), action="ROLLBACK_COMMIT"),
                  "no transaction hash", approved=False)


# ------------------------------------------------------------------ pure helpers

def test_remaining_findings_and_pr_body_unit():
    findings = make_vuln_report(INC).cve_findings
    assert {f.vuln_id for f in remaining_findings(findings, REQS)} == {"GHSA-mh33-7rrq-662w"}
    assert len(remaining_findings(findings, DEMO_FILES["requirements.txt"])) == 3
    ctx_info = {"evidence": {"sha": HEAD_SHA, "url": "u", "author": "a", "explanation": "x | y"}, "target_file": "app.py", "cves": [], "sast": []}
    body = build_pr_body(INC, ctx_info, "OPEN_PR_AND_HOTFIX", "h" * 64, "", "", "", "sbom-url", REQS)
    assert "| — | none |" in body and "x \\| y" in body and "`" + "h" * 64 + "`" in body
