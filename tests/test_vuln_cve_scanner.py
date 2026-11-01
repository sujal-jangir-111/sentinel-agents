import json

import pytest

from agents.Agent_4 import VulnScanner, create_agent, sast_candidates
from common.ast_mapper import extract_symbols
from common.github_client import GitHubClient
from common.gatekeeper import attestation_hash
from common.models import (
    AgentErrorReport, PatchVettingRequest, SecurityApprovalAttestation, VulnerabilityReport, VulnerabilityScanRequest,
)
from common.patching import bump_requirements, fix_unsafe_yaml, harden_secrets, make_unified_diff
from common.osv_client import CRITICAL_EXPLOITABLE, LATENT_DEPENDENCY, classify
from tests.bureau_harness import agent_test_kwargs, run_roundtrip
from tests.fakes import (
    draft_adding_a_new_finding,
    DEMO_FILES, HEAD_SHA, REPO, FakeWeb, fully_fixed_app_source, runtime_fixed_app_source, sql_fixed,
)

FULL_SECRET = "sk_test_51SENTINELDEMOxxxxxxxx"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_):
        return None

    monkeypatch.setattr("common.http_retry._sleep", instant)


def make_scanner(web: FakeWeb) -> VulnScanner:
    http = web.client()
    return VulnScanner(gh=GitHubClient(http, token="t", write_allowlist=[]), http=http)


def request(imports=None, modified=("app.py",), incident_id="inc-scan") -> VulnerabilityScanRequest:
    return VulnerabilityScanRequest(
        incident_id=incident_id, repo_full_name=REPO, branch="main", suspect_commit_sha=HEAD_SHA,
        modified_files=list(modified),
        active_ast_imports=extract_symbols(DEMO_FILES["app.py"]) if imports is None else imports,
    )


def only_reply(ctx):
    (dest, msg), = ctx.sent
    return dest, msg


# ------------------------------------------------------------------ the demo scenario

async def test_reachable_pyyaml_cve_and_latent_urllib3(ctx):
    web = FakeWeb()
    await make_scanner(web).handle_scan_request(ctx, "agent1qsender", request())
    dest, report = only_reply(ctx)
    assert dest == "agent1qsender" and isinstance(report, VulnerabilityReport)

    by_pkg = {}
    for f in report.cve_findings:
        by_pkg.setdefault(f.package_name, []).append(f)
    assert {f.vuln_id for f in by_pkg["pyyaml"]} == {"GHSA-8q59-q68h-6hv4", "GHSA-6757-jp84-gxfx"}
    assert all(f.is_reachable_in_ast and classify(f) == CRITICAL_EXPLOITABLE for f in by_pkg["pyyaml"])
    critical = next(f for f in by_pkg["pyyaml"] if f.severity == "CRITICAL")
    assert critical.installed_version == "5.3" and critical.fixed_version == "5.4"
    assert all(not f.is_reachable_in_ast and classify(f) == LATENT_DEPENDENCY for f in by_pkg["urllib3"])
    assert by_pkg["urllib3"][0].fixed_version == "1.24.2"
    assert report.total_reachable_critical == 1
    assert [f.severity for f in report.cve_findings][0] == "CRITICAL"  # worst first


async def test_sast_catches_demo_app_and_dockerfile_issues_with_masked_secret(ctx):
    web = FakeWeb()
    await make_scanner(web).handle_scan_request(ctx, "s", request())
    report = only_reply(ctx)[1]
    app = {f.rule_id: f for f in report.sast_findings if f.file_path == "app.py"}
    assert set(app) == {"HARDCODED_SECRET", "UNSAFE_DESERIALIZATION", "SQL_INJECTION"}
    src = DEMO_FILES["app.py"].splitlines()
    assert "STRIPE_SECRET_KEY" in src[app["HARDCODED_SECRET"].line_number - 1]
    assert "yaml.load(" in src[app["UNSAFE_DESERIALIZATION"].line_number - 1]
    docker = [f for f in report.sast_findings if f.file_path == "Dockerfile"]
    assert len(docker) == 3 and {f.rule_id for f in docker} == {"INSECURE_DOCKER"}
    # the full secret must not appear anywhere in what leaves the agent
    assert FULL_SECRET not in report.json() and "sk_tes****" in app["HARDCODED_SECRET"].code_snippet


async def test_unreachable_when_package_not_imported(ctx):
    web = FakeWeb()
    await make_scanner(web).handle_scan_request(ctx, "s", request(imports=["json"]))
    report = only_reply(ctx)[1]
    assert report.total_reachable_critical == 0
    assert all(classify(f) == LATENT_DEPENDENCY for f in report.cve_findings) and len(report.cve_findings) == 3


async def test_sbom_generated_and_stored_per_incident(ctx):
    web = FakeWeb()
    await make_scanner(web).handle_scan_request(ctx, "s", request(incident_id="inc-sbom"))
    sbom = json.loads(ctx.storage.get("sbom:inc-sbom"))
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    assert {c["purl"] for c in sbom["components"]} == {"pkg:pypi/pyyaml@5.3", "pkg:pypi/urllib3@1.24.1"}
    assert {v["id"] for v in sbom["vulnerabilities"]} >= {"GHSA-8q59-q68h-6hv4", "GHSA-mh33-7rrq-662w"}


async def test_single_osv_batch_call_and_vuln_details_cached(ctx):
    web = FakeWeb()
    scanner = make_scanner(web)
    await scanner.handle_scan_request(ctx, "s", request())
    batches = [r for r in web.requests if r.url.path == "/v1/querybatch"]
    assert len(batches) == 1
    queries = json.loads(batches[0].content)["queries"]
    assert {(q["package"]["name"], q["version"]) for q in queries} == {("pyyaml", "5.3"), ("urllib3", "1.24.1")}
    detail_calls = web.count("api.osv.dev") - 1
    assert detail_calls == 3
    await scanner.handle_scan_request(ctx, "s", request())  # second scan: details come from the cache
    assert web.count("api.osv.dev") - 2 == 3


# ------------------------------------------------------------------ edge cases and failures

async def test_repo_without_manifests_returns_empty_report(ctx):
    web = FakeWeb()
    web.github.files = {"app.py": "print('hi')\n"}
    await make_scanner(web).handle_scan_request(ctx, "s", request())
    report = only_reply(ctx)[1]
    assert isinstance(report, VulnerabilityReport) and report.cve_findings == [] and report.sast_findings == []


async def test_deleted_modified_file_is_skipped(ctx):
    web = FakeWeb()
    await make_scanner(web).handle_scan_request(ctx, "s", request(modified=["app.py", "gone.py"]))
    assert isinstance(only_reply(ctx)[1], VulnerabilityReport)


async def test_osv_outage_sends_agent_error_report(ctx):
    web = FakeWeb()
    web.osv.fail_status = 503
    await make_scanner(web).handle_scan_request(ctx, "agent1qsender", request(incident_id="inc-osv"))
    dest, err = only_reply(ctx)
    assert dest == "agent1qsender" and isinstance(err, AgentErrorReport)
    assert err.incident_id == "inc-osv" and err.agent == "Agent_4" and "dependency scan failed" in err.error


async def test_github_outage_sends_agent_error_report(ctx):
    web = FakeWeb()
    web.github.fail_status = 500
    await make_scanner(web).handle_scan_request(ctx, "s", request())
    assert isinstance(only_reply(ctx)[1], AgentErrorReport)


async def test_uninitialised_clients_report_error(ctx):
    await VulnScanner().handle_scan_request(ctx, "s", request())
    assert isinstance(only_reply(ctx)[1], AgentErrorReport)


def test_sast_candidates():
    assert sast_candidates(["app.py", "README.md", "app.py", "deploy/Dockerfile.prod", "x.js"]) == [
        "app.py", "deploy/Dockerfile.prod", "Dockerfile"]
    assert sast_candidates([]) == ["Dockerfile"]
    assert len(sast_candidates([f"f{i}.py" for i in range(100)])) == 30


# ------------------------------------------------------------------ agent wiring + Bureau round trip

def test_create_agent_requires_seed(monkeypatch):
    monkeypatch.delenv("SCANNER_SEED", raising=False)
    with pytest.raises(RuntimeError, match="SCANNER_SEED"):
        create_agent(mailbox=False)


async def test_create_agent_defaults():
    agent = create_agent(seed="scanner wiring seed", enable_agent_inspector=False)
    assert agent.name == "Agent_4" and agent.mailbox_client is not None  # mailbox=True by default


def test_bureau_round_trip_catches_reachable_pyyaml_cve():
    web = FakeWeb()

    async def make_target(port: int):
        return create_agent(seed="bureau scanner seed", port=port, scanner=make_scanner(web), **agent_test_kwargs())

    target_addr, sender, report = run_roundtrip(make_target, lambda: request(incident_id="inc-bureau-scan"))
    assert sender == target_addr and isinstance(report, VulnerabilityReport)
    assert report.incident_id == "inc-bureau-scan" and report.total_reachable_critical == 1
    assert {f.rule_id for f in report.sast_findings} == {
        "HARDCODED_SECRET", "UNSAFE_DESERIALIZATION", "SQL_INJECTION", "INSECURE_DOCKER"}
    assert any(f.package_name == "pyyaml" and f.is_reachable_in_ast and f.fixed_version == "5.4"
               for f in report.cve_findings)


# ------------------------------------------------------------------ Part B: patch gatekeeper

FAKE_CTX_ADDRESS = "agent1qfakeaddress"  # FakeContext.agent.address


def vet_request(patched=None, reqs=None, diff=None, target="app.py", incident_id="inc-scan") -> PatchVettingRequest:
    patched = fully_fixed_app_source() if patched is None else patched
    return PatchVettingRequest(
        incident_id=incident_id, repo_full_name=REPO, target_file=target, patched_code_content=patched,
        updated_requirements_txt=bump_requirements(DEMO_FILES["requirements.txt"], {"pyyaml": "5.4"}) if reqs is None else reqs,
        unified_diff=make_unified_diff(DEMO_FILES["app.py"], patched, target) if diff is None else diff,
    )


async def scanned(ctx, web=None):
    """A scanner that has already scanned the incident (so the gatekeeper knows the reachable CVEs)."""
    web = web or FakeWeb()
    scanner = make_scanner(web)
    await scanner.handle_scan_request(ctx, "s", request())
    ctx.sent.clear()
    return scanner, web


async def vet(scanner, ctx, req) -> SecurityApprovalAttestation:
    await scanner.handle_vetting_request(ctx, "agent1qexecutor", req)
    dest, reply = only_reply(ctx)
    assert dest == "agent1qexecutor"
    return reply


async def test_gatekeeper_approves_a_clean_complete_patch(ctx):
    scanner, _ = await scanned(ctx)
    req = vet_request()
    att = await vet(scanner, ctx, req)
    assert att.approved is True and att.rejection_reasons == []
    assert att.attestation_hash == attestation_hash("inc-scan", "app.py", req.unified_diff,
                                                    req.updated_requirements_txt, FAKE_CTX_ADDRESS)
    assert (att.target_file, att.patched_code_content, att.unified_diff) == ("app.py", req.patched_code_content, req.unified_diff)
    assert "pyyaml==5.4" in att.updated_requirements_txt


async def test_gatekeeper_rejects_unfixed_reachable_cve(ctx):
    scanner, _ = await scanned(ctx)
    att = await vet(scanner, ctx, vet_request(reqs=DEMO_FILES["requirements.txt"]))  # pyyaml still 5.3
    assert att.approved is False and att.attestation_hash == ""
    assert any("GHSA-8q59-q68h-6hv4 still affects pyyaml==5.3" in r for r in att.rejection_reasons)
    assert any("GHSA-6757-jp84-gxfx" in r for r in att.rejection_reasons)
    assert not any("urllib3" in r for r in att.rejection_reasons)  # latent CVEs are not required to be fixed


async def test_gatekeeper_rejects_a_patch_that_adds_a_security_finding(ctx):
    scanner, _ = await scanned(ctx)
    att = await vet(scanner, ctx, vet_request(patched=draft_adding_a_new_finding()))
    assert att.approved is False
    joined = " | ".join(att.rejection_reasons)
    assert "UNSAFE_EVAL" in joined and "sk_test_51SENTINELDEMOxxxxxxxx" not in joined


async def test_findings_the_file_already_had_do_not_block_a_fix(ctx):
    """In a real codebase one old warning would otherwise reject every patch, so a fix only has to not make things worse."""
    scanner, _ = await scanned(ctx)
    att = await vet(scanner, ctx, vet_request(patched=runtime_fixed_app_source()))
    assert att.approved is True and att.rejection_reasons == []


async def test_gatekeeper_rejects_patch_that_leaves_the_offending_line(ctx):
    scanner, _ = await scanned(ctx)
    still_broken = fix_unsafe_yaml(harden_secrets(sql_fixed(DEMO_FILES["app.py"])))  # clean, but fault untouched
    att = await vet(scanner, ctx, vet_request(patched=still_broken))
    assert att.approved is False
    assert any("runtime fault not fixed" in r and 'PRICING["discount_rate"]' in r for r in att.rejection_reasons)


async def test_gatekeeper_rejects_forged_diff_empty_patch_and_syntax_errors(ctx):
    scanner, _ = await scanned(ctx)
    forged = await vet(scanner, ctx, vet_request(diff="--- a/app.py\n+++ b/app.py\n+harmless"))
    assert any("unified_diff does not match" in r for r in forged.rejection_reasons)
    ctx.sent.clear()
    unchanged = await vet(scanner, ctx, vet_request(patched=DEMO_FILES["app.py"]))
    assert any("no changes" in r for r in unchanged.rejection_reasons)
    ctx.sent.clear()
    broken = await vet(scanner, ctx, vet_request(patched="def f(:\n"))
    assert any("does not parse" in r for r in broken.rejection_reasons)


async def test_gatekeeper_rejects_missing_target_and_unpinned_package(ctx):
    scanner, _ = await scanned(ctx)
    missing = await vet(scanner, ctx, vet_request(target="nope.py", diff="x"))
    assert any("not found on main" in r for r in missing.rejection_reasons)
    ctx.sent.clear()
    dropped = await vet(scanner, ctx, vet_request(reqs="fastapi\nurllib3==1.24.1\n"))
    assert any("pyyaml" in r and "not pinned" in r for r in dropped.rejection_reasons)


async def test_gatekeeper_without_stored_scan_uses_conservative_critical_rule(ctx):
    scanner = make_scanner(FakeWeb())  # never scanned this incident
    ok = await vet(scanner, ctx, vet_request())
    assert ok.approved is True
    ctx.sent.clear()
    bad = await vet(scanner, ctx, vet_request(reqs=DEMO_FILES["requirements.txt"]))
    assert bad.approved is False and any("[CRITICAL] still affects pyyaml==5.3" in r for r in bad.rejection_reasons)


async def test_gatekeeper_errors_become_agent_error_reports(ctx):
    web = FakeWeb()
    scanner, _ = await scanned(ctx, web)
    web.osv.fail_status = 503
    await scanner.handle_vetting_request(ctx, "agent1qexecutor", vet_request())
    dest, err = only_reply(ctx)
    assert isinstance(err, AgentErrorReport) and err.stage == "gatekeeper" and err.agent == "Agent_4"
    ctx.sent.clear()
    await VulnScanner().handle_vetting_request(ctx, "agent1qexecutor", vet_request())
    assert isinstance(only_reply(ctx)[1], AgentErrorReport)
