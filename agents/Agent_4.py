"""Agent_4 agent (CLAUDE.md §5.4 part A): reachability-aware SCA + SAST + SBOM.

Part B is the adversarial patch gatekeeper: it re-checks every proposed patch (SAST, syntax, honest diff,
offending change removed, reachable CVEs fixed) before issuing a hash-bound SecurityApprovalAttestation.

Run standalone:  python -m agents.Agent_4                           
"""     
import asyncio
import json
import os
from typing import Any, Dict, List, Optional

import httpx
from uagents import Context

from common import gatekeeper, osv_client
from common.dependency_check import new_conflicts
from common.activity import DONE, report as activity
from common.agent_factory import build_agent
from common.config import get_settings  
from common.github_client import GitHubClient
from common.logging import configure_console_utf8, log
from common.models import (
    AgentErrorReport, PatchVettingRequest, SASTFinding, SecurityApprovalAttestation, VulnerabilityReport,
    VulnerabilityScanRequest,
)
from common.osv_client import OSVError
from common.patching import added_lines
from common.sast_rules import scan_files
from common.sbom_generator import build_sbom, sbom_to_json

AGENT_NAME = "Agent_4"
AGENT_LABEL = "Agent_4"  # display name on Agentverse and in uagents logs
PORT = 8004
MAX_SAST_FILES = 30
DESCRIPTION = (
    "Agent_4 (Vuln-CVE-Scanner): reachability-aware CVE scan (OSV.dev), SAST, CycloneDX SBOM, and the patch gatekeeper that vets every fix. Part of the Sentinel self-healing DevSecOps swarm (Fetch-A-Thon 3.0)."
)
DEFAULT_BRANCH = "main"
WHOLE_REPO = "*"


def sast_candidates(modified_files: List[str]) -> List[str]:
    """Scannable paths from the modified files (Python / Dockerfile) plus the root Dockerfile, deduplicated."""
    wanted = [p for p in modified_files if p.endswith(".py") or os.path.basename(p).lower().startswith("dockerfile")]
    return list(dict.fromkeys([*wanted, "Dockerfile"]))[:MAX_SAST_FILES]


class VulnScanner:
    def __init__(self, gh: Optional[GitHubClient] = None, http: Optional[httpx.AsyncClient] = None) -> None:
        self.gh, self.http = gh, http
        self._owns_http = False
        self.vuln_cache: Dict[str, Dict[str, Any]] = {}

    async def startup(self, ctx: Context) -> None:
        if self.http is None:
            self.http, self._owns_http = httpx.AsyncClient(timeout=30), True
        if self.gh is None:
            self.gh = GitHubClient(self.http)
        ctx.logger.info(f"Address: {ctx.agent.address}")
        log(ctx.logger, "-", AGENT_NAME, "startup", "✅ ready")

    async def shutdown(self, ctx: Context) -> None:
        if self.http is not None and self._owns_http:
            await self.http.aclose()

    async def handle_scan_request(self, ctx: Context, sender: str, msg: VulnerabilityScanRequest) -> None:
        inc = msg.incident_id
        try:
            report = await self.scan(ctx, msg)
            await ctx.send(sender, report)
        except Exception as exc:  # handlers never raise
            log(ctx.logger, inc, AGENT_NAME, "scan", f"error: {type(exc).__name__}: {exc}", level="error")
            try:
                await ctx.send(sender, AgentErrorReport(
                    incident_id=inc, agent=AGENT_NAME, stage="scan", error=f"{type(exc).__name__}: {exc}"[:500]))
            except Exception as send_exc:
                log(ctx.logger, inc, AGENT_NAME, "scan", f"could not deliver error report: {send_exc}", level="error")

    async def scan(self, ctx: Context, msg: VulnerabilityScanRequest) -> VulnerabilityReport:
        assert self.gh is not None and self.http is not None, "clients not initialised"
        inc, repo, ref = msg.incident_id, msg.repo_full_name, msg.branch

        await activity(ctx, inc, AGENT_NAME, "Reading the project's dependency list")
        manifests = await self.gh.fetch_manifests(repo, ref)
        deps = osv_client.parse_manifests(manifests)
        modified = msg.modified_files
        if WHOLE_REPO in modified:    # a security audit looks at the code, not only one suspect file
            modified = list(await self.gh.fetch_python_sources(repo, ref))
        paths = sast_candidates(modified)
        log(ctx.logger, inc, AGENT_NAME, "scan",
            f"🛡️ Scanning {len(deps)} pinned dependencies and {len(paths)} file(s) at {repo}@{ref}")

        await activity(ctx, inc, AGENT_NAME, f"Checking {len(deps)} dependencies and {len(paths)} file(s) for known problems")
        cve_findings, (sast_findings, files_scanned) = await asyncio.gather(
            self._scan_dependencies(deps, msg.active_ast_imports), self._scan_code(repo, ref, paths),
        )
        reachable_critical = osv_client.count_reachable(cve_findings, "CRITICAL")

        sbom = build_sbom(deps, repo, inc, cve_findings)
        ctx.storage.set(f"sbom:{inc}", sbom_to_json(sbom))  # the executor rebuilds it for the PR; kept for the audit trail
        ctx.storage.set(f"scan:{inc}", json.dumps({  # what the gatekeeper later holds the patch to
            "branch": ref, "suspect_commit_sha": msg.suspect_commit_sha,
            "reachable": [f.dict() for f in cve_findings if f.is_reachable_in_ast],
        }))

        for f in cve_findings:
            if f.is_reachable_in_ast:
                log(ctx.logger, inc, AGENT_NAME, "cve",
                    f"{osv_client.classify(f)}: {f.package_name}=={f.installed_version} {f.vuln_id} "
                    f"[{f.severity}] fix → {f.fixed_version}")
        log(ctx.logger, inc, AGENT_NAME, "report",
            f"📋 {len(cve_findings)} CVEs ({reachable_critical} reachable CRITICAL), "
            f"{len(sast_findings)} SAST findings, SBOM with {len(sbom['components'])} components")
        reachable = sum(1 for f in cve_findings if f.is_reachable_in_ast)
        await activity(ctx, inc, AGENT_NAME, f"Checked {files_scanned} files and {len(deps)} dependencies: {reachable} vulnerabilities "
                                             f"affect this code, {len(sast_findings)} code problems", DONE)
        return VulnerabilityReport(
            incident_id=inc, repo_full_name=repo, cve_findings=cve_findings, sast_findings=sast_findings,
            total_reachable_critical=reachable_critical, files_scanned=files_scanned, dependencies_scanned=len(deps),
        )

    async def _scan_dependencies(self, deps: List[osv_client.Dependency], imports: List[str]) -> list:
        assert self.http is not None
        try:
            return await osv_client.build_cve_findings(self.http, deps, imports, self.vuln_cache)
        except OSVError as exc:
            raise OSVError(f"dependency scan failed: {exc}") from exc

    async def _scan_code(self, repo: str, ref: str, paths: List[str]) -> "tuple[List[SASTFinding], int]":
        """(findings, how many files really existed and were scanned)."""
        assert self.gh is not None
        files = await asyncio.gather(*(self.gh.get_file(repo, p, ref) for p in paths))
        found = {f.path: f.text for f in files if f is not None}
        return scan_files(found), len(found)


    # -- Part B: adversarial patch gatekeeper ------------------------------------------------

    async def handle_vetting_request(self, ctx: Context, sender: str, msg: PatchVettingRequest) -> None:
        inc = msg.incident_id
        try:
            attestation = await self.vet(ctx, msg)
            await ctx.send(sender, attestation)
        except Exception as exc:  # handlers never raise
            log(ctx.logger, inc, AGENT_NAME, "gatekeeper", f"error: {type(exc).__name__}: {exc}", level="error")
            try:
                await ctx.send(sender, AgentErrorReport(
                    incident_id=inc, agent=AGENT_NAME, stage="gatekeeper", error=f"{type(exc).__name__}: {exc}"[:500]))
            except Exception as send_exc:
                log(ctx.logger, inc, AGENT_NAME, "gatekeeper", f"could not deliver error report: {send_exc}", level="error")

    async def vet(self, ctx: Context, msg: PatchVettingRequest) -> SecurityApprovalAttestation:
        assert self.gh is not None and self.http is not None, "clients not initialised"
        inc, repo, target = msg.incident_id, msg.repo_full_name, msg.target_file
        raw_context = ctx.storage.get(f"scan:{inc}")
        scan_ctx: Optional[dict] = json.loads(raw_context) if raw_context else None
        branch = (scan_ctx or {}).get("branch", DEFAULT_BRANCH)
        log(ctx.logger, inc, AGENT_NAME, "gatekeeper", f"🔒 Vetting patch for {target} against {repo}@{branch}")
        await activity(ctx, inc, AGENT_NAME, "Reviewing the draft: does it parse, is it safe, can it install?")

        original = await self.gh.get_file(repo, target, branch)
        reasons: List[str] = []
        reasons += gatekeeper.check_diff(original.text if original else None, msg.patched_code_content,
                                         target, msg.unified_diff, branch)
        reasons += gatekeeper.check_syntax(target, msg.patched_code_content)
        reasons += gatekeeper.check_references(target, msg.patched_code_content, original.text if original else None)
        reasons += gatekeeper.check_sast(target, msg.patched_code_content, original.text if original else None)
        if scan_ctx and scan_ctx.get("suspect_commit_sha"):
            commit = await self.gh.get_commit(repo, scan_ctx["suspect_commit_sha"])
            offending = [ln for f in commit.files if f.filename == target for ln in added_lines(f.patch)]
            reasons += gatekeeper.check_fault_fixed(msg.patched_code_content, offending)

        before = await self.gh.get_file(repo, "requirements.txt", branch)
        reasons += [c.reason for c in await new_conflicts(self.http, before.text if before else "", msg.updated_requirements_txt)]
        new_deps = osv_client.parse_requirements(msg.updated_requirements_txt)
        new_findings = await osv_client.build_cve_findings(self.http, new_deps, [], self.vuln_cache)
        if scan_ctx is not None:
            current = await self.gh.get_file(repo, "requirements.txt", branch)
            managed = {d.name for d in osv_client.parse_requirements(current.text)} if current else set()
            required = [r for r in scan_ctx.get("reachable", []) if r["package_name"] in managed]   # a patch can only bump these
            reasons += gatekeeper.check_cves_fixed(required, new_deps, new_findings)
        else:
            reasons += gatekeeper.check_no_critical(new_findings)  # no stored scan: be conservative

        approved = not reasons
        digest = gatekeeper.attestation_hash(
            inc, target, msg.unified_diff, msg.updated_requirements_txt, ctx.agent.address) if approved else ""
        if approved:
            log(ctx.logger, inc, AGENT_NAME, "gatekeeper", f"✅ Patch APPROVED (attestation {digest[:12]}…)")
            await activity(ctx, inc, AGENT_NAME, "Draft passed the security review", DONE)
        else:
            await activity(ctx, inc, AGENT_NAME, f"Sent the draft back: {reasons[0][:140]}")
            log(ctx.logger, inc, AGENT_NAME, "gatekeeper", f"❌ Patch REJECTED: {len(reasons)} reason(s)", level="warning")
            for reason in reasons:
                log(ctx.logger, inc, AGENT_NAME, "gatekeeper", f"   - {reason}", level="warning")
        return SecurityApprovalAttestation(
            incident_id=inc, approved=approved, attestation_hash=digest, rejection_reasons=reasons,
            target_file=target, patched_code_content=msg.patched_code_content,
            updated_requirements_txt=msg.updated_requirements_txt, unified_diff=msg.unified_diff,
        )


def create_agent(
    seed: Optional[str] = None, mailbox: bool = True, port: int = PORT,
    scanner: Optional[VulnScanner] = None, **agent_kwargs: Any,
):
    cfg = get_settings()
    sc = scanner or VulnScanner()
    agent = build_agent(
        name=AGENT_LABEL, seed=seed or cfg.scanner_seed, seed_env="SCANNER_SEED", port=port,
        description=DESCRIPTION, mailbox=mailbox, **agent_kwargs,
    )

    @agent.on_event("startup")
    async def _startup(ctx: Context) -> None:
        await sc.startup(ctx)

    @agent.on_event("shutdown")
    async def _shutdown(ctx: Context) -> None:
        await sc.shutdown(ctx)

    @agent.on_message(VulnerabilityScanRequest)
    async def _on_scan(ctx: Context, sender: str, msg: VulnerabilityScanRequest) -> None:
        await sc.handle_scan_request(ctx, sender, msg)

    @agent.on_message(PatchVettingRequest)
    async def _on_vetting(ctx: Context, sender: str, msg: PatchVettingRequest) -> None:
        await sc.handle_vetting_request(ctx, sender, msg)

    agent.scanner = sc  # type: ignore[attr-defined]
    return agent


if __name__ == "__main__":
    configure_console_utf8()
    create_agent(mailbox=True).run()
