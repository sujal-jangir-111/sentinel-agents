"""Helpers for executing an approved remediation (CLAUDE.md §5.5 ExecuteRemediationCommand, §10 PR body).

Pure functions plus two small async helpers (GitHub publish, hotfix webhook) so the Executor agent stays thin
and everything is unit-testable offline.
"""
import json
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from common.config import Settings
from common.dorado import DoradoVerifier, explorer_url
from common.gatekeeper import attestation_hash, check_sast
from common.github_client import FIX_BRANCH_PREFIX, GitHubClient, GitHubError, blob_url
from common.models import CVEFinding, ExecuteRemediationCommand, RemediationCompletionReport
from common.osv_client import normalize_name, parse_requirements
from common.sbom_generator import build_sbom

HOTFIX_PATH = "/admin/apply-hotfix"
SBOM_PATH = "sbom.cdx.json"
WEBHOOK_TIMEOUT = 15.0


def fix_branch(incident_id: str) -> str:
    return f"{FIX_BRANCH_PREFIX}{incident_id}"


def webhook_allowed(url: str, service_url: str = "") -> bool:
    """The reload webhook carries the admin token, so it may only be the demo hotfix endpoint (and, when a service
    URL is configured, only on that service's host)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path.rstrip("/") != HOTFIX_PATH:
        return False
    if parts.username or parts.password:
        return False
    if service_url:
        return (urlsplit(service_url).hostname or "").lower() == parts.hostname.lower()
    return True


async def trigger_webhook(http: httpx.AsyncClient, url: str, token: str) -> Tuple[bool, str]:
    """POST the hotfix webhook with X-Sentinel-Token. Never raises; returns (ok, short note)."""
    if not token:
        return False, "DEMO_ADMIN_TOKEN is not configured"
    try:
        resp = await http.post(url, headers={"X-Sentinel-Token": token}, timeout=WEBHOOK_TIMEOUT)
    except httpx.HTTPError as exc:
        return False, f"{type(exc).__name__} while calling the hotfix webhook"
    if resp.status_code >= 400:
        return False, f"hotfix webhook answered HTTP {resp.status_code}"
    return True, f"hotfix webhook answered HTTP {resp.status_code}"


def remaining_findings(findings: Iterable[CVEFinding], requirements_txt: str) -> List[CVEFinding]:
    """Findings whose affected version is still pinned in `requirements_txt` (i.e. not fixed by this change)."""
    pinned = {d.name: d.version for d in parse_requirements(requirements_txt)}
    return [f for f in findings if pinned.get(normalize_name(f.package_name)) == f.installed_version]


def sbom_json(requirements_txt: str, repo: str, incident_id: str, findings: Iterable[CVEFinding]) -> str:
    """CycloneDX 1.5 SBOM of the dependencies as they will be AFTER this change, listing only unresolved findings."""
    sbom = build_sbom(parse_requirements(requirements_txt), repo, incident_id, remaining_findings(findings, requirements_txt))
    return json.dumps(sbom, indent=2) + "\n"


def _cell(text: Any, limit: int = 200) -> str:
    s = str(text).replace("|", "\\|").replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def build_pr_body(
    incident_id: str, ctx: Dict[str, Any], action_type: str, attestation_hash: str, tx_hash: str, explorer: str,
    payer: str, sbom_url: str, requirements_txt: str,
) -> str:
    """CLAUDE.md §10 template. `ctx` is what the Executor remembered from the draft stage."""
    ev = ctx["evidence"]
    short = ev["sha"][:7]
    rows: List[str] = []
    fixed = {normalize_name(d.name): d.version for d in parse_requirements(requirements_txt)}
    for f in ctx["cves"]:
        resolved = action_type == "OPEN_PR_AND_HOTFIX" and fixed.get(normalize_name(f["package_name"])) != f["installed_version"]
        fix = f"{f['package_name']} → {f['fixed_version']}" if resolved else "not changed by this PR"
        rows.append(f"| {_cell(f['vuln_id'])} | `{f['package_name']}=={f['installed_version']}` | {f['severity']} | "
                    f"{'yes' if f['is_reachable_in_ast'] else 'no'} | {fix} |")
    for s in ctx["sast"]:
        fix = "patched" if action_type == "OPEN_PR_AND_HOTFIX" and s["file_path"] == ctx["target_file"] else "not changed by this PR"
        rows.append(f"| {s['rule_id']} | `{_cell(s['file_path'])}:{s['line_number']}` | {s['severity']} | in modified code | {fix} |")
    table = "| ID | Package / Rule | Severity | Reachable | Fix |\n|---|---|---|---|---|\n" + ("\n".join(rows) if rows else "| — | none | — | — | — |")
    audit = [f"- **Dorado testnet tx:** [`{tx_hash}`]({explorer})" if tx_hash else "- **Dorado testnet tx:** none (payment skipped, dev mode)"]
    if payer:
        audit.append(f"- **Authorized by wallet:** `{payer}`")
    audit.append(f"- **Security attestation:** `{attestation_hash}` (Agent_4)" if attestation_hash
                 else "- **Security attestation:** none — rollback to the pre-incident version of the file")
    audit.append(f"- **SBOM:** [`{SBOM_PATH}`]({sbom_url}) (CycloneDX v1.5)")
    kind = "Rollback of the suspect commit" if action_type == "ROLLBACK_COMMIT" else "Forward patch"
    return (
        f"## 🛡️ Sentinel Auto-Remediation — {incident_id}\n\n_{kind}._\n\n### Root Cause\n"
        "| Field | Value |\n|---|---|\n"
        f"| Suspect commit | [{short}]({ev['url']}) by @{ev['author']} |\n"
        f"| File | `{ctx['target_file']}` |\n"
        f"| Explanation | {_cell(ev['explanation'], 500)} |\n\n"
        f"### Security Findings Fixed\n{table}\n\n### Change-Control Audit Trail\n" + "\n".join(audit)
        + "\n\n_Generated by the Sentinel multi-agent swarm on Fetch.ai._\n"
    )


async def publish_fix(
    gh: GitHubClient, repo: str, incident_id: str, files: Dict[str, str], title: str, body: str, base: str = "main",
) -> Tuple[str, str]:
    """Create sentinel/fix-<id> from `base`, commit `files`, open the PR. Idempotent: an existing branch is reused and
    an existing open PR is returned. Returns (pr_url, branch)."""
    branch = fix_branch(incident_id)
    try:
        await gh.create_branch(repo, branch, await gh.get_branch_sha(repo, base))
    except GitHubError as exc:
        if exc.status != 422:        # 422 = the branch already exists (a retry of an earlier partial run)
            raise
    for path, content in files.items():
        await gh.put_file(repo, path, content, f"Sentinel {incident_id}: update {path}", branch)
    try:
        pr = await gh.create_pull_request(repo, title, branch, base, body)
    except GitHubError as exc:
        if exc.status != 422:
            raise
        existing = await gh.find_open_pull_request(repo, branch)
        if existing is None:
            raise
        pr = existing
    return pr["html_url"], branch


# --------------------------------------------------------------------------- ExecuteRemediationCommand

class ExecutionRefused(Exception):
    """The command failed a safety check; nothing was written. The message is safe to show to the user."""


async def run_remediation(
    cmd: ExecuteRemediationCommand, ctx: Dict[str, Any], *, gh: GitHubClient, http: httpx.AsyncClient,
    verifier: DoradoVerifier, cfg: Settings, scanner_address: str, tx_used: Callable[[str], bool],
    mark_tx: Callable[[str], None], release_tx: Callable[[str], None],
    progress: Optional[Callable[[str], Awaitable[None]]] = None,
) -> RemediationCompletionReport:
    """Verify -> branch -> commit patch + manifest + SBOM -> PR -> hotfix webhook. Order matters: every refusal happens
    before the first GitHub write (CLAUDE.md §15: no PR without an approved attestation AND a verified, unused tx)."""
    inc, repo, att, base = cmd.incident_id, cmd.repo_full_name, cmd.attestation, cmd.branch

    async def step(text: str) -> None:
        if progress:
            await progress(text)

    rollback = cmd.action_type == "ROLLBACK_COMMIT"
    if cmd.action_type not in ("OPEN_PR_AND_HOTFIX", "ROLLBACK_COMMIT"):
        raise ExecutionRefused(f"unknown action_type {cmd.action_type!r}")
    if repo != ctx["repo"] or att.incident_id != inc:
        raise ExecutionRefused("the command does not match the incident this Executor drafted a fix for")
    target = ctx["target_file"]
    if rollback:
        if not ctx["rollback_available"]:
            raise ExecutionRefused("no rollback is available for this incident")
    else:
        expected = attestation_hash(inc, att.target_file, att.unified_diff, att.updated_requirements_txt, scanner_address)
        if not att.approved or not att.attestation_hash or att.attestation_hash != expected or att.attestation_hash != ctx.get("approved_hash"):
            raise ExecutionRefused("the security attestation is missing or does not verify against the Agent_4's approval")
        if att.target_file != target:
            raise ExecutionRefused("the attested file is not the file this incident is about")
        current = await gh.get_file(repo, target, base)
        if check_sast(target, att.patched_code_content, current.text if current else None):
            raise ExecutionRefused("the attested patch adds security findings")

    tx = (cmd.dorado_tx_hash or "").strip().upper()
    reserved = False
    explorer = ""
    if not cfg.skip_payment:
        if not tx:
            raise ExecutionRefused("a verified Dorado payment is required, but no transaction hash was supplied")
        if tx_used(tx):
            raise ExecutionRefused("that Dorado transaction was already used to authorize a change (replay refused)")
        mark_tx(tx)                      # reserve before the slow lookup
        reserved = True
        check = await verifier.verify(tx, cfg.orchestrator_wallet_address, cfg.remediation_price_atestfet)
        if not check.ok or (cmd.payer_wallet and check.payer != cmd.payer_wallet):
            release_tx(tx)
            raise ExecutionRefused("the Dorado payment could not be re-verified: " + (check.reason if not check.ok else "payer wallet mismatch"))
        explorer = explorer_url(cfg.dorado_explorer_base, tx)
    elif tx:
        explorer = explorer_url(cfg.dorado_explorer_base, tx)

    try:
        branch = fix_branch(inc)
        if rollback:
            commit = await gh.get_commit(repo, ctx["evidence"]["sha"])
            old = await gh.get_file(repo, target, commit.parents[0]) if commit.parents else None
            if old is None:
                raise ExecutionRefused("the pre-incident version of the file could not be fetched")
            requirements = (await gh.get_file(repo, "requirements.txt", base))
            requirements_txt = requirements.text if requirements else ""
            files = {target: old.text}
            title = f"Sentinel {inc}: roll back {target} to its pre-incident version"
        else:
            requirements_txt = att.updated_requirements_txt
            files = {target: att.patched_code_content}
            if requirements_txt.strip():    # a repo without requirements.txt must not gain an empty one
                files["requirements.txt"] = requirements_txt
            title = f"Sentinel {inc}: fix {target}"
        findings = [CVEFinding(**f) for f in ctx["cves"]]
        files[SBOM_PATH] = sbom_json(requirements_txt, repo, inc, findings)
        sbom_url = blob_url(repo, branch, SBOM_PATH)
        body = build_pr_body(inc, ctx, cmd.action_type, "" if rollback else att.attestation_hash, tx, explorer,
                             cmd.payer_wallet, sbom_url, requirements_txt)
        await step(f"Creating a branch and committing {len(files)} file(s)")
        pr_url, branch = await publish_fix(gh, repo, inc, files, title, body, base)
        await step("Pull request opened")
    except BaseException:
        if reserved:
            release_tx(tx)                # nothing was opened, so the payment may authorize a retry
        raise

    redeploy, note = False, "no reload webhook was requested"
    hook = cmd.service_reload_webhook
    if hook:
        if not (cfg.demo_service_url and webhook_allowed(hook, cfg.demo_service_url)):
            note = "the reload webhook was refused (only the demo /admin/apply-hotfix endpoint on the target service is allowed)"
        else:
            redeploy, note = await trigger_webhook(http, hook, cfg.demo_admin_token)
    what = "Rollback PR" if rollback else "Fix PR"
    summary = f"{what} opened: {pr_url}. SBOM committed as {SBOM_PATH}. Redeploy {'triggered' if redeploy else 'NOT triggered'} ({note})."
    return RemediationCompletionReport(
        incident_id=inc, success=True, pr_url=pr_url, sbom_file_url=sbom_url, dorado_tx_hash=tx, dorado_explorer_url=explorer,
        redeploy_triggered=redeploy, summary_message=summary)
