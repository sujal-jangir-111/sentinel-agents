"""Markdown renderers for the ASI:One chat (CLAUDE.md §9.1: headings, tables and code blocks).

The installed chat protocol has no interactive-card content type, so the "incident card" is a rich
Markdown message; the native payment card is the separate RequestPayment message (build step 9).
"""
from typing import Any, Dict, List, Optional

from common.blast_radius import BlastRadius
from common.models import (
    CommitEvidenceReport, EndpointMetric, PatchDraftResult, RemediationCompletionReport, VulnerabilityReport,
)
from common.osv_client import SEVERITY_RANK
from common.probe import summarize

MAX_ROWS = 8
DIFF_CHARS = 1500

HELP_TEXT = """## 🛡️ Sentinel — autonomous DevSecOps swarm
I probe your service, find the commit that broke it, scan for reachable CVEs, draft a fix that a second agent must security-vet, and wait for **your approval** before anything changes.

**Try:**
- `Diagnose and heal the outage on https://your-service.example for repo owner/repo`
- `Run a security audit of owner/repo`
- `Chaos test https://your-service.example for repo owner/repo` (injects the demo fault first)
- `status` — progress of your latest incident

When a fix is ready I'll show an incident card and you reply **approve** or **reject**."""


def _cell(text: Any, limit: int = 180) -> str:
    s = str(text).replace("|", "\\|").replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def short_sha(sha: str) -> str:
    return sha[:7]


def findings_table(vuln: VulnerabilityReport) -> str:
    rows: List[str] = []
    cves = sorted(vuln.cve_findings, key=lambda f: (not f.is_reachable_in_ast, -SEVERITY_RANK.get(f.severity, 0)))
    for f in cves[:MAX_ROWS]:
        verdict = "🔴 CRITICAL_EXPLOITABLE (reachable)" if f.is_reachable_in_ast else "⚪ LATENT_DEPENDENCY"
        rows.append(f"| {_cell(f.vuln_id)} | `{f.package_name}=={f.installed_version}` | {f.severity} | {verdict} | → {f.fixed_version} |")
    for s in vuln.sast_findings[:MAX_ROWS]:
        rows.append(f"| {s.rule_id} | `{_cell(s.file_path)}:{s.line_number}` | {s.severity} | in modified code | {_cell(s.remediation_advice, 70)} |")
    if not rows:
        return "_No dependency or code findings._"
    hidden = len(vuln.cve_findings) + len(vuln.sast_findings) - len(rows)
    table = "| ID / Rule | Package / Location | Severity | Reachability | Fix |\n|---|---|---|---|---|\n" + "\n".join(rows)
    return table + (f"\n\n_…and {hidden} more._" if hidden > 0 else "")


def blast_table(b: BlastRadius) -> str:
    exposure = f"{b.credential_exposure_minutes:.0f} min" if b.credential_exposure_minutes is not None else "n/a (no secret introduced by the suspect commit)"
    return (
        "| Metric | Value |\n|---|---|\n"
        f"| **Blast score** | **{b.score:.0f} / 100** |\n"
        f"| Failing probes | {b.failure_ratio * 100:.0f}% |\n"
        f"| Dropped requests / hour | {b.dropped_requests_hr:,.0f} |\n"
        f"| Revenue at risk / hour | ${b.revenue_at_risk_hr:,.0f} |\n"
        f"| Minutes since suspect commit | {b.minutes_since_commit:.0f} |\n"
        f"| SLA error-budget burned ({b.sla_target * 100:g}% / 30d) | {b.sla_budget_burn_pct:.1f}% |\n"
        f"| Credential exposure | {exposure} |\n\n"
        f"_Assumptions: {b.assumptions()}._"
    )


def root_cause_table(probe: Dict[str, Any], ev: CommitEvidenceReport) -> str:
    return (
        "| Field | Value |\n|---|---|\n"
        f"| Failing endpoint | `{probe['endpoint']}` → HTTP {probe['status']} @ {probe['latency_ms']:.0f} ms |\n"
        f"| Suspect commit | [`{short_sha(ev.suspect_commit_sha)}`]({ev.suspect_commit_url}) by @{ev.author} — _{_cell(ev.commit_message, 100)}_ |\n"
        f"| File | `{ev.offending_file}` |\n"
        f"| Explanation | {_cell(ev.root_cause_explanation, 400)} |"
    )


def build_incident_card(
    incident_id: str, service_url: str, repo: str, probe: Dict[str, Any], ev: CommitEvidenceReport,
    vuln: VulnerabilityReport, result: PatchDraftResult, blast: BlastRadius, max_attempts: int,
    payment_required: bool = False,
) -> str:
    att = result.attestation
    parts = [
        f"## 🛡️ Sentinel Incident `{incident_id}`",
        f"**Target:** {service_url} · **Repo:** `{repo}`",
        "### 🔥 What broke\n" + root_cause_table(probe, ev),
        "### 🔐 Security findings\n" + findings_table(vuln),
        "### 💥 Counterfactual blast radius\n" + blast_table(blast),
    ]
    if att.approved:
        bumps = [f"- `{f.package_name}` {f.installed_version} → **{f.fixed_version}**" for f in vuln.cve_findings
                 if f.is_reachable_in_ast and f.fixed_version != "unknown"]
        diff = att.unified_diff if len(att.unified_diff) <= DIFF_CHARS else att.unified_diff[:DIFF_CHARS] + "\n…[diff truncated]"
        parts += [
            f"### 🩹 Proposed fix (attempt {result.attempts}/{max_attempts})",
            f"✅ Approved by **Agent_4** · attestation `{att.attestation_hash[:16]}…`",
            f"```diff\n{diff}\n```",
            ("**Dependency bumps**\n" + "\n".join(dict.fromkeys(bumps))) if bumps else "_No dependency bumps needed._",
            ("### 💳 Your decision\nAuthorize this fix by paying **0.1 FET** (Dorado testnet) with the payment request I just sent "
             "— that is the change-control authorization. Reply **reject** to cancel."
             if payment_required else
             "### ✅ Your decision\nReply **approve** to authorize the fix (branch + PR + SBOM + hotfix) or **reject** to cancel."),
        ]
    else:
        reasons = "\n".join(f"- {_cell(r, 220)}" for r in att.rejection_reasons[:MAX_ROWS]) or "- no reason given"
        parts += [
            f"### ⛔ No safe patch after {result.attempts} attempt(s)",
            "The security gatekeeper rejected every draft:\n" + reasons,
            (("### 💳 Your decision\nI can only offer a **rollback** of the suspect commit. Authorize it by paying **0.1 FET** "
              "(Dorado testnet) with the payment request I just sent, or reply **reject** to cancel."
              if payment_required else
              "### ↩️ Your decision\nI can only offer a **rollback** of the suspect commit. Reply **rollback** to authorize it, or **reject** to cancel.")
             if result.rollback_available else
             "### ↩️ Your decision\nNo rollback is available either. Reply **reject** to close this incident."),
        ]
    return "\n\n".join(parts)


def build_already_fixed(ev: CommitEvidenceReport, fix_title: str) -> str:
    return (f"**Nothing to patch.** The service is still failing, but the newest change to this code is Sentinel's own "
            f"fix: [`{short_sha(ev.suspect_commit_sha)}`]({ev.suspect_commit_url}), _{fix_title}_. So `main` already has "
            "the fix and the running service has not deployed it. Patching again has nothing to change, and a rollback "
            "would only undo the fix, so I stopped here.")


ALREADY_FIXED_HINT = ("Redeploy the service from `main`. The bundled demo app always runs its own local code, so to "
                      "repeat the demo rebuild its history: `python -m scripts.seed_demo_repo --reset`.")


def build_audit_report(incident_id: str, repo: str, ev: CommitEvidenceReport, vuln: VulnerabilityReport) -> str:
    reachable = [f for f in vuln.cve_findings if f.is_reachable_in_ast]
    return "\n\n".join([
        f"## 🛡️ Sentinel Security Audit `{incident_id}`",
        f"**Repo:** `{repo}` · **Active imports mapped:** {len(ev.active_ast_imports)} · "
        f"**CVEs:** {len(vuln.cve_findings)} ({len(reachable)} reachable, {vuln.total_reachable_critical} reachable CRITICAL) · "
        f"**SAST findings:** {len(vuln.sast_findings)}",
        findings_table(vuln),
        "_Audit mode is read-only: no patch is drafted and no payment is requested. Say "
        "`diagnose and heal …` to remediate._",
    ])


def build_status(inc: Dict[str, Any]) -> str:
    extra = f"\n\n{inc['last_note']}" if inc.get("last_note") else ""
    return (f"### 📋 Incident `{inc['incident_id']}`\n| Field | Value |\n|---|---|\n"
            f"| State | **{inc['state']}** |\n| Mode | {inc['mode']} |\n| Repo | `{inc['repo']}` |\n"
            f"| Service | {inc.get('service_url') or 'n/a'} |{extra}")



def build_final_report(inc: Dict[str, Any], rem: RemediationCompletionReport, canary: List[EndpointMetric], healthy: bool,
                       attestation_hash: str, explorer_base: str) -> str:
    """The closing ASI:One message: before/after canary health, PR, SBOM, Dorado tx and hotfix status."""
    before = inc["probe"]
    endpoint = before["endpoint"]
    after = summarize(canary)
    statuses = sorted({m.status_code for m in canary if m.endpoint == endpoint}) or sorted({m.status_code for m in canary})
    after_status = " / ".join(f"HTTP {s}" for s in statuses) if statuses and statuses != [0] else "unreachable"
    rolled_back = inc["action_type"] == "ROLLBACK_COMMIT"
    if healthy:
        title = f"## ✅ Incident `{inc['incident_id']}` RESOLVED — `{endpoint}` HTTP {before['status']} → {after_status}"
    else:
        title = f"## ⚠️ Incident `{inc['incident_id']}` — change delivered, but `{endpoint}` is still failing ({after_status})"
    tx = (f"[`{rem.dorado_tx_hash[:12]}…`]({rem.dorado_explorer_url or explorer_url_for(explorer_base, rem.dorado_tx_hash)}) (0.1 FET, Dorado testnet)"
          if rem.dorado_tx_hash else "none (payment skipped, dev mode)")
    parts = [
        title,
        "### 📊 Before → after (canary)\n| Metric | Before | After |\n|---|---|---|\n"
        f"| `{endpoint}` | HTTP {before['status']} | {after_status} |\n"
        f"| Failing probes | {before['failing']}/{before['total']} | {int(after['failing'])}/{int(after['total'])} |\n"
        f"| p95 latency | {before['p95_ms']:.0f} ms | {after['p95_ms']:.0f} ms |",
        "### 🔗 Change record\n| Item | Link |\n|---|---|\n"
        f"| {'Rollback' if rolled_back else 'Fix'} pull request | {rem.pr_url} |\n"
        f"| SBOM (CycloneDX 1.5) | {rem.sbom_file_url} |\n"
        f"| Dorado payment | {tx} |\n"
        f"| Security attestation | {('`' + attestation_hash[:16] + '…`') if attestation_hash else 'n/a (rollback)'} |\n"
        f"| Hotfix / redeploy | {'✅ triggered' if rem.redeploy_triggered else '⚠️ not triggered'} |",
        "The pull request is **not merged** — review it and merge when you are happy; the hotfix only reloaded the running demo service."
        if healthy else
        "Nothing was merged automatically. Review the pull request, check that the service picked up the hotfix, then ask me to probe again.",
    ]
    return "\n\n".join(parts)


def explorer_url_for(base: str, tx_hash: str) -> str:
    return f"{base.rstrip('/')}/{tx_hash}"
