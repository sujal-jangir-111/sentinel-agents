"""Turns Agent_1's incident record into what the chat shows. Pure functions, no I/O."""
from typing import Any, Dict, List, Optional, Tuple

from common.models import CVEFinding
from common.patching import compute_bumps
from common.sast_rules import scan_text

DIFF_LIMIT = 12_000
MAX_ITEMS = 8
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

RUNNING = "running"
NEEDS_APPROVAL = "needs_approval"
PUBLISHING = "publishing"
DONE = "done"
FAILED = "failed"
CANCELLED = "cancelled"
NO_BUG = "no_bug"
OPEN_PHASES = {RUNNING, NEEDS_APPROVAL, PUBLISHING}

_PHASES = {"AWAITING_APPROVAL": NEEDS_APPROVAL, "AWAITING_PAYMENT": NEEDS_APPROVAL, "APPROVED": PUBLISHING, "EXECUTING": PUBLISHING,
           "VERIFYING": PUBLISHING, "RESOLVED": DONE, "FAILED": FAILED, "CANCELLED": CANCELLED}


def phase_of(state: str) -> str:
    return _PHASES.get(state, RUNNING)


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0] if text.strip() else ""


def _cause(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ev = rec.get("evidence")
    if not ev or rec.get("mode") == "security_audit" or rec.get("delivery") == NO_BUG:
        return None      # with nothing wrong, a "what went wrong" would only contradict the result
    sha = ev.get("suspect_commit_sha") or ""
    commit = {"sha": sha[:7], "url": ev.get("suspect_commit_url", ""), "title": _first_line(ev.get("commit_message", "")),
              "author": ev.get("author", "")} if sha else None
    return {"summary": ev.get("root_cause_explanation", ""), "file": ev.get("offending_file", ""), "commit": commit,
            "certain": ev.get("confidence", "high") == "high"}


def _service(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    probe = rec.get("probe")
    if probe:
        return {"status": "failing", "endpoint": probe["endpoint"], "code": probe["status"],
                "failing": probe["failing"], "total": probe["total"]}
    note = rec.get("service_note")
    return {"status": note} if note else None


def _security(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    vuln = rec.get("vuln")
    if not vuln:
        return None
    cves, code = vuln.get("cve_findings") or [], vuln.get("sast_findings") or []
    reachable = [c for c in cves if c.get("is_reachable_in_ast")]
    # Imports are only mapped for Python. Without a map, "not reachable" means "not analysed", never "safe".
    mapped = bool((rec.get("evidence") or {}).get("active_ast_imports"))
    listed = reachable if mapped else cves
    items: List[Dict[str, str]] = [
        {"severity": c["severity"], "title": f"{c['package_name']} {c['installed_version']}: {c.get('summary') or c['vuln_id']}"[:140],
         "where": c["vuln_id"], "advice": f"Upgrade to {c['fixed_version']}" if c["fixed_version"] != "unknown" else "No fixed version yet"}
        for c in listed
    ] + [
        {"severity": f["severity"], "title": f["rule_id"].replace("_", " ").capitalize(), "where": f"{f['file_path']}:{f['line_number']}",
         "advice": f["remediation_advice"]}
        for f in code
    ]
    items.sort(key=lambda i: SEVERITY_ORDER.get(i["severity"], 9))
    return {"known": len(cves), "reachable": len(reachable), "unverified": 0 if mapped else len(cves), "code": len(code), "items": items[:MAX_ITEMS],
            "more": max(0, len(items) - MAX_ITEMS), "files": vuln.get("files_scanned", 0),
            "dependencies": vuln.get("dependencies_scanned", 0)}


def _requirements_changed(rec: Dict[str, Any]) -> bool:
    findings = [CVEFinding(**c) for c in (rec.get("vuln") or {}).get("cve_findings") or []]
    return bool(compute_bumps(findings))


def _fix(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    result = rec.get("result")
    if not result or rec.get("delivery") == NO_BUG:
        return None
    att = result["attestation"]
    approved = bool(att.get("approved"))
    target = att.get("target_file", "")
    fix: Dict[str, Any] = {"approved": approved, "attempts": result.get("attempts", 1), "explanation": result.get("explanation", ""),
                           "file": target, "reasons": (att.get("rejection_reasons") or [])[:4], "diff": "", "files": [],
                           "upgrades": result.get("upgrades") or {}}
    if approved:
        diff = att.get("unified_diff", "")
        fix["diff"] = diff if len(diff) <= DIFF_LIMIT else diff[:DIFF_LIMIT] + "\n... (diff truncated)"
        fix["files"] = [name for _, name in _downloads(rec)]
        fix["open_issues"] = len(scan_text(target, att.get("patched_code_content", "")))
    return fix


def _downloads(rec: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(key in the attestation, file name) of each file the fix changes."""
    att = (rec.get("result") or {}).get("attestation") or {}
    if not att.get("approved"):
        return []
    files = [("patched_code_content", att.get("target_file", ""))]
    if att.get("target_file") != "requirements.txt" and (att.get("updated_requirements_txt") or "").strip() and _requirements_changed(rec):
        files.append(("updated_requirements_txt", "requirements.txt"))
    return files


def fixed_file(rec: Dict[str, Any], index: int) -> Optional[Tuple[str, str]]:
    """(file name, full content) of a changed file. Patched content has no secrets: they became os.getenv calls."""
    files = _downloads(rec)
    if not 0 <= index < len(files):
        return None
    key, name = files[index]
    return name.rsplit("/", 1)[-1], rec["result"]["attestation"][key]


def _outcome(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    remediation = rec.get("remediation") or {}
    state = rec.get("state")
    if state not in ("RESOLVED", "FAILED"):
        return {"pr_url": remediation.get("pr_url", "")} if remediation.get("pr_url") else None
    if state == "RESOLVED" and rec.get("mode") == "security_audit":
        return {"kind": "audit"}
    if state == "RESOLVED" and rec.get("delivery") == NO_BUG:
        result = rec.get("result") or {}
        return {"kind": NO_BUG, "file": result.get("attestation", {}).get("target_file", ""), "why": result.get("explanation", "")}
    if state == "RESOLVED" and rec.get("delivery") == "files":
        return {"kind": "files"}
    if remediation.get("pr_url"):
        note = rec.get("last_note", "")
        return {"kind": "pr", "pr_url": remediation["pr_url"],
                "verified": True if note == "recovered" else False if note == "canary still failing" else None}
    return None


def incident_view(rec: Dict[str, Any]) -> Dict[str, Any]:
    phase = phase_of(rec.get("state", ""))
    view: Dict[str, Any] = {
        "id": rec["incident_id"], "phase": phase, "mode": rec.get("mode", ""), "repo": rec.get("repo", ""),
        "branch": rec.get("branch", ""), "service_url": rec.get("service_url", ""), "cause": _cause(rec),
        "service": _service(rec), "security": _security(rec), "fix": _fix(rec), "outcome": _outcome(rec),
    }
    if phase == FAILED:
        view["failure"] = {"message": rec.get("last_note", "") if rec.get("last_note") != "canary still failing" else "",
                           "hint": rec.get("hint", "")}
    if phase == CANCELLED:
        view["expired"] = rec.get("cancel_reason") == "expired"
    return view
