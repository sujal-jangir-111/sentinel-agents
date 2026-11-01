"""Pure checks behind the Scanner's adversarial patch gatekeeper (CLAUDE.md §5.4 part B).

Each check returns a list of specific rejection reasons (empty = pass).
"""
import ast
import hashlib
from collections import Counter
from typing import Iterable, List, Optional, Sequence

from common.code_checks import broken_references
from common.models import CVEFinding
from common.osv_client import Dependency, version_key
from common.patching import make_unified_diff, touches_offending_change
from common.sast_rules import scan_text

MAX_REASON = 300


def attestation_hash(incident_id: str, target_file: str, unified_diff: str, updated_requirements_txt: str,
                     scanner_address: str) -> str:
    """sha256(incident_id + target_file + unified_diff + updated_requirements_txt + scanner_address), hex."""
    payload = incident_id + target_file + unified_diff + updated_requirements_txt + scanner_address
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def check_syntax(target_file: str, patched_code: str) -> List[str]:
    if not target_file.endswith(".py"):
        return []
    try:
        ast.parse(patched_code)
    except SyntaxError as exc:
        return [f"patched file does not parse: {exc.msg} (line {exc.lineno})"]
    return []


def check_references(target_file: str, patched_code: str, original: Optional[str] = None) -> List[str]:
    """Names and standard-library attributes that cannot exist. Only new ones count, as with security findings."""
    if not target_file.endswith(".py"):
        return []
    known = broken_references(original) if original else set()
    return [f"{name} does not exist, so this code would crash when it reaches that line"[:MAX_REASON]
            for name in sorted(broken_references(patched_code) - known)]


def check_sast(target_file: str, patched_code: str, original: Optional[str] = None) -> List[str]:
    """A patch may not add a security finding. Findings the file already had do not block a fix: one old warning in a
    real codebase would otherwise reject every patch. Without `original`, every finding counts."""
    baseline = Counter((f.rule_id, f.code_snippet) for f in scan_text(target_file, original)) if original is not None else Counter()
    reasons: List[str] = []
    for f in scan_text(target_file, patched_code):
        key = (f.rule_id, f.code_snippet)
        if baseline[key] > 0:
            baseline[key] -= 1
        else:
            reasons.append(f"{f.rule_id} at line {f.line_number}: {f.code_snippet} -> {f.remediation_advice}"[:MAX_REASON])
    return reasons


def check_diff(original: Optional[str], patched_code: str, target_file: str, claimed_diff: str, base_ref: str) -> List[str]:
    """The claimed diff must be exactly original -> patched, and the patch must change something."""
    if original is None:
        return [f"target file {target_file} not found on {base_ref}"]
    expected = make_unified_diff(original, patched_code, target_file)
    if not expected:
        return ["patch makes no changes to the target file"]
    if expected != claimed_diff:
        return [f"unified_diff does not match patched_code_content compared with {base_ref}"]
    return []


def check_fault_fixed(patched_code: str, offending_added_lines: Sequence[str]) -> List[str]:
    """The line(s) the offending commit introduced must no longer be present."""
    if touches_offending_change(patched_code, offending_added_lines):
        return []
    shown = next((ln.strip() for ln in offending_added_lines if len(ln.strip()) >= 8), "")
    return [f"runtime fault not fixed: offending line is still present: `{shown[:150]}`"]


def check_cves_fixed(
    previously_reachable: Sequence[dict],
    new_deps: Iterable[Dependency],
    new_findings: Iterable[CVEFinding],
) -> List[str]:
    """Every previously reachable CVE with a published fix must be gone and its package pinned at or above that
    version. A CVE with no fixed release cannot be solved by a patch, so it does not block one.
    Without a stored scan (previously_reachable is None-equivalent) use check_no_critical instead."""
    deps = {d.name: d for d in new_deps}
    still = {(f.package_name, f.vuln_id) for f in new_findings}
    reasons: List[str] = []
    for prev in previously_reachable:
        name, vuln_id, fixed = prev["package_name"], prev["vuln_id"], prev["fixed_version"]
        if fixed == "unknown":
            continue
        dep = deps.get(name)
        if dep is None:
            reasons.append(f"{name} ({vuln_id}) is not pinned in the updated requirements.txt")
        elif (name, vuln_id) in still:
            reasons.append(f"{vuln_id} still affects {name}=={dep.version} (fixed in {fixed})")
        elif version_key(dep.version) < version_key(fixed):
            reasons.append(f"{name}=={dep.version} is below the fixed version {fixed} ({vuln_id})")
    return reasons


def check_no_critical(new_findings: Iterable[CVEFinding]) -> List[str]:
    """Fallback when no scan context is known: no CRITICAL CVE may remain."""
    return [f"{f.vuln_id} [{f.severity}] still affects {f.package_name}=={f.installed_version}"
            for f in new_findings if f.severity == "CRITICAL"]
