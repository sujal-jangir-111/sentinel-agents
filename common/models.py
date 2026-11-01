"""ALL inter-agent uagents.Model schemas live here (contract in CLAUDE.md §6)."""
from typing import Any, Dict, List, Optional

from uagents import Model


# 1. Orchestrator -> Agent_2
class HealthProbeRequest(Model):
    incident_id: str
    service_url: str
    endpoints: List[str] = ["/health", "/api/checkout"] 
    inject_chaos: bool = False
    is_canary_check: bool = False


class EndpointMetric(Model):
    endpoint: str
    status_code: int
    latency_ms: float
    error_snippet: Optional[str] = None
    timestamp_utc: str


class HealthProbeReport(Model):
    incident_id: str
    service_url: str
    is_healthy: bool
    is_canary_check: bool
    metrics: List[EndpointMetric]


# 2. Orchestrator -> Agent_3
class CommitCorrelationRequest(Model):
    incident_id: str
    repo_full_name: str
    branch: str = "main"
    failure_timestamp_utc: str
    failing_endpoint: str
    error_snippet: Optional[str] = None


class CommitEvidenceReport(Model):
    incident_id: str
    repo_full_name: str
    suspect_commit_sha: str
    suspect_commit_url: str
    author: str
    commit_message: str
    committed_at_utc: str
    offending_file: str
    offending_diff_snippet: str
    root_cause_explanation: str
    active_ast_imports: List[str]
    confidence: str = "high"   # "low": no error location, so the commit/file is the LLM's best guess


# 3. Orchestrator -> Agent_4
class VulnerabilityScanRequest(Model):
    incident_id: str
    repo_full_name: str
    branch: str = "main"
    suspect_commit_sha: str
    modified_files: List[str]
    active_ast_imports: List[str]


class CVEFinding(Model):
    package_name: str
    installed_version: str
    fixed_version: str
    vuln_id: str  # GHSA-xxxx or CVE-YYYY-xxxx
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    is_reachable_in_ast: bool
    summary: str


class SASTFinding(Model):
    file_path: str
    line_number: int
    rule_id: str  # HARDCODED_SECRET, SQL_INJECTION, UNSAFE_EVAL, UNSAFE_DESERIALIZATION, COMMAND_INJECTION, INSECURE_DOCKER
    severity: str
    code_snippet: str  # secrets MUST be masked
    remediation_advice: str


class VulnerabilityReport(Model):
    incident_id: str
    repo_full_name: str
    cve_findings: List[CVEFinding]
    sast_findings: List[SASTFinding]
    total_reachable_critical: int
    files_scanned: int = 0          # so "no problems" can never be claimed about code that was not looked at
    dependencies_scanned: int = 0


# 4. Agent_5 <-> Agent_4
class PatchDraftRequest(Model):
    incident_id: str
    repo_full_name: str
    commit_evidence: CommitEvidenceReport
    vuln_report: VulnerabilityReport
    branch: str = "main"
    problem: str = ""


class PatchVettingRequest(Model):
    incident_id: str
    repo_full_name: str
    target_file: str
    patched_code_content: str
    updated_requirements_txt: str
    unified_diff: str


class SecurityApprovalAttestation(Model):
    incident_id: str
    approved: bool
    attestation_hash: str
    rejection_reasons: List[str] = []
    target_file: str
    patched_code_content: str
    updated_requirements_txt: str
    unified_diff: str


# 5. Orchestrator -> Agent_5
class ExecuteRemediationCommand(Model):
    incident_id: str
    repo_full_name: str
    action_type: str  # "OPEN_PR_AND_HOTFIX" | "ROLLBACK_COMMIT"
    dorado_tx_hash: str
    payer_wallet: str
    attestation: SecurityApprovalAttestation
    service_reload_webhook: Optional[str] = None
    branch: str = "main"


class RemediationCompletionReport(Model):
    incident_id: str
    success: bool
    pr_url: str
    sbom_file_url: str
    dorado_tx_hash: str
    dorado_explorer_url: str
    redeploy_triggered: bool
    summary_message: str


# Additional small models
class AgentErrorReport(Model):
    incident_id: str
    agent: str
    stage: str
    error: str


class PatchDraftResult(Model):
    incident_id: str
    attestation: SecurityApprovalAttestation
    rollback_available: bool
    attempts: int
    explanation: str = ""
    no_bug: bool = False                # the Fixer read the code and the reported problem is not there
    upgrades: Dict[str, str] = {}       # every pinned package this fix changes, with its new version


# Web console: web/gateway.py <-> Agent_1, and every agent -> web/gateway.py
class IncidentRequest(Model):
    """A structured request from the console. The console creates incident_id, so it knows who owns the incident."""
    incident_id: str
    mode: str                  # "diagnose_and_heal" | "security_audit" | "chaos_test"
    repo_full_name: str
    branch: str
    problem: str = ""
    service_url: str = ""      # optional: without it the agents work from the description alone
    endpoints: List[str] = []


class IncidentUpdate(Model):
    incident_id: str
    record_json: str           # Agent_1's full incident record


class AgentActivity(Model):
    incident_id: str
    agent: str
    status: str                # "working" | "done" | "failed"
    text: str


# GET http://127.0.0.1:8001/incidents (read-only, the console's heartbeat; not published outside the host)
class IncidentListResponse(Model):
    incidents: List[Dict[str, Any]] = []
