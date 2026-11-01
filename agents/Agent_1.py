"""Agent_1 (CLAUDE.md §5.1, §7): the ASI:One entry point and incident state machine.

Run standalone:  python -m agents.Agent_1

Non-blocking: every handler loads the incident by id, advances the state machine, sends the next
request and returns. States:
  PROBING -> CORRELATING -> SCANNING -> PATCHING -> AWAITING_APPROVAL (or AWAITING_PAYMENT) -> APPROVED
  (FAILED / CANCELLED / RESOLVED are terminal.)  APPROVED is where the next build steps hook in:
  Step 9 puts RequestPayment/CommitPayment in front of it, Step 10 executes the change after it.
"""
import json
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import httpx
from uagents import Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement, ChatMessage, EndSessionContent, StartSessionContent, TextContent, chat_protocol_spec,
)
from uagents_core.contrib.protocols.payment import (
    CancelPayment, CommitPayment, CompletePayment, Funds, RejectPayment, RequestPayment, payment_protocol_spec,
)

from common import incident_card as card
from common.activity import DONE, report as activity
from common.addresses import agent_address, gateway_address
from common.agent_factory import build_agent
from common.llm_client import LLMClient, LLMError
from common.blast_radius import compute_blast_radius
from common.commit_scoring import sentinel_fix_title
from common.config import Settings, get_settings
from common.dorado import DENOM, DoradoVerifier, explorer_url, format_fet
from common.intent import MODES, Intent, extract_repo, extract_url, parse_intent
from common.logging import configure_console_utf8, log
from common.models import (
    AgentErrorReport, CommitCorrelationRequest, CommitEvidenceReport, ExecuteRemediationCommand, HealthProbeReport,
    HealthProbeRequest, IncidentListResponse, IncidentRequest, IncidentUpdate, PatchDraftRequest, PatchDraftResult, RemediationCompletionReport, SecurityApprovalAttestation,
    VulnerabilityReport, VulnerabilityScanRequest,
)
from common.osv_client import count_reachable
from common.probe import summarize

AGENT_NAME = "Agent_1"
AGENT_LABEL = "Agent_1"  # display name on Agentverse and in uagents logs
PORT = 8001
DESCRIPTION = (
    "Sentinel: autonomous DevSecOps and self-healing swarm. Tell me which service is failing and which GitHub "
    "repo owns it: I probe it, find the commit that broke it, scan for reachable CVEs, have a second agent "
    "security-vet a fix, and wait for your approval. Chat with me on ASI:One (Fetch-A-Thon 3.0)."
)
FINAL_STATES = {"RESOLVED", "FAILED", "CANCELLED"}
STAGE_TIMEOUTS = {"PROBING": 60.0, "CORRELATING": 120.0, "SCANNING": 60.0, "PATCHING": 180.0, "EXECUTING": 120.0, "VERIFYING": 60.0}
WEB = "web"    # incidents started from the web console (inc["source"])
APPROVAL_TIMEOUT = 1800.0
MAX_PAYMENT_FAILURES = 3                   # definitive verification failures before the incident is cancelled
PAYMENT_BACKDATE = timedelta(minutes=2)    # tolerated clock skew when checking a tx is newer than the request
WAITING_FOR = {"PROBING": "Agent_2", "CORRELATING": "Agent_3",
               "SCANNING": "Agent_4", "PATCHING": "Agent_5", "EXECUTING": "Agent_5",
               "VERIFYING": "Agent_2"}
RECOVERY = {
    "Agent_2": "Check that the service URL is reachable, then try again.",
    "Agent_3": "Check the repo name and that the GitHub token can read it. You can still run `security audit` on a different repo.",
    "Agent_4": "OSV.dev or GitHub may be unavailable; try again in a minute.",
    "Agent_5": "Nothing was merged to your main branch. Try again, or ask for a `security audit` to review findings only.",
}


def make_chat(text: str, end_session: bool = False) -> ChatMessage:
    content: List[Any] = [TextContent(text=text)]
    if end_session:
        content.append(EndSessionContent())
    return ChatMessage(content=content)


class Orchestrator:
    def __init__(
        self,
        addresses: Optional[Dict[str, Optional[str]]] = None,
        llm: Optional[LLMClient] = None,
        skip_payment: Optional[bool] = None,
        settings: Optional[Settings] = None,
        clock: Callable[[], float] = time.time,
        stage_timeouts: Optional[Dict[str, float]] = None,
        approval_timeout: float = APPROVAL_TIMEOUT,
        verifier: Optional[DoradoVerifier] = None,
        gateway: Optional[str] = None,
    ) -> None:
        keys = ("watchdog", "detective", "scanner", "executor")
        self.addresses = {k: (addresses or {}).get(k) if addresses is not None else agent_address(k) for k in keys}
        self.gateway = gateway if gateway is not None else (gateway_address() if addresses is None else None)
        self.llm, self._http = llm, None
        self._settings, self._skip_payment = settings, skip_payment
        self.clock = clock
        self.stage_timeouts = {**STAGE_TIMEOUTS, **(stage_timeouts or {})}
        self.approval_timeout = approval_timeout
        self._verifier = verifier

    @property
    def cfg(self) -> Settings:
        return self._settings or get_settings()

    @property
    def skip_payment(self) -> bool:
        return self.cfg.skip_payment if self._skip_payment is None else self._skip_payment

    @property
    def verifier(self) -> DoradoVerifier:
        if self._verifier is None:
            self._verifier = DoradoVerifier()   # live Dorado lookups via cosmpy
        return self._verifier

    async def startup(self, ctx: Context) -> None:
        if self.llm is None:
            self._http = httpx.AsyncClient(timeout=30)
            self.llm = LLMClient(self._http)
        ctx.logger.info(f"Address: {ctx.agent.address}")
        log(ctx.logger, "-", AGENT_NAME, "startup",
            f"✅ ready (payment {'SKIPPED (dev)' if self.skip_payment else 'required'})")
        if not self.skip_payment and not self.cfg.orchestrator_wallet_address:
            log(ctx.logger, "-", AGENT_NAME, "startup", "ORCHESTRATOR_WALLET_ADDRESS is not set: payments cannot be requested", level="warning")

    async def shutdown(self, ctx: Context) -> None:
        if self._http is not None:
            await self._http.aclose()

    # -- storage ------------------------------------------------------------------------------------

    @staticmethod
    def _load(ctx: Context, inc_id: str) -> Optional[Dict[str, Any]]:
        raw = ctx.storage.get(f"inc:{inc_id}")
        return json.loads(raw) if raw else None

    def _put(self, ctx: Context, inc: Dict[str, Any]) -> None:
        ctx.storage.set(f"inc:{inc['incident_id']}", json.dumps(inc))
        index = json.loads(ctx.storage.get("incidents") or "[]")
        if inc["incident_id"] not in index:
            ctx.storage.set("incidents", json.dumps(index + [inc["incident_id"]]))

    def _all(self, ctx: Context) -> List[Dict[str, Any]]:
        found = (self._load(ctx, i) for i in json.loads(ctx.storage.get("incidents") or "[]"))
        return [i for i in found if i]

    def _set_state(self, inc: Dict[str, Any], state: str) -> None:
        inc["state"], inc["stage_since"] = state, self.clock()

    # -- messaging ----------------------------------------------------------------------------------

    async def _say(self, ctx: Context, inc: Dict[str, Any], text: str, end: bool = False) -> None:
        if not inc.get("user"):
            return  # headless (watchdog-raised) incident: the next chat message claims it
        try:
            await ctx.send(inc["user"], self._web_update(inc) if inc.get("source") == WEB else make_chat(text, end))
        except Exception as exc:
            log(ctx.logger, inc["incident_id"], AGENT_NAME, "chat", f"could not reach user: {exc}", level="error")

    @staticmethod
    def _web_update(inc: Dict[str, Any]) -> IncidentUpdate:
        """The console renders its own cards from the record, so it gets data rather than this agent's Markdown."""
        return IncidentUpdate(incident_id=inc["incident_id"], record_json=json.dumps(inc))

    async def _send(self, ctx: Context, key: str, message: Any) -> None:
        address = self.addresses.get(key)
        if not address:
            raise RuntimeError(f"{key} agent address unknown (set {key.upper()}_SEED or {key.upper()}_ADDRESS)")
        await ctx.send(address, message)

    def _accept(self, ctx: Context, sender: str, key: str, inc_id: str, states: set) -> Optional[Dict[str, Any]]:
        """The incident, if the sender is the expected agent and the incident is in an expected state."""
        if self.addresses.get(key) != sender:
            log(ctx.logger, inc_id, AGENT_NAME, "guard", f"ignoring message from unexpected sender {sender[:16]}…", level="warning")
            return None
        inc = self._load(ctx, inc_id)
        if inc is None or inc["state"] not in states:
            log(ctx.logger, inc_id, AGENT_NAME, "guard", "ignoring message for unknown/finished incident or wrong stage")
            return None
        return inc

    async def _fail(self, ctx: Context, inc: Dict[str, Any], what: str, hint: str = "") -> None:
        self._set_state(inc, "FAILED")
        inc["last_note"], inc["hint"] = what, hint
        self._put(ctx, inc)
        log(ctx.logger, inc["incident_id"], AGENT_NAME, "failed", what, level="error")
        paid = (f"\n\n💳 Your payment [`{inc['dorado_tx_hash'][:12]}…`]({explorer_url(self.cfg.dorado_explorer_base, inc['dorado_tx_hash'])}) "
                "was verified before this failed; it is recorded against this incident." if inc.get("dorado_tx_hash") else "")
        await self._say(ctx, inc, f"### ❌ Incident `{inc['incident_id']}` stopped\n{what}" + (f"\n\n**Recovery:** {hint}" if hint else "") + paid, end=True)

    # -- chat protocol --------------------------------------------------------------------------------

    async def handle_chat(self, ctx: Context, sender: str, msg: ChatMessage) -> None:
        await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))  # always ack first
        try:
            ctx.storage.set("last_user", sender)
            text = msg.text().strip()
            if not text:
                if any(isinstance(c, StartSessionContent) for c in msg.content):
                    await ctx.send(sender, make_chat(card.HELP_TEXT))
                return
            await self._claim_unowned(ctx, sender)
            intent = parse_intent(text)
            if intent.action:
                await self._decide(ctx, sender, intent)
            elif intent.mode == "status":
                await self._status(ctx, sender, intent)
            else:
                if not intent.is_request:
                    intent = await self._llm_intent(text) or intent
                if not intent.is_request:
                    await ctx.send(sender, make_chat(card.HELP_TEXT))
                else:
                    await self._start_incident(ctx, sender, intent)
        except Exception as exc:  # handlers never raise
            log(ctx.logger, "-", AGENT_NAME, "chat", f"error: {type(exc).__name__}: {exc}", level="error")
            try:
                await ctx.send(sender, make_chat(f"⚠️ Something went wrong on my side (`{type(exc).__name__}`). Nothing was changed — please try again."))
            except Exception:
                pass

    async def handle_ack(self, ctx: Context, sender: str, msg: ChatAcknowledgement) -> None:
        return None

    async def _llm_intent(self, text: str) -> Optional[Intent]:
        """Fallback only when the regexes found no request."""
        if self.llm is None:
            return None
        try:
            data = await self.llm.chat_json(
                "Extract what the user wants from a DevSecOps assistant. mode is one of: diagnose_and_heal, "
                "security_audit, chaos_test, status, or null if the message is not a request.",
                text[:1000], '{"mode": "<mode or null>", "repo_full_name": "<owner/repo or null>", "service_url": "<https url or null>"}')
        except LLMError:
            return None
        mode = data.get("mode")
        repo, url = extract_repo(str(data.get("repo_full_name") or "")), extract_url(str(data.get("service_url") or ""))
        return Intent(mode=mode, repo=repo, url=url) if mode in MODES else None

    # -- incidents started from the web console -------------------------------------------------------

    async def handle_incident_request(self, ctx: Context, sender: str, req: IncidentRequest) -> None:
        """The console's structured request. Unlike chat, nothing here falls back to a configured repo or URL."""
        inc_id = req.incident_id
        try:
            if not self.gateway or sender != self.gateway:
                log(ctx.logger, inc_id, AGENT_NAME, "guard", f"ignoring request from unexpected sender {sender[:16]}…", level="warning")
                return
            if self._load(ctx, inc_id) is not None:
                return  # duplicate delivery
            inc = {"incident_id": inc_id, "user": sender, "session": "", "mode": req.mode, "repo": req.repo_full_name,
                   "branch": req.branch, "problem": req.problem, "service_url": req.service_url,
                   "endpoints": req.endpoints, "created_at": self.clock(), "source": WEB}
            log(ctx.logger, inc_id, AGENT_NAME, "start", f"🔍 {req.mode} for {req.repo_full_name}@{req.branch}")
            if req.service_url:
                self._set_state(inc, "PROBING")
                self._put(ctx, inc)
                await activity(ctx, inc_id, AGENT_NAME, "Asked Health Checker to test the live service")
                await self._say(ctx, inc, "")
                probe = HealthProbeRequest(incident_id=inc_id, service_url=req.service_url, inject_chaos=req.mode == "chaos_test")
                await self._send(ctx, "watchdog", probe.copy(update={"endpoints": req.endpoints}) if req.endpoints else probe)
                return
            await self._correlate_web(ctx, inc, "", "" if req.mode == "security_audit" else req.problem, _now_iso())
        except Exception as exc:
            await self._pipeline_error(ctx, inc_id, "start", exc)

    async def _correlate_web(self, ctx: Context, inc: Dict[str, Any], endpoint: str, evidence: Optional[str], when: str) -> None:
        self._set_state(inc, "CORRELATING")
        self._put(ctx, inc)
        audit = inc["mode"] == "security_audit"
        await activity(ctx, inc["incident_id"], AGENT_NAME, "Asked Detective to map the code" if audit else "Asked Detective to find the cause")
        await self._say(ctx, inc, "")
        await self._send(ctx, "detective", CommitCorrelationRequest(
            incident_id=inc["incident_id"], repo_full_name=inc["repo"], branch=inc["branch"], failure_timestamp_utc=when,
            failing_endpoint=endpoint, error_snippet=evidence or None))

    async def _after_web_probe(self, ctx: Context, inc: Dict[str, Any], rep: HealthProbeReport) -> None:
        """A healthy or unreachable service does not end a web incident: the user described a problem and gave a repo."""
        failing = next((m for m in rep.metrics if not 200 <= m.status_code < 300), None)
        stats = summarize(rep.metrics)
        problem = inc.get("problem", "")
        if failing is None or failing.status_code == 0:
            inc["service_note"] = "healthy" if failing is None else "unreachable"
            await self._correlate_web(ctx, inc, "", problem, _now_iso())
            return
        inc["probe"] = {"endpoint": failing.endpoint, "status": failing.status_code, "latency_ms": failing.latency_ms,
                        "failure_ts": failing.timestamp_utc, "failing": int(stats["failing"]), "total": int(stats["total"]),
                        "p95_ms": stats["p95_ms"]}
        evidence = "\n".join(p for p in (failing.error_snippet, f"User report: {problem}" if problem else "") if p)
        await self._correlate_web(ctx, inc, failing.endpoint, evidence, failing.timestamp_utc)

    async def _finish_web_draft(self, ctx: Context, inc: Dict[str, Any], res: PatchDraftResult) -> None:
        inc["result"] = res.dict()
        if res.no_bug:
            self._set_state(inc, "RESOLVED")
            inc["delivery"] = "no_bug"
            self._put(ctx, inc)
            await activity(ctx, inc["incident_id"], AGENT_NAME, "Nothing to change, so I'm not proposing a fix", DONE)
            await self._say(ctx, inc, "", end=True)
            return
        if not res.attestation.approved:
            await self._fail(ctx, inc, "I could not write a fix that passed the security check, so I am not proposing one.",
                             "Try adding more detail to the problem, such as the exact error message or file.")
            return
        inc["action_type"] = "OPEN_PR_AND_HOTFIX"
        if inc["repo"].lower() in self.cfg.writable_repos:
            self._set_state(inc, "AWAITING_APPROVAL")
            inc["authorization"] = "operator click in the web console"
            self._put(ctx, inc)
            await activity(ctx, inc["incident_id"], AGENT_NAME, "Waiting for your approval in the chat")
            await self._say(ctx, inc, "")
            return
        self._set_state(inc, "RESOLVED")      # nothing to authorize: Sentinel cannot write here, so it hands over the fix
        inc["delivery"] = "files"
        self._put(ctx, inc)
        await activity(ctx, inc["incident_id"], AGENT_NAME, "The fix is ready to download", DONE)
        await self._say(ctx, inc, "", end=True)

    async def _start_incident(self, ctx: Context, sender: str, intent: Intent) -> None:
        cfg, notes = self.cfg, []
        repo, url = intent.repo, intent.url
        if not repo and cfg.demo_repo_full_name:
            repo, notes = cfg.demo_repo_full_name, notes + [f"repo `{cfg.demo_repo_full_name}`"]
        if intent.mode != "security_audit" and not url and cfg.demo_service_url:
            url, notes = cfg.demo_service_url, notes + [f"service {cfg.demo_service_url}"]
        if not repo or (intent.mode != "security_audit" and not url):
            await ctx.send(sender, make_chat("I need the **service URL** and the GitHub **owner/repo**, e.g.\n"
                                             "`Diagnose and heal the outage on https://my-service.example for repo acme/my-service`"))
            return
        inc = {
            "incident_id": "inc-" + uuid.uuid4().hex[:8], "user": sender, "session": str(getattr(ctx, "session", "")),
            "mode": intent.mode, "repo": repo, "service_url": url or "", "created_at": self.clock(),
        }
        inc_id = inc["incident_id"]
        used = f" (using the configured {' and '.join(notes)})" if notes else ""
        if intent.mode == "security_audit":
            self._set_state(inc, "CORRELATING")
            self._put(ctx, inc)
            await self._say(ctx, inc, f"🔎 Starting a **security audit** of `{repo}`{used} — incident `{inc_id}`. Mapping active imports…")
            await self._send(ctx, "detective", CommitCorrelationRequest(
                incident_id=inc_id, repo_full_name=repo, failure_timestamp_utc=_now_iso(), failing_endpoint="/"))
            return
        self._set_state(inc, "PROBING")
        self._put(ctx, inc)
        chaos = intent.mode == "chaos_test"
        await self._say(ctx, inc, f"{'💥 Injecting the demo fault, then probing' if chaos else '🔍 Probing'} {url}{used} — incident `{inc_id}`. "
                                  "3 requests per endpoint…")
        log(ctx.logger, inc_id, AGENT_NAME, "probe", f"🔍 {intent.mode} for {repo} @ {url}")
        await self._send(ctx, "watchdog", HealthProbeRequest(incident_id=inc_id, service_url=url, inject_chaos=chaos))

    # -- the A2A pipeline ------------------------------------------------------------------------------

    async def handle_probe_report(self, ctx: Context, sender: str, rep: HealthProbeReport) -> None:
        try:
            if rep.is_canary_check:
                inc = self._accept(ctx, sender, "watchdog", rep.incident_id, {"VERIFYING"})
                if inc is not None:
                    await self._finish_canary(ctx, inc, rep)
                return
            inc = self._load(ctx, rep.incident_id)
            if inc is None and rep.incident_id.startswith("auto-"):
                inc = await self._open_alert_incident(ctx, sender, rep)
            else:
                inc = self._accept(ctx, sender, "watchdog", rep.incident_id, {"PROBING"})
            if inc is None:
                return
            if inc.get("source") == WEB:
                await self._after_web_probe(ctx, inc, rep)
                return
            if rep.is_healthy:
                self._set_state(inc, "RESOLVED")
                self._put(ctx, inc)
                await self._say(ctx, inc, f"✅ `{rep.service_url}` is **healthy** — all endpoints returned 2xx.\n\n"
                                          f"Want me to check `{inc['repo']}` for vulnerabilities? Say `security audit of {inc['repo']}`.")
                return
            failing = next(m for m in rep.metrics if not 200 <= m.status_code < 300)
            if failing.status_code == 0:
                await self._fail(ctx, inc, f"`{failing.endpoint}` is **unreachable** (`{(failing.error_snippet or 'network error')[:150]}`) — "
                                           "that is a network/infrastructure problem, not a code regression I can trace to a commit.",
                                 "Check DNS, TLS and that the service is running, then ask me again.")
                return
            stats = summarize(rep.metrics)
            inc["probe"] = {"endpoint": failing.endpoint, "status": failing.status_code, "latency_ms": failing.latency_ms,
                            "failure_ts": failing.timestamp_utc, "failing": int(stats["failing"]), "total": int(stats["total"]),
                            "p95_ms": stats["p95_ms"]}
            self._set_state(inc, "CORRELATING")
            self._put(ctx, inc)
            await self._say(ctx, inc, f"🚨 `{failing.endpoint}` is returning **HTTP {failing.status_code}** "
                                      f"({int(stats['failing'])}/{int(stats['total'])} probes failing, p95 {stats['p95_ms']:.0f} ms). "
                                      "Looking for the commit that caused it…")
            await self._send(ctx, "detective", CommitCorrelationRequest(
                incident_id=inc["incident_id"], repo_full_name=inc["repo"], failure_timestamp_utc=failing.timestamp_utc,
                failing_endpoint=failing.endpoint, error_snippet=failing.error_snippet))
        except Exception as exc:
            await self._pipeline_error(ctx, rep.incident_id, "probe", exc)

    async def _open_alert_incident(self, ctx: Context, sender: str, rep: HealthProbeReport) -> Optional[Dict[str, Any]]:
        """A Watchdog auto-alert for a service we are not yet handling."""
        repo = self.cfg.demo_repo_full_name
        if self.addresses.get("watchdog") != sender or rep.is_healthy or not repo:
            log(ctx.logger, rep.incident_id, AGENT_NAME, "alert", "ignoring alert (untrusted sender, healthy, or DEMO_REPO_FULL_NAME unset)", level="warning")
            return None
        if any(i["service_url"] == rep.service_url and i["state"] not in FINAL_STATES for i in self._all(ctx)):
            return None  # already handling this service
        inc = {"incident_id": rep.incident_id, "user": ctx.storage.get("last_user") or "", "session": "", "mode": "diagnose_and_heal",
               "repo": repo, "service_url": rep.service_url, "created_at": self.clock(), "source": "watchdog-alert"}
        self._set_state(inc, "PROBING")
        self._put(ctx, inc)
        log(ctx.logger, inc["incident_id"], AGENT_NAME, "alert", f"🚨 Watchdog alert for {rep.service_url}")
        await self._say(ctx, inc, f"🚨 **Agent_2 alert**: `{rep.service_url}` just turned unhealthy. Opening incident `{inc['incident_id']}`…")
        return inc

    async def handle_evidence(self, ctx: Context, sender: str, ev: CommitEvidenceReport) -> None:
        try:
            inc = self._accept(ctx, sender, "detective", ev.incident_id, {"CORRELATING"})
            if inc is None:
                return
            inc["evidence"] = ev.dict()
            web = inc.get("source") == WEB
            if web and ev.offending_file == "unknown" and inc["mode"] != "security_audit":
                await self._fail(ctx, inc, "I could not tell which file this problem comes from.",
                                 "Add the error message, or name the page or file that is failing.")
                return
            fix_title = sentinel_fix_title(ev.commit_message)
            if fix_title and inc["mode"] != "security_audit":   # blaming our own fix would roll it back: see build_already_fixed
                await self._fail(ctx, inc, card.build_already_fixed(ev, fix_title), card.ALREADY_FIXED_HINT)
                return
            self._set_state(inc, "SCANNING")
            self._put(ctx, inc)
            await self._say(ctx, inc, f"🧬 Commit [`{card.short_sha(ev.suspect_commit_sha)}`]({ev.suspect_commit_url}) by @{ev.author} identified — "
                                      f"`{ev.offending_file}`.\n> {ev.root_cause_explanation}\n\n🛡️ Scanning dependencies and code…")
            whole_repo = web and inc["mode"] == "security_audit"
            await self._send(ctx, "scanner", VulnerabilityScanRequest(
                incident_id=ev.incident_id, repo_full_name=ev.repo_full_name, branch=inc.get("branch", "main"),
                suspect_commit_sha=ev.suspect_commit_sha if ev.confidence == "high" else "",
                modified_files=["*"] if whole_repo else [ev.offending_file], active_ast_imports=ev.active_ast_imports))
        except Exception as exc:
            await self._pipeline_error(ctx, ev.incident_id, "correlate", exc)

    async def handle_vuln_report(self, ctx: Context, sender: str, rep: VulnerabilityReport) -> None:
        try:
            inc = self._accept(ctx, sender, "scanner", rep.incident_id, {"SCANNING"})
            if inc is None:
                return
            inc["vuln"] = rep.dict()
            ev = CommitEvidenceReport.model_validate(inc["evidence"])
            if inc["mode"] == "security_audit":
                self._set_state(inc, "RESOLVED")
                self._put(ctx, inc)
                if inc.get("source") == WEB:
                    await activity(ctx, rep.incident_id, AGENT_NAME, "The security check is finished", DONE)
                await self._say(ctx, inc, card.build_audit_report(inc["incident_id"], inc["repo"], ev, rep), end=True)
                return
            self._set_state(inc, "PATCHING")
            self._put(ctx, inc)
            reachable = sum(1 for f in rep.cve_findings if f.is_reachable_in_ast)
            await self._say(ctx, inc, f"📋 {len(rep.cve_findings)} CVE(s) ({reachable} reachable, {rep.total_reachable_critical} reachable CRITICAL) and "
                                      f"{len(rep.sast_findings)} code finding(s).\n\n🩹 Drafting a fix — every draft must pass the security gatekeeper first…")
            await self._send(ctx, "executor", PatchDraftRequest(
                incident_id=rep.incident_id, repo_full_name=inc["repo"], commit_evidence=ev, vuln_report=rep,
                branch=inc.get("branch", "main"), problem=inc.get("problem", "")))
        except Exception as exc:
            await self._pipeline_error(ctx, rep.incident_id, "scan", exc)

    async def handle_patch_result(self, ctx: Context, sender: str, res: PatchDraftResult) -> None:
        try:
            inc = self._accept(ctx, sender, "executor", res.incident_id, {"PATCHING"})
            if inc is None:
                return
            if inc.get("source") == WEB:
                await self._finish_web_draft(ctx, inc, res)
                return
            if res.no_bug:
                await self._fail(ctx, inc, f"I read `{res.attestation.target_file}` and did not find this problem there. {res.explanation}")
                return
            # Everything the card needs is computed BEFORE the first await (CLAUDE.md §9.2 timing rule),
            # so step 9 can fire RequestPayment immediately in _request_authorization.
            ev = CommitEvidenceReport.model_validate(inc["evidence"])
            vuln = VulnerabilityReport.model_validate(inc["vuln"])
            p, att = inc["probe"], res.attestation
            secrets = [f for f in vuln.sast_findings if f.rule_id == "HARDCODED_SECRET"]
            blast = compute_blast_radius(
                failing_probes=p["failing"], total_probes=p["total"], p95_ms=p["p95_ms"], commit_time_iso=ev.committed_at_utc,
                failure_time_iso=p["failure_ts"], reachable_critical=vuln.total_reachable_critical,
                reachable_high=count_reachable(vuln.cve_findings, "HIGH"), secrets_found=len(secrets),
                secret_introduced_by_suspect=bool(secrets) and "****" in ev.offending_diff_snippet, settings=self.cfg)
            text = card.build_incident_card(inc["incident_id"], inc["service_url"], inc["repo"], p, ev, vuln, res, blast,
                                            self.cfg.patch_max_attempts, payment_required=not self.skip_payment)
            inc["result"] = res.dict()
            inc["blast"] = asdict(blast)
            inc["action_type"] = "OPEN_PR_AND_HOTFIX" if att.approved else "ROLLBACK_COMMIT"
            inc["card"] = text
            if not att.approved and not res.rollback_available:
                await self._fail(ctx, inc, text)
                return
            if not self.skip_payment and not self.cfg.orchestrator_wallet_address:
                await self._fail(ctx, inc, "I cannot take the change-control payment: `ORCHESTRATOR_WALLET_ADDRESS` is not configured. "
                                           "No change was made.", "Ask the operator to set the wallet, or run with `SKIP_PAYMENT=true` for development.")
                return
            # _request_authorization persists the incident itself BEFORE its first await, so a fast CommitPayment finds it
            note = await self._request_authorization(ctx, inc)
            await self._say(ctx, inc, text + (f"\n\n{note}" if note else ""))
        except Exception as exc:
            await self._pipeline_error(ctx, res.incident_id, "patch", exc)

    async def _request_authorization(self, ctx: Context, inc: Dict[str, Any]) -> str:
        """Change-control gate. SKIP_PAYMENT: record the bypass. Otherwise state -> AWAITING_PAYMENT, persist, and send
        RequestPayment as the first await (CLAUDE.md §9.2) -- the incident card is sent after it by the caller."""
        if self.skip_payment:
            self._set_state(inc, "AWAITING_APPROVAL")
            inc["authorization"] = "skipped (SKIP_PAYMENT=true, dev only)"
            self._put(ctx, inc)
            return "_Dev mode: on-chain payment is skipped (`SKIP_PAYMENT=true`)._"
        self._set_state(inc, "AWAITING_PAYMENT")
        inc["payment_requested_at"] = _now_iso()
        inc.setdefault("payment_failures", 0)
        self._put(ctx, inc)
        await self._send_payment_request(ctx, inc)
        return ""

    async def _send_payment_request(self, ctx: Context, inc: Dict[str, Any]) -> None:
        if not inc.get("user"):
            return  # headless (watchdog-raised) incident: re-sent once the user claims it and asks again
        cfg = self.cfg
        request = RequestPayment(
            accepted_funds=[Funds(amount=str(cfg.remediation_price_atestfet), currency=DENOM, payment_method="fet_direct")],
            recipient=cfg.orchestrator_wallet_address, deadline_seconds=int(self.approval_timeout), reference=inc["incident_id"],
            description=f"Sentinel change-control authorization for incident {inc['incident_id']} "
                        f"({format_fet(cfg.remediation_price_atestfet)}, Dorado testnet)",
            metadata={"incident_id": inc["incident_id"], "action": inc["action_type"], "network": "dorado-1"})
        try:
            await ctx.send(inc["user"], request)
            log(ctx.logger, inc["incident_id"], AGENT_NAME, "payment",
                f"💳 requested {format_fet(cfg.remediation_price_atestfet)} to {cfg.orchestrator_wallet_address[:12]}…")
        except Exception as exc:
            log(ctx.logger, inc["incident_id"], AGENT_NAME, "payment", f"could not send RequestPayment: {exc}", level="error")

    # -- payment protocol (seller role) -----------------------------------------------------------------------

    def _pending_payment(self, ctx: Context, user: str, reference: Optional[str] = None) -> Optional[Dict[str, Any]]:
        waiting = [i for i in self._mine(ctx, user) if i["state"] == "AWAITING_PAYMENT"]
        if reference:
            return next((i for i in waiting if i["incident_id"] == reference), None)
        return waiting[-1] if waiting else None

    @staticmethod
    def _used_key(tx_hash: str) -> str:
        return f"used_tx:{tx_hash.upper()}"

    def _already_authorized_by(self, ctx: Context, user: str, tx: str) -> bool:
        inc_id = ctx.storage.get(self._used_key(tx))
        inc = self._load(ctx, inc_id) if inc_id else None
        return bool(inc and inc.get("user") == user and inc.get("dorado_tx_hash", "").upper() == tx.upper())

    async def handle_commit_payment(self, ctx: Context, sender: str, msg: CommitPayment) -> None:
        tx = (msg.transaction_id or "").strip()
        reserved = False
        try:
            inc = self._pending_payment(ctx, sender, msg.reference)
            if inc is None and tx and self._already_authorized_by(ctx, sender, tx):
                await ctx.send(sender, CompletePayment(transaction_id=tx.upper()))   # duplicate delivery: stay idempotent
                return
            if inc is None:
                log(ctx.logger, msg.reference or "-", AGENT_NAME, "payment", "CommitPayment with no pending payment request", level="warning")
                await ctx.send(sender, CancelPayment(transaction_id=tx or None, reason="No payment is pending for you (it may have expired or been cancelled)."))
                await ctx.send(sender, make_chat("💳 I received a payment confirmation but no incident of yours is waiting for payment (it may have expired or "
                                                 "been cancelled), so nothing was authorized. If you paid on-chain, that transaction has **not** been consumed."))
                return
            inc_id, used_key = inc["incident_id"], self._used_key(tx)
            if tx and ctx.storage.get(used_key):       # replay: a hash authorizes exactly one incident
                await self._payment_failed(ctx, inc, tx, "That transaction hash was already used to authorize a change, so it cannot be used again.", definitive=True)
                return
            if tx:
                ctx.storage.set(used_key, inc_id)      # reserve BEFORE the slow lookup so concurrent commits cannot both pass
                reserved = True
            log(ctx.logger, inc_id, AGENT_NAME, "payment", f"🔗 verifying Dorado tx {tx[:12]}…")
            not_before = datetime.fromisoformat(inc["payment_requested_at"]) - PAYMENT_BACKDATE
            result = await self.verifier.verify(tx, self.cfg.orchestrator_wallet_address, self.cfg.remediation_price_atestfet, DENOM, not_before)
            fresh = self._load(ctx, inc_id)           # the incident may have changed while we waited on the chain
            if result.ok and (fresh is None or fresh["state"] != "AWAITING_PAYMENT"):
                ctx.storage.set(used_key, "")
                reserved = False
                await ctx.send(sender, CancelPayment(transaction_id=tx, reason="This incident is no longer waiting for payment."))
                return
            if not result.ok:
                ctx.storage.set(used_key, "")          # release the reservation
                reserved = False
                await self._payment_failed(ctx, fresh or inc, tx, result.reason, definitive=result.definitive)
                return
            inc = fresh
            self._set_state(inc, "APPROVED")
            inc.update(dorado_tx_hash=result.tx_hash, payer_wallet=result.payer, authorized_by=sender, authorized_at=_now_iso(),
                       authorization=f"paid {format_fet(result.amount)} (tx {result.tx_hash})")
            ctx.storage.set(self._used_key(result.tx_hash), inc_id)
            self._put(ctx, inc)
            reserved = False
            log(ctx.logger, inc_id, AGENT_NAME, "payment", f"✅ payment verified: {result.reason} tx={result.tx_hash[:12]}…")
            await ctx.send(sender, CompletePayment(transaction_id=result.tx_hash))
            link = explorer_url(self.cfg.dorado_explorer_base, result.tx_hash)
            await self._say(ctx, inc, f"✅ **Payment verified** on Dorado: {result.reason}\n\n[`{result.tx_hash[:16]}…`]({link})\n\n" + self._authorized_text(inc))
            await self._begin_execution(ctx, inc)
        except Exception as exc:  # handlers never raise
            log(ctx.logger, "-", AGENT_NAME, "payment", f"error: {type(exc).__name__}: {exc}", level="error")
            try:
                if reserved:
                    ctx.storage.set(self._used_key(tx), "")
                await ctx.send(sender, make_chat(f"⚠️ I could not process that payment (`{type(exc).__name__}`). Nothing was authorized — please try again."))
            except Exception:
                pass

    async def _payment_failed(self, ctx: Context, inc: Dict[str, Any], tx: str, reason: str, definitive: bool) -> None:
        inc_id = inc["incident_id"]
        log(ctx.logger, inc_id, AGENT_NAME, "payment", f"⛔ payment refused: {reason}", level="warning")
        await ctx.send(inc["user"], CancelPayment(transaction_id=tx or None, reason=reason[:300]))
        if definitive:
            inc["payment_failures"] = inc.get("payment_failures", 0) + 1
        left = MAX_PAYMENT_FAILURES - inc.get("payment_failures", 0)
        if left <= 0:
            self._set_state(inc, "CANCELLED")
            self._put(ctx, inc)
            await self._say(ctx, inc, f"⛔ Payment refused: {reason}\n\nToo many failed payments — incident `{inc_id}` is **cancelled**. No changes were made.", end=True)
            return
        self._put(ctx, inc)
        retry = ("You can pay again with the new request below" if definitive
                 else "If the transaction is real, give it a minute and then pay/confirm again")
        await self._say(ctx, inc, f"⛔ **Payment not accepted:** {reason}\n\nNothing was authorized or changed. {retry} ({left} attempt(s) left), "
                                  "or reply **reject** to cancel.")
        await self._send_payment_request(ctx, inc)

    async def handle_payment_declined(self, ctx: Context, sender: str, msg: Any) -> None:
        """RejectPayment / CancelPayment from the user: they decline to pay."""
        try:
            inc = self._pending_payment(ctx, sender)
            if inc is None:
                return
            self._set_state(inc, "CANCELLED")
            self._put(ctx, inc)
            reason = (getattr(msg, "reason", None) or "no reason given")[:200]
            log(ctx.logger, inc["incident_id"], AGENT_NAME, "payment", f"❎ payment declined by user ({reason})")
            await self._say(ctx, inc, f"❎ Payment declined — incident `{inc['incident_id']}` **cancelled**. No changes were made to `{inc['repo']}`.", end=True)
        except Exception as exc:
            log(ctx.logger, "-", AGENT_NAME, "payment", f"error: {type(exc).__name__}: {exc}", level="error")

    @staticmethod
    def _authorized_text(inc: Dict[str, Any]) -> str:
        rollback_only = inc["action_type"] == "ROLLBACK_COMMIT"
        what = "roll back the suspect commit" if rollback_only else "open the pull request (patch + SBOM) and trigger the hotfix"
        return (f"✅ **Change authorized** for incident `{inc['incident_id']}` ({inc['action_type']}).\n\n"
                f"🚀 Agent_5 will now {what}, then I will re-probe the service to confirm recovery…")

    # -- execution and canary verification (Step 10) -----------------------------------------------------------

    async def _begin_execution(self, ctx: Context, inc: Dict[str, Any]) -> None:
        """APPROVED -> EXECUTING: hand the vetted, paid-for change to the Agent_5. Never raises."""
        try:
            att = SecurityApprovalAttestation.model_validate(inc["result"]["attestation"])
            url = (inc.get("service_url") or "").rstrip("/")
            cmd = ExecuteRemediationCommand(
                incident_id=inc["incident_id"], repo_full_name=inc["repo"], action_type=inc["action_type"],
                dorado_tx_hash=inc.get("dorado_tx_hash", ""), payer_wallet=inc.get("payer_wallet", ""), attestation=att,
                service_reload_webhook=f"{url}/admin/apply-hotfix" if url else None, branch=inc.get("branch", "main"))
            self._set_state(inc, "EXECUTING")
            self._put(ctx, inc)
            if inc.get("source") == WEB:
                await self._say(ctx, inc, "")
            log(ctx.logger, inc["incident_id"], AGENT_NAME, "execute", f"🚀 sending {inc['action_type']} to Agent_5")
            await self._send(ctx, "executor", cmd)
        except Exception as exc:
            await self._pipeline_error(ctx, inc["incident_id"], "execute", exc)

    async def handle_remediation_report(self, ctx: Context, sender: str, rep: RemediationCompletionReport) -> None:
        try:
            inc = self._accept(ctx, sender, "executor", rep.incident_id, {"EXECUTING"})
            if inc is None:
                return
            inc["remediation"] = rep.model_dump()
            if not rep.success:
                await self._fail(ctx, inc, f"The Agent_5 could not complete the change: {rep.summary_message[:300]}",
                                 RECOVERY["Agent_5"])
                return
            if inc.get("source") == WEB and not rep.redeploy_triggered:
                self._set_state(inc, "RESOLVED")    # the service changes when the PR is merged and deployed, not now
                inc["last_note"] = "pr-opened"
                self._put(ctx, inc)
                await activity(ctx, rep.incident_id, AGENT_NAME, "The pull request is ready for your review", DONE)
                await self._say(ctx, inc, "", end=True)
                return
            self._set_state(inc, "VERIFYING")
            self._put(ctx, inc)
            hook = "✅ hotfix triggered" if rep.redeploy_triggered else "⚠️ hotfix **not** triggered"
            await self._say(ctx, inc, f"🔀 Pull request opened: {rep.pr_url}\n\n📦 SBOM: {rep.sbom_file_url} · {hook}\n\n"
                                      "🐤 Running a canary probe against the live service…")
            canary = HealthProbeRequest(incident_id=rep.incident_id, service_url=inc["service_url"], is_canary_check=True)
            await self._send(ctx, "watchdog", canary.copy(update={"endpoints": inc["endpoints"]}) if inc.get("endpoints") else canary)
        except Exception as exc:
            await self._pipeline_error(ctx, rep.incident_id, "execute", exc)

    async def _finish_canary(self, ctx: Context, inc: Dict[str, Any], rep: HealthProbeReport) -> None:
        rem = RemediationCompletionReport.model_validate(inc["remediation"])
        att_hash = inc["result"]["attestation"].get("attestation_hash", "")
        text = card.build_final_report(inc, rem, rep.metrics, rep.is_healthy, att_hash, self.cfg.dorado_explorer_base)
        self._set_state(inc, "RESOLVED" if rep.is_healthy else "FAILED")
        inc["last_note"] = "recovered" if rep.is_healthy else "canary still failing"
        self._put(ctx, inc)
        log(ctx.logger, inc["incident_id"], AGENT_NAME, "canary", "✅ canary healthy: incident RESOLVED" if rep.is_healthy
            else "⛔ canary still failing", level="info" if rep.is_healthy else "error")
        if inc.get("source") == WEB:
            await activity(ctx, inc["incident_id"], AGENT_NAME, "Service recovered" if rep.is_healthy else "Service is still failing", DONE)
        await self._say(ctx, inc, text, end=True)

    async def handle_agent_error(self, ctx: Context, sender: str, err: AgentErrorReport) -> None:
        try:
            if sender not in {a for a in self.addresses.values() if a}:
                return
            inc = self._load(ctx, err.incident_id)
            if inc is None or inc["state"] in FINAL_STATES:
                return
            await self._fail(ctx, inc, f"**{err.agent}** reported an error during *{err.stage}*: `{err.error[:300]}`",
                             RECOVERY.get(err.agent, "Please try again."))
        except Exception as exc:
            log(ctx.logger, err.incident_id, AGENT_NAME, "error", f"{type(exc).__name__}: {exc}", level="error")

    async def _pipeline_error(self, ctx: Context, inc_id: str, stage: str, exc: Exception) -> None:
        log(ctx.logger, inc_id, AGENT_NAME, stage, f"error: {type(exc).__name__}: {exc}", level="error")
        try:
            inc = self._load(ctx, inc_id)
            if inc and inc["state"] not in FINAL_STATES:
                await self._fail(ctx, inc, f"Internal error while handling the *{stage}* step (`{type(exc).__name__}: {str(exc)[:200]}`).",
                                 "Nothing was changed. Please try again.")
        except Exception:
            pass

    # -- user decisions and status ------------------------------------------------------------------------

    def _mine(self, ctx: Context, user: str) -> List[Dict[str, Any]]:
        return [i for i in self._all(ctx) if i.get("user") == user]

    async def _claim_unowned(self, ctx: Context, user: str) -> None:
        for inc in self._all(ctx):
            if not inc.get("user") and inc["state"] not in FINAL_STATES:
                inc["user"] = user
                self._put(ctx, inc)
                await self._say(ctx, inc, f"🚨 While you were away the Watchdog opened incident `{inc['incident_id']}`.\n\n" + self._status_text(inc))

    @staticmethod
    def _status_text(inc: Dict[str, Any]) -> str:
        text = card.build_status(inc)
        if inc["state"] in ("AWAITING_APPROVAL", "AWAITING_PAYMENT") and inc.get("card"):
            text += "\n\n" + inc["card"]
        return text

    async def _status(self, ctx: Context, user: str, intent: Intent) -> None:
        mine = self._mine(ctx, user)
        inc = next((i for i in mine if i["incident_id"] == intent.incident_id), None) if intent.incident_id else (mine[-1] if mine else None)
        await ctx.send(user, make_chat(self._status_text(inc) if inc else "No incidents yet. " + "Tell me which service is failing and which repo owns it."))

    def _nothing_waiting_text(self, mine: List[Dict[str, Any]]) -> str:
        """Why an approve/reject found nothing to act on, and how to start over."""
        text = "Nothing is waiting for your decision right now."
        last = mine[-1] if mine else None
        if last and last["state"] == "CANCELLED" and last.get("cancel_reason") == "expired":
            text = (f"Incident `{last['incident_id']}` is no longer waiting: it was **cancelled** (approvals expire after "
                    f"{self.approval_timeout / 60:.0f} min without a reply). No changes were made.")
        if last and last.get("service_url") and last.get("repo"):
            text += f"\n\nTo start again, send:\n`Diagnose and heal {last['service_url']} for repo {last['repo']}`"
        return text + "\n\nSay `status` to see your incidents."

    def incidents_snapshot(self, ctx: Context, limit: int = 20) -> List[Dict[str, Any]]:
        """Newest-first ids and states: the console's heartbeat. Records reach it through IncidentUpdate."""
        return [{"incident_id": inc["incident_id"], "state": inc["state"]} for inc in reversed(self._all(ctx)[-limit:])]

    async def _decide(self, ctx: Context, user: str, intent: Intent) -> None:
        mine = self._mine(ctx, user)
        waiting = [i for i in mine if i["state"] in ("AWAITING_APPROVAL", "AWAITING_PAYMENT")]
        inc = next((i for i in waiting if i["incident_id"] == intent.incident_id), None) if intent.incident_id else (waiting[-1] if waiting else None)
        if inc is None:
            await ctx.send(user, make_chat(self._nothing_waiting_text(mine)))
            return
        inc_id, action, rollback_only = inc["incident_id"], intent.action, inc["action_type"] == "ROLLBACK_COMMIT"
        if action == "reject":
            self._set_state(inc, "CANCELLED")
            self._put(ctx, inc)
            log(ctx.logger, inc_id, AGENT_NAME, "decision", "❎ rejected by user")
            await self._say(ctx, inc, f"❎ Incident `{inc_id}` **cancelled**. No changes were made to `{inc['repo']}`.", end=True)
            return
        if inc["state"] == "AWAITING_PAYMENT":   # the payment IS the authorization; typing approve re-sends the request
            await self._say(ctx, inc, f"💳 Incident `{inc_id}` is waiting for your **{format_fet(self.cfg.remediation_price_atestfet)}** payment — "
                                      "use the payment request below. Reply **reject** to cancel.")
            await self._send_payment_request(ctx, inc)
            return
        if action == "approve" and rollback_only:
            await self._say(ctx, inc, "No vetted forward patch exists for this incident — the only option is a **rollback**. Reply **rollback** to authorize it, or **reject**.")
            return
        if action == "rollback" and not rollback_only:
            await self._say(ctx, inc, "A security-vetted patch is ready, so no rollback is needed. Reply **approve** to authorize it, or **reject**.")
            return
        self._set_state(inc, "APPROVED")
        inc["authorized_by"], inc["authorized_at"] = user, _now_iso()
        self._put(ctx, inc)
        log(ctx.logger, inc_id, AGENT_NAME, "decision", f"✅ authorized by user ({inc['action_type']}); {inc.get('authorization', '')}")
        await self._say(ctx, inc, self._authorized_text(inc))
        await self._begin_execution(ctx, inc)

    # -- timeouts -----------------------------------------------------------------------------------------

    async def sweep(self, ctx: Context) -> None:
        """Fail incidents stuck in a stage; expire approvals nobody answered. Never raises."""
        try:
            now = self.clock()
            for inc in self._all(ctx):
                state, waited = inc["state"], now - inc.get("stage_since", now)
                if state in self.stage_timeouts and waited > self.stage_timeouts[state]:
                    agent = WAITING_FOR[state]
                    await self._fail(ctx, inc, f"⏱️ Timed out after {self.stage_timeouts[state]:.0f}s waiting for **{agent}** ({state.lower()} stage).",
                                     RECOVERY.get(agent, "Please try again."))
                elif state in ("AWAITING_APPROVAL", "AWAITING_PAYMENT") and waited > self.approval_timeout:
                    self._set_state(inc, "CANCELLED")
                    inc["cancel_reason"] = "expired"
                    self._put(ctx, inc)
                    what = "payment" if state == "AWAITING_PAYMENT" else "a decision"
                    await self._say(ctx, inc, f"⌛ Incident `{inc['incident_id']}` expired without {what} and was **cancelled**. No changes were made.", end=True)
        except Exception as exc:
            log(ctx.logger, "-", AGENT_NAME, "sweep", f"error: {type(exc).__name__}: {exc}", level="error")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def create_agent(
    seed: Optional[str] = None, mailbox: bool = True, port: int = PORT,
    orchestrator: Optional[Orchestrator] = None, **agent_kwargs: Any,
):
    cfg = get_settings()
    orch = orchestrator or Orchestrator()
    agent = build_agent(
        name=AGENT_LABEL, seed=seed or cfg.orchestrator_seed, seed_env="ORCHESTRATOR_SEED", port=port,
        description=DESCRIPTION, mailbox=mailbox, **agent_kwargs,
    )
    chat_proto = Protocol(spec=chat_protocol_spec)

    @chat_proto.on_message(ChatMessage)
    async def _on_chat(ctx: Context, sender: str, msg: ChatMessage) -> None:
        await orch.handle_chat(ctx, sender, msg)

    @chat_proto.on_message(ChatAcknowledgement)
    async def _on_ack(ctx: Context, sender: str, msg: ChatAcknowledgement) -> None:
        await orch.handle_ack(ctx, sender, msg)

    agent.include(chat_proto, publish_manifest=True)

    payment_proto = Protocol(spec=payment_protocol_spec, role="seller")

    @payment_proto.on_message(CommitPayment)
    async def _on_commit(ctx: Context, sender: str, msg: CommitPayment) -> None:
        await orch.handle_commit_payment(ctx, sender, msg)

    @payment_proto.on_message(RejectPayment)
    async def _on_reject(ctx: Context, sender: str, msg: RejectPayment) -> None:
        await orch.handle_payment_declined(ctx, sender, msg)

    agent.include(payment_proto, publish_manifest=True)

    @agent.on_message(CancelPayment)   # not among the seller role's handlers, so it is registered on the agent directly
    async def _on_cancel(ctx: Context, sender: str, msg: CancelPayment) -> None:
        await orch.handle_payment_declined(ctx, sender, msg)

    @agent.on_event("startup")
    async def _startup(ctx: Context) -> None:
        await orch.startup(ctx)

    @agent.on_event("shutdown")
    async def _shutdown(ctx: Context) -> None:
        await orch.shutdown(ctx)

    @agent.on_message(HealthProbeReport)
    async def _on_probe(ctx: Context, sender: str, msg: HealthProbeReport) -> None:
        await orch.handle_probe_report(ctx, sender, msg)

    @agent.on_message(CommitEvidenceReport)
    async def _on_evidence(ctx: Context, sender: str, msg: CommitEvidenceReport) -> None:
        await orch.handle_evidence(ctx, sender, msg)

    @agent.on_message(VulnerabilityReport)
    async def _on_vuln(ctx: Context, sender: str, msg: VulnerabilityReport) -> None:
        await orch.handle_vuln_report(ctx, sender, msg)

    @agent.on_message(PatchDraftResult)
    async def _on_patch(ctx: Context, sender: str, msg: PatchDraftResult) -> None:
        await orch.handle_patch_result(ctx, sender, msg)

    @agent.on_message(RemediationCompletionReport)
    async def _on_remediation(ctx: Context, sender: str, msg: RemediationCompletionReport) -> None:
        await orch.handle_remediation_report(ctx, sender, msg)

    @agent.on_message(AgentErrorReport)
    async def _on_error(ctx: Context, sender: str, msg: AgentErrorReport) -> None:
        await orch.handle_agent_error(ctx, sender, msg)

    @agent.on_message(IncidentRequest)
    async def _on_incident_request(ctx: Context, sender: str, msg: IncidentRequest) -> None:
        await orch.handle_incident_request(ctx, sender, msg)

    @agent.on_rest_get("/incidents", IncidentListResponse)
    async def _incidents(ctx: Context) -> IncidentListResponse:
        return IncidentListResponse(incidents=orch.incidents_snapshot(ctx))

    @agent.on_interval(period=10.0)
    async def _sweep(ctx: Context) -> None:
        await orch.sweep(ctx)

    agent.orchestrator = orch  # type: ignore[attr-defined]
    return agent


if __name__ == "__main__":
    configure_console_utf8()
    create_agent(mailbox=True).run()
