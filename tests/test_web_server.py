"""The console's safety: sessions, sign-in, cross-site protection, private networks, and what each view shows."""
import json
from typing import Any, Dict, Optional

import pytest
from fastapi.testclient import TestClient

from common.models import AgentActivity, IncidentUpdate
from common.url_safety import same_host, target_problem
from web import server
from web.auth import MAX_FAILURES, OperatorAuth, exposure_error, is_loopback, same_origin
from web.console import Console, Session, split_service_url
from web.views import CANCELLED, DONE, FAILED, NEEDS_APPROVAL, PUBLISHING, RUNNING, fixed_file, incident_view, phase_of

SAME = {"host": "testserver"}
FULL_FIX = {"approved": True, "attestation_hash": "abc", "rejection_reasons": [], "target_file": "src/app.py",
            "patched_code_content": "print('fixed')\n", "updated_requirements_txt": "pyyaml==5.4\n", "unified_diff": "--- a/src/app.py\n+++ b/src/app.py\n"}


def record(incident_id: str = "inc-1234abcd", state: str = "AWAITING_APPROVAL", **extra: Any) -> Dict[str, Any]:
    return {"incident_id": incident_id, "state": state, "mode": "diagnose_and_heal", "repo": "acme/shop", "branch": "main",
            "service_url": "", "result": {"attestation": FULL_FIX, "attempts": 1, "explanation": "Uses a safe default."}, **extra}


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class FakeGateway:
    def __init__(self) -> None:
        self.requests, self.decisions = [], []
        self.address = "agent1qfake"

    def send_request(self, request) -> None:
        self.requests.append(request)

    def send_decision(self, action: str, incident_id: str) -> None:
        self.decisions.append((action, incident_id))


class FakeGitHub:
    def __init__(self, repos: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.repos = repos if repos is not None else {"acme/shop": {"full_name": "acme/shop", "default_branch": "develop", "private": False}}

    async def get_repo(self, repo: str) -> Optional[Dict[str, Any]]:
        return self.repos.get(repo)


def console_with(password: str = "") -> Console:
    c = Console(password)
    c.gateway, c.gh = FakeGateway(), FakeGitHub()
    return c


@pytest.fixture
def web(monkeypatch):
    """TestClient without lifespan: no gateway agent and no agents needed."""
    c = console_with()
    monkeypatch.setattr(server, "console", c)

    async def no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr(server.asyncio, "sleep", no_wait)
    client = TestClient(app=server.app)
    client.get("/api/session")
    client.console = c  # type: ignore[attr-defined]
    return client


def session_of(client: TestClient) -> Session:
    return client.console.session(client.cookies[server.SESSION_COOKIE])  # type: ignore[attr-defined]


def give_incident(client: TestClient, rec: Dict[str, Any]) -> None:
    client.console.owners[rec["incident_id"]] = session_of(client).id  # type: ignore[attr-defined]
    client.console.records[rec["incident_id"]] = rec                   # type: ignore[attr-defined]


# ------------------------------------------------------------------ OperatorAuth

def test_session_token_is_signed_and_expires():
    clock = Clock()
    auth = OperatorAuth("pw", clock=clock)
    token = auth.login("pw")
    assert token and auth.is_operator(token)
    assert not auth.is_operator(None) and not auth.is_operator("") and not auth.is_operator("9999999999.forged")
    expires, signature = token.split(".")
    assert not auth.is_operator(f"{int(expires) + 999}.{signature}")
    clock.t += 13 * 3600
    assert not auth.is_operator(token)


def test_login_locks_after_repeated_failures_then_recovers():
    clock = Clock()
    auth = OperatorAuth("pw", clock=clock)
    for _ in range(MAX_FAILURES):
        assert auth.login("wrong") is None
    assert auth.locked and auth.login("pw") is None
    clock.t += 61
    assert not auth.locked and auth.login("pw")


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_needs_no_password(host):
    assert is_loopback(host) and exposure_error(host, "") is None


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.20", "::"])
def test_public_bind_without_a_password_is_refused(host):
    assert "CONSOLE_PASSWORD" in exposure_error(host, "") and exposure_error(host, "pw") is None


def test_same_origin_rules():
    assert same_origin({})
    assert same_origin({"origin": "http://127.0.0.1:8080", "host": "127.0.0.1:8080"})
    assert same_origin({"origin": "https://sentinel.example", "host": "internal:8080", "x-forwarded-host": "sentinel.example"})
    assert same_origin({"origin": "http://localhost:5173", "host": "127.0.0.1:8080"})
    assert not same_origin({"origin": "https://evil.example", "host": "127.0.0.1:8080"})


# ------------------------------------------------------------------ private networks

@pytest.mark.parametrize("url", ["http://127.0.0.1:8001/incidents", "http://localhost:9000", "http://10.0.0.5", "http://192.168.1.1",
                                 "http://169.254.169.254/latest/meta-data", "http://[::1]:8080"])
def test_a_public_deployment_never_calls_its_own_network(url):
    assert target_problem(url) is not None


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com", "javascript:alert(1)", "http://user:pass@example.com"])
def test_only_plain_web_urls_are_accepted(url):
    assert target_problem(url) is not None


def test_a_public_address_is_fine(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 80))])
    assert target_problem("https://shop.example") is None


def test_a_name_that_resolves_to_a_private_address_is_refused(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 80))])
    assert "private" in target_problem("https://sneaky.example")


def test_local_use_and_the_demo_service_may_be_private():
    assert target_problem("http://127.0.0.1:9000", allow_private=True) is None
    assert target_problem("http://127.0.0.1:9000", known_safe_url="http://127.0.0.1:9000/") is None
    assert same_host("http://Demo:1/x", "http://demo:2/y") and not same_host("http://a/", "http://b/")


def test_paths_come_from_the_url_and_the_description():
    assert split_service_url("https://shop.example", "it crashes") == ("https://shop.example", ["/"])
    assert split_service_url("https://shop.example/api/checkout?x=1", "broken") == ("https://shop.example", ["/api/checkout"])
    assert split_service_url("https://shop.example", "/cart and /api/pay fail, see https://a.example/docs") == (
        "https://shop.example", ["/cart", "/api/pay"])


# ------------------------------------------------------------------ starting a case

async def test_a_case_starts_on_the_repos_real_default_branch():
    c = console_with()
    session = c.session("s1")
    out = await c.start(session, "diagnose_and_heal", "acme/shop", "it crashes", "")
    req, = c.gateway.requests
    assert out["status"] == "started" and req.branch == "develop" and req.repo_full_name == "acme/shop"
    assert c.owners[req.incident_id] == "s1"
    assert session.items == []     # the card follows the assistant's reply, so the conversation reads in order


async def test_a_repo_that_cannot_be_read_gets_a_clear_answer():
    c = console_with()
    out = await c.start(c.session("s1"), "diagnose_and_heal", "nobody/nothing", "it crashes", "")
    assert "can't open" in out["error"] and c.gateway.requests == []


async def test_private_repos_are_refused_unless_sentinel_was_given_them():
    c = console_with()
    c.gh = FakeGitHub({"acme/secret": {"full_name": "acme/secret", "default_branch": "main", "private": True}})
    assert "public" in (await c.start(c.session("s1"), "security_audit", "acme/secret", "", ""))["error"]


async def test_one_open_case_per_conversation():
    c = console_with()
    session = c.session("s1")
    await c.start(session, "diagnose_and_heal", "acme/shop", "it crashes", "")
    assert "still open" in (await c.start(session, "diagnose_and_heal", "acme/shop", "again", ""))["error"]


async def test_chaos_only_runs_against_the_configured_demo_service(monkeypatch):
    monkeypatch.setenv("DEMO_SERVICE_URL", "http://127.0.0.1:9000")
    c = console_with()
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 80))])
    out = await c.start(c.session("s1"), "chaos_test", "acme/shop", "", "https://shop.example")
    assert "demo" in out["error"] and c.gateway.requests == []


async def test_a_private_url_is_refused_on_a_public_deployment():
    c = Console("pw", host="0.0.0.0")
    c.gateway, c.gh = FakeGateway(), FakeGitHub()
    out = await c.start(c.session("s1"), "diagnose_and_heal", "acme/shop", "broken", "http://169.254.169.254/")
    assert "private" in out["error"] and c.gateway.requests == []


# ------------------------------------------------------------------ users stay apart

async def test_updates_and_activity_only_reach_the_owner():
    c = console_with()
    alice, bob = c.session("alice"), c.session("bob")
    await c.start(alice, "diagnose_and_heal", "acme/shop", "it crashes", "")
    inc = c.gateway.requests[0].incident_id
    await c.on_update(IncidentUpdate(incident_id=inc, record_json=json.dumps(record(inc))))
    await c.on_activity(AgentActivity(incident_id=inc, agent="Agent_3", status="working", text="Reading commits"))
    assert alice.activity[0]["text"] == "Reading commits" and alice.items[-1]["incident"]["phase"] == NEEDS_APPROVAL
    assert bob.items == [] and bob.activity == [] and c.current(bob) == []


async def test_an_update_for_an_unknown_incident_goes_nowhere():
    c = console_with()
    await c.on_update(IncidentUpdate(incident_id="inc-00000000", record_json=json.dumps(record("inc-00000000"))))
    assert c.records == {}


def test_nobody_can_decide_on_or_download_someone_elses_fix(web):
    other = TestClient(app=server.app)
    other.get("/api/session")
    other.console = web.console
    give_incident(other, record())
    assert web.post("/api/incidents/inc-1234abcd/decision", json={"action": "approve"}).status_code == 404
    assert web.get("/api/incidents/inc-1234abcd/files/0").status_code == 404
    assert web.console.gateway.decisions == []


def test_the_owner_can_decide_and_the_click_reaches_agent_1(web):
    give_incident(web, record())
    assert web.post("/api/incidents/inc-1234abcd/decision", json={"action": "approve"}).status_code == 200
    assert web.console.gateway.decisions == [("approve", "inc-1234abcd")]


def test_a_finished_case_cannot_be_approved(web):
    give_incident(web, record(state="RESOLVED"))
    assert web.post("/api/incidents/inc-1234abcd/decision", json={"action": "approve"}).status_code == 409


@pytest.mark.parametrize("action", ["merge-to-main", "rollback", ""])
def test_only_approve_and_reject_exist(web, action):
    give_incident(web, record())
    assert web.post("/api/incidents/inc-1234abcd/decision", json={"action": action}).status_code == 400


def test_the_owner_can_download_the_fixed_file(web):
    give_incident(web, record(state="RESOLVED", delivery="files"))
    resp = web.get("/api/incidents/inc-1234abcd/files/0")
    assert resp.status_code == 200 and resp.text == "print('fixed')\n" and 'filename="app.py"' in resp.headers["content-disposition"]


def test_new_chat_clears_the_conversation(web):
    session_of(web).items.append({"id": "x", "kind": "user", "text": "hi", "ts": 0})
    assert web.post("/api/reset").status_code == 200 and session_of(web).items == []


def test_the_page_never_shows_a_configured_repo(web):
    assert "repo" not in json.dumps(web.get("/api/health").json()).lower()


def test_health_says_which_commit_is_running(web, monkeypatch):
    """A push that never redeployed looked exactly like one that had: the live site must say what it runs."""
    monkeypatch.setenv("RENDER_GIT_COMMIT", "464cad0f1e2d3c4b5a69788796a5b4c3d2e1f0a9")
    assert web.get("/api/health").json()["version"] == "464cad0"
    monkeypatch.delenv("RENDER_GIT_COMMIT")
    assert web.get("/api/health").json()["version"] == ""


# ------------------------------------------------------------------ sign-in and cross-site

@pytest.fixture
def locked(web):
    web.console.auth = OperatorAuth("right-password")
    return web


def test_everything_needs_the_password_once_it_is_set(locked):
    assert locked.get("/api/session").json() == {"auth_required": True, "signed_in": False}
    assert locked.post("/api/reset").status_code == 401
    assert locked.post("/api/incidents/inc-1234abcd/decision", json={"action": "approve"}).status_code == 401


def test_wrong_password_then_right_password(locked):
    assert locked.post("/api/login", json={"password": "nope"}).status_code == 401
    resp = locked.post("/api/login", json={"password": "right-password"})
    assert resp.status_code == 200 and "httponly" in resp.headers["set-cookie"].lower()
    assert locked.get("/api/session").json()["signed_in"] is True


def test_login_is_throttled(locked):
    for _ in range(MAX_FAILURES):
        locked.post("/api/login", json={"password": "nope"})
    assert locked.post("/api/login", json={"password": "right-password"}).status_code == 429


def test_websocket_needs_the_password(locked):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with locked.websocket_connect("/ws"):
            pass


def test_cross_site_post_is_refused(web):
    give_incident(web, record())
    resp = web.post("/api/incidents/inc-1234abcd/decision", json={"action": "approve"}, headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403 and web.console.gateway.decisions == []


def test_websocket_from_another_site_is_refused(web):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with web.websocket_connect("/ws", headers={"Origin": "https://evil.example"}):
            pass


def test_websocket_replays_the_conversation_after_a_refresh(web):
    session_of(web).items.append({"id": "x", "kind": "user", "text": "hello", "ts": 0})
    with web.websocket_connect("/ws") as ws:
        hello = ws.receive_json()
    assert hello["type"] == "hello" and hello["items"][0]["text"] == "hello"


# ------------------------------------------------------------------ views

@pytest.mark.parametrize("state,phase", [
    ("STARTING", RUNNING), ("PROBING", RUNNING), ("PATCHING", RUNNING), ("AWAITING_APPROVAL", NEEDS_APPROVAL), ("EXECUTING", PUBLISHING),
    ("VERIFYING", PUBLISHING), ("RESOLVED", DONE), ("FAILED", FAILED), ("CANCELLED", CANCELLED)])
def test_phases(state, phase):
    assert phase_of(state) == phase


def test_a_new_case_has_nothing_to_show_yet():
    view = incident_view({"incident_id": "inc-1", "state": "STARTING", "repo": "acme/shop"})
    assert view["phase"] == RUNNING and view["cause"] is None and view["fix"] is None and view["security"] is None


def test_a_case_with_no_commit_still_explains_the_cause():
    view = incident_view(record(evidence={"suspect_commit_sha": "", "offending_file": "a.py", "root_cause_explanation": "Bad", "confidence": "low"}))
    assert view["cause"]["commit"] is None and view["cause"]["file"] == "a.py" and view["cause"]["certain"] is False


def test_requirements_are_only_offered_when_the_fix_changed_them():
    assert incident_view(record())["fix"]["files"] == ["src/app.py"]
    assert fixed_file(record(), 1) is None and fixed_file(record(), 0) == ("app.py", "print('fixed')\n")
    cve = {"package_name": "pyyaml", "installed_version": "5.3", "fixed_version": "5.4", "vuln_id": "GHSA-1", "severity": "CRITICAL",
           "is_reachable_in_ast": True, "summary": "bad"}
    rec = record(vuln={"cve_findings": [cve], "sast_findings": [], "total_reachable_critical": 1})
    assert incident_view(rec)["fix"]["files"] == ["src/app.py", "requirements.txt"]
    assert fixed_file(rec, 1) == ("requirements.txt", "pyyaml==5.4\n")


def test_a_rejected_fix_offers_nothing_to_download():
    rejected = {**FULL_FIX, "approved": False, "rejection_reasons": ["adds eval"]}
    rec = record(state="FAILED", result={"attestation": rejected, "attempts": 3})
    view = incident_view(rec)
    assert view["fix"]["files"] == [] and view["fix"]["reasons"] == ["adds eval"] and fixed_file(rec, 0) is None


def test_outcomes():
    assert incident_view(record(state="RESOLVED", delivery="files"))["outcome"] == {"kind": "files"}
    assert incident_view(record(state="RESOLVED", mode="security_audit"))["outcome"] == {"kind": "audit"}
    pr = {"pr_url": "https://github.com/a/b/pull/1"}
    assert incident_view(record(state="RESOLVED", remediation=pr, last_note="recovered"))["outcome"]["verified"] is True
    assert incident_view(record(state="RESOLVED", remediation=pr, last_note="pr-opened"))["outcome"]["verified"] is None
    assert incident_view(record(state="FAILED", remediation=pr, last_note="canary still failing"))["outcome"]["verified"] is False


def test_a_failure_says_what_to_do_next():
    view = incident_view(record(state="FAILED", last_note="Could not fix it", hint="Add the error message."))
    assert view["failure"] == {"message": "Could not fix it", "hint": "Add the error message."}


def test_the_view_says_how_much_was_really_checked():
    security = incident_view(record(vuln={"cve_findings": [], "sast_findings": [], "total_reachable_critical": 0,
                                          "files_scanned": 12, "dependencies_scanned": 3}))["security"]
    assert security["files"] == 12 and security["dependencies"] == 3
    empty = incident_view(record(vuln={"cve_findings": [], "sast_findings": [], "total_reachable_critical": 0}))["security"]
    assert empty["files"] == 0 and empty["dependencies"] == 0       # older records must not look scanned


def test_unmapped_code_never_counts_a_vulnerability_as_unused():
    """Regression: a JavaScript repo said its CVEs were in packages it doesn't use. Imports are only mapped for Python."""
    cve = {"package_name": "qs", "installed_version": "6.0.0", "fixed_version": "6.1.0", "vuln_id": "GHSA-2", "severity": "HIGH",
           "is_reachable_in_ast": False, "summary": "bad"}
    vuln = {"cve_findings": [cve], "sast_findings": [], "total_reachable_critical": 0, "dependencies_scanned": 1}
    unmapped = incident_view(record(vuln=vuln, evidence={"active_ast_imports": []}))["security"]
    assert unmapped["unverified"] == 1 and len(unmapped["items"]) == 1
    mapped = incident_view(record(vuln=vuln, evidence={"active_ast_imports": ["yaml"]}))["security"]
    assert mapped["unverified"] == 0 and mapped["items"] == []


def test_security_items_put_the_worst_first():
    cve = {"package_name": "pyyaml", "installed_version": "5.3", "fixed_version": "unknown", "vuln_id": "GHSA-1", "severity": "LOW",
           "is_reachable_in_ast": True, "summary": "minor"}
    sast = {"file_path": "a.py", "line_number": 3, "rule_id": "SQL_INJECTION", "severity": "HIGH", "code_snippet": "x", "remediation_advice": "Use params"}
    view = incident_view(record(vuln={"cve_findings": [cve], "sast_findings": [sast], "total_reachable_critical": 0}))
    items = view["security"]["items"]
    assert items[0]["title"] == "Sql injection" and items[1]["advice"] == "No fixed version yet"
