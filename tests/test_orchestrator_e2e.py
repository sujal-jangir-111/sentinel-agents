"""Full multi-agent lifecycle in one local Bureau: user chat (or Watchdog alert) -> Watchdog -> Agent_3 ->
Agent_4 -> Agent_5 (+ Scanner gatekeeper loop) -> incident card -> user approval.

Everything external is an offline fake: the demo target app is served through an ASGI transport, GitHub, OSV.dev
and ASI:One through tests.fakes. The swarm code itself is the real thing."""
import json
import re
from dataclasses import replace
from typing import Any, Dict, List

import httpx
import pytest

from uagents_core.contrib.protocols.payment import (
    CancelPayment, CommitPayment, CompletePayment, Funds, RejectPayment, RequestPayment,
)

from agents import Agent_3, Agent_5, Agent_1, Agent_2, Agent_4
from common.addresses import address_from_seed
from common.llm_client import ASI1Client
from common.config import Settings
from common.github_client import GitHubClient
from demo_target_app import app as demo
from tests.bureau_harness import agent_test_kwargs, free_port, run_chat_session
from tests.fakes import (
    draft_adding_a_new_finding,
    ASI1_URL, PAYER, PRICE, README_SHA, REPO, TX_GOOD, TX_UNDER, WALLET, FakeWeb, fully_fixed_app_source, fake_verifier, runtime_fixed_app_source,
    smart_llm, standard_chain,
)

SEEDS = {"orchestrator": "e2e orchestrator seed", "watchdog": "e2e watchdog seed", "detective": "e2e detective seed",
         "scanner": "e2e scanner seed", "executor": "e2e executor seed"}
ADDRESSES = {k: address_from_seed(v) for k, v in SEEDS.items()}
SETTINGS = replace(Settings(), demo_repo_full_name=REPO, demo_service_url="http://demo", skip_payment=True, patch_max_attempts=3,
                   traffic_rpm=120, avg_order_value_usd=40, conversion_rate=0.03, sla_target=0.999)
PAY_SETTINGS = replace(SETTINGS, skip_payment=False, orchestrator_wallet_address=WALLET, remediation_price_atestfet=PRICE)
HEAL = f"Diagnose and heal the outage on http://demo for repo {REPO}"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DEMO_ADMIN_TOKEN", "e2e-token")
    demo.PATCHED = False
    yield
    demo.PATCHED = False


def swarm_factory(web: FakeWeb, handles: Dict[str, Any], verifier=None, exec_token: str = "e2e-token"):
    async def make_swarm(port: int):
        demo_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=demo.app, raise_app_exceptions=False), base_url="http://demo")
        exec_cfg = replace(PAY_SETTINGS if verifier else SETTINGS, demo_admin_token=exec_token, skip_payment=verifier is None)
        watchdog = Agent_2.Watchdog(http=demo_http, admin_token="", orchestrator_address=ADDRESSES["orchestrator"], targets=[])
        handles["watchdog"] = watchdog
        scanner_http = web.client()
        det_http = web.client()
        exec_http = web.client()
        orch_http = web.client()
        kw = lambda: dict(port=free_port(), **agent_test_kwargs())  # noqa: E731
        agents = [
            Agent_2.create_agent(seed=SEEDS["watchdog"], watchdog=watchdog, **kw()),
            Agent_3.create_agent(seed=SEEDS["detective"], detective=Agent_3.CommitDetective(
                gh=GitHubClient(det_http, token="t", write_allowlist=[]), llm=ASI1Client(det_http, api_key="k", base_url=ASI1_URL)), **kw()),
            Agent_4.create_agent(seed=SEEDS["scanner"], scanner=Agent_4.VulnScanner(
                gh=GitHubClient(scanner_http, token="t", write_allowlist=[]), http=scanner_http), **kw()),
            Agent_5.create_agent(seed=SEEDS["executor"], executor=Agent_5.RemediationExecutor(
                gh=GitHubClient(exec_http, token="t", write_allowlist=[REPO]), llm=ASI1Client(exec_http, api_key="k", base_url=ASI1_URL),
                scanner_address=ADDRESSES["scanner"], max_attempts=3, orchestrator_address=ADDRESSES["orchestrator"],
                verifier=verifier, settings=exec_cfg, webhook_http=demo_http), **kw()),
        ]
        orchestrator = Agent_1.create_agent(
            seed=SEEDS["orchestrator"], port=port, **agent_test_kwargs(),
            orchestrator=Agent_1.Orchestrator(
                addresses={k: v for k, v in ADDRESSES.items() if k != "orchestrator"},
                llm=ASI1Client(orch_http, api_key="k", base_url=ASI1_URL), skip_payment=verifier is None,
                settings=SETTINGS if verifier is None else PAY_SETTINGS, verifier=verifier))
        return orchestrator, agents

    return make_swarm


def approve_when_card_arrives():
    answered: List[bool] = []

    def respond(texts: List[str]):
        if not answered and any("Reply **approve**" in t for t in texts):
            answered.append(True)
            return "approve"
        return None

    return respond


def order_of(texts: List[str], *needles: str) -> List[int]:
    """Index of the first message containing each needle (asserts they all exist)."""
    found = []
    for needle in needles:
        idx = next((i for i, t in enumerate(texts) if needle in t), None)
        assert idx is not None, f"{needle!r} never appeared in:\n" + "\n---\n".join(texts)
        found.append(idx)
    return found


def test_chat_to_approval_with_a_rejected_then_fixed_patch():
    web = FakeWeb()
    # attempt 1 introduces eval() -> the real gatekeeper rejects it; attempt 2 is clean
    web.llm = smart_llm([draft_adding_a_new_finding(), fully_fixed_app_source()])
    texts = run_chat_session(swarm_factory(web, {}), HEAL, approve_when_card_arrives(),
                             lambda t: any("Change authorized" in m for m in t), timeout=120)

    idx = order_of(texts, "Probing http://demo", "returning **HTTP 500**", "Commit [`c0ffee1`]", "CVE(s)", "Drafting a fix",
                   "Sentinel Incident", "Change authorized")
    assert idx == sorted(idx)                                                            # progress arrives in pipeline order
    assert "3/6 probes failing" in texts[idx[1]]                                         # real burst: 3 failing of 6 probes
    assert "2 reachable, 1 reachable CRITICAL" in texts[idx[3]]                          # pyyaml reachable via the AST map
    card = texts[idx[5]]
    for needle in ("What broke", "`/api/checkout` → HTTP 500", "Require discount_rate in pricing config", "CRITICAL_EXPLOITABLE",
                   "HARDCODED_SECRET", "Blast score", "$4,320", "attempt 2/3", "Approved by **Agent_4**", "```diff",
                   "`pyyaml` 5.3 → **5.4**", "Reply **approve**"):
        assert needle in card, needle
    assert re.search(r"attestation `[0-9a-f]{16}…`", card)                              # real sha256 from the real scanner
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in "\n".join(texts)                      # the secret never reaches the user
    assert "OPEN_PR_AND_HOTFIX" in texts[idx[6]]


def test_watchdog_alert_flows_through_the_swarm_to_the_user():
    web = FakeWeb()
    web.llm = smart_llm([fully_fixed_app_source()])
    handles: Dict[str, Any] = {}
    armed: List[bool] = []
    approve = approve_when_card_arrives()

    def respond(texts: List[str]):
        if not armed:                                   # the user has said hello; now let the Watchdog's poll find the outage
            armed.append(True)
            handles["watchdog"].targets.append("http://demo")
            return None
        return approve(texts)

    # poll every second instead of every minute (read when the Watchdog agent is created)
    import os
    os.environ["WATCHDOG_INTERVAL_SECONDS"] = "1"
    try:
        texts = run_chat_session(swarm_factory(web, handles), "hello", respond,
                                 lambda t: any("Change authorized" in m for m in t), timeout=120)
    finally:
        os.environ.pop("WATCHDOG_INTERVAL_SECONDS", None)

    idx = order_of(texts, "Sentinel — autonomous DevSecOps swarm", "Agent_2 alert", "Commit [`c0ffee1`]",
                   "Sentinel Incident", "Change authorized")
    assert idx == sorted(idx)
    assert re.search(r"incident `auto-[0-9a-f]{8}`", texts[idx[1]])
    assert "attempt 1/3" in texts[idx[3]]


def test_security_audit_over_chat_is_read_only():
    web = FakeWeb()                                    # no LLM answers: the Detective falls back to its deterministic summary
    texts = run_chat_session(swarm_factory(web, {}), f"Run a security audit of {REPO}", lambda t: None,
                             lambda t: any("Security Audit" in m for m in t), timeout=90)
    report = texts[-1]
    assert "Security Audit" in report and "2 reachable, 1 reachable CRITICAL" in report
    for needle in ("CRITICAL_EXPLOITABLE", "LATENT_DEPENDENCY", "HARDCODED_SECRET", "UNSAFE_DESERIALIZATION", "SQL_INJECTION", "read-only"):
        assert needle in report, needle
    assert not any("Drafting a fix" in t or "Reply **approve**" in t for t in texts)      # no patch, no approval prompt
    assert web.count("api.asi1.ai") >= 1 and not [r for r in web.requests if r.method in ("PUT", "POST") and r.url.host == "api.github.com"]


def test_gatekeeper_failure_reaches_the_user_with_a_rollback_offer():
    web = FakeWeb()
    web.llm = smart_llm([draft_adding_a_new_finding()] * 3)          # never fixes the SQL injection -> 3 rejections
    answered: List[bool] = []

    def respond(texts: List[str]):
        if not answered and any("Reply **rollback**" in t for t in texts):
            answered.append(True)
            return "rollback"
        return None

    texts = run_chat_session(swarm_factory(web, {}), HEAL, respond, lambda t: any("Change authorized" in m for m in t), timeout=120)
    card = next(t for t in texts if "Sentinel Incident" in t)
    assert "No safe patch after 3 attempt(s)" in card and "UNSAFE_EVAL" in card and "Reply **rollback**" in card
    assert "ROLLBACK_COMMIT" in texts[-1]


# ------------------------------------------------------------------ Step 9: payment protocol over the real swarm

def commit_for(request: RequestPayment, tx: str) -> CommitPayment:
    return CommitPayment(funds=request.accepted_funds[0], recipient=request.recipient, transaction_id=tx, reference=request.reference)


def run_paid_session(on_payment, done, chain=None, timeout=120):
    web = FakeWeb()
    web.llm = smart_llm([fully_fixed_app_source()])
    inbox: List[Any] = []
    verifier = fake_verifier(chain or standard_chain())
    texts = run_chat_session(swarm_factory(web, {}, verifier=verifier), HEAL, lambda t: None, done, timeout=timeout,
                             on_payment=on_payment, inbox=inbox)
    return texts, inbox


def test_valid_payment_is_verified_completed_and_authorizes_the_change():
    texts, inbox = run_paid_session(lambda req: commit_for(req, TX_GOOD), lambda t: any("Change authorized" in m for m in t))
    requests = [m for m in inbox if isinstance(m, RequestPayment)]
    assert len(requests) == 1 and requests[0].recipient == WALLET and requests[0].reference.startswith("inc-")
    assert requests[0].accepted_funds == [Funds(amount=str(PRICE), currency="atestfet", payment_method="fet_direct")]
    completes = [m for m in inbox if isinstance(m, CompletePayment)]
    assert [c.transaction_id for c in completes] == [TX_GOOD] and not [m for m in inbox if isinstance(m, CancelPayment)]
    idx = order_of(texts, "Sentinel Incident", "Payment verified", "Change authorized")
    assert idx == sorted(idx)
    assert "paying **0.1 FET**" in texts[idx[0]] and f"/{TX_GOOD}" in texts[idx[1]]


def test_underpaid_transaction_is_refused_then_a_correct_payment_succeeds():
    attempts = iter([TX_UNDER, TX_GOOD])
    texts, inbox = run_paid_session(lambda req: commit_for(req, next(attempts)), lambda t: any("Change authorized" in m for m in t))
    kinds = [type(m).__name__ for m in inbox]
    assert kinds == ["RequestPayment", "CancelPayment", "RequestPayment", "CompletePayment"]
    cancel = next(m for m in inbox if isinstance(m, CancelPayment))
    assert "Underpaid" in cancel.reason and cancel.transaction_id == TX_UNDER
    refusal = next(t for t in texts if "Payment not accepted" in t)
    assert "Nothing was authorized" in refusal
    assert order_of(texts, "Payment not accepted", "Payment verified", "Change authorized") == sorted(order_of(texts, "Payment not accepted", "Payment verified", "Change authorized"))


def test_user_declining_the_payment_cancels_the_incident_without_any_change():
    texts, inbox = run_paid_session(lambda req: RejectPayment(reason="not now"), lambda t: any("Payment declined" in m for m in t))
    assert "cancelled" in texts[-1] and "No changes were made" in texts[-1]
    assert not [m for m in inbox if isinstance(m, CompletePayment)] and not any("Change authorized" in t for t in texts)


def test_wrong_recipient_never_authorizes_and_ends_after_repeated_failures():
    from tests.fakes import FakeChain, TX_OTHER, make_tx
    chain = FakeChain(make_tx(TX_OTHER, recipient="fetch1someoneelse0000000000000000000000000"))
    texts, inbox = run_paid_session(lambda req: commit_for(req, TX_OTHER), lambda t: any("Too many failed payments" in m for m in t), chain=chain)
    assert not any("Change authorized" in t for t in texts) and not [m for m in inbox if isinstance(m, CompletePayment)]
    assert sum(isinstance(m, CancelPayment) for m in inbox) == 3


# ------------------------------------------------------------------ Step 10: execution, hotfix and canary over the real swarm

RESOLVED = lambda t: any("RESOLVED" in m for m in t)  # noqa: E731
STOPPED = lambda t: any("stopped" in m or "still failing" in m for m in t)  # noqa: E731


def lifecycle(web, done, **swarm_kw):
    handles: Dict[str, Any] = {}
    return run_chat_session(swarm_factory(web, handles, **swarm_kw), HEAL, approve_when_card_arrives(), done, timeout=150)


def fix_branch_files(web):
    (branch,) = [b for b in web.github.branch_files]
    return branch, web.github.branch_files[branch]


def test_full_lifecycle_chat_to_resolved_without_payment():
    web = FakeWeb()
    web.llm = smart_llm([draft_adding_a_new_finding(), fully_fixed_app_source()])
    assert demo.PATCHED is False
    texts = lifecycle(web, RESOLVED)
    idx = order_of(texts, "returning **HTTP 500**", "Sentinel Incident", "Change authorized", "Pull request opened", "canary probe", "RESOLVED")
    assert idx == sorted(idx)
    final = texts[-1]
    for needle in ("`/api/checkout` HTTP 500 → HTTP 200", "3/6", "0/6", "pull/1", "sbom.cdx.json", "none (payment skipped, dev mode)", "✅ triggered"):
        assert needle in final, needle
    assert demo.PATCHED is True                                                          # the real demo app was hot-fixed
    branch, files = fix_branch_files(web)
    assert re.fullmatch(r"sentinel/fix-inc-[0-9a-f]{8}", branch) and set(files) == {"app.py", "requirements.txt", "sbom.cdx.json"}
    assert "pyyaml==5.4" in files["requirements.txt"] and "sk_test_51SENTINELDEMOxxxxxxxx" not in files["app.py"]
    assert json.loads(files["sbom.cdx.json"])["specVersion"] == "1.5"
    (pull,) = web.github.pulls
    assert pull["head"] == branch and pull["base"] == "main" and "Change-Control Audit Trail" in pull["body"]
    assert all(not (m == "PUT" and b["branch"] == "main") for m, _, b in web.github.writes)
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in "\n".join(texts)


def test_full_lifecycle_with_dorado_payment_ends_resolved_with_the_tx_in_pr_and_chat():
    web = FakeWeb()
    web.llm = smart_llm([fully_fixed_app_source()])
    inbox: List[Any] = []
    texts = run_chat_session(swarm_factory(web, {}, verifier=fake_verifier(standard_chain())), HEAL, lambda t: None, RESOLVED, timeout=150,
                             on_payment=lambda req: commit_for(req, TX_GOOD), inbox=inbox)
    final = texts[-1]
    assert f"explore-dorado.fetch.ai/transactions/{TX_GOOD}" in final and "0.1 FET" in final and "HTTP 500 → HTTP 200" in final
    order_of(texts, "Payment verified", "Change authorized", "Pull request opened", "RESOLVED")
    assert [type(m).__name__ for m in inbox] == ["RequestPayment", "CompletePayment"]
    (pull,) = web.github.pulls
    assert f"[`{TX_GOOD}`]" in pull["body"] and PAYER in pull["body"] and demo.PATCHED is True


def test_rollback_lifecycle_restores_the_previous_file_and_recovers():
    web = FakeWeb()
    web.llm = smart_llm([draft_adding_a_new_finding()] * 3)                                  # never fixes the SQL injection
    web.github.ref_files[(README_SHA, "app.py")] = runtime_fixed_app_source()              # the file before the suspect commit
    answered: List[bool] = []

    def respond(texts: List[str]):
        if not answered and any("Reply **rollback**" in t for t in texts):
            answered.append(True)
            return "rollback"
        return None

    texts = run_chat_session(swarm_factory(web, {}), HEAL, respond, RESOLVED, timeout=150)
    assert "Rollback pull request" in texts[-1] and "n/a (rollback)" in texts[-1] and "HTTP 500 → HTTP 200" in texts[-1]
    branch, files = fix_branch_files(web)
    assert files["app.py"] == runtime_fixed_app_source() and set(files) == {"app.py", "sbom.cdx.json"}
    assert "roll" in web.github.pulls[0]["title"].lower() and demo.PATCHED is True


def test_github_outage_during_execution_is_reported_and_nothing_is_changed(monkeypatch):
    async def instant(_):
        return None

    monkeypatch.setattr("common.http_retry._sleep", instant)
    web = FakeWeb()
    web.llm = smart_llm([fully_fixed_app_source()])
    web.github.fail_write_status = 503
    texts = lifecycle(web, STOPPED)
    msg = texts[-1]
    assert "stopped" in msg and "Agent_5" in msg and "Nothing was merged" in msg
    assert web.github.pulls == [] and demo.PATCHED is False                                # no PR, no hotfix
    assert not any("RESOLVED" in t for t in texts)


def test_rejected_hotfix_token_leaves_the_pr_open_but_the_service_unhealthy():
    web = FakeWeb()
    web.llm = smart_llm([fully_fixed_app_source()])
    texts = lifecycle(web, STOPPED, exec_token="wrong-token")
    final = texts[-1]
    assert "still failing" in final and "not triggered" in final and "RESOLVED" not in final and "pull/1" in final
    assert len(web.github.pulls) == 1 and demo.PATCHED is False
