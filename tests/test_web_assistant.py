"""The assistant: tool routing, and the rules that keep the LLM from approving anything or choosing a target."""
import json
from typing import Any, Dict, List, Tuple

from common.intent import extract_github_repo
from common.llm_client import LLMError
from web.assistant import MODES, TOOLS, Assistant, _started_text


class ScriptedLLM:
    """Returns queued assistant messages and records what it was sent."""

    def __init__(self, *replies: Any) -> None:
        self.replies, self.calls = list(replies), []

    async def complete(self, messages: List[Dict[str, Any]], tools=None) -> Dict[str, Any]:
        self.calls.append([dict(m) for m in messages])
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class FakeActions:
    def __init__(self, error: str = "") -> None:
        self.started: List[Tuple[str, str, str, str]] = []
        self.error = error

    async def start(self, mode: str, repo: str, problem: str, service_url: str) -> Dict[str, Any]:
        if self.error:
            return {"error": self.error}
        self.started.append((mode, repo, problem, service_url))
        return {"status": "started", "mode": mode, "repo": repo, "service_url": service_url or None}

    def current(self) -> List[Dict[str, Any]]:
        return [{"phase": "needs_approval", "cause": {"summary": "KeyError at app.py:90"}}]


def tool_call(name: str, **args: Any) -> Dict[str, Any]:
    return {"role": "assistant", "content": None,
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


def text(content: str) -> Dict[str, Any]:
    return {"role": "assistant", "content": content}


async def test_plain_answer_without_tools():
    actions = FakeActions()
    llm = ScriptedLLM(text("Please share your GitHub link."))
    assert await Assistant(llm, actions).reply([], "my app is broken") == "Please share your GitHub link."
    assert actions.started == [] and llm.calls[0][0]["role"] == "system"


async def test_a_github_link_and_a_problem_start_the_agents_on_that_repo():
    actions = FakeActions()
    llm = ScriptedLLM(tool_call("run_sentinel", mode="diagnose_and_heal", repo="https://github.com/acme/shop.git", problem="checkout crashes"))
    said = "checkout crashes, see https://github.com/acme/shop.git"
    answer = await Assistant(llm, actions).reply([], said)
    assert actions.started == [("diagnose_and_heal", "acme/shop", f"checkout crashes\n\nIn the user's words:\n{said}", "")]
    assert "acme/shop" in answer and len(llm.calls) == 1        # a started run needs no second, slow model round trip


async def test_there_are_no_default_targets():
    """A new user's request must never fall back to the operator's own repository."""
    actions = FakeActions()
    out = await Assistant(ScriptedLLM(), actions).run_tool("run_sentinel", {"mode": "diagnose_and_heal", "problem": "it broke"}, "it broke")
    assert "error" in out and actions.started == []


async def test_a_target_the_user_never_typed_is_refused():
    """Regression: Gemini invented http://checkout:8080 live. The model must not pick what gets touched."""
    actions = FakeActions()
    assistant = Assistant(ScriptedLLM(), actions)
    invented_repo = {"mode": "diagnose_and_heal", "repo": "evil/repo", "problem": "broken"}
    assert "error" in await assistant.run_tool("run_sentinel", invented_repo, "checkout is broken")
    invented_url = {"mode": "diagnose_and_heal", "repo": "acme/shop", "problem": "broken", "service_url": "http://checkout:8080"}
    out = await assistant.run_tool("run_sentinel", invented_url, "acme/shop is broken")
    assert out["status"] == "started" and actions.started == [("diagnose_and_heal", "acme/shop", "broken", "")]


async def test_targets_typed_earlier_in_the_conversation_count():
    actions = FakeActions()
    llm = ScriptedLLM(tool_call("run_sentinel", mode="diagnose_and_heal", repo="acme/shop", problem="500s", service_url="https://shop.example"))
    await Assistant(llm, actions).reply([{"role": "user", "content": "It runs at https://shop.example, repo acme/shop"}], "yes, go")
    assert actions.started[0][1] == "acme/shop" and actions.started[0][3] == "https://shop.example"
    assert actions.started[0][2].startswith("500s\n\nIn the user's words:\n")


async def test_a_problem_is_required_but_an_audit_does_not_need_one():
    actions = FakeActions()
    assistant = Assistant(ScriptedLLM(), actions)
    assert "error" in await assistant.run_tool("run_sentinel", {"mode": "diagnose_and_heal", "repo": "acme/shop"}, "acme/shop")
    out = await assistant.run_tool("run_sentinel", {"mode": "security_audit", "repo": "acme/shop"}, "audit acme/shop")
    assert out["status"] == "started"


async def test_a_refusal_goes_back_to_the_model_so_it_can_explain():
    llm = ScriptedLLM(tool_call("run_sentinel", mode="security_audit", repo="acme/shop"), text("I can't open that repository."))
    answer = await Assistant(llm, FakeActions(error="I can't open acme/shop")).reply([], "check acme/shop")
    assert answer == "I can't open that repository." and "can't open" in llm.calls[1][-1]["content"]


async def test_the_llm_has_no_way_to_approve_a_change():
    assert {t["function"]["name"] for t in TOOLS} == {"run_sentinel", "get_incidents"}
    assert "error" in await Assistant(ScriptedLLM(), FakeActions()).run_tool("approve", {"incident_id": "inc-1234abcd"})


async def test_status_questions_are_answered_from_the_case_data():
    llm = ScriptedLLM(tool_call("get_incidents"), text("It's waiting for your approval."))
    assert "waiting" in await Assistant(llm, FakeActions()).reply([], "what's happening?")
    assert "KeyError" in llm.calls[1][-1]["content"]


async def test_an_llm_outage_does_not_stop_a_clear_request():
    actions = FakeActions()
    said = "checkout crashes https://github.com/acme/shop"
    answer = await Assistant(ScriptedLLM(LLMError("HTTP 503")), actions).reply([], said)
    assert actions.started == [("diagnose_and_heal", "acme/shop", said, "")] and "acme/shop" in answer


async def test_an_llm_outage_without_a_repo_asks_for_one():
    answer = await Assistant(ScriptedLLM(LLMError("HTTP 503")), FakeActions()).reply([], "hello")
    assert "GitHub link" in answer


async def test_tool_loop_is_bounded():
    llm = ScriptedLLM(*[tool_call("get_incidents") for _ in range(5)])
    assert "could not finish" in await Assistant(llm, FakeActions()).reply([], "loop forever")
    assert len(llm.calls) == 3


def test_every_mode_has_a_friendly_message():
    for mode in MODES:
        assert "acme/shop" in _started_text({"mode": mode, "repo": "acme/shop"})


def test_github_links_in_every_form_people_paste_them():
    for link in ("https://github.com/acme/shop", "https://github.com/acme/shop.git", "http://www.github.com/acme/shop/issues/3",
                 "git@github.com:acme/shop.git", "github.com/acme/shop", "see https://github.com/acme/shop.", "acme/shop"):
        assert extract_github_repo(link) == "acme/shop", link
    assert extract_github_repo("my app is broken") is None
