"""Sentinel Assistant: the LLM front door of the web console.

The LLM chats with the user and calls tools; the tools hand structured requests to Agent_1 through the gateway.
Two things are deliberately out of its reach. Approving a change is not a tool: only the user's click on the card can
authorize a GitHub write. And it cannot choose a target: a repo or URL only counts if the user actually typed it, so a
confused or prompt-injected model can neither approve anything nor point Sentinel at something else.
"""
import json
import re
from typing import Any, Dict, List, Optional, Protocol

from common.intent import extract_github_repo, extract_service_url
from common.llm_client import LLMClient, LLMError

MAX_TOOL_ROUNDS = 3
HISTORY_TURNS = 20
OWN_WORDS_TURNS = 3
MIN_REPORT_WORDS = 4    # "yes, go" is consent, not a report
MODES = ("diagnose_and_heal", "security_audit", "chaos_test")

SYSTEM_PROMPT = """You are Sentinel, an assistant that helps developers fix problems in their GitHub repositories.
A team of five agents does the work: a Manager coordinates, a Health Checker tests the live service, a Detective finds
the cause, a Security Inspector checks for vulnerabilities and tests every fix, and a Fixer writes the fix.

How to help:
- To investigate you need a GitHub repository link and a description of what is wrong. If either is missing, ask for it
  in one short sentence. Never guess or invent a repository or URL.
- A live service URL is optional, but ask for nothing extra if you already have a repository and a problem.
- As soon as you have them, call run_sentinel with mode diagnose_and_heal and the user's own words as the problem.
- For a vulnerability or security check of a repository, call run_sentinel with mode security_audit.
- Only use chaos_test if the user explicitly asks for a chaos test.
- For questions about the current case, call get_incidents and answer from that data only.
- You cannot approve or reject a change. If the user asks you to, tell them to use the buttons on the card in this chat.
- If you are asked what you can do, explain it simply. Speak plainly to someone who may be new to this.
- Be brief: 1-3 short sentences, Markdown allowed. Never invent incident details."""

TOOLS: List[Dict[str, Any]] = [
    {"type": "function", "function": {
        "name": "run_sentinel",
        "description": "Start the agents on the user's repository: diagnose and fix a reported problem, run a security audit, "
                       "or run a chaos test.",
        "parameters": {"type": "object", "properties": {
            "mode": {"type": "string", "enum": list(MODES)},
            "repo": {"type": "string", "description": "The GitHub repository link or owner/name exactly as the user gave it"},
            "problem": {"type": "string", "description": "What is wrong, in the user's own words"},
            "service_url": {"type": "string", "description": "URL of the running service, only if the user gave one"},
        }, "required": ["mode", "repo"]},
    }},
    {"type": "function", "function": {
        "name": "get_incidents",
        "description": "The current case: its stage, root cause, findings, fix and pull request link.",
        "parameters": {"type": "object", "properties": {}},
    }},
]


class Actions(Protocol):
    """What the assistant may do, bound to one user's session."""

    async def start(self, mode: str, repo: str, problem: str, service_url: str) -> Dict[str, Any]: ...

    def current(self) -> List[Dict[str, Any]]: ...


class Assistant:
    def __init__(self, llm: LLMClient, actions: Actions) -> None:
        self.llm, self.actions = llm, actions

    async def reply(self, history: List[Dict[str, str]], user_text: str) -> str:
        """One assistant turn. `history` holds earlier {"role", "content"} user/assistant turns (not mutated)."""
        recent = history[-HISTORY_TURNS:]
        messages: List[Dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT},
                                          *recent, {"role": "user", "content": user_text}]
        turns = [*(t["content"] for t in recent if t.get("role") == "user"), user_text]
        said, words = "\n".join(turns), _own_words(turns)
        try:
            for _ in range(MAX_TOOL_ROUNDS):
                message = await self.llm.complete(messages, TOOLS)
                calls = message.get("tool_calls") or []
                if not calls:
                    return (message.get("content") or "").strip() or "Could you tell me a bit more?"
                messages.append(message)  # verbatim: Gemini needs its thought signatures back
                started = None
                for call in calls:
                    result = await self.run_tool(call.get("function", {}).get("name", ""),
                                                 _arguments(call.get("function", {}).get("arguments")), said, words)
                    started = result if result.get("status") == "started" else started
                    messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": json.dumps(result)})
                if started:   # nothing left for the model to add: answer now, saving a slow round trip
                    return _started_text(started)
            return "I could not finish that. Could you rephrase it?"
        except LLMError:
            return await self._without_llm(user_text, said, words)

    async def _without_llm(self, user_text: str, said: str, words: str) -> str:
        """The agents do not need the chat model to start, so an overloaded LLM should not stop a clear request."""
        repo = extract_github_repo(user_text)
        if repo:
            result = await self.run_tool("run_sentinel", {"mode": "diagnose_and_heal", "repo": repo, "problem": user_text,
                                                          "service_url": extract_service_url(user_text) or ""}, said, words)
            if result.get("status") == "started":
                return _started_text(result)
            return str(result.get("error", "I could not start that."))
        return "The assistant is busy right now. Send your GitHub link and the problem, and I can still start the agents."

    async def run_tool(self, name: str, args: Dict[str, Any], said: str = "", words: str = "") -> Dict[str, Any]:
        """`said` is everything the user has typed: a target the model named but the user never did is refused.
        `words` is their report as they wrote it."""
        if name == "run_sentinel":
            return await self._run_sentinel(args, said, words)
        if name == "get_incidents":
            return {"incidents": self.actions.current()}
        return {"error": f"unknown tool {name!r}"}

    async def _run_sentinel(self, args: Dict[str, Any], said: str, words: str = "") -> Dict[str, Any]:
        mode = str(args.get("mode") or "")
        if mode not in MODES:
            return {"error": f"mode must be one of {list(MODES)}"}
        repo = extract_github_repo(str(args.get("repo") or ""))
        url = extract_service_url(str(args.get("service_url") or "")) or ""
        problem = str(args.get("problem") or "").strip()
        # Models invent plausible targets (seen live: http://checkout:8080). Only the user chooses what gets touched.
        if not repo or not _typed(repo, said):
            return {"error": "the user has not given a GitHub repository: ask them for the link"}
        if url and not _typed(url, said):
            url = ""
        if mode == "diagnose_and_heal" and not problem:
            return {"error": "the user has not said what is wrong: ask them"}
        if mode == "chaos_test" and not url:
            return {"error": "a chaos test needs the service URL: ask the user for it"}
        return await self.actions.start(mode, repo, _with_own_words(problem, words), url)


def _own_words(turns: List[str]) -> str:
    """The user's latest message that reads as a report. Models summarise away what the agents need most: in a live run a
    pasted traceback lost its file and line on the way through."""
    recent = turns[-OWN_WORDS_TURNS:]
    reports = [text for text in recent if len(re.sub(r"\S*[/.]\S*", "", text).split()) >= MIN_REPORT_WORDS]
    return (reports or recent or [""])[-1].strip()


def _with_own_words(problem: str, words: str) -> str:
    if not words or words in problem:
        return problem
    return f"{problem}\n\nIn the user's words:\n{words}" if problem else words


def _typed(value: Optional[str], said: str) -> bool:
    return bool(value) and str(value).lower().rstrip("/") in said.lower()


def _started_text(result: Dict[str, Any]) -> str:
    what = {"diagnose_and_heal": "Looking into", "security_audit": "Running a security check on",
            "chaos_test": "Running a chaos test on"}[result["mode"]]
    live = " I'll also test the live service." if result.get("service_url") and result["mode"] == "diagnose_and_heal" else ""
    return f"{what} `{result['repo']}`.{live} You can watch the agents work live, and I'll post the result here."


def _arguments(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}
