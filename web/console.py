"""Per-user state of the web console.

Each browser is a session with its own conversation and its own incidents. The console creates every incident id, so
it always knows which session owns an update, and nobody sees another user's repository, results or approval card.
"""
import asyncio
import json
import re
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

import httpx
from fastapi import WebSocket

from common.agent_factory import LOCAL_PORTS
from common.config import get_settings
from common.github_client import GitHubClient, GitHubError
from common.models import AgentActivity, IncidentRequest, IncidentUpdate
from common.url_safety import same_host, target_problem
from web.auth import OperatorAuth, is_loopback
from web.gateway import Gateway
from web.views import OPEN_PHASES, incident_view, phase_of

SESSION_TTL_SECONDS = 24 * 60 * 60
MAX_ITEMS = 200
HEALTH_SECONDS = 5.0
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_PATH_RE = re.compile(r"(?<![\w/:.-])/[A-Za-z0-9_][\w\-./]*")


class Session:
    def __init__(self, session_id: str) -> None:
        self.id = session_id
        self.sockets: Set[WebSocket] = set()
        self.items: List[Dict[str, Any]] = []      # the conversation: user, assistant and incident items
        self.history: List[Dict[str, str]] = []    # what the assistant LLM sees
        self.incident_id: Optional[str] = None     # the current case
        self.activity: List[Dict[str, Any]] = []   # live agent events of the current case
        self.typing = False
        self.seen = time.time()
        self.lock = asyncio.Lock()                 # one assistant turn at a time


def split_service_url(url: str, problem: str) -> Tuple[str, List[str]]:
    """(base URL, paths to probe). A path in the URL or the problem text is probed; otherwise just the home page."""
    parts = urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"
    paths = [parts.path] if parts.path not in ("", "/") else []
    paths += _PATH_RE.findall(_URL_RE.sub(" ", problem))
    return base, list(dict.fromkeys(p.rstrip(".,;:") for p in paths))[:5] or ["/"]


class Console:
    def __init__(self, password: str = "", host: str = "127.0.0.1") -> None:
        self.auth = OperatorAuth(password)
        self.allow_private_targets = is_loopback(host)
        self.sessions: Dict[str, Session] = {}
        self.owners: Dict[str, str] = {}                # incident id -> session id
        self.records: Dict[str, Dict[str, Any]] = {}    # incident id -> Agent_1's latest record
        self.agents_online = False
        self.gateway: Optional[Gateway] = None
        self.gh: Optional[GitHubClient] = None
        self.http: Optional[httpx.AsyncClient] = None

    # -- sessions ------------------------------------------------------------------------------------

    @staticmethod
    def new_session_id() -> str:
        return secrets.token_urlsafe(32)

    def session(self, session_id: str) -> Session:
        current = self.sessions.get(session_id)
        if current is None:
            current = self.sessions[session_id] = Session(session_id)
        current.seen = time.time()
        return current

    def forget_idle_sessions(self) -> None:
        cutoff = time.time() - SESSION_TTL_SECONDS
        for session_id, s in list(self.sessions.items()):
            if s.seen < cutoff and not s.sockets:
                del self.sessions[session_id]
                for incident_id in [i for i, owner in self.owners.items() if owner == session_id]:
                    del self.owners[incident_id]
                    self.records.pop(incident_id, None)

    def reset(self, session: Session) -> None:
        session.items, session.history, session.activity, session.incident_id = [], [], [], None

    def owned_record(self, session: Session, incident_id: str) -> Optional[Dict[str, Any]]:
        return self.records.get(incident_id) if self.owners.get(incident_id) == session.id else None

    def hello(self, session: Session) -> Dict[str, Any]:
        return {"type": "hello", "items": session.items, "activity": session.activity, "agents_online": self.agents_online,
                "incident_id": session.incident_id, "typing": session.typing}

    # -- talking to browsers ---------------------------------------------------------------------------

    @staticmethod
    async def send(session: Session, event: Dict[str, Any]) -> None:
        data = json.dumps(event)
        for ws in list(session.sockets):
            try:
                await ws.send_text(data)
            except Exception:
                session.sockets.discard(ws)

    async def push_item(self, session: Session, item: Dict[str, Any]) -> None:
        """Add an item to the conversation, or replace the one with the same id (a card that changed state)."""
        for i, existing in enumerate(session.items):
            if existing["id"] == item["id"]:
                session.items[i] = item
                break
        else:
            session.items.append(item)
            del session.items[:-MAX_ITEMS]
        await self.send(session, {"type": "item", "item": item})

    async def say(self, session: Session, role: str, text: str) -> None:
        await self.push_item(session, {"id": uuid.uuid4().hex, "kind": role, "text": text, "ts": time.time()})

    async def set_typing(self, session: Session, typing: bool) -> None:
        session.typing = typing
        await self.send(session, {"type": "typing", "typing": typing})

    # -- from the agents ------------------------------------------------------------------------------

    async def on_update(self, update: IncidentUpdate) -> None:
        owner = self.sessions.get(self.owners.get(update.incident_id, ""))
        if owner is None:
            return
        record = json.loads(update.record_json)
        self.records[update.incident_id] = record
        await self.push_item(owner, self.incident_item(record))

    async def on_activity(self, msg: AgentActivity) -> None:
        owner = self.sessions.get(self.owners.get(msg.incident_id, ""))
        if owner is None or owner.incident_id != msg.incident_id:
            return
        event = {"agent": msg.agent, "status": msg.status, "text": msg.text, "ts": time.time()}
        owner.activity.append(event)
        await self.send(owner, {"type": "activity", "event": event})

    @staticmethod
    def incident_item(record: Dict[str, Any]) -> Dict[str, Any]:
        return {"id": record["incident_id"], "kind": "incident", "incident": incident_view(record), "ts": time.time()}

    # -- what the assistant may do ----------------------------------------------------------------------

    def is_busy(self, session: Session) -> bool:
        record = self.records.get(session.incident_id or "")
        return bool(record) and phase_of(record.get("state", "")) in OPEN_PHASES

    async def start(self, session: Session, mode: str, repo: str, problem: str, service_url: str) -> Dict[str, Any]:
        """Validate a request and hand it to Agent_1. Anything wrong comes back as a message for the user."""
        if self.is_busy(session):
            return {"error": "the current case is still open: finish it first, or start a new chat"}
        assert self.gh is not None and self.gateway is not None
        try:
            meta = await self.gh.get_repo(repo)
        except GitHubError:
            return {"error": "GitHub could not be reached just now, so please try again in a moment"}
        if meta is None or meta["private"] and meta["full_name"].lower() not in get_settings().writable_repos:
            return {"error": f"I can't open {repo}. Check the link. Right now I can only read public repositories."}
        base, endpoints = "", []
        if service_url:
            demo = get_settings().demo_service_url
            refused = await asyncio.to_thread(target_problem, service_url, self.allow_private_targets, demo)
            if refused:
                return {"error": refused}
            if mode == "chaos_test" and not (demo and same_host(service_url, demo)):
                return {"error": "chaos tests only run against the bundled demo service, so that I never break a real one"}
            base, endpoints = split_service_url(service_url, problem)
            if mode == "chaos_test":
                endpoints = []            # the demo service's own default endpoints
        incident_id = "inc-" + uuid.uuid4().hex[:8]
        self.owners[incident_id] = session.id
        session.incident_id, session.activity = incident_id, []
        record = {"incident_id": incident_id, "state": "STARTING", "mode": mode, "repo": meta["full_name"],
                  "branch": meta["default_branch"], "service_url": base}
        self.records[incident_id] = record
        await self.send(session, {"type": "new_case", "incident_id": incident_id})
        self.gateway.send_request(IncidentRequest(      # its card appears with Agent_1's first update, after the assistant's reply
            incident_id=incident_id, mode=mode, repo_full_name=meta["full_name"], branch=meta["default_branch"],
            problem=problem, service_url=base, endpoints=endpoints))
        return {"status": "started", "mode": mode, "repo": meta["full_name"], "service_url": base or None,
                "note": "The agents are working on it."}

    def current(self, session: Session) -> List[Dict[str, Any]]:
        """The current case as data for the LLM: no code, and nothing from any other session."""
        record = self.records.get(session.incident_id or "")
        if not record:
            return []
        view = incident_view(record)
        fix = view.get("fix") or {}
        return [{k: v for k, v in {
            "phase": view["phase"], "repo": view["repo"], "cause": view["cause"], "service": view["service"],
            "security": {k2: v2 for k2, v2 in (view["security"] or {}).items() if k2 != "items"},
            "fix": {"approved": fix.get("approved"), "file": fix.get("file"), "explanation": fix.get("explanation")} if fix else None,
            "outcome": view["outcome"], "failure": view.get("failure"),
        }.items() if v}]

    # -- agent health -------------------------------------------------------------------------------------

    async def check_agents(self) -> None:
        assert self.http is not None
        async def up(port: int) -> bool:
            try:
                await self.http.get(f"http://127.0.0.1:{port}/", timeout=2)   # type: ignore[union-attr]
                return True
            except httpx.HTTPError:
                return False
        online = all(await asyncio.gather(*(up(p) for p in LOCAL_PORTS.values())))
        if online != self.agents_online:
            self.agents_online = online
            for session in list(self.sessions.values()):
                await self.send(session, {"type": "status", "agents_online": online})

    async def watch_agents(self) -> None:
        while True:
            try:
                await self.check_agents()
                self.forget_idle_sessions()
            except Exception:
                pass
            await asyncio.sleep(HEALTH_SECONDS)


class SessionActions:
    """The assistant's tools, bound to one session (implements web.assistant.Actions)."""

    def __init__(self, console: Console, session: Session) -> None:
        self.console, self.session = console, session

    async def start(self, mode: str, repo: str, problem: str, service_url: str) -> Dict[str, Any]:
        return await self.console.start(self.session, mode, repo, problem, service_url)

    def current(self) -> List[Dict[str, Any]]:
        return self.console.current(self.session)
