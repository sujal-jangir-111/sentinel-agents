"""Sentinel web console backend.

    python -m web.server            # http://127.0.0.1:8080  (API + WebSocket; also serves frontend/dist if built)

Browser <-WebSocket-> this server -> assistant LLM (tools) -> gateway agent -> Agent_1 -> Agents 2-5.
The five agents must run in local mode (AGENT_MAILBOX=false) so they can reach the gateway.

Every browser is its own session (web/console.py). When CONSOLE_PASSWORD is set the whole console needs it, and the
server refuses to listen beyond loopback without one (web/auth.py).
"""
import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import uvicorn
from fastapi import Cookie, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from common.config import get_settings
from common.github_client import GitHubClient
from common.intent import _INCIDENT_RE
from common.llm_client import LLMClient
from common.logging import configure_console_utf8
from web.assistant import Assistant
from web.auth import COOKIE_NAME, SESSION_SECONDS, exposure_error, same_origin
from web.console import Console, Session, SessionActions
from web.gateway import Gateway
from web.views import NEEDS_APPROVAL, fixed_file, phase_of

PORT = int(os.getenv("WEB_PORT") or os.getenv("PORT") or 8080)   # most hosts inject PORT
HOST = os.getenv("WEB_HOST", "127.0.0.1")
SESSION_COOKIE = "sentinel_session"
SESSION_COOKIE_SECONDS = 7 * 24 * 60 * 60
MAX_MESSAGE_CHARS = 4000
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
DECISIONS = {"approve", "reject"}

console = Console(os.getenv("CONSOLE_PASSWORD", "").strip(), HOST)
llm: Optional[LLMClient] = None


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    global llm
    cfg = get_settings()
    console.http = httpx.AsyncClient()
    console.gh = GitHubClient(console.http)
    console.gateway = Gateway(console.on_update, console.on_activity, loop=asyncio.get_running_loop())
    llm = LLMClient(console.http, model=cfg.llm_assistant_model)
    tasks = [asyncio.create_task(console.gateway.agent.run_async()), asyncio.create_task(console.watch_agents())]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await console.http.aclose()


app = FastAPI(title="Sentinel", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"], allow_credentials=True)


@app.middleware("http")
async def block_cross_site_writes(request: Request, call_next):
    if request.method not in ("GET", "HEAD", "OPTIONS") and not same_origin(request.headers):
        return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
    return await call_next(request)


class Decision(BaseModel):
    action: str


class Login(BaseModel):
    password: str


def is_secure(request: Request) -> bool:
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def require_session(request: Request) -> Session:
    """The caller's session, if they are allowed to use the console at all."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if not console.auth.is_operator(request.cookies.get(COOKIE_NAME)):
        raise HTTPException(401, "Please sign in first")
    if not session_id:
        raise HTTPException(400, "No session: reload the page")
    return console.session(session_id)


@app.get("/api/health")
async def health() -> Dict[str, Any]:
    # The commit Render built, so a redeploy can be confirmed from outside (pushes don't always redeploy)
    return {"ok": True, "agents_online": console.agents_online, "assistant_model": get_settings().llm_assistant_model,
            "version": os.getenv("RENDER_GIT_COMMIT", "")[:7]}


@app.get("/api/session")
async def session_info(request: Request, response: Response) -> Dict[str, bool]:
    """First call of every page load: hands out the session cookie the WebSocket then identifies itself with."""
    if not request.cookies.get(SESSION_COOKIE):
        response.set_cookie(SESSION_COOKIE, console.new_session_id(), max_age=SESSION_COOKIE_SECONDS, httponly=True,
                            samesite="lax", secure=is_secure(request))
    return {"auth_required": console.auth.required, "signed_in": console.auth.is_operator(request.cookies.get(COOKIE_NAME))}


@app.post("/api/login")
async def login(body: Login, request: Request, response: Response) -> Dict[str, bool]:
    if console.auth.locked:
        raise HTTPException(429, "Too many failed attempts. Try again in a minute.")
    token = console.auth.login(body.password)
    if token is None:
        await asyncio.sleep(0.5)
        raise HTTPException(401, "Wrong password")
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_SECONDS, httponly=True, samesite="strict", secure=is_secure(request))
    return {"signed_in": True}


@app.post("/api/reset")
async def new_chat(request: Request) -> Dict[str, bool]:
    session = require_session(request)
    console.reset(session)
    await console.send(session, console.hello(session))
    return {"ok": True}


@app.post("/api/incidents/{incident_id}/decision")
async def decide(incident_id: str, decision: Decision, request: Request) -> Dict[str, Any]:
    """The only way to authorize a change: an explicit click on the user's own card."""
    session = require_session(request)
    action = decision.action.lower()
    if action not in DECISIONS:
        raise HTTPException(400, f"action must be one of {sorted(DECISIONS)}")
    if not _INCIDENT_RE.fullmatch(incident_id):
        raise HTTPException(400, "invalid incident id")
    record = console.owned_record(session, incident_id.lower())
    if record is None:
        raise HTTPException(404, "unknown incident")
    if phase_of(record.get("state", "")) != NEEDS_APPROVAL:
        raise HTTPException(409, "this change is no longer waiting for a decision")
    assert console.gateway is not None
    console.gateway.send_decision(action, incident_id.lower())
    return {"sent": True, "action": action}


@app.get("/api/incidents/{incident_id}/files/{index}")
async def download(incident_id: str, index: int, request: Request) -> Response:
    """A fixed file, for repositories Sentinel cannot open a pull request on."""
    record = console.owned_record(require_session(request), incident_id)
    found = fixed_file(record, index) if record else None
    if found is None:
        raise HTTPException(404, "no such file")
    name, content = found
    return Response(content, media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    session_id = websocket.cookies.get(SESSION_COOKIE)
    if not same_origin(websocket.headers) or not session_id or not console.auth.is_operator(websocket.cookies.get(COOKIE_NAME)):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    session = console.session(session_id)
    session.sockets.add(websocket)
    await websocket.send_text(json.dumps(console.hello(session)))
    try:
        while True:
            data = json.loads(await websocket.receive_text())
            text = str(data.get("text", "")).strip()[:MAX_MESSAGE_CHARS]
            if data.get("type") == "user_message" and text:
                asyncio.create_task(answer(session, text))
    except (WebSocketDisconnect, RuntimeError, ValueError):
        pass
    finally:
        session.sockets.discard(websocket)


async def answer(session: Session, text: str) -> None:
    """One chat turn. Runs apart from the socket loop, so a slow model never blocks live agent updates."""
    assert llm is not None
    async with session.lock:
        await console.say(session, "user", text)
        await console.set_typing(session, True)
        try:
            reply = await Assistant(llm, SessionActions(console, session)).reply(session.history, text)
        except Exception as exc:     # the chat must always answer
            reply = f"Sorry, something went wrong on my side ({type(exc).__name__}). Please try again."
        session.history += [{"role": "user", "content": text}, {"role": "assistant", "content": reply}]
        await console.set_typing(session, False)
        await console.say(session, "assistant", reply)


if FRONTEND_DIST.is_dir():   # production: serve the built React app from the same origin
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{path:path}")
    async def spa(path: str) -> FileResponse:
        file = FRONTEND_DIST / path
        return FileResponse(file if path and file.is_file() else FRONTEND_DIST / "index.html")


if __name__ == "__main__":
    configure_console_utf8()
    problem = exposure_error(HOST, os.getenv("CONSOLE_PASSWORD", "").strip())
    if problem:
        sys.exit(problem)
    uvicorn.run(app, host=HOST, port=PORT)
