"""Run the whole Sentinel stack from one command: demo target, the five agents and the web console.

    python -m scripts.run_stack          # used by the Docker image; also works on any machine with the venv

The agents reach each other on 127.0.0.1, so everything lives on one host (one container). Only the console port
is meant to be public. A process that crashes is restarted with a growing delay; stopping this script stops them all.
"""
import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional

from dotenv import load_dotenv

REQUIRED_ENV = ("ORCHESTRATOR_SEED", "WATCHDOG_SEED", "DETECTIVE_SEED", "SCANNER_SEED", "EXECUTOR_SEED",
                "GITHUB_TOKEN", "DEMO_REPO_FULL_NAME", "DEMO_ADMIN_TOKEN")
DEMO_APP_URL = "http://127.0.0.1:9000"
START_GAP_SECONDS = 1.0
MAX_RESTART_DELAY = 30.0
STABLE_SECONDS = 60.0        # a process that ran this long has its restart delay reset
POLL_SECONDS = 1.0
CONSOLE = "console"
CONSOLE_WAIT_SECONDS = 120.0

PROCESSES = [
    # The page answers first: on a small plan the agents take minutes to load, and a visitor should see that, not nothing
    (CONSOLE, ["-m", "web.server"]),
    ("demo-app", ["-m", "uvicorn", "demo_target_app.app:app", "--host", "127.0.0.1", "--port", "9000"]),
    ("Agent_5", ["-m", "agents.Agent_5"]),
    ("Agent_4", ["-m", "agents.Agent_4"]),
    ("Agent_3", ["-m", "agents.Agent_3"]),
    ("Agent_2", ["-m", "agents.Agent_2"]),
    ("Agent_1", ["-m", "agents.Agent_1"]),   # receivers first, so Agent_1 can reach everyone
]


def stack_env(base: Mapping[str, str]) -> Dict[str, str]:
    """The environment every process runs with: local agent network, no payment step, the bundled demo target."""
    env = dict(base)
    env.update(AGENT_MAILBOX="false", SKIP_PAYMENT="true", PYTHONUTF8="1", PYTHONUNBUFFERED="1")
    if not env.get("DEMO_SERVICE_URL"):
        env["DEMO_SERVICE_URL"] = DEMO_APP_URL
    return env


def missing_env(env: Mapping[str, str]) -> List[str]:
    provider = env.get("LLM_PROVIDER", "").strip().lower()
    llm_key = {"asi1": "ASI1_API_KEY", "groq": "GROQ_API_KEY"}.get(provider, "GEMINI_API_KEY")
    return [name for name in (*REQUIRED_ENV, llm_key) if not env.get(name, "").strip()]


def console_port(env: Mapping[str, str]) -> int:
    return int(env.get("WEB_PORT") or env.get("PORT") or 8080)


def wait_for_port(port: int, seconds: float, stopped: Callable[[], bool]) -> bool:
    """True once something listens on `port`. The agents wait for this so they don't compete with the console for CPU."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not stopped():
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(POLL_SECONDS)
    return False


def next_delay(delay: float, ran_for: float) -> float:
    """Restart at once after a long healthy run; back off (1, 2, 4 ... 30 s) on a crash loop."""
    return 0.0 if ran_for >= STABLE_SECONDS else min(max(delay * 2, 1.0), MAX_RESTART_DELAY)


@dataclass
class Managed:
    name: str
    args: List[str]
    proc: Optional[subprocess.Popen] = None
    started: float = 0.0
    delay: float = 0.0
    restart_at: float = field(default=0.0)

    def start(self, env: Dict[str, str]) -> None:
        self.proc = subprocess.Popen([sys.executable, *self.args], env=env)
        self.started, self.restart_at = time.monotonic(), 0.0
        print(f"[stack] started {self.name} (pid {self.proc.pid})", flush=True)


def stop_all(procs: List[Managed]) -> None:
    for m in procs:
        if m.proc and m.proc.poll() is None:
            m.proc.terminate()
    deadline = time.monotonic() + 10
    for m in procs:
        if m.proc:
            try:
                m.proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                m.proc.kill()


def main() -> int:
    load_dotenv()      # a .env on a normal machine; hosted platforms set real environment variables
    env = stack_env(os.environ)
    missing = missing_env(env)
    if missing:
        print("[stack] missing environment variables: " + ", ".join(missing), file=sys.stderr)
        return 2

    stopping = {"now": False}

    def request_stop(_signum: int, _frame: object) -> None:
        stopping["now"] = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    procs = [Managed(name, args) for name, args in PROCESSES]
    for m in procs:
        if stopping["now"]:
            break
        m.start(env)
        if m.name == CONSOLE:
            wait_for_port(console_port(env), CONSOLE_WAIT_SECONDS, lambda: stopping["now"])
        time.sleep(START_GAP_SECONDS)

    while not stopping["now"]:
        now = time.monotonic()
        for m in procs:
            if m.proc is None or m.proc.poll() is None:
                continue
            if not m.restart_at:
                ran_for = now - m.started
                m.delay = next_delay(m.delay, ran_for)
                m.restart_at = now + m.delay
                print(f"[stack] {m.name} exited with code {m.proc.returncode} after {ran_for:.0f}s; "
                      f"restarting in {m.delay:.0f}s", flush=True)
            elif now >= m.restart_at:
                m.start(env)
        time.sleep(POLL_SECONDS)

    print("[stack] stopping", flush=True)
    stop_all(procs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
