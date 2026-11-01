"""scripts/run_stack.py: the environment it forces, its preflight, and crash-loop backoff."""
from pathlib import Path

from scripts import run_stack
from scripts.run_stack import (
    DEMO_APP_URL, MAX_RESTART_DELAY, PROCESSES, REQUIRED_ENV, STABLE_SECONDS, main, missing_env, next_delay, stack_env,
)


def test_stack_runs_local_without_payment_whatever_the_host_sets():
    env = stack_env({"AGENT_MAILBOX": "true", "SKIP_PAYMENT": "false", "KEEP": "me"})
    assert env["AGENT_MAILBOX"] == "false" and env["SKIP_PAYMENT"] == "true" and env["KEEP"] == "me"


def test_demo_target_is_the_default_but_a_real_url_is_kept():
    assert stack_env({})["DEMO_SERVICE_URL"] == DEMO_APP_URL
    assert stack_env({"DEMO_SERVICE_URL": "https://shop.example"})["DEMO_SERVICE_URL"] == "https://shop.example"


def test_preflight_names_missing_variables():
    assert missing_env({}) == [*REQUIRED_ENV, "GEMINI_API_KEY"]
    full = {**{name: "x" for name in REQUIRED_ENV}, "GEMINI_API_KEY": "k"}
    assert missing_env(full) == [] and missing_env({**full, "GITHUB_TOKEN": "  "}) == ["GITHUB_TOKEN"]
    assert missing_env({**full, "LLM_PROVIDER": "asi1"}) == ["ASI1_API_KEY"]


def test_main_refuses_to_start_without_configuration(monkeypatch, capsys):
    monkeypatch.setattr(run_stack, "load_dotenv", lambda: False)   # never read the real .env: that would start the stack
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    for name in (*REQUIRED_ENV, "GEMINI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert main() == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().err


def test_restart_backoff_grows_then_caps_and_resets_after_a_healthy_run():
    delay, seen = 0.0, []
    for _ in range(8):
        delay = next_delay(delay, ran_for=1)
        seen.append(delay)
    assert seen[:3] == [1.0, 2.0, 4.0] and seen[-1] == MAX_RESTART_DELAY
    assert next_delay(MAX_RESTART_DELAY, ran_for=STABLE_SECONDS) == 0.0


def test_every_agent_starts_and_agent_1_starts_after_its_receivers():
    names = [name for name, _ in PROCESSES]
    assert {"Agent_1", "Agent_2", "Agent_3", "Agent_4", "Agent_5", "console", "demo-app"} == set(names)
    assert names.index("Agent_1") > max(names.index(n) for n in ("Agent_2", "Agent_3", "Agent_4", "Agent_5"))


def test_docker_context_cannot_contain_secrets():
    root = Path(__file__).resolve().parent.parent
    ignored = (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in ignored and "*_data.json" in ignored
    assert "COPY . " not in (root / "Dockerfile").read_text(encoding="utf-8")


def test_the_page_answers_before_the_agents_load():
    """On a 0.1 CPU plan the agents take minutes to load, and a visitor must not see nothing for that long."""
    assert PROCESSES[0][0] == "console"
    assert [name for name, _ in PROCESSES].count("Agent_1") == 1


def test_the_console_port_follows_the_host():
    assert run_stack.console_port({"PORT": "10000"}) == 10000
    assert run_stack.console_port({"WEB_PORT": "9001", "PORT": "10000"}) == 9001
    assert run_stack.console_port({}) == 8080


def test_waiting_for_the_console_stops_when_it_listens_or_time_runs_out():
    import socket
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        assert run_stack.wait_for_port(port, 2, lambda: False) is True
    assert run_stack.wait_for_port(port, 0, lambda: False) is False
    assert run_stack.wait_for_port(port, 5, lambda: True) is False
