"""The helper scripts: demo-repo seeding (against a fake GitHub) and the address table."""
import base64
import difflib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
import pytest

from common import commit_scoring as cs
from common.github_client import ChangedFile, CommitInfo
from scripts import seed_demo_repo as seed_mod
from scripts.seed_demo_repo import SeedError, faulty_source, parent_source, seed
from tests.fakes import ERROR_SNIPPET, FAULT_LINE

REPO = "alice/sentinel-target"
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


class FakeGithubWriter:
    """Just enough of GitHub: repos, /user, contents GET/PUT with a real commit list."""

    def __init__(self, exists: bool = True, files: Dict[str, str] = None) -> None:
        self.exists = exists
        self.files: Dict[str, str] = dict(files or {})
        self.commits: List[Dict[str, Any]] = []
        self.created: List[Dict[str, Any]] = []
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/user":
            return httpx.Response(200, json={"login": "alice", "id": 42, "name": "Alice"})
        if path == "/user/repos" and request.method == "POST":
            self.created.append(json.loads(request.content))
            self.exists = True
            self.files["README.md"] = "# auto\n"
            return httpx.Response(201, json={})
        if path == f"/repos/{REPO}":
            return httpx.Response(200 if self.exists else 404, json={})
        if path.startswith(f"/repos/{REPO}/contents/"):
            name = path.split("/contents/", 1)[1]
            if request.method == "GET":
                if name not in self.files:
                    return httpx.Response(404, json={"message": "Not Found"})
                return httpx.Response(200, json={"sha": f"blob-{len(self.commits)}-{name}", "content": base64.b64encode(self.files[name].encode()).decode()})
            body = json.loads(request.content)
            if name in self.files and not body.get("sha"):
                return httpx.Response(422, json={"message": "sha wasn't supplied"})
            old = self.files.get(name, "")
            new = base64.b64decode(body["content"]).decode()
            self.files[name] = new
            sha = f"{len(self.commits) + 1:040x}"
            self.commits.append({"sha": sha, "message": body["message"], "path": name, "old": old, "new": new,
                                 "date": body["committer"]["date"], "author": body["author"], "branch": body["branch"]})
            return httpx.Response(200, json={"commit": {"sha": sha}})
        return httpx.Response(404, json={"message": "Not Found"})


def run_seed(fake: FakeGithubWriter, token: str = "tok", **kw):
    with httpx.Client(transport=httpx.MockTransport(fake)) as client:
        return seed(client, REPO, token, now=NOW, **kw)


# ------------------------------------------------------------------ the demo history

def test_parent_and_faulty_versions_differ_by_exactly_the_faulty_line():
    old, new = parent_source().splitlines(), faulty_source().splitlines()
    changed = [i + 1 for i, (a, b) in enumerate(zip(old, new)) if a != b]
    assert len(old) == len(new) and changed == [FAULT_LINE]                      # the line the live app reports in X-Error-Line
    assert 'PRICING["discount_rate"]' in new[FAULT_LINE - 1] and 'PRICING.get("discount_rate", 0.0)' in old[FAULT_LINE - 1]
    compile(parent_source(), "app.py", "exec")


def test_commit_detective_scoring_picks_the_seeded_faulty_commit():
    patch = "\n".join(list(difflib.unified_diff(parent_source().splitlines(), faulty_source().splitlines(), lineterm="", n=3))[2:])
    noise = CommitInfo("n" * 40, "u", "alice", "Update README", "2026-03-01T11:40:00Z", [], [ChangedFile("README.md", "modified", "@@ -1 +1,2 @@\n a\n+b")])
    faulty = CommitInfo("f" * 40, "u", "alice", seed_mod.FAULTY_MESSAGE, "2026-03-01T11:30:00Z", ["n" * 40], [ChangedFile("app.py", "modified", patch)])
    ranked = cs.rank_commits([noise, faulty], "app.py", FAULT_LINE, "/api/checkout", "2026-03-01T12:00:00Z")
    assert ranked[0].commit.sha == "f" * 40 and ranked[0].score >= 80 and not cs.is_ambiguous(ranked)


def test_sentinel_fix_title_uses_the_real_commit_messages():
    merged = "Merge pull request #2 from sujal-jangir-111/sentinel/fix-inc-51626f69\n\nSentinel inc-51626f69: fix app.py"
    assert cs.sentinel_fix_title(merged) == "Sentinel inc-51626f69: fix app.py"
    assert cs.sentinel_fix_title("Sentinel inc-51626f69: fix app.py (#2)")                       # squash merge
    for message in ("Merge pull request #3 from x/sentinel/fix-inc-d5faec4b\n\nSentinel inc-d5faec4b: roll back app.py",
                    "Require discount_rate in pricing config", "Sentinel inc-51626f69: update app.py", "Fix the Sentinel docs", ""):
        assert cs.sentinel_fix_title(message) is None


def test_scoring_blames_the_faulty_commit_not_the_commit_that_created_the_file():
    """The live seeded history: 'Add checkout service' adds all of app.py (so it 'covers' the line and mentions the
    endpoint), and the later faulty commit edits one line. Blame must land on the faulty commit."""
    created = "\n".join(list(difflib.unified_diff([], parent_source().splitlines(), lineterm="", n=3))[2:])
    edited = "\n".join(list(difflib.unified_diff(parent_source().splitlines(), faulty_source().splitlines(), lineterm="", n=3))[2:])
    faulty = CommitInfo("f" * 40, "u", "alice", seed_mod.FAULTY_MESSAGE, "2026-03-01T11:30:00Z", ["n" * 40], [ChangedFile("app.py", "modified", edited)])
    noise = CommitInfo("n" * 40, "u", "alice", "Update README", "2026-03-01T11:29:00Z", ["c" * 40], [ChangedFile("README.md", "modified", "@@ -1 +1,2 @@\n a\n+b")])
    creator = CommitInfo("c" * 40, "u", "alice", "Add checkout service", "2026-03-01T11:28:00Z", [], [ChangedFile("app.py", "added", created)])
    ranked = cs.rank_commits([faulty, noise, creator], "app.py", FAULT_LINE, "/api/checkout", "2026-03-01T12:00:00Z")
    assert ranked[0].commit.sha == "f" * 40 and not cs.is_ambiguous(ranked)
    assert next(r for r in ranked if r.commit.sha == "c" * 40).score < ranked[0].score
    # GitHub sometimes omits the status; the @@ -0,0 hunk header alone marks a created file
    assert cs.is_new_file(ChangedFile("app.py", "", created))


# ------------------------------------------------------------------ seeding

def test_seeding_creates_the_expected_history_on_main():
    fake = FakeGithubWriter(files={"README.md": "# auto\n"})
    result = run_seed(fake)
    assert result["status"] == "seeded" and result["faulty_commit"] == fake.commits[-1]["sha"]
    assert [c["message"] for c in fake.commits] == ["Add README", "Add pinned requirements", "Add Dockerfile", "Add checkout service",
                                                    "Update README", seed_mod.FAULTY_MESSAGE]
    assert {c["branch"] for c in fake.commits} == {"main"}
    assert set(fake.files) == {"README.md", "requirements.txt", "Dockerfile", "app.py"}                 # repo root layout the agents expect
    assert fake.files["app.py"] == faulty_source() and "pyyaml==5.3" in fake.files["requirements.txt"] and "python:latest" in fake.files["Dockerfile"]
    parent = next(c for c in fake.commits if c["message"] == "Add checkout service")
    assert parent["new"] == parent_source()                                                              # rollback target is the working app
    faulty = fake.commits[-1]
    assert faulty["old"] == parent_source() and faulty["new"] == faulty_source()
    dates = [c["date"] for c in fake.commits]
    assert dates == sorted(dates) and faulty["date"] == "2026-03-01T11:30:00Z"                           # back-dated 30 min, in order
    assert faulty["author"]["email"] == "42+alice@users.noreply.github.com"


def test_faulty_age_zero_commits_at_now():
    fake = FakeGithubWriter(files={"README.md": "# auto\n"})
    run_seed(fake, faulty_age_minutes=0)
    assert fake.commits[-1]["date"] == "2026-03-01T12:00:00Z"


def test_seeding_twice_is_a_no_op():
    fake = FakeGithubWriter(files={"README.md": "# auto\n"})
    run_seed(fake)
    count = len(fake.commits)
    assert run_seed(fake)["status"] == "already-seeded" and len(fake.commits) == count


def test_a_different_existing_app_is_not_overwritten_without_reset():
    fake = FakeGithubWriter(files={"app.py": "print('mine')\n"})
    with pytest.raises(SeedError, match="--reset"):
        run_seed(fake)
    assert fake.commits == [] and fake.files["app.py"] == "print('mine')\n"
    assert run_seed(fake, reset=True)["status"] == "seeded" and fake.files["app.py"] == faulty_source()


def test_reset_rebuilds_the_history_on_a_seeded_repo():
    fake = FakeGithubWriter(files={"README.md": "# auto\n"})
    run_seed(fake)
    before = len(fake.commits)
    result = run_seed(fake, reset=True)
    new = fake.commits[before:]
    assert result["status"] == "seeded"
    assert [c["message"] for c in new] == ["Add README", "Add checkout service", "Update README", seed_mod.FAULTY_MESSAGE]   # unchanged requirements/Dockerfile are skipped
    assert new[-1]["old"] == parent_source() and fake.files["app.py"] == faulty_source()


def test_missing_repo_needs_create_and_create_works():
    fake = FakeGithubWriter(exists=False)
    with pytest.raises(SeedError, match="--create"):
        run_seed(fake)
    assert fake.commits == [] and fake.created == []
    assert run_seed(fake, create=True, private=True)["status"] == "seeded"
    assert fake.created[0]["name"] == "sentinel-target" and fake.created[0]["private"] is True


def test_missing_token_and_bad_repo_names_are_refused_before_any_request():
    fake = FakeGithubWriter()
    with pytest.raises(SeedError, match="GITHUB_TOKEN"):
        run_seed(fake, token="")
    with httpx.Client(transport=httpx.MockTransport(fake)) as client, pytest.raises(SeedError, match="invalid repo"):
        seed(client, "not-a-repo", "tok")
    assert fake.requests == []


def test_github_errors_become_readable_seed_errors_without_the_token():
    def broken(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    with httpx.Client(transport=httpx.MockTransport(broken)) as client, pytest.raises(SeedError) as info:
        seed(client, REPO, "super-secret-token")
    assert "401" in str(info.value) and "Bad credentials" in str(info.value) and "super-secret-token" not in str(info.value)


def test_cli_refuses_the_placeholder_repo(monkeypatch, capsys):
    monkeypatch.setenv("DEMO_REPO_FULL_NAME", "your-org/sentinel-target")
    assert seed_mod.main(["--yes"]) == 2
    assert "DEMO_REPO_FULL_NAME" in capsys.readouterr().err


def test_cli_asks_for_confirmation(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _: "wrong")
    assert seed_mod.main(["--repo", REPO]) == 1 and "Aborted" in capsys.readouterr().out


# ------------------------------------------------------------------ local (no mailbox) mode

async def test_local_mode_uses_http_endpoints_instead_of_the_mailbox(monkeypatch):
    from common.agent_factory import build_agent, local_rules
    for k in ("ORCHESTRATOR", "WATCHDOG", "DETECTIVE", "SCANNER", "EXECUTOR"):
        monkeypatch.setenv(f"{k}_SEED", f"local-{k}")
    monkeypatch.setenv("AGENT_MAILBOX", "false")
    rules = local_rules()
    assert sorted(rules.values()) == [f"http://127.0.0.1:{p}/submit" for p in range(8001, 8007)]   # 8006 = web gateway
    from common.addresses import address_from_seed, gateway_address
    assert gateway_address() == address_from_seed("local-ORCHESTRATOR/web-gateway")         # derived from ORCHESTRATOR_SEED
    monkeypatch.setenv("GATEWAY_SEED", "explicit-gateway")
    assert gateway_address() == address_from_seed("explicit-gateway")
    agent = build_agent(name="x", seed="local-ORCHESTRATOR", seed_env="S", port=8001, description="d")
    assert agent.mailbox_client is None and "127.0.0.1:8001/submit" in str(agent._endpoints)
    monkeypatch.delenv("AGENT_MAILBOX")
    assert build_agent(name="x", seed="local-ORCHESTRATOR", seed_env="S", port=8001, description="d").mailbox_client is not None


def test_agent_descriptions_fit_agentverse_limit():
    """Agentverse rejects mailbox registration when the description exceeds 300 characters."""
    import importlib
    for name in ("Agent_1", "Agent_2", "Agent_3", "Agent_4", "Agent_5"):
        assert len(importlib.import_module(f"agents.{name}").DESCRIPTION) <= 300, name
