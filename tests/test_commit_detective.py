import json
from typing import Optional

import httpx
import pytest

from agents.Agent_3 import CommitDetective, create_agent
from common import commit_scoring as cs
from common.llm_client import ASI1Client
from common.github_client import ChangedFile, CommitInfo, GitHubClient
from common.models import AgentErrorReport, CommitCorrelationRequest, CommitEvidenceReport
from tests.bureau_harness import agent_test_kwargs, run_roundtrip
from tests.fakes import (
    ASI1_URL, ERROR_SNIPPET, FAULT_LINE, HEAD_SHA, OLD_SHA, README_SHA, REPO, FakeWeb, llm_reply,
)

EXPLANATION = "The commit made checkout read PRICING['discount_rate'] directly, which the config lacks, so it raises KeyError."
FAILURE_TS = "2026-01-02T12:00:00+00:00"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_):
        return None

    monkeypatch.setattr("common.http_retry._sleep", instant)


def make_detective(web: FakeWeb) -> CommitDetective:
    http = web.client()
    return CommitDetective(
        gh=GitHubClient(http, token="t", write_allowlist=[]),
        llm=ASI1Client(http, api_key="test-key", base_url=ASI1_URL),
    )


def request(snippet: Optional[str] = ERROR_SNIPPET, incident_id: str = "inc-det") -> CommitCorrelationRequest:
    return CommitCorrelationRequest(
        incident_id=incident_id, repo_full_name=REPO, branch="main", failure_timestamp_utc=FAILURE_TS,
        failing_endpoint="/api/checkout", error_snippet=snippet,
    )


def only_reply(ctx):
    (dest, msg), = ctx.sent
    return dest, msg


# ------------------------------------------------------------------ the demo scenario

def test_fixture_fault_line_is_90():
    assert FAULT_LINE == 90  # demo_target_app/app.py: discount_rate = PRICING["discount_rate"]


async def test_pinpoints_checkout_keyerror_commit(ctx):
    web = FakeWeb()
    web.llm = lambda r: llm_reply(EXPLANATION)
    await make_detective(web).handle_request(ctx, "agent1qsender", request())
    dest, report = only_reply(ctx)
    assert dest == "agent1qsender" and isinstance(report, CommitEvidenceReport)
    assert report.suspect_commit_sha == HEAD_SHA and report.author == "alice"
    assert report.suspect_commit_url.endswith(f"/commit/{HEAD_SHA}")
    assert report.commit_message == "Require discount_rate in pricing config"
    assert report.committed_at_utc == "2026-01-02T10:00:00+00:00"
    assert report.offending_file == "app.py"
    assert 'PRICING["discount_rate"]' in report.offending_diff_snippet and len(report.offending_diff_snippet) <= 1000
    assert report.root_cause_explanation == EXPLANATION
    # active imports prove yaml.load is reachable; urllib3 is never imported
    assert {"yaml", "yaml.load", "sqlite3", "sqlite3.connect", "os.getenv"} <= set(report.active_ast_imports)
    assert "urllib3" not in report.active_ast_imports


async def test_deterministic_win_needs_no_tiebreak_and_prompt_is_grounded(ctx):
    web = FakeWeb()
    web.llm = lambda r: llm_reply(EXPLANATION)
    await make_detective(web).handle_request(ctx, "s", request())
    prompts = web.llm_prompts()
    assert len(prompts) == 1  # only the root-cause explanation; scoring decided the commit
    p = prompts[0]
    assert "KeyError" in p and "in checkout()" in p and f"app.py:{FAULT_LINE}" in p
    assert 'discount_rate = PRICING["discount_rate"]' in p  # the failing line, from the file at HEAD
    assert "STRIPE" not in p and "sk_test_51SENTINELDEMOxxxxxxxx" not in p


async def test_commit_fetches_use_github_endpoints(ctx):
    web = FakeWeb()
    await make_detective(web).handle_request(ctx, "s", request())
    paths = [r.url.path for r in web.requests if r.url.host == "api.github.com"]
    assert f"/repos/{REPO}/commits" in paths
    assert {f"/repos/{REPO}/commits/{s}" for s in (HEAD_SHA, README_SHA, OLD_SHA)} <= set(paths)
    first = next(r for r in web.requests if r.url.path == f"/repos/{REPO}/commits")
    assert first.url.params["per_page"] == "5" and first.url.params["sha"] == "main"


async def test_secret_in_the_offending_diff_is_masked_in_the_report(ctx):
    web = FakeWeb()
    web.github.commits[0]["files"][0]["patch"] = (
        "@@ -88,3 +88,3 @@\n x\n"
        '+STRIPE = "sk_test_51SENTINELDEMOxxxxxxxx"  # PRICING["discount_rate"]\n y'
    )
    web.llm = lambda r: llm_reply(EXPLANATION)
    await make_detective(web).handle_request(ctx, "s", request())
    report = only_reply(ctx)[1]
    assert isinstance(report, CommitEvidenceReport) and report.suspect_commit_sha == HEAD_SHA
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in report.json() and "sk_tes****" in report.offending_diff_snippet
    assert all("sk_test_51SENTINELDEMOxxxxxxxx" not in p for p in web.llm_prompts())


async def test_llm_unavailable_falls_back_to_deterministic_explanation(ctx):
    web = FakeWeb()  # default fake LLM answers 401
    await make_detective(web).handle_request(ctx, "s", request())
    _, report = only_reply(ctx)
    assert isinstance(report, CommitEvidenceReport) and report.suspect_commit_sha == HEAD_SHA
    assert HEAD_SHA[:7] in report.root_cause_explanation and "app.py:90" in report.root_cause_explanation
    assert 'PRICING["discount_rate"]' in report.root_cause_explanation


async def test_traceback_style_snippet_also_works(ctx):
    web = FakeWeb()
    snippet = f'Traceback (most recent call last):\n  File "/srv/app.py", line {FAULT_LINE}, in checkout\nKeyError: \'discount_rate\''
    await make_detective(web).handle_request(ctx, "s", request(snippet))
    assert only_reply(ctx)[1].suspect_commit_sha == HEAD_SHA


# ------------------------------------------------------------------ tie-break

async def test_ambiguous_ranking_asks_llm_to_choose(ctx):
    web = FakeWeb()
    answers = iter([json.dumps({"sha": OLD_SHA}), EXPLANATION])
    web.llm = lambda r: llm_reply(next(answers))
    await make_detective(web).handle_request(ctx, "s", request(snippet=None))  # no file/line signal at all
    _, report = only_reply(ctx)
    assert report.suspect_commit_sha == OLD_SHA
    assert "Add health endpoint" in web.llm_prompts()[0] and "Update README" in web.llm_prompts()[0]


async def test_bad_llm_answer_falls_back_to_most_recent(ctx):
    web = FakeWeb()
    answers = iter([json.dumps({"sha": "deadbeefdeadbeef"}), EXPLANATION])
    web.llm = lambda r: llm_reply(next(answers))
    await make_detective(web).handle_request(ctx, "s", request(snippet=None))
    assert only_reply(ctx)[1].suspect_commit_sha == HEAD_SHA


# ------------------------------------------------------------------ edge cases and failures

async def test_repo_without_python_files_gives_empty_imports(ctx):
    web = FakeWeb()
    web.github.files = {"README.md": "# hi", "requirements.txt": "x==1"}
    await make_detective(web).handle_request(ctx, "s", request())
    _, report = only_reply(ctx)
    assert isinstance(report, CommitEvidenceReport) and report.active_ast_imports == []


async def test_no_commits_sends_agent_error_report(ctx):
    web = FakeWeb()
    web.github.commits = []
    await make_detective(web).handle_request(ctx, "agent1qsender", request(incident_id="inc-empty"))
    dest, err = only_reply(ctx)
    assert dest == "agent1qsender" and isinstance(err, AgentErrorReport)
    assert err.incident_id == "inc-empty" and err.agent == "Agent_3" and "no commits" in err.error


async def test_github_outage_sends_agent_error_report_and_never_raises(ctx):
    web = FakeWeb()
    web.github.fail_status = 500
    await make_detective(web).handle_request(ctx, "s", request())
    assert isinstance(only_reply(ctx)[1], AgentErrorReport)


async def test_uninitialised_clients_report_error(ctx):
    await CommitDetective().handle_request(ctx, "s", request())
    assert isinstance(only_reply(ctx)[1], AgentErrorReport)


# ------------------------------------------------------------------ scoring unit tests

def commit(sha: str, files, date: str = "2026-01-01T00:00:00Z") -> CommitInfo:
    return CommitInfo(sha=sha, url="", author="a", message=sha, committed_at=date, files=files)


def test_parse_hunks_and_cover():
    patch = "@@ -1,3 +1,4 @@ ctx\n a\n+b\n@@ -50 +60,2 @@\n x\n+y"
    assert [(a, b) for a, b, _ in cs.parse_hunks(patch)] == [(1, 4), (60, 61)]
    assert cs.hunk_covering(patch, 61).startswith("@@ -50")
    assert cs.hunk_covering(patch, 30) is None and cs.hunk_covering(patch, None) is None


def test_file_matching():
    assert cs.file_matches("app.py", "app.py") and cs.file_matches("src/app.py", "app.py")
    assert not cs.file_matches("other.py", "app.py") and not cs.file_matches("app.py", None)


def test_score_components_sum_to_100_for_the_full_match():
    f = ChangedFile("app.py", "modified", "@@ -88,3 +88,3 @@\n a\n+ /api/checkout\n c")
    score, reasons = cs.score_file(f, "app.py", 90, "/api/checkout")
    assert score == 50 + 30 + 15 and len(reasons) == 3
    ranked = cs.rank_commits([commit("c1", [f])], "app.py", 90, "/api/checkout", FAILURE_TS)
    assert ranked[0].score == 100 and ranked[0].offending_file == "app.py"


def test_ranking_prefers_error_file_and_keeps_newest_first_on_ties():
    py = ChangedFile("app.py", "modified", "@@ -1 +1 @@\n x")
    md = ChangedFile("README.md", "modified", "@@ -1 +1 @@\n x")
    newest, older = commit("n", [md], "2026-01-02T00:00:00Z"), commit("o", [py], "2026-01-01T00:00:00Z")
    ranked = cs.rank_commits([newest, older], "app.py", None, "/e", FAILURE_TS)
    assert [r.commit.sha for r in ranked] == ["o", "n"]  # o: 50, n: 0 + 5 recency
    assert cs.is_ambiguous(cs.rank_commits([newest, older], None, None, "/e", FAILURE_TS))  # no signal
    tie = cs.rank_commits([commit("x", [md]), commit("y", [md])], None, None, "/e", "bad-timestamp")
    assert [r.commit.sha for r in tie] == ["x", "y"] and cs.is_ambiguous(tie)


def test_latest_before_respects_failure_time():
    cs_ = [commit("late", [], "2026-01-05T00:00:00Z"), commit("mid", [], "2026-01-02T00:00:00Z"), commit("old", [], "2026-01-01T00:00:00Z")]
    assert cs.latest_before(cs_, "2026-01-03T00:00:00+00:00") == "mid"
    assert cs.latest_before(cs_, "2025-01-01T00:00:00+00:00") == "late"  # nothing eligible -> newest
    assert cs.latest_before([], FAILURE_TS) is None


def test_extract_error_location_and_time_helpers():
    assert cs.extract_error_location(ERROR_SNIPPET) == ("app.py", FAULT_LINE)
    assert cs.extract_error_location('File "C:\\srv\\app.py", line 7, in f') == ("app.py", 7)
    assert cs.extract_error_location(None) == (None, None)
    assert cs.to_utc_iso("2026-01-02T05:00:00+05:00") == "2026-01-02T00:00:00+00:00"
    assert cs.to_utc_iso("2026-01-02T10:00:00Z") == "2026-01-02T10:00:00+00:00"
    assert cs.to_utc_iso("garbage") == "garbage"


# ------------------------------------------------------------------ agent wiring + Bureau round trip

def test_create_agent_requires_seed(monkeypatch):
    monkeypatch.delenv("DETECTIVE_SEED", raising=False)
    with pytest.raises(RuntimeError, match="DETECTIVE_SEED"):
        create_agent(mailbox=False)


async def test_create_agent_defaults():
    agent = create_agent(seed="detective wiring seed", enable_agent_inspector=False)
    assert agent.name == "Agent_3" and agent.mailbox_client is not None  # mailbox=True by default


def test_bureau_round_trip_pinpoints_the_checkout_commit():
    web = FakeWeb()
    web.llm = lambda r: llm_reply(EXPLANATION)

    async def make_target(port: int):
        return create_agent(seed="bureau detective seed", port=port, detective=make_detective(web), **agent_test_kwargs())

    target_addr, sender, report = run_roundtrip(make_target, lambda: request(incident_id="inc-bureau-det"))
    assert sender == target_addr and isinstance(report, CommitEvidenceReport)
    assert report.incident_id == "inc-bureau-det" and report.suspect_commit_sha == HEAD_SHA
    assert report.offending_file == "app.py" and "yaml.load" in report.active_ast_imports
    assert report.root_cause_explanation == EXPLANATION
