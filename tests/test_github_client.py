import base64
import json
import os
import time
from typing import Callable, Dict, List

import httpx
import pytest

from common.github_client import (
    GitHubClient, GitHubError, GitHubNotFound, blob_url, parse_commit,
)

REPO = "acme/sentinel-target"
TOKEN = "ghp_" + "t" * 36  # fake token used only to assert it never leaks


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    sleeps: List[float] = []

    async def fake(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr("common.http_retry._sleep", fake)
    return sleeps


class Router:
    """Tiny fake GitHub: route on (method, path); records every request."""

    def __init__(self) -> None:
        self.routes: Dict[tuple, Callable[[httpx.Request], httpx.Response]] = {}
        self.seen: List[httpx.Request] = []

    def add(self, method: str, path: str, response):
        self.routes[(method, path)] = response if callable(response) else (lambda r, _r=response: _r)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        handler = self.routes.get((request.method, request.url.path))
        return handler(request) if handler else httpx.Response(404, json={"message": "Not Found"})

    def calls(self, method: str, path: str) -> List[httpx.Request]:
        return [r for r in self.seen if r.method == method and r.url.path == path]


def make(router: Router, token: str = TOKEN, allow=(REPO,)):
    http = httpx.AsyncClient(transport=httpx.MockTransport(router))
    return GitHubClient(http, token=token, write_allowlist=allow), http


def file_json(path: str, text: str, sha: str = "blob1") -> httpx.Response:
    return httpx.Response(200, json={
        "type": "file", "path": path, "sha": sha, "encoding": "base64",
        "content": base64.encodebytes(text.encode()).decode(),
    })


def commit_json(sha="abc123", login="alice", parents=("p1",)) -> dict:
    return {
        "sha": sha, "html_url": f"https://github.com/{REPO}/commit/{sha}",
        "author": {"login": login} if login else None,
        "commit": {"message": "break checkout", "author": {"name": "Alice A", "date": "2026-01-02T03:04:05Z"}},
        "parents": [{"sha": p} for p in parents],
        "files": [{"filename": "app.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"}, {"filename": "img.png", "status": "added"}],
    }


# ------------------------------------------------------------------ reads

async def test_list_commits_and_params():
    r = Router()
    r.add("GET", f"/repos/{REPO}/commits", httpx.Response(200, json=[commit_json("c1"), commit_json("c2", login=None)]))
    gh, http = make(r)
    async with http:
        commits = await gh.list_commits(REPO, "main", per_page=5)
    assert [c.sha for c in commits] == ["c1", "c2"]
    assert commits[1].author == "Alice A"  # falls back to git author name
    q = r.seen[0].url.params
    assert q["sha"] == "main" and q["per_page"] == "5"
    h = r.seen[0].headers
    assert h["Authorization"] == f"Bearer {TOKEN}" and h["X-GitHub-Api-Version"] == "2022-11-28"


async def test_get_commit_parses_patches_and_parents():
    r = Router()
    r.add("GET", f"/repos/{REPO}/commits/abc123", httpx.Response(200, json=commit_json()))
    gh, http = make(r)
    async with http:
        c = await gh.get_commit(REPO, "abc123")
    assert c.parents == ["p1"] and c.committed_at == "2026-01-02T03:04:05Z" and c.author == "alice"
    assert c.files[0].patch.startswith("@@") and c.files[1].patch == ""
    assert parse_commit(commit_json()).url.endswith("/commit/abc123")


async def test_get_file_decodes_and_returns_sha():
    r = Router()
    r.add("GET", f"/repos/{REPO}/contents/app/main.py", lambda req: file_json("app/main.py", "print('héllo')\n", "s9"))
    gh, http = make(r)
    async with http:
        f = await gh.get_file(REPO, "app/main.py", ref="main")
    assert f.text == "print('héllo')\n" and f.sha == "s9"
    assert r.seen[0].url.params["ref"] == "main"


async def test_get_file_missing_returns_none():
    gh, http = make(Router())
    async with http:
        assert await gh.get_file(REPO, "nope.txt") is None


async def test_get_file_large_file_falls_back_to_raw():
    r = Router()

    def handler(req):
        if "raw" in req.headers["Accept"]:
            return httpx.Response(200, text="BIG CONTENT")
        return httpx.Response(200, json={"type": "file", "path": "big.py", "sha": "s", "encoding": "none", "content": ""})

    r.add("GET", f"/repos/{REPO}/contents/big.py", handler)
    gh, http = make(r)
    async with http:
        assert (await gh.get_file(REPO, "big.py")).text == "BIG CONTENT"


async def test_get_file_on_directory_raises():
    r = Router()
    r.add("GET", f"/repos/{REPO}/contents/app", httpx.Response(200, json=[{"name": "x.py"}]))
    gh, http = make(r)
    async with http:
        with pytest.raises(GitHubError, match="not a file"):
            await gh.get_file(REPO, "app")


async def test_fetch_manifests_returns_only_existing_files():
    r = Router()
    r.add("GET", f"/repos/{REPO}/contents/requirements.txt", file_json("requirements.txt", "pyyaml==5.3\n"))
    r.add("GET", f"/repos/{REPO}/contents/Dockerfile", file_json("Dockerfile", "FROM python:latest\n"))
    gh, http = make(r)
    async with http:
        m = await gh.fetch_manifests(REPO, "main")
    assert m == {"requirements.txt": "pyyaml==5.3\n", "Dockerfile": "FROM python:latest\n"}


async def test_fetch_python_sources_root_app_src_with_cap():
    r = Router()
    listing = lambda *names: httpx.Response(200, json=[{"name": n, "path": p, "type": t} for n, p, t in names])
    r.add("GET", f"/repos/{REPO}/contents", listing(("app.py", "app.py", "file"), ("README.md", "README.md", "file"), ("app", "app", "dir")))
    r.add("GET", f"/repos/{REPO}/contents/app", listing(("views.py", "app/views.py", "file")))
    # src/ does not exist -> 404 -> []
    for p in ("app.py", "app/views.py"):
        r.add("GET", f"/repos/{REPO}/contents/{p}", file_json(p, f"# {p}\n"))
    gh, http = make(r)
    async with http:
        sources = await gh.fetch_python_sources(REPO, "main")
        capped = await gh.fetch_python_sources(REPO, "main", cap=1)
    assert sources == {"app.py": "# app.py\n", "app/views.py": "# app/views.py\n"}
    assert list(capped) == ["app.py"]


async def test_list_directory_missing_is_empty():
    gh, http = make(Router())
    async with http:
        assert await gh.list_directory(REPO, "src") == []


async def test_get_branch_sha():
    r = Router()
    r.add("GET", f"/repos/{REPO}/git/ref/heads/main", httpx.Response(200, json={"object": {"sha": "head1"}}))
    r.add("GET", f"/repos/{REPO}/git/ref/heads/odd", httpx.Response(200, json={}))
    gh, http = make(r)
    async with http:
        assert await gh.get_branch_sha(REPO) == "head1"
        with pytest.raises(GitHubError, match="unexpected ref"):
            await gh.get_branch_sha(REPO, "odd")


async def test_public_reads_work_without_token():
    r = Router()
    r.add("GET", f"/repos/{REPO}/commits", httpx.Response(200, json=[]))
    gh, http = make(r, token="")
    async with http:
        assert await gh.list_commits(REPO) == []
    assert "Authorization" not in r.seen[0].headers


# ------------------------------------------------------------------ writes

BRANCH = "sentinel/fix-inc-1"


async def test_create_branch_posts_ref():
    r = Router()
    r.add("POST", f"/repos/{REPO}/git/refs", httpx.Response(201, json={}))
    gh, http = make(r)
    async with http:
        await gh.create_branch(REPO, BRANCH, "head1")
    assert json.loads(r.seen[0].content) == {"ref": f"refs/heads/{BRANCH}", "sha": "head1"}


async def test_put_file_creates_new_file_without_sha():
    r = Router()
    r.add("PUT", f"/repos/{REPO}/contents/sbom.cdx.json", httpx.Response(201, json={"commit": {"sha": "c9"}, "content": {"html_url": "https://x/y"}}))
    gh, http = make(r)
    async with http:
        out = await gh.put_file(REPO, "sbom.cdx.json", "{}", "add sbom", BRANCH)
    body = json.loads(r.calls("PUT", f"/repos/{REPO}/contents/sbom.cdx.json")[0].content)
    assert "sha" not in body and body["branch"] == BRANCH and base64.b64decode(body["content"]) == b"{}"
    assert out == {"commit_sha": "c9", "html_url": "https://x/y"}


async def test_put_file_updates_existing_with_current_blob_sha():
    r = Router()
    path = f"/repos/{REPO}/contents/requirements.txt"
    r.add("GET", path, file_json("requirements.txt", "old\n", "blobOLD"))
    r.add("PUT", path, httpx.Response(200, json={"commit": {"sha": "c1"}, "content": {"html_url": "u"}}))
    gh, http = make(r)
    async with http:
        await gh.put_file(REPO, "requirements.txt", "new\n", "bump", BRANCH)
    assert r.seen[0].url.params["ref"] == BRANCH
    assert json.loads(r.calls("PUT", path)[0].content)["sha"] == "blobOLD"


async def test_create_pull_request():
    r = Router()
    r.add("POST", f"/repos/{REPO}/pulls", httpx.Response(201, json={"number": 7, "html_url": f"https://github.com/{REPO}/pull/7"}))
    gh, http = make(r)
    async with http:
        pr = await gh.create_pull_request(REPO, "Fix", BRANCH, "main", "body")
    assert pr == {"number": 7, "html_url": f"https://github.com/{REPO}/pull/7"}
    assert json.loads(r.seen[0].content) == {"title": "Fix", "head": BRANCH, "base": "main", "body": "body"}


async def test_write_safety_guards_make_no_requests():
    r = Router()
    gh, http = make(r)
    async with http:
        with pytest.raises(GitHubError, match="allowlist"):
            await gh.create_branch("evil/other-repo", BRANCH, "s")
        with pytest.raises(GitHubError, match="sentinel/fix-"):
            await gh.put_file(REPO, "app.py", "x", "m", "main")
        with pytest.raises(GitHubError, match="sentinel/fix-"):
            await gh.create_pull_request(REPO, "t", "main", "main", "b")
        with pytest.raises(GitHubError, match="sentinel/fix-"):
            await gh.create_branch(REPO, "feature/x", "s")
    assert r.seen == []


async def test_write_requires_token_and_valid_repo_name():
    gh, http = make(Router(), token="")
    async with http:
        with pytest.raises(GitHubError, match="GITHUB_TOKEN"):
            await gh.create_branch(REPO, BRANCH, "s")
        with pytest.raises(GitHubError, match="invalid repo"):
            await gh.list_commits("../../etc/passwd")


# ------------------------------------------------------------------ retries / errors

async def test_retries_5xx_then_succeeds(no_sleep):
    r = Router()
    replies = iter([httpx.Response(502), httpx.Response(503), httpx.Response(200, json=[])])
    r.add("GET", f"/repos/{REPO}/commits", lambda req: next(replies))
    gh, http = make(r)
    async with http:
        assert await gh.list_commits(REPO) == []
    assert len(r.seen) == 3 and no_sleep == [0.5, 1.0]


async def test_gives_up_after_three_attempts():
    r = Router()
    r.add("GET", f"/repos/{REPO}/commits", httpx.Response(500))
    gh, http = make(r)
    async with http:
        with pytest.raises(GitHubError, match="3 attempts.*HTTP 500"):
            await gh.list_commits(REPO)
    assert len(r.seen) == 3


async def test_transport_error_is_retried_and_reported():
    def boom(request):
        raise httpx.ConnectError("dns", request=request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    gh = GitHubClient(http, token=TOKEN, write_allowlist=[REPO])
    async with http:
        with pytest.raises(GitHubError, match="ConnectError"):
            await gh.list_commits(REPO)


async def test_rate_limit_reset_is_awaited_then_retried(no_sleep):
    r = Router()
    reset = str(int(time.time()) + 5)
    replies = iter([
        httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}, json={"message": "rate limit"}),
        httpx.Response(200, json=[]),
    ])
    r.add("GET", f"/repos/{REPO}/commits", lambda req: next(replies))
    gh, http = make(r)
    async with http:
        assert await gh.list_commits(REPO) == []
    assert len(no_sleep) == 1 and 4 <= no_sleep[0] <= 7


async def test_retry_after_header_honoured(no_sleep):
    r = Router()
    replies = iter([httpx.Response(429, headers={"retry-after": "3"}), httpx.Response(200, json=[])])
    r.add("GET", f"/repos/{REPO}/commits", lambda req: next(replies))
    gh, http = make(r)
    async with http:
        await gh.list_commits(REPO)
    assert no_sleep == [3.0]


async def test_long_rate_limit_fails_fast_without_sleeping(no_sleep):
    r = Router()
    reset = str(int(time.time()) + 3000)
    r.add("GET", f"/repos/{REPO}/commits", httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}))
    gh, http = make(r)
    async with http:
        with pytest.raises(GitHubError, match="rate limit"):
            await gh.list_commits(REPO)
    assert no_sleep == [] and len(r.seen) == 1


async def test_plain_403_is_not_retried_and_token_never_leaks():
    r = Router()
    r.add("GET", f"/repos/{REPO}/commits", httpx.Response(403, json={"message": f"Resource not accessible {TOKEN}"[:60]}))
    gh, http = make(r)
    async with http:
        with pytest.raises(GitHubError) as exc:
            await gh.list_commits(REPO)
    assert exc.value.status == 403 and len(r.seen) == 1 and TOKEN not in str(exc.value)


async def test_404_maps_to_not_found_and_422_to_error():
    r = Router()
    r.add("POST", f"/repos/{REPO}/git/refs", httpx.Response(422, json={"message": "Reference already exists"}))
    gh, http = make(r)
    async with http:
        with pytest.raises(GitHubNotFound):
            await gh.get_commit(REPO, "deadbeef")
        with pytest.raises(GitHubError, match="422.*already exists"):
            await gh.create_branch(REPO, BRANCH, "s")


async def test_invalid_json_body_raises_clean_error():
    r = Router()
    r.add("GET", f"/repos/{REPO}/commits", httpx.Response(200, text="<html>"))
    gh, http = make(r)
    async with http:
        with pytest.raises(GitHubError, match="invalid JSON"):
            await gh.list_commits(REPO)


def test_blob_url():
    assert blob_url(REPO, BRANCH, "sbom.cdx.json") == f"https://github.com/{REPO}/blob/{BRANCH}/sbom.cdx.json"


# ------------------------------------------------------------------ live (opt-in)

@pytest.mark.integration
async def test_live_github_reads_public_repo():
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        pytest.skip("GITHUB_TOKEN not set")
    async with httpx.AsyncClient() as http:
        gh = GitHubClient(http, token=token, write_allowlist=[])
        commits = await gh.list_commits("octocat/Hello-World", "master", per_page=1)
    assert len(commits) == 1 and commits[0].sha


# ------------------------------------------------------------------ finding the code in a real project

def tree_client(paths):
    """A client whose repository tree holds `paths`; every file's content is its own path."""
    import base64

    def handler(request: httpx.Request) -> httpx.Response:
        url = request.url.path
        if "/git/trees/" in url:
            return httpx.Response(200, json={"tree": [{"path": p, "type": "blob"} for p in paths]})
        path = url.split("/contents/", 1)[1]
        return httpx.Response(200, json={"type": "file", "encoding": "base64", "sha": "s",
                                         "content": base64.b64encode(path.encode()).decode()})

    return GitHubClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), token="t", write_allowlist=[])


async def test_python_code_is_found_in_nested_packages():
    """Regression: pallets/click keeps its code in src/click/, which used to scan as 0 files and report no problems."""
    gh = tree_client(["src/click/core.py", "src/click/types.py", "README.md"])
    assert sorted(await gh.fetch_python_sources("pallets/click", "main")) == ["src/click/core.py", "src/click/types.py"]


async def test_application_code_is_kept_before_tests_when_a_repo_hits_the_cap():
    gh = tree_client(["tests/test_a.py", "docs/conf.py", "test_root.py", "pkg/deep/er/mod.py", "pkg/core.py"])
    assert list(await gh.fetch_python_sources("a/b", "main", cap=2)) == ["pkg/core.py", "pkg/deep/er/mod.py"]


async def test_vendored_folders_are_not_treated_as_the_project():
    gh = tree_client(["node_modules/x/y.py", "venv/lib/z.py", "app.py"])
    assert list(await gh.fetch_python_sources("a/b", "main")) == ["app.py"]
