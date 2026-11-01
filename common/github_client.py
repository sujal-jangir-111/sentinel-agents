"""Async GitHub REST v3 client: commits, diffs, file contents, branches, PRs.

Safety (CLAUDE.md §15), enforced here so no agent can bypass it:
- writes only go to repos on the allowlist (DEMO_REPO_FULL_NAME + GITHUB_WRITE_ALLOWLIST);
- writes only touch `sentinel/fix-*` branches, never main;
- the token is never logged or included in error messages.
"""
import asyncio
import base64
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import httpx

from common.config import get_settings
from common.http_retry import send_with_retry

API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
FIX_BRANCH_PREFIX = "sentinel/fix-"
MAX_RATE_LIMIT_WAIT = 30.0  # seconds; longer waits fail fast instead of freezing a demo
TIMEOUT_SECONDS = 20.0
MANIFEST_FILES = ("requirements.txt", "pyproject.toml", "package.json", "Dockerfile")

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php", ".rs", ".cs", ".kt", ".swift", ".c", ".cpp", ".h")
SECONDARY_DIRS = {"test", "tests", "docs", "doc", "examples", "example", "benchmarks", "migrations"}
PYTHON_FILE_CAP = 50
SKIPPED_DIRS = {"node_modules", "vendor", "dist", "build", "venv", ".venv", "__pycache__", "site-packages", "third_party", ".git"}


class GitHubError(Exception):
    def __init__(self, message: str, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status


class GitHubNotFound(GitHubError):
    pass


@dataclass(frozen=True)
class FileContent:
    path: str
    text: str
    sha: str


@dataclass(frozen=True)
class ChangedFile:
    filename: str
    status: str
    patch: str = ""


@dataclass(frozen=True)
class CommitInfo:
    sha: str
    url: str
    author: str
    message: str
    committed_at: str
    parents: List[str] = field(default_factory=list)
    files: List[ChangedFile] = field(default_factory=list)


def parse_commit(data: Dict[str, Any]) -> CommitInfo:
    commit = data.get("commit") or {}
    git_author = commit.get("author") or {}
    author = (data.get("author") or {}).get("login") or git_author.get("name") or "unknown"
    return CommitInfo(
        sha=data["sha"],
        url=data.get("html_url", ""),
        author=author,
        message=commit.get("message", ""),
        committed_at=git_author.get("date", ""),
        parents=[p["sha"] for p in data.get("parents") or []],
        files=[
            ChangedFile(f.get("filename", ""), f.get("status", ""), f.get("patch") or "")
            for f in data.get("files") or []
        ],
    )


def _rate_limit_wait(resp: httpx.Response) -> Optional[float]:
    """Seconds to wait if this is a rate-limit response, raising if the wait is too long."""
    if resp.status_code not in (403, 429):
        return None
    headers = resp.headers
    try:
        if headers.get("retry-after"):
            wait = float(headers["retry-after"])
        elif headers.get("x-ratelimit-remaining") == "0":
            wait = max(0.0, float(headers.get("x-ratelimit-reset", "0")) - time.time()) + 1.0
        else:
            return None  # plain permission error, or a 429 handled by generic backoff
    except ValueError:
        return None
    if wait > MAX_RATE_LIMIT_WAIT:
        raise GitHubError(f"GitHub rate limit reached; resets in {int(wait)}s", resp.status_code)
    return wait


class GitHubClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        token: Optional[str] = None,
        write_allowlist: Optional[Iterable[str]] = None,
    ) -> None:
        cfg = get_settings()
        self._client = client
        self._token = cfg.github_token if token is None else token
        if write_allowlist is None:
            write_allowlist = [cfg.demo_repo_full_name, *cfg.github_write_allowlist]
        self._write_allowlist = {r.lower() for r in write_allowlist if r}

    # ------------------------------------------------------------------ plumbing

    @staticmethod
    def _check_repo(repo: str) -> None:
        if not _REPO_RE.match(repo):
            raise GitHubError(f"invalid repo name {repo!r} (expected owner/name)")

    def _check_write(self, repo: str, branch: Optional[str] = None) -> None:
        self._check_repo(repo)
        if repo.lower() not in self._write_allowlist:
            raise GitHubError(f"write refused: {repo} is not on the write allowlist")
        if not self._token:
            raise GitHubError("write refused: GITHUB_TOKEN is not configured")
        if branch is not None and not branch.startswith(FIX_BRANCH_PREFIX):
            raise GitHubError(f"write refused: only {FIX_BRANCH_PREFIX}* branches may be modified (got {branch!r})")

    async def _api(
        self, method: str, path: str, *, accept: str = "application/vnd.github+json", **kwargs: Any
    ) -> httpx.Response:
        headers = {"Accept": accept, "X-GitHub-Api-Version": API_VERSION}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        resp = await send_with_retry(
            self._client, method, f"{API_BASE}{path}", error_cls=GitHubError, label=f"GitHub {method} {path}",
            wait_hint=_rate_limit_wait, headers=headers, timeout=TIMEOUT_SECONDS, **kwargs,
        )
        if resp.status_code >= 400:
            try:
                detail = str(resp.json().get("message", ""))[:200]
            except ValueError:
                detail = ""
            exc_cls = GitHubNotFound if resp.status_code == 404 else GitHubError
            raise exc_cls(f"GitHub {method} {path} failed: HTTP {resp.status_code} {detail}".strip(), resp.status_code)
        return resp

    @staticmethod
    def _json(resp: httpx.Response) -> Any:
        try:
            return resp.json()
        except ValueError as exc:
            raise GitHubError("GitHub returned invalid JSON") from exc

    # ------------------------------------------------------------------ reads

    async def get_repo(self, repo: str) -> Optional[Dict[str, Any]]:
        """{full_name, default_branch, private} of a repository this token can read, or None."""
        self._check_repo(repo)
        try:
            data = self._json(await self._api("GET", f"/repos/{repo}"))
        except GitHubNotFound:
            return None
        return {"full_name": data.get("full_name") or repo, "default_branch": data.get("default_branch") or "main",
                "private": bool(data.get("private"))}

    async def list_source_paths(self, repo: str, ref: str, cap: int = 5000) -> List[str]:
        """Source files anywhere in the repo, without vendored or generated folders. [] if the tree is unreadable."""
        self._check_repo(repo)
        try:
            data = self._json(await self._api("GET", f"/repos/{repo}/git/trees/{quote(ref, safe='')}", params={"recursive": "1"}))
        except GitHubNotFound:
            return []
        paths = [e["path"] for e in data.get("tree") or [] if e.get("type") == "blob" and _is_source(e.get("path", ""))]
        return paths[:cap]

    async def list_commits(self, repo: str, branch: str = "main", per_page: int = 5) -> List[CommitInfo]:
        """Most recent commits on `branch` (list endpoint carries no file patches)."""
        self._check_repo(repo)
        resp = await self._api("GET", f"/repos/{repo}/commits", params={"sha": branch, "per_page": per_page})
        return [parse_commit(c) for c in self._json(resp)]

    async def get_commit(self, repo: str, sha: str) -> CommitInfo:
        """A single commit including per-file patches."""
        self._check_repo(repo)
        return parse_commit(self._json(await self._api("GET", f"/repos/{repo}/commits/{quote(sha, safe='')}")))

    async def get_file(self, repo: str, path: str, ref: Optional[str] = None) -> Optional[FileContent]:
        """Decoded file text + blob sha, or None if the file does not exist."""
        self._check_repo(repo)
        url = f"/repos/{repo}/contents/{quote(path, safe='/')}"
        params = {"ref": ref} if ref else None
        try:
            data = self._json(await self._api("GET", url, params=params))
        except GitHubNotFound:
            return None
        if not isinstance(data, dict) or data.get("type") != "file":
            raise GitHubError(f"{path} is not a file")
        if data.get("encoding") == "base64" and data.get("content"):
            text = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        else:  # files over 1 MB come back without inline content
            raw = await self._api("GET", url, params=params, accept="application/vnd.github.raw+json")
            text = raw.text
        return FileContent(path=path, text=text, sha=data.get("sha", ""))

    async def list_directory(self, repo: str, path: str = "", ref: Optional[str] = None) -> List[Dict[str, str]]:
        """Entries ({name, path, type}) of a directory; [] if it does not exist."""
        self._check_repo(repo)
        try:
            resp = await self._api(
                "GET", f"/repos/{repo}/contents/{quote(path, safe='/')}".rstrip("/"),
                params={"ref": ref} if ref else None,
            )
        except GitHubNotFound:
            return []
        data = self._json(resp)
        if not isinstance(data, list):
            return []
        return [{"name": e["name"], "path": e["path"], "type": e["type"]} for e in data]

    async def fetch_manifests(self, repo: str, ref: Optional[str] = None) -> Dict[str, str]:
        """Root-level requirements.txt / pyproject.toml / package.json / Dockerfile that exist."""
        files = await asyncio.gather(*(self.get_file(repo, name, ref) for name in MANIFEST_FILES))
        return {f.path: f.text for f in files if f is not None}

    async def fetch_python_sources(
        self, repo: str, ref: Optional[str] = None, cap: int = PYTHON_FILE_CAP, dirs: Iterable[str] = ("", "app", "src")
    ) -> Dict[str, str]:
        """`.py` files wherever they live (real projects keep code in src/<package>/), application code before tests,
        at most `cap` files. `dirs` is only the fallback for a repository whose tree cannot be listed."""
        tree = await self.list_source_paths(repo, ref) if ref else []
        paths = sorted((p for p in tree if p.endswith(".py")), key=_python_priority)
        if not paths:
            listings = await asyncio.gather(*(self.list_directory(repo, d, ref) for d in dirs))
            paths = [e["path"] for entries in listings for e in entries if e["type"] == "file" and e["name"].endswith(".py")]
        files = await asyncio.gather(*(self.get_file(repo, p, ref) for p in paths[:cap]))
        return {f.path: f.text for f in files if f is not None}

    async def get_branch_sha(self, repo: str, branch: str = "main") -> str:
        self._check_repo(repo)
        data = self._json(await self._api("GET", f"/repos/{repo}/git/ref/heads/{quote(branch, safe='/')}"))
        try:
            return data["object"]["sha"]
        except (KeyError, TypeError) as exc:
            raise GitHubError(f"unexpected ref response for branch {branch}") from exc

    # ------------------------------------------------------------------ writes (guarded)

    async def create_branch(self, repo: str, name: str, from_sha: str) -> None:
        self._check_write(repo, name)
        await self._api("POST", f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{name}", "sha": from_sha})

    async def put_file(self, repo: str, path: str, content: str, message: str, branch: str) -> Dict[str, str]:
        """Create or update a file on `branch` (looks up the current blob sha when it exists)."""
        self._check_write(repo, branch)
        existing = await self.get_file(repo, path, branch)
        body: Dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if existing:
            body["sha"] = existing.sha
        data = self._json(await self._api("PUT", f"/repos/{repo}/contents/{quote(path, safe='/')}", json=body))
        return {
            "commit_sha": (data.get("commit") or {}).get("sha", ""),
            "html_url": (data.get("content") or {}).get("html_url", ""),
        }

    async def create_pull_request(self, repo: str, title: str, head: str, base: str, body: str) -> Dict[str, Any]:
        """Open a PR from a sentinel/fix-* branch. Auto-merge is never enabled."""
        self._check_write(repo, head)
        data = self._json(await self._api(
            "POST", f"/repos/{repo}/pulls", json={"title": title, "head": head, "base": base, "body": body},
        ))
        return {"number": data.get("number"), "html_url": data.get("html_url", "")}

    async def find_open_pull_request(self, repo: str, head_branch: str) -> Optional[Dict[str, Any]]:
        """The open PR whose head is `head_branch` (makes PR creation idempotent), or None."""
        self._check_repo(repo)
        owner = repo.split("/", 1)[0]
        data = self._json(await self._api("GET", f"/repos/{repo}/pulls", params={"head": f"{owner}:{head_branch}", "state": "open"}))
        if not isinstance(data, list) or not data:
            return None
        return {"number": data[0].get("number"), "html_url": data[0].get("html_url", "")}


def _is_source(path: str) -> bool:
    parts = path.split("/")
    return path.lower().endswith(SOURCE_SUFFIXES) and not SKIPPED_DIRS.intersection(p.lower() for p in parts[:-1])


def _python_priority(path: str) -> Tuple[bool, int, str]:
    """Application code first, then shallow paths: when a large repo hits the cap, tests and docs are what get dropped."""
    parts = path.lower().split("/")
    secondary = bool(SECONDARY_DIRS.intersection(parts[:-1])) or parts[-1].startswith("test_")
    return secondary, len(parts), path


def blob_url(repo: str, branch: str, path: str) -> str:
    """Browser URL of a file on a branch (used for the SBOM link)."""
    return f"https://github.com/{repo}/blob/{branch}/{path}"
