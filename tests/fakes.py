"""Offline fakes for GitHub, OSV.dev and ASI:One, served through one httpx.MockTransport.

The fake repository is built from the REAL demo_target_app files, so tests exercise the same
code, line numbers and vulnerabilities that the live demo will.
"""
import base64
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo_target_app"
DEMO_FILES: Dict[str, str] = {
    "app.py": (DEMO_DIR / "app.py").read_text(encoding="utf-8"),
    "requirements.txt": (DEMO_DIR / "requirements.txt").read_text(encoding="utf-8"),
    "Dockerfile": (DEMO_DIR / "Dockerfile").read_text(encoding="utf-8"),
}
_SRC_LINES = DEMO_FILES["app.py"].splitlines()
FAULT_LINE = next(i for i, ln in enumerate(_SRC_LINES, 1) if 'PRICING["discount_rate"]' in ln)
REPO = "acme/sentinel-target"
ASI1_URL = "https://api.asi1.ai/v1/chat/completions"

ERROR_SNIPPET = (
    "HTTP 500 {\"error\":\"KeyError\",\"detail\":\"'discount_rate'\"}\n"
    f"X-Error-File: app.py\nX-Error-Line: {FAULT_LINE}"
)

HEAD_SHA = "c0ffee1" + "0" * 33
README_SHA = "b0b0b0b" + "0" * 33
OLD_SHA = "a1a1a1a" + "0" * 33
MAIN_SHA = "fa1afe1" + "0" * 33


# ------------------------------------------------------------------ commits

def checkout_patch() -> str:
    """Diff hunk (new-file lines FAULT_LINE-3 .. FAULT_LINE+3) that introduces the faulty line."""
    first = FAULT_LINE - 3
    body = []
    for lineno in range(first, FAULT_LINE + 4):
        text = _SRC_LINES[lineno - 1]
        if lineno == FAULT_LINE:
            body += ['-        discount_rate = PRICING.get("discount_rate", 0.0)', f"+{text}"]
        else:
            body.append(f" {text}")
    return f"@@ -{first},7 +{first},7 @@ async def checkout\n" + "\n".join(body)


def commit_json(sha: str, message: str, date: str, files: List[Dict[str, str]], login: str = "alice",
                parents: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        "sha": sha, "html_url": f"https://github.com/{REPO}/commit/{sha}",
        "author": {"login": login},
        "commit": {"message": message, "author": {"name": login.title(), "date": date}},
        "parents": [{"sha": p} for p in (parents or [])], "files": files,
    }


def demo_commits() -> List[Dict[str, Any]]:
    """Newest first: the commit that broke checkout, a README tweak, and an older app.py commit."""
    return [
        commit_json(HEAD_SHA, "Require discount_rate in pricing config", "2026-01-02T10:00:00Z",
                    [{"filename": "app.py", "status": "modified", "patch": checkout_patch()}], parents=[README_SHA]),
        commit_json(README_SHA, "Update README", "2026-01-01T12:00:00Z",
                    [{"filename": "README.md", "status": "modified", "patch": "@@ -1 +1,2 @@\n # demo\n+docs"}]),
        commit_json(OLD_SHA, "Add health endpoint", "2025-12-30T09:00:00Z",
                    [{"filename": "app.py", "status": "modified", "patch": "@@ -20,3 +20,4 @@\n x\n+y\n z"}]),
    ]


# ------------------------------------------------------------------ GitHub

class FakeGitHub:
    def __init__(self, repo: str = REPO, files: Optional[Dict[str, str]] = None,
                 commits: Optional[List[Dict[str, Any]]] = None) -> None:
        self.repo = repo
        self.files = dict(DEMO_FILES) if files is None else files
        self.commits = demo_commits() if commits is None else commits
        self.fail_status: Optional[int] = None
        # write side (Step 10)
        self.branches: Dict[str, str] = {"main": MAIN_SHA}
        self.branch_files: Dict[str, Dict[str, str]] = {}
        self.ref_files: Dict[Tuple[str, str], str] = {}      # (ref, path) -> text, e.g. a parent commit's version of a file
        self.pulls: List[Dict[str, Any]] = []
        self.writes: List[Tuple[str, str, Any]] = []         # (method, path, json body) of every mutating call
        self.fail_write_status: Optional[int] = None

    def _write(self, request: httpx.Request, rest: str) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        self.writes.append((request.method, rest, body))
        if self.fail_write_status:
            return httpx.Response(self.fail_write_status, json={"message": "write failed"})
        if request.method == "POST" and rest == "git/refs":
            name = body["ref"].removeprefix("refs/heads/")
            if name in self.branches:
                return httpx.Response(422, json={"message": "Reference already exists"})
            self.branches[name] = body["sha"]
            return httpx.Response(201, json={"ref": body["ref"]})
        if request.method == "PUT" and rest.startswith("contents/"):
            path, branch = rest[len("contents/"):], body["branch"]
            files = self.branch_files.setdefault(branch, {})
            if (path in self.files or path in files) and not body.get("sha"):
                return httpx.Response(422, json={"message": "\"sha\" wasn't supplied."})
            files[path] = base64.b64decode(body["content"]).decode()
            return httpx.Response(200, json={"commit": {"sha": f"commit-{len(self.writes)}"},
                                             "content": {"html_url": f"https://github.com/{self.repo}/blob/{branch}/{path}"}})
        if request.method == "POST" and rest == "pulls":
            if any(p["head"] == body["head"] for p in self.pulls):
                return httpx.Response(422, json={"message": "A pull request already exists"})
            pull = {**body, "number": len(self.pulls) + 1, "html_url": f"https://github.com/{self.repo}/pull/{len(self.pulls) + 1}"}
            self.pulls.append(pull)
            return httpx.Response(201, json=pull)
        return httpx.Response(404, json={"message": "Not Found"})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.fail_status:
            return httpx.Response(self.fail_status, json={"message": "boom"})
        prefix = f"/repos/{self.repo}/"
        if not request.url.path.startswith(prefix):
            return httpx.Response(404, json={"message": "Not Found"})
        rest = request.url.path[len(prefix):]
        if request.method in ("POST", "PUT"):
            return self._write(request, rest)
        if rest.startswith("git/ref/heads/"):
            sha = self.branches.get(rest[len("git/ref/heads/"):])
            return httpx.Response(200, json={"object": {"sha": sha}}) if sha else httpx.Response(404, json={"message": "Not Found"})
        if rest == "pulls":
            head = request.url.params.get("head", "").split(":", 1)[-1]
            return httpx.Response(200, json=[p for p in self.pulls if p["head"] == head])
        if rest.startswith("git/trees/"):
            return httpx.Response(200, json={"tree": [{"path": p, "type": "blob"} for p in self.files]})
        if rest == "commits":
            return httpx.Response(200, json=[{k: v for k, v in c.items() if k != "files"} for c in self.commits])
        if rest.startswith("commits/"):
            sha = rest.split("/", 1)[1]
            found = next((c for c in self.commits if c["sha"] == sha), None)
            return httpx.Response(200, json=found) if found else httpx.Response(404, json={"message": "Not Found"})
        if rest.startswith("contents"):
            return self._contents(rest[len("contents"):].strip("/"), request.url.params.get("ref"))
        return httpx.Response(404, json={"message": "Not Found"})

    def _contents(self, path: str, ref: Optional[str] = None) -> httpx.Response:
        text = self.ref_files.get((ref or "", path))
        if text is None:
            text = self.branch_files.get(ref or "", {}).get(path)
        if text is None:
            text = self.files.get(path)
        if text is not None:
            return httpx.Response(200, json={
                "type": "file", "path": path, "sha": f"blob-{abs(hash(path)) % 10**6}", "encoding": "base64",
                "content": base64.encodebytes(text.encode()).decode(),
            })
        depth = path.count("/") + 1 if path else 0
        entries: Dict[str, str] = {}
        for file_path in self.files:
            if path and not file_path.startswith(path + "/"):
                continue
            parts = file_path.split("/")
            if len(parts) == depth + 1:
                entries[file_path] = "file"
            elif len(parts) > depth + 1:
                entries["/".join(parts[: depth + 1])] = "dir"
        if not entries:
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, json=[
            {"name": p.rsplit("/", 1)[-1], "path": p, "type": t} for p, t in sorted(entries.items())
        ])


# ------------------------------------------------------------------ OSV

VULN_PYYAML_CRITICAL = {
    "id": "GHSA-8q59-q68h-6hv4", "summary": "Improper Input Validation in PyYAML",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{"package": {"name": "PyYAML", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}],
}
VULN_PYYAML_HIGH = {
    "id": "GHSA-6757-jp84-gxfx", "summary": "Arbitrary code execution in PyYAML",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"name": "PyYAML", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.3.1"}]}]}],
}
VULN_URLLIB3 = {
    "id": "GHSA-mh33-7rrq-662w", "summary": "urllib3 CRLF injection",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"name": "urllib3", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.24.2"}]}]}],
}


class FakeOSV:
    def __init__(self) -> None:
        self.vulns = {v["id"]: v for v in (VULN_PYYAML_CRITICAL, VULN_PYYAML_HIGH, VULN_URLLIB3)}
        self.hits: Dict[Tuple[str, str], List[str]] = {
            ("pyyaml", "5.3"): [VULN_PYYAML_CRITICAL["id"], VULN_PYYAML_HIGH["id"]],
            ("urllib3", "1.24.1"): [VULN_URLLIB3["id"]],
        }
        self.fail_status: Optional[int] = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.fail_status:
            return httpx.Response(self.fail_status)
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": i} for i in self.hits.get((q["package"]["name"], q["version"]), [])]} or {}
                for q in queries
            ]})
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=self.vulns[vuln_id]) if vuln_id in self.vulns else httpx.Response(404)


# ------------------------------------------------------------------ ASI:One + dispatcher

def llm_reply(text: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": text}}]})


class FakeWeb:
    """Routes by host. Any host without a handler raises ConnectError (so stray live calls fail loudly)."""

    def __init__(self) -> None:
        self.github = FakeGitHub()
        self.osv = FakeOSV()
        self.llm: Callable[[httpx.Request], httpx.Response] = lambda r: httpx.Response(401, json={"error": "no key"})
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = {"api.github.com": self.github, "api.osv.dev": self.osv, "api.asi1.ai": self.llm}.get(request.url.host)    # pypi.org stays unmocked: a lookup that fails blocks nothing
        if handler is None:
            raise httpx.ConnectError(f"unmocked host {request.url.host}", request=request)
        return handler(request)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self), timeout=30)

    def count(self, host: str) -> int:
        return sum(1 for r in self.requests if r.url.host == host)

    def llm_prompts(self) -> List[str]:
        """User prompts sent to the fake ASI:One endpoint."""
        return [json.loads(r.content)["messages"][1]["content"] for r in self.requests if r.url.host == "api.asi1.ai"]


# ------------------------------------------------------------------ patched-source builders

def runtime_fixed_app_source() -> str:
    """demo app.py with ONLY the runtime fault fixed (secret, unsafe yaml and f-string SQL still present)."""
    fixed = DEMO_FILES["app.py"].replace('discount_rate = PRICING["discount_rate"]', 'discount_rate = PRICING.get("discount_rate", 0.0)')
    assert fixed != DEMO_FILES["app.py"]
    return fixed


def sql_fixed(code: str) -> str:
    old = "f\"SELECT price FROM products WHERE sku = '{sku}'\""
    fixed = code.replace(old, '"SELECT price FROM products WHERE sku = ?", (sku,)')
    assert fixed != code
    return fixed


def fully_fixed_app_source() -> str:
    """What a perfect patch looks like: runtime fix + parameterized SQL + env secret + safe_load."""
    from common.patching import fix_unsafe_yaml, harden_secrets
    return fix_unsafe_yaml(harden_secrets(sql_fixed(runtime_fixed_app_source())))


def draft_adding_a_new_finding() -> str:
    """A patch that fixes everything but introduces a security problem the file did not have."""
    return fully_fixed_app_source().rstrip("\n") + "\n\n\ndef debug(expression: str) -> object:\n    return eval(expression)\n"


# ------------------------------------------------------------------ typed message builders (Orchestrator tests)

def make_probe_report(incident_id: str, healthy: bool = False, url: str = "http://demo", status: int = 500):
    from common.models import EndpointMetric, HealthProbeReport
    ts = "2026-01-02T12:00:00+00:00"
    metrics = [EndpointMetric(endpoint="/health", status_code=200, latency_ms=5.0, timestamp_utc=ts) for _ in range(3)]
    bad_status = 200 if healthy else status
    snippet = None if healthy else (ERROR_SNIPPET if status else "ConnectError: name resolution failed")
    metrics += [EndpointMetric(endpoint="/api/checkout", status_code=bad_status, latency_ms=12.0 if status else 3.0,
                               error_snippet=snippet, timestamp_utc=ts) for _ in range(3)]
    return HealthProbeReport(incident_id=incident_id, service_url=url, is_healthy=healthy, is_canary_check=False, metrics=metrics)


def make_evidence(incident_id: str, snippet: Optional[str] = None):
    from common.models import CommitEvidenceReport
    return CommitEvidenceReport(
        incident_id=incident_id, repo_full_name=REPO, suspect_commit_sha=HEAD_SHA,
        suspect_commit_url=f"https://github.com/{REPO}/commit/{HEAD_SHA}", author="alice",
        commit_message="Require discount_rate in pricing config", committed_at_utc="2026-01-02T10:00:00+00:00",
        offending_file="app.py", offending_diff_snippet=snippet or checkout_patch(),
        root_cause_explanation="checkout reads PRICING['discount_rate'] directly, which the config lacks.",
        active_ast_imports=["yaml", "yaml.load", "sqlite3"],
    )


def make_vuln_report(incident_id: str):
    from common.models import CVEFinding, VulnerabilityReport
    from common.sast_rules import scan_text
    cves = [
        CVEFinding(package_name="pyyaml", installed_version="5.3", fixed_version="5.4", vuln_id="GHSA-8q59-q68h-6hv4",
                   severity="CRITICAL", is_reachable_in_ast=True, summary="s"),
        CVEFinding(package_name="pyyaml", installed_version="5.3", fixed_version="5.3.1", vuln_id="GHSA-6757-jp84-gxfx",
                   severity="HIGH", is_reachable_in_ast=True, summary="s"),
        CVEFinding(package_name="urllib3", installed_version="1.24.1", fixed_version="1.24.2", vuln_id="GHSA-mh33-7rrq-662w",
                   severity="HIGH", is_reachable_in_ast=False, summary="s"),
    ]
    return VulnerabilityReport(incident_id=incident_id, repo_full_name=REPO, cve_findings=cves,
                               sast_findings=scan_text("app.py", DEMO_FILES["app.py"]), total_reachable_critical=1)


def make_patch_result(incident_id: str, approved: bool = True, attempts: int = 1, rollback: bool = True):
    from common.models import PatchDraftResult, SecurityApprovalAttestation
    from common.patching import make_unified_diff
    patched = fully_fixed_app_source()
    att = SecurityApprovalAttestation(
        incident_id=incident_id, approved=approved, attestation_hash="ab12cd34ef567890" * 4 if approved else "",
        rejection_reasons=[] if approved else ["SQL_INJECTION at line 83: f-string query -> use placeholders"],
        target_file="app.py", patched_code_content=patched,
        updated_requirements_txt=DEMO_FILES["requirements.txt"].replace("pyyaml==5.3", "pyyaml==5.4"),
        unified_diff=make_unified_diff(DEMO_FILES["app.py"], patched, "app.py"))
    return PatchDraftResult(incident_id=incident_id, attestation=att, rollback_available=rollback, attempts=attempts)


def smart_llm(patch_codes: List[str], explanation: str = "The suspect commit made checkout read PRICING['discount_rate'] directly, raising KeyError."):
    """One fake ASI:One for the whole swarm: routes on the system prompt (explanation vs. patch drafting)."""
    codes = iter(patch_codes)

    def handler(request: httpx.Request) -> httpx.Response:
        system = json.loads(request.content)["messages"][0]["content"]
        if "root-cause note" in system:
            return llm_reply(explanation)
        if "fixing a production outage" in system:
            return llm_reply(json.dumps({"patched_code": next(codes), "explanation": "fix"}))
        return httpx.Response(401, json={"error": "unexpected prompt"})

    return handler


# ------------------------------------------------------------------ Dorado (offline)

WALLET = "fetch1sentinelorchestratorwallet0000000000000"
PAYER = "fetch1payerwalletpayerwalletpayerwallet000000"
TX_GOOD = "A" * 64
TX_UNDER = "B" * 64
TX_OTHER = "C" * 64
TX_FAILED = "D" * 64
TX_SECOND = "E" * 64
PRICE = 10 ** 17


def make_tx(tx_hash: str, amount: int = PRICE, recipient: str = WALLET, sender: str = PAYER, code: int = 0,
            denom: str = "atestfet", timestamp=None):
    from common.dorado import Transfer, TxInfo
    return TxInfo(tx_hash=tx_hash, code=code, transfers=(Transfer(sender, recipient, amount, denom),), timestamp=timestamp)


class FakeChain:
    """Stands in for Dorado: `fetch` is what DoradoVerifier calls; `lookups` records every attempt."""

    def __init__(self, *txs) -> None:
        self.txs = {t.tx_hash: t for t in txs}
        self.lookups: list = []
        self.gate = None          # optional asyncio.Event to hold lookups open (concurrency tests)

    async def fetch(self, tx_hash: str):
        self.lookups.append(tx_hash)
        if self.gate is not None:
            await self.gate.wait()
        return self.txs.get(tx_hash)


def standard_chain() -> "FakeChain":
    return FakeChain(make_tx(TX_GOOD), make_tx(TX_SECOND), make_tx(TX_UNDER, amount=PRICE - 1),
                     make_tx(TX_OTHER, recipient="fetch1someoneelse0000000000000000000000000"), make_tx(TX_FAILED, code=5))


async def _no_sleep(_: float) -> None:
    return None


def fake_verifier(chain: "FakeChain", attempts: int = 3):
    from common.dorado import DoradoVerifier
    return DoradoVerifier(fetch=chain.fetch, attempts=attempts, delay=0, sleep=_no_sleep)
