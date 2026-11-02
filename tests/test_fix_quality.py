"""Regressions from a live test with planted bugs: a fix must be right, not only safe.

Each test names what went wrong on the real repository before it was fixed.
"""
import json
from dataclasses import replace

import httpx
import pytest

from agents.Agent_1 import Orchestrator
from agents.Agent_3 import CommitDetective
from agents.Agent_5 import RemediationExecutor
from common import gatekeeper
from common.code_checks import broken_references
from common.code_search import code_context, rank_sources, read_order, report_words
from common.commit_scoring import changed_error_line, locate_in_repo
from common.config import Settings
from common.dependency_check import companion_upgrades, find_conflicts, new_conflicts, pick_version
from common.github_client import ChangedFile, CommitInfo, GitHubClient
from common.llm_client import LLMClient
from common.models import CommitCorrelationRequest, IncidentRequest, IncidentUpdate, PatchDraftResult, PatchVettingRequest
from common.patching import bump_requirements
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from tests.fakes import ASI1_URL, FakeWeb, llm_reply, make_evidence, make_vuln_report, commit_json
from web.views import incident_view

INC = "inc-1234abcd"
SCANNER = "agent1qscannerscannerscannerscannerscannerscanner"
GATEWAY = "agent1qgatewaygatewaygatewaygatewaygatewaygateway"
ADDR = {"watchdog": "agent1qwatchdogwatchdogwatchdogwatchdogwatchdog", "detective": "agent1qdetectivedetectivedetectivedetectivedetec",
        "scanner": SCANNER, "executor": "agent1qexecutorexecutorexecutorexecutorexecutor"}


def report(snippet, endpoint="") -> CommitCorrelationRequest:
    return CommitCorrelationRequest(incident_id=INC, repo_full_name="acme/sentinel-target", branch="main",
                                    failure_timestamp_utc="2026-03-01T12:00:00Z", failing_endpoint=endpoint, error_snippet=snippet)


def detective(web: FakeWeb) -> CommitDetective:
    http = web.client()
    return CommitDetective(gh=GitHubClient(http, token="t", write_allowlist=[]), llm=LLMClient(http, api_key="k", base_url=ASI1_URL))


def store_web() -> FakeWeb:
    web = FakeWeb()
    web.github.files = {
        "store/routes.py": "from store import cart\n\ndef coupon(total, percent):\n    return cart.apply_coupon(total, percent)\n",
        "store/cart.py": 'def apply_coupon(total, percent):\n    """10 means 10% off."""\n    return total - percent\n',
        "store/shipping.py": "def shipping_cost(subtotal):\n    return 0.0 if subtotal >= 50 else 4.99\n",
        "tests/test_cart.py": "def test_nothing():\n    pass\n",
    }
    return web


# ------------------------------------------------------------------ cause 1: a traceback keeps its file and line

async def test_a_pasted_traceback_reaches_the_agents_word_for_word():
    """Live: the model's summary dropped `File "...", line 9`, so a pasted traceback told the Detective nothing."""
    from tests.test_web_assistant import FakeActions, ScriptedLLM, tool_call
    from web.assistant import Assistant
    actions = FakeActions()
    typed = 'Dashboard crashes. https://github.com/acme/shop\n\nFile "/srv/store/reports.py", line 9, in average\nZeroDivisionError'
    llm = ScriptedLLM(tool_call("run_sentinel", mode="diagnose_and_heal", repo="acme/shop", problem="Dashboard crashes with ZeroDivisionError"))
    await Assistant(llm, actions).reply([], typed)
    problem = actions.started[0][2]
    assert 'File "/srv/store/reports.py", line 9' in problem and "Dashboard crashes with ZeroDivisionError" in problem


async def test_a_short_go_ahead_does_not_replace_the_report():
    from tests.test_web_assistant import FakeActions, ScriptedLLM, tool_call
    from web.assistant import Assistant
    actions = FakeActions()
    llm = ScriptedLLM(tool_call("run_sentinel", mode="diagnose_and_heal", repo="acme/shop", problem="cart is wrong"))
    earlier = [{"role": "user", "content": "The cart total is wrong for every customer at checkout"},
               {"role": "assistant", "content": "Which repository?"}]
    await Assistant(llm, actions).reply(earlier, "https://github.com/acme/shop yes, go")
    assert "The cart total is wrong for every customer" in actions.started[0][2]


# ------------------------------------------------------------------ cause 5: blame needs the failing line

def commit(filename: str, patch: str) -> CommitInfo:
    return CommitInfo(sha="a" * 40, url="", author="a", message="m", committed_at="2026-01-01T00:00:00Z", parents=[],
                      files=[ChangedFile(filename=filename, status="modified", patch=patch)])


def test_a_commit_is_only_blamed_for_lines_it_changed():
    """Live: a commit that appended to app.py was blamed for a crash on an old line of the same file."""
    tail = commit("app.py", "@@ -108,3 +108,6 @@\n x\n+y\n+z\n w")
    assert not changed_error_line(tail, "app.py", 90)
    assert changed_error_line(tail, "app.py", 109)


def test_the_error_location_is_the_innermost_frame_in_this_repository():
    snippet = ('File "/srv/app/store/reports.py", line 9, in average\n'
               'File "/usr/lib/python3.11/json/decoder.py", line 337, in decode\n')
    assert locate_in_repo(snippet, ["store/reports.py", "app.py"]) == ("store/reports.py", 9)


def test_two_files_with_one_name_are_told_apart_by_their_folders():
    paths = ["views.py", "api/views.py", "admin/views.py"]
    assert locate_in_repo('File "/srv/src/api/views.py", line 3, in x', paths) == ("api/views.py", 3)


def test_an_error_outside_the_repository_locates_nothing():
    assert locate_in_repo('File "/usr/lib/python3.11/json/decoder.py", line 337', ["app.py"]) == (None, None)


async def test_an_old_bug_blames_no_commit_and_forces_no_line_out(ctx):
    """Live: blaming that commit made the gatekeeper demand its lines go, so the fix deleted every store route."""
    web = FakeWeb()
    web.github.commits = [commit_json("b" * 40, "Expose store features", "2026-02-01T00:00:00Z",
                                      [{"filename": "app.py", "status": "modified", "patch": "@@ -200,1 +200,3 @@\n x\n+y\n+z"}])]
    web.llm = lambda r: llm_reply("KeyError on the discount lookup.")
    await detective(web).handle_request(ctx, "orch", report('File "/srv/app.py", line 90, in checkout\nKeyError: x'))
    (_, ev), = ctx.sent
    assert ev.offending_file == "app.py" and ev.suspect_commit_sha == "" and ev.offending_diff_snippet == ""
    assert ev.confidence == "high"     # the location is known; only the commit isn't


# ------------------------------------------------------------------ cause 2: the Detective reads the code

def test_the_reports_words_rank_the_file_that_holds_the_logic():
    sources = {"store/routes.py": "def coupon(): return cart.apply_coupon()", "store/cart.py": "def apply_coupon(total, percent): ...",
               "store/shipping.py": "def shipping_cost(): ..."}
    assert rank_sources("a 10% coupon on a cart is wrong", sources)[0][0] == "store/cart.py"


def test_application_code_is_read_before_tests():
    order = read_order("cart total", ["tests/test_cart.py", "store/cart.py", "docs/cart.py", "store/other.py"])
    assert order.index("store/cart.py") < order.index("tests/test_cart.py") and order[0] == "store/cart.py"


def test_snake_case_is_searchable_and_filler_words_are_not():
    assert {"discount", "rate"} <= report_words("discount_rate is missing") and "please" not in report_words("please fix the bug")


def test_context_keeps_whole_files_within_the_budget():
    sources = {"big.py": "cart " * 500, "small.py": "cart"}
    context = code_context("cart", sources, limit=100)
    assert "small.py" in context and "big.py" not in context


async def test_the_detective_is_shown_the_code_and_told_to_look_past_callers(ctx):
    """Live: choosing from file names alone, it blamed store/routes.py for bugs in the functions it only calls."""
    web = store_web()
    web.github.commits = []
    prompts = []

    def reply(request):
        body = json.loads(request.content)
        prompts.append(body["messages"])
        return llm_reply(json.dumps({"file": "store/cart.py", "sha": ""}) if len(prompts) == 1 else "It subtracts the percent as dollars.")

    web.llm = reply
    web.github.commits = [commit_json("c" * 40, "Add routes", "2026-02-01T00:00:00Z",
                                      [{"filename": "store/routes.py", "status": "added", "patch": "@@ -0,0 +1,4 @@\n+x"}])]
    await detective(web).handle_request(ctx, "orch", report("A 10% coupon on a $200 cart gives $190"))
    (_, ev), = ctx.sent
    assert ev.offending_file == "store/cart.py" and ev.confidence == "low"
    assert "return total - percent" in prompts[0][1]["content"] and "only calls or routes" in prompts[0][0]["content"]


async def test_a_commit_is_not_named_for_a_file_it_never_touched(ctx):
    web = store_web()
    web.github.commits = [commit_json("c" * 40, "Add routes", "2026-02-01T00:00:00Z",
                                      [{"filename": "store/routes.py", "status": "added", "patch": "@@ -0,0 +1,4 @@\n+x"}])]
    calls = []
    web.llm = lambda r: (calls.append(1), llm_reply(json.dumps({"file": "store/cart.py", "sha": "c" * 40}) if len(calls) == 1 else "x"))[1]
    await detective(web).handle_request(ctx, "orch", report("coupon wrong"))
    (_, ev), = ctx.sent
    assert ev.offending_file == "store/cart.py" and ev.suspect_commit_sha == ""


async def test_a_model_that_shrugs_gets_the_keyword_match_for_the_fixer_to_check(ctx):
    """Live: gpt-oss-20b answered an empty file for reports that named the code plainly, so obvious bugs went unfixed."""
    web = store_web()
    web.github.commits = [commit_json("c" * 40, "x", "2026-02-01T00:00:00Z", [])]
    calls = []
    web.llm = lambda r: (calls.append(1), llm_reply(json.dumps({"file": "", "sha": ""}) if len(calls) == 1 else "x"))[1]
    await detective(web).handle_request(ctx, "orch", report("the coupon on my cart is wrong"))
    (_, ev), = ctx.sent
    assert ev.offending_file == "store/cart.py" and ev.confidence == "low"


async def test_a_file_the_model_never_read_does_not_beat_one_that_matches(ctx):
    """Live: asked about a restock alert, gpt-oss-20b named store/inventory.py from the file list without reading it, over
    store/stock_alerts.py, which it was shown. The Fixer then 'fixed' unrelated bugs there."""
    web = store_web()
    web.github.files["store/inventory.py"] = "def reserve(sku, quantity):\n    return STOCK[sku] > quantity\n"
    web.github.files["store/stock_alerts.py"] = 'def needs_restock(units_left):\n    """Alert when 5 or fewer units are left."""\n    return units_left <= 5\n'
    web.github.commits = [commit_json("c" * 40, "x", "2026-02-01T00:00:00Z", [])]
    calls = []
    web.llm = lambda r: (calls.append(1), llm_reply(json.dumps({"file": "store/inventory.py", "sha": ""}) if len(calls) == 1 else "x"))[1]
    await detective(web).handle_request(ctx, "orch", report("We don't get a restock alert when exactly 5 units are left"))
    (_, ev), = ctx.sent
    assert ev.offending_file == "store/stock_alerts.py"


def test_files_unrelated_to_the_report_are_not_sent():
    context = code_context("cart coupon", {"store/cart.py": "coupon", "store/tax.py": "rates", "store/users.py": "email"})
    assert "store/cart.py" in context and "store/tax.py" not in context and "store/users.py" not in context


async def test_no_file_fitting_is_an_answer(ctx):
    web = store_web()
    web.github.commits = [commit_json("c" * 40, "x", "2026-02-01T00:00:00Z", [])]
    calls = []
    web.llm = lambda r: (calls.append(1), llm_reply(json.dumps({"file": "", "sha": ""}) if len(calls) == 1 else "x"))[1]
    await detective(web).handle_request(ctx, "orch", report("the printer is on fire"))
    (_, ev), = ctx.sent
    assert ev.offending_file == "unknown"


async def test_without_the_llm_the_reports_words_still_find_the_file(ctx):
    web = store_web()
    web.github.commits = [commit_json("c" * 40, "x", "2026-02-01T00:00:00Z", [])]
    await detective(web).handle_request(ctx, "orch", report("the coupon on my cart is wrong"))
    (_, ev), = ctx.sent
    assert ev.offending_file == "store/cart.py"


# ------------------------------------------------------------------ cause 3: nothing to fix is an answer

def executor(web: FakeWeb) -> RemediationExecutor:
    http = web.client()
    return RemediationExecutor(gh=GitHubClient(http, token="t", write_allowlist=[]), llm=LLMClient(http, api_key="k", base_url=ASI1_URL),
                               scanner_address=SCANNER, orchestrator_address="orch", webhook_http=http)


def draft(web: FakeWeb, file: str, problem: str = "shipping is wrong"):
    from common.models import PatchDraftRequest
    ev = make_evidence(INC, snippet="")
    ev = type(ev).model_validate({**ev.dict(), "offending_file": file, "confidence": "low", "suspect_commit_sha": ""})
    vuln = make_vuln_report(INC)
    return PatchDraftRequest(incident_id=INC, repo_full_name="acme/sentinel-target", commit_evidence=ev, vuln_report=vuln, problem=problem)


async def test_correct_code_is_left_alone(ctx):
    """Live: a false report about correct code ended with `>=` changed to `>`, because "no change" was rejected and retried."""
    web = store_web()
    web.github.files["requirements.txt"] = "pyyaml==5.3\n"
    original = web.github.files["store/shipping.py"]
    prompts = []

    def reply(request):
        prompts.append(1)
        return llm_reply(json.dumps({"verdict": "no_bug", "patched_code": original, "explanation": "Orders of $50 already ship free."}))

    web.llm = reply
    await executor(web).handle_patch_draft_request(ctx, "orch", draft(web, "store/shipping.py"))
    (_, result), = ctx.sent
    assert isinstance(result, PatchDraftResult) and result.no_bug and result.explanation == "Orders of $50 already ship free."
    assert len(prompts) == 1 and not result.attestation.approved


async def test_an_unchanged_answer_is_not_retried_into_a_change(ctx):
    web = store_web()
    web.github.files["requirements.txt"] = "pyyaml==5.3\n"
    original = web.github.files["store/shipping.py"]
    prompts = []
    web.llm = lambda r: (prompts.append(1), llm_reply(json.dumps({"patched_code": original, "explanation": "Looks right."})))[1]
    await executor(web).handle_patch_draft_request(ctx, "orch", draft(web, "store/shipping.py"))
    (_, result), = ctx.sent
    assert result.no_bug and len(prompts) == 1


async def test_a_dependency_report_changes_only_the_pins(ctx):
    """Live: asked about a vulnerable package, the Fixer rewrote working code to stop using it."""
    web = store_web()
    web.github.files["requirements.txt"] = "pyyaml==5.3\n"
    original = web.github.files["store/shipping.py"]
    web.llm = lambda r: llm_reply(json.dumps({"verdict": "dependencies_only", "patched_code": original, "explanation": "Upgrades pyyaml."}))
    await executor(web).handle_patch_draft_request(ctx, "orch", draft(web, "store/shipping.py", "pyyaml is flagged by our scanner"))
    (_, vetting), = ctx.sent
    assert isinstance(vetting, PatchVettingRequest) and vetting.target_file == "requirements.txt"
    assert vetting.patched_code_content == "pyyaml==5.4\n" == vetting.updated_requirements_txt and "pyyaml==5.4" in vetting.unified_diff


def orch() -> Orchestrator:
    cfg = replace(Settings(), demo_repo_full_name="me/repo", demo_service_url="http://demo", github_write_allowlist=[], skip_payment=True)
    return Orchestrator(addresses=ADDR, skip_payment=True, settings=cfg, gateway=GATEWAY)


async def test_the_case_closes_honestly_with_nothing_to_approve(ctx):
    from tests.fakes import make_patch_result
    o = orch()
    await o.handle_incident_request(ctx, GATEWAY, IncidentRequest(incident_id=INC, mode="diagnose_and_heal", repo_full_name="me/repo",
                                                                   branch="main", problem="wrong", service_url="", endpoints=[]))
    await o.handle_evidence(ctx, ADDR["detective"], make_evidence(INC))
    await o.handle_vuln_report(ctx, ADDR["scanner"], make_vuln_report(INC))
    result = make_patch_result(INC, approved=False, rollback=False)
    await o.handle_patch_result(ctx, ADDR["executor"], type(result).model_validate({**result.dict(), "no_bug": True, "explanation": "It is correct."}))
    record = json.loads([m.record_json for _, m in ctx.sent if isinstance(m, IncidentUpdate)][-1])
    view = incident_view(record)
    assert record["state"] == "RESOLVED" and view["phase"] == "done"
    assert view["outcome"] == {"kind": "no_bug", "file": "app.py", "why": "It is correct."}
    assert view["cause"] is None and view["fix"] is None


# ------------------------------------------------------------------ cause 4: what can be seen without running the code

def test_a_standard_library_typo_is_caught():
    """Live: `ast.Truediv` parsed, passed every check, and stopped the app from starting."""
    assert broken_references("import ast\nOPS = {ast.Truediv: 1, ast.Add: 2}\n") == {"ast.Truediv"}


def test_names_nothing_defines_are_caught():
    assert broken_references("def f():\n    return helper(1)\n") == {"helper"}


@pytest.mark.parametrize("code", [
    "import urllib.request\ntry:\n    urllib.request.urlopen('x')\nexcept urllib.error.HTTPError as e:\n    print(e)\n",
    "import os.path as p\nprint(p.join('a'))\n",
    "from os.path import join\nprint(join('a'))\n",
    "import requests\nrequests.anything_at_all()\n",
    "class A:\n    def m(self, x=1):\n        return [y for y in range(x)], __class__, self\n",
    "from somewhere import *\nprint(mystery)\n",
    "def f(ast):\n    return ast.Truediv\nimport ast\n",
    "import ast\nast = None\nprint(ast.Truediv)\n",
    "def broken(:\n",
])
def test_valid_code_is_not_accused(code):
    assert broken_references(code) == set()


def test_only_new_broken_references_block_a_fix():
    old = "print(existing_mystery)\n"
    assert gatekeeper.check_references("a.py", old + "print(1)\n", old) == []
    assert "new_mystery" in gatekeeper.check_references("a.py", old + "print(new_mystery)\n", old)[0]
    assert gatekeeper.check_references("package.json", "{not python", "") == []


# ------------------------------------------------------------------ cause 7: upgrades must install

def fake_pypi(requires: dict, releases: dict = None):
    """`requires` maps "name/version" to its requires_dist; `releases` maps a name to its versions."""
    releases = releases or {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/pypi/").removesuffix("/json").strip("/")
        if path in requires:
            return httpx.Response(200, json={"info": {"requires_dist": requires[path]}})
        if path in releases:
            return httpx.Response(200, json={"releases": {v: [{"yanked": False}] for v in releases[path]}})
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


REQUESTS_233 = {"requests/2.33.0": ["urllib3<3,>=1.26", "certifi>=2023", 'PySocks!=1.5.7; extra == "socks"']}


async def test_a_version_that_cannot_install_is_found():
    """Live: requests==2.33.0 next to urllib3==1.24.1, which pip refuses to install."""
    async with fake_pypi(REQUESTS_233) as http:
        (conflict,) = await find_conflicts(http, "requests==2.33.0\nurllib3==1.24.1\n")
    assert (conflict.dependency, conflict.pinned) == ("urllib3", "1.24.1") and "cannot be installed" in conflict.reason


async def test_optional_extras_are_not_requirements():
    async with fake_pypi(REQUESTS_233) as http:
        assert await find_conflicts(http, "requests==2.33.0\npysocks==1.5.7\n") == []


async def test_the_companion_package_moves_too():
    async with fake_pypi(REQUESTS_233, {"urllib3": ["1.24.1", "1.26.0", "1.26.20", "2.0.0", "2.3.0", "3.0.0a1"]}) as http:
        upgrades, text = await companion_upgrades(http, "requests==2.33.0\nurllib3==1.24.1\n", bump_requirements)
    assert upgrades == {"urllib3": "1.26.20"} and text == "requests==2.33.0\nurllib3==1.26.20\n"


def test_the_smallest_major_upgrade_is_chosen():
    versions = [Version(v) for v in ("1.25.0", "1.26.0", "1.26.20", "2.0.0")]
    assert pick_version(versions, SpecifierSet(">=1.26,<3")) == "1.26.20"
    assert pick_version(versions, SpecifierSet(">=9")) is None


async def test_pypi_being_down_blocks_nothing():
    web = FakeWeb()      # no handler for pypi.org: every call raises ConnectError
    async with web.client() as http:
        assert await find_conflicts(http, "requests==2.33.0\nurllib3==1.24.1\n") == []
        assert await companion_upgrades(http, "requests==2.33.0\n", bump_requirements) == ({}, "requests==2.33.0\n")


async def test_a_project_already_in_conflict_does_not_block_an_unrelated_fix():
    pypi = {**REQUESTS_233, "pyyaml/6.0.1": []}
    async with fake_pypi(pypi) as http:
        before = "requests==2.33.0\nurllib3==1.24.1\npyyaml==5.4\n"
        assert await new_conflicts(http, before, before.replace("pyyaml==5.4", "pyyaml==6.0.1")) == []
        assert len(await new_conflicts(http, "urllib3==1.24.1\n", "requests==2.33.0\nurllib3==1.24.1\n")) == 1


async def test_the_fixer_adds_the_companion_and_reports_every_upgrade(ctx):
    web = store_web()
    web.github.files["requirements.txt"] = "pyyaml==5.3\nurllib3==1.24.1\n"
    pypi = fake_pypi({"pyyaml/5.4": ["urllib3>=1.26"]}, {"urllib3": ["1.24.1", "1.26.20"]})
    http = web.client()
    fixer = RemediationExecutor(gh=GitHubClient(http, token="t", write_allowlist=[]), llm=LLMClient(http, api_key="k", base_url=ASI1_URL),
                                scanner_address=SCANNER, orchestrator_address="orch", webhook_http=pypi)
    changed = web.github.files["store/shipping.py"].replace("4.99", "5.99")
    web.llm = lambda r: llm_reply(json.dumps({"patched_code": changed, "explanation": "x"}))
    await fixer.handle_patch_draft_request(ctx, "orch", draft(web, "store/shipping.py"))
    (_, vetting), = ctx.sent
    assert vetting.updated_requirements_txt == "pyyaml==5.4\nurllib3==1.26.20\n"
    state = json.loads(ctx.storage.get(f"loop:{INC}"))
    assert state["bumps"] == {"pyyaml": "5.4", "urllib3": "1.26.20"}
