"""Chat intent parsing for the Orchestrator (CLAUDE.md §5.1): regex first, LLM only as a fallback.

`parse_intent` is pure. It extracts the service URL, the `owner/repo`, the mode and, when the user
is answering an approval prompt, the action (approve / reject / rollback / status).
"""
import re
from dataclasses import dataclass
from typing import Optional

MODES = ("diagnose_and_heal", "security_audit", "chaos_test", "status")

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_REPO_RE = re.compile(r"(?<![\w./:@-])([A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)(?![\w/])")
_GITHUB_RE = re.compile(r"github\.com[/:]([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*)", re.IGNORECASE)
_INCIDENT_RE = re.compile(r"\b(inc-[0-9a-f]{8}|auto-[0-9a-f]{8})\b", re.IGNORECASE)
_NOT_REPOS = {"and/or", "w/o", "n/a", "i/o", "tcp/ip", "yes/no", "y/n", "either/or", "http/https"}

_APPROVE = re.compile(r"^\W*(approve[ds]?|yes|y|ok|okay|confirm(ed)?|authori[sz]e[ds]?|go ahead|proceed|ship it|do it|lgtm)\b", re.I)
_REJECT = re.compile(r"^\W*(reject(ed)?|no|n|deny|denied|decline[d]?|cancel(led)?|abort|stop|don'?t|do not)\b", re.I)
_ROLLBACK = re.compile(r"\brollback\b|\broll back\b|\brevert\b", re.I)
_STATUS = re.compile(r"\b(status|progress|where are we|what'?s happening|update)\b", re.I)
_AUDIT = re.compile(r"\b(audit|security scan|vulnerabilit|cve|sast|sbom|scan)\b", re.I)
_CHAOS = re.compile(r"\b(chaos|simulate (a )?(fault|failure|outage)|inject|break (the )?(service|target))\b", re.I)
_HEAL = re.compile(r"\b(diagnos|heal|fix|repair|outage|down|broken|failing|500|error|incident|recover|investigate)\w*", re.I)


@dataclass(frozen=True)
class Intent:
    mode: Optional[str] = None  # one of MODES when this is a new request
    repo: Optional[str] = None
    url: Optional[str] = None
    action: Optional[str] = None  # "approve" | "reject" | "rollback" | None
    incident_id: Optional[str] = None

    @property
    def is_request(self) -> bool:
        return self.mode is not None

    @property
    def is_complete(self) -> bool:
        return self.mode == "status" or bool(self.repo and (self.url or self.mode == "security_audit"))


def extract_url(text: str) -> Optional[str]:
    m = _URL_RE.search(text)
    return m.group(0).rstrip(".,;:!?") if m else None


def extract_repo(text: str) -> Optional[str]:
    """First `owner/repo` outside of URLs."""
    for m in _REPO_RE.finditer(_URL_RE.sub(" ", text)):
        candidate = m.group(1).rstrip(".")
        if candidate.lower() not in _NOT_REPOS:
            return candidate
    return None


def extract_service_url(text: str) -> Optional[str]:
    """The first URL that is not GitHub itself: a repository link is not the service to test."""
    urls = (u.rstrip(".,;:!?") for u in _URL_RE.findall(text))
    return next((u for u in urls if "github.com" not in u.lower()), None)


def extract_github_repo(text: str) -> Optional[str]:
    """owner/repo from a GitHub link (https, ssh, or with a deeper path), else from a bare owner/repo."""
    link = _GITHUB_RE.search(text)
    if link:
        name = link.group(2).rstrip(".")
        return f"{link.group(1)}/{name[:-4] if name.lower().endswith('.git') else name}"
    return extract_repo(text)


def parse_action(text: str) -> Optional[str]:
    """approve / reject / rollback for short answers to an approval prompt."""
    stripped = text.strip()
    if len(stripped.split()) > 12:  # a long sentence is a new request, not an answer
        return None
    if _ROLLBACK.search(stripped):
        return "rollback"
    if _APPROVE.match(stripped):
        return "approve"
    if _REJECT.match(stripped):
        return "reject"
    return None


def parse_intent(text: str) -> Intent:
    url, repo = extract_url(text), extract_repo(text)
    incident = _INCIDENT_RE.search(text)
    incident_id = incident.group(1).lower() if incident else None
    action = parse_action(text)
    if action and not url:
        return Intent(action=action, incident_id=incident_id, repo=repo)

    if _STATUS.search(text) and not (url and _HEAL.search(text)):
        return Intent(mode="status", incident_id=incident_id, repo=repo, url=url)
    if _CHAOS.search(text):
        mode: Optional[str] = "chaos_test"
    elif _AUDIT.search(text) and not re.search(r"\b(outage|down|failing|500)\b", text, re.I):
        mode = "security_audit"
    elif _HEAL.search(text) or url:
        mode = "diagnose_and_heal"
    elif repo and _AUDIT.search(text):
        mode = "security_audit"
    else:
        mode = None
    return Intent(mode=mode, repo=repo, url=url, incident_id=incident_id)
