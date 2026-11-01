"""Deterministic commit-suspect scoring (CLAUDE.md §5.3). Pure functions, no I/O.

Per changed file:  +50 file matches the error file, +30 a diff hunk covers the error line,
+15 the diff mentions the failing endpoint.  Per commit: best file score, +5 if it is the most
recent commit not after the failure timestamp.

A diff that creates the file (status "added", hunk `@@ -0,0 ...`) covers every line and mentions
every endpoint, so for it those two signals are weak: +10 for the line, nothing for the endpoint.
Otherwise the commit that introduced a file would outrank the later commit that broke it.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple

from common.github_client import ChangedFile, CommitInfo
from common.probe import parse_error_snippet

SCORE_FILE_MATCH = 50
SCORE_LINE_COVERED = 30
SCORE_ENDPOINT = 15
SCORE_RECENT = 5
SCORE_NEW_FILE_LINE = 10   # line "covered" only because the commit created the whole file
MIN_SIGNAL = 15  # below this the ranking is noise and the LLM may break the tie

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@.*$", re.MULTILINE)
_TRACEBACK_RE = re.compile(r'File "([^"]+)", line (\d+)')
_SENTINEL_FIX_RE = re.compile(r"^Sentinel inc-[0-9a-f]{8}: fix .+$", re.MULTILINE)


@dataclass
class ScoredCommit:
    commit: CommitInfo
    score: int
    offending_file: Optional[str]
    reasons: List[str] = field(default_factory=list)


def sentinel_fix_title(message: str) -> Optional[str]:
    """The PR title if this commit merged a Sentinel forward fix (merge-commit body or squash title), else None.
    Rollbacks are titled "roll back ..." and don't match: a merged rollback may well be the real cause of a failure."""
    match = _SENTINEL_FIX_RE.search(message or "")
    return match.group(0) if match else None


def extract_error_location(snippet: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """(file, line) from X-Error-* headers in the snippet, else from the last traceback frame."""
    file, line = parse_error_snippet(snippet)
    if file or line:
        return file, line
    frames = _TRACEBACK_RE.findall(snippet or "")
    if frames:
        path, lineno = frames[-1]
        return path.replace("\\", "/").rsplit("/", 1)[-1], int(lineno)
    return None, None


def _matching_path(path: str, paths: Sequence[str]) -> Optional[str]:
    """The repository file a traceback path means: most trailing folders in common, then the shortest path."""
    wanted = path.replace("\\", "/").strip("/").split("/")

    def shared(candidate: str) -> int:
        count = 0
        for ours, theirs in zip(reversed(candidate.split("/")), reversed(wanted)):
            if ours != theirs:
                break
            count += 1
        return count

    best = max(paths, key=lambda p: (shared(p), -len(p)), default=None)
    return best if best is not None and shared(best) else None


def locate_in_repo(snippet: Optional[str], paths: Sequence[str]) -> Tuple[Optional[str], Optional[int]]:
    """(repository path, line) of the innermost error location that is really this repository's code: a traceback often
    ends inside a library. `paths` lists the repository's files."""
    file, line = parse_error_snippet(snippet)
    frames = [(file, line)] if file else []
    frames += [(path, int(number)) for path, number in reversed(_TRACEBACK_RE.findall(snippet or ""))]
    for path, number in frames:
        found = _matching_path(path, paths)
        if found:
            return found, number
    return None, None


def changed_error_line(commit: CommitInfo, path: str, line: int) -> bool:
    """Touching the same file proves nothing: a bug older than the recent commits still sits in a file they changed."""
    return any(f.filename == path and hunk_covering(f.patch, line) for f in commit.files)


def parse_hunks(patch: str) -> List[Tuple[int, int, str]]:
    """[(first_line, last_line, hunk_text)] using the new-file side of each @@ header."""
    matches = list(_HUNK_RE.finditer(patch))
    hunks = []
    for i, m in enumerate(matches):
        start = int(m.group(1))
        length = int(m.group(2)) if m.group(2) is not None else 1
        end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(patch)
        hunks.append((start, start + max(length, 1) - 1, patch[m.start():end_pos].rstrip("\n")))
    return hunks


def hunk_covering(patch: str, line: Optional[int]) -> Optional[str]:
    if line is None:
        return None
    return next((text for first, last, text in parse_hunks(patch) if first <= line <= last), None)


def file_matches(changed: str, error_file: Optional[str]) -> bool:
    if not error_file:
        return False
    changed, error_file = changed.replace("\\", "/"), error_file.replace("\\", "/")
    return changed == error_file or changed.endswith("/" + error_file) or error_file.endswith("/" + changed)


def is_new_file(f: ChangedFile) -> bool:
    return f.status == "added" or f.patch.lstrip().startswith("@@ -0,0 ")


def score_file(f: ChangedFile, error_file: Optional[str], error_line: Optional[int], endpoint: str) -> Tuple[int, List[str]]:
    score, reasons = 0, []
    new_file = is_new_file(f)
    if file_matches(f.filename, error_file):
        score += SCORE_FILE_MATCH
        reasons.append(f"changes error file {f.filename}")
    if hunk_covering(f.patch, error_line):
        if new_file:
            score += SCORE_NEW_FILE_LINE
            reasons.append(f"creates {f.filename} (line {error_line} included)")
        else:
            score += SCORE_LINE_COVERED
            reasons.append(f"hunk covers line {error_line}")
    if endpoint and endpoint in f.patch and not new_file:
        score += SCORE_ENDPOINT
        reasons.append(f"diff mentions {endpoint}")
    return score, reasons


def parse_iso(value: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def to_utc_iso(value: str) -> str:
    dt = parse_iso(value)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds") if dt else value


def latest_before(commits: Sequence[CommitInfo], failure_ts: str) -> Optional[str]:
    """SHA of the newest commit not after the failure time (all commits are 'before' if the time is unparseable)."""
    failed_at = parse_iso(failure_ts)
    dated = [(parse_iso(c.committed_at), c) for c in commits]
    eligible = [(d, c) for d, c in dated if d is not None and (failed_at is None or d <= failed_at)]
    if not eligible:
        return commits[0].sha if commits else None
    return max(eligible, key=lambda dc: dc[0])[1].sha


def _best_file(commit: CommitInfo, error_file: Optional[str], error_line: Optional[int], endpoint: str) -> Tuple[int, Optional[str], List[str]]:
    best: Tuple[int, Optional[str], List[str]] = (0, None, [])
    for f in commit.files:
        score, reasons = score_file(f, error_file, error_line, endpoint)
        if best[1] is None or score > best[0]:
            best = (score, f.filename, reasons)
    if best[0] == 0:  # no signal: prefer a Python file as the likely culprit
        py = next((f.filename for f in commit.files if f.filename.endswith(".py")), None)
        best = (0, py or best[1], [])
    return best


def rank_commits(
    commits: Sequence[CommitInfo], error_file: Optional[str], error_line: Optional[int],
    endpoint: str, failure_ts: str,
) -> List[ScoredCommit]:
    """Highest score first; ties keep the input (newest-first) order."""
    recent = latest_before(commits, failure_ts)
    scored = []
    for c in commits:
        score, file, reasons = _best_file(c, error_file, error_line, endpoint)
        if c.sha == recent:
            score += SCORE_RECENT
            reasons = reasons + ["most recent commit before failure"]
        scored.append(ScoredCommit(c, score, file, reasons))
    return sorted(scored, key=lambda s: -s.score)


def is_ambiguous(ranked: Sequence[ScoredCommit]) -> bool:
    """True when there is no real signal or the top two commits tie."""
    if not ranked:
        return False
    return ranked[0].score < MIN_SIGNAL or (len(ranked) > 1 and ranked[1].score == ranked[0].score)
