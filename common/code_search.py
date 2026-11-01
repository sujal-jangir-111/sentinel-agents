"""Finding the code a bug report is about. Pure functions, no I/O.

File names alone mislead: "the coupon is wrong" names no file, and a routing file that calls everything looks relevant to
every report. So the Detective ranks the repository by the report's words, then gives the LLM the code itself.
"""
import re
from typing import Dict, Iterable, List, Set, Tuple

from common.github_client import SECONDARY_DIRS

READ_CAP = 40                  # files read for one report
CONTEXT_CHARS = 40_000         # code sent to the LLM for one report
MAX_HITS_PER_WORD = 5          # one word repeated all over a file proves little
PATH_WEIGHT = 3

_WORD_RE = re.compile(r"[a-z][a-z0-9]{2,}")
_STOP_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "has", "had", "was", "were", "this", "that", "with",
    "from", "have", "they", "their", "them", "when", "then", "than", "into", "out", "our", "your", "should", "would", "could",
    "does", "doesn", "don", "isn", "wasn", "bug", "bugs", "error", "errors", "problem", "issue", "fix", "fixed", "please",
    "seems", "keep", "working", "work", "works", "page", "https", "http", "github", "com", "file", "code",
}


def report_words(text: str) -> Set[str]:
    """Meaningful words of a report, with snake_case split: `discount_rate` should find `discount` too."""
    return set(_WORD_RE.findall(text.lower().replace("_", " "))) - _STOP_WORDS


def _path_hits(words: Set[str], path: str) -> int:
    return len(words & report_words(path.replace("/", " ").replace(".", " ")))


def read_order(report: str, paths: Iterable[str]) -> List[str]:
    """Which files to read first when a repository is too big to read: named by the report, then application code."""
    words = report_words(report)

    def rank(path: str) -> Tuple[int, bool, int, str]:
        parts = path.lower().split("/")
        secondary = bool(SECONDARY_DIRS.intersection(parts[:-1])) or parts[-1].startswith("test_")
        return -_path_hits(words, path), secondary, len(parts), path

    return sorted(paths, key=rank)


def relevance(words: Set[str], path: str, text: str) -> int:
    lowered = text.lower().replace("_", " ")
    return PATH_WEIGHT * _path_hits(words, path) + sum(min(lowered.count(w), MAX_HITS_PER_WORD) for w in words)


def rank_sources(report: str, sources: Dict[str, str]) -> List[Tuple[str, int]]:
    """(path, score), best first."""
    words = report_words(report)
    return sorted(((p, relevance(words, p, t)) for p, t in sources.items()), key=lambda item: (-item[1], item[0]))


def code_context(report: str, sources: Dict[str, str], limit: int = CONTEXT_CHARS) -> str:
    """The most relevant files in full, until the budget is spent. Partial files would hide the bug they cut off, and files
    with nothing in common with the report only cost tokens."""
    blocks: List[str] = []
    left = limit
    for path, score in rank_sources(report, sources):
        if not score and blocks:
            break
        block = f"--- {path}\n{sources[path]}"
        if len(block) > left:
            continue
        blocks.append(block)
        left -= len(block)
    return "\n\n".join(blocks)
