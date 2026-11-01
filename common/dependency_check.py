"""Can these pinned packages be installed together?

OSV says which version fixes a vulnerability, not what that version needs. A live run bumped requests to 2.33.0 next to
urllib3==1.24.1, which pip refuses to install. PyPI publishes each release's requirements, so this can be checked without
installing anything. If PyPI can't be reached nothing is claimed either way: this must not block an unrelated fix.
"""
import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import httpx
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from common.osv_client import parse_requirements

PYPI = "https://pypi.org/pypi"
TIMEOUT = 15.0
MAX_ROUNDS = 3


@dataclass(frozen=True)
class Conflict:
    package: str         # the pinned package that sets the requirement
    version: str
    dependency: str      # the pinned package it disagrees with
    pinned: str
    needs: str           # the version range it asks for

    @property
    def reason(self) -> str:
        return (f"{self.package}=={self.version} needs {self.dependency}{self.needs}, but requirements.txt pins "
                f"{self.dependency}=={self.pinned}, so it cannot be installed")


async def _project(http: httpx.AsyncClient, path: str) -> Optional[dict]:
    try:
        resp = await http.get(f"{PYPI}/{path}/json", timeout=TIMEOUT)
        return resp.json() if resp.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None


def _requirements_of(project: Optional[dict]) -> List[Requirement]:
    """What this release needs on this platform, leaving out optional extras."""
    needed: List[Requirement] = []
    for text in ((project or {}).get("info") or {}).get("requires_dist") or []:
        try:
            req = Requirement(text)
        except InvalidRequirement:
            continue
        if req.marker is None or req.marker.evaluate({"extra": ""}):
            needed.append(req)
    return needed


def _allows(specifier: SpecifierSet, version: str) -> bool:
    try:
        return specifier.contains(Version(version), prereleases=True)
    except InvalidVersion:
        return True


async def find_conflicts(http: httpx.AsyncClient, requirements_txt: str) -> List[Conflict]:
    pins = {d.name: d.version for d in parse_requirements(requirements_txt)}
    projects = await asyncio.gather(*(_project(http, f"{name}/{version}") for name, version in pins.items()))
    conflicts: List[Conflict] = []
    for (name, version), project in zip(pins.items(), projects):
        for req in _requirements_of(project):
            dependency = canonicalize_name(req.name)
            if dependency in pins and not _allows(req.specifier, pins[dependency]):
                conflicts.append(Conflict(name, version, dependency, pins[dependency], str(req.specifier)))
    return conflicts


def _stable_releases(project: Optional[dict]) -> List[Version]:
    releases: List[Version] = []
    for text, files in ((project or {}).get("releases") or {}).items():
        try:
            version = Version(text)
        except InvalidVersion:
            continue
        if files and not version.is_prerelease and not all(f.get("yanked") for f in files):
            releases.append(version)
    return sorted(releases)


def pick_version(releases: List[Version], needs: SpecifierSet) -> Optional[str]:
    """The newest release of the lowest major version that fits: security fixes without an avoidable major upgrade."""
    fitting = [v for v in releases if needs.contains(v)]
    if not fitting:
        return None
    return str(max(v for v in fitting if v.major == fitting[0].major))


async def companion_upgrades(http: httpx.AsyncClient, requirements_txt: str, bump) -> Tuple[Dict[str, str], str]:
    """Other pins that must move for these requirements to install. `bump(text, {name: version})` rewrites the text.
    Returns (the upgrades, the resulting text). Whatever still conflicts is left for the gatekeeper to refuse."""
    upgrades: Dict[str, str] = {}
    text = requirements_txt
    for _ in range(MAX_ROUNDS):
        conflicts = await find_conflicts(http, text)
        needed: Dict[str, SpecifierSet] = {}
        for c in conflicts:
            needed[c.dependency] = needed.get(c.dependency, SpecifierSet()) & SpecifierSet(c.needs)
        if not needed:
            break
        projects = await asyncio.gather(*(_project(http, name) for name in needed))
        chosen = {name: pick_version(_stable_releases(project), spec) for (name, spec), project in zip(needed.items(), projects)}
        chosen = {name: version for name, version in chosen.items() if version}
        if not chosen:
            break
        upgrades.update(chosen)
        text = bump(text, chosen)
    return upgrades, text


async def new_conflicts(http: httpx.AsyncClient, before: str, after: str) -> List[Conflict]:
    """Conflicts `after` has that `before` didn't: a project that was already broken doesn't block an unrelated fix."""
    if before == after:
        return []
    old, new = await asyncio.gather(find_conflicts(http, before), find_conflicts(http, after))
    known: Set[Tuple[str, str]] = {(c.package, c.dependency) for c in old}
    return [c for c in new if (c.package, c.dependency) not in known]
