"""Mistakes a patch can be checked for without running it.

Sentinel must not execute code from a stranger's repository, so a patch that parses can still crash on import. This catches
the part that can be seen from the text: names nothing defines, and attributes the standard library doesn't have (a live
patch used `ast.Truediv`, which stopped the whole app from starting).
"""
import ast
import builtins
import importlib
import sys
from typing import Dict, Set

MODULE_NAMES = {"__file__", "__name__", "__package__", "__spec__", "__loader__", "__doc__", "__path__", "__builtins__",
                "__annotations__", "__class__", "__module__", "__qualname__"}
NOT_IMPORTED = {"antigravity", "this", "idlelib", "tkinter", "turtle", "turtledemo"}    # importing these has side effects


def _bound_names(tree: ast.AST) -> Set[str]:
    """Every name the file binds anywhere. Scopes are ignored on purpose: a miss is better than a false alarm on real code."""
    bound: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            bound.update((a.asname or a.name).split(".")[0] for a in node.names)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
    return bound


def _stdlib_module(name: str):
    if name.split(".")[0] not in sys.stdlib_module_names or name.split(".")[0] in NOT_IMPORTED:
        return None
    try:
        return importlib.import_module(name)
    except Exception:       # missing on this platform (winreg, fcntl): nothing can be said about it
        return None


def _has(module: object, name: str, dotted: str) -> bool:
    if hasattr(module, name):
        return True
    try:
        importlib.import_module(f"{dotted}.{name}")     # a submodule nobody has imported yet
        return True
    except Exception:
        return False


def _imported_modules(tree: ast.AST) -> Dict[str, str]:
    """Local name -> real module, for plain `import x` and `import x as y`."""
    modules: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
    return modules


def _rebound(tree: ast.AST) -> Set[str]:
    """Names assigned or taken as parameters: `ast` may not be the module wherever one of these exists."""
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            names.add(node.id)
    return names


def broken_references(code: str) -> Set[str]:
    """Names and standard-library attributes that cannot exist, as text such as `ast.Truediv`. Empty if the code won't parse."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()
    found: Set[str] = set()
    star_import = any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in ast.walk(tree))
    if not star_import:
        known = _bound_names(tree) | set(dir(builtins)) | MODULE_NAMES
        found.update(n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in known)
    rebound = _rebound(tree)
    modules = {local: real for local, real in _imported_modules(tree).items() if local not in rebound}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in modules:
            real = modules[node.value.id]
            module = _stdlib_module(real)
            if module is not None and not _has(module, node.attr, real):
                found.add(f"{node.value.id}.{node.attr}")
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            module = _stdlib_module(node.module)
            if module is not None:
                found.update(f"{node.module}.{a.name}" for a in node.names if a.name != "*" and not _has(module, a.name, node.module))
    return found
