"""Path confinement for the MCP server: every path stays inside the roots.

The allowed roots are fixed when the server starts (each ``--allow-dir``,
or the server's working directory when none was given) and widened at
runtime only by the MCP roots the client announces in its session. Every
path a tool takes, a resource names or a spill file needs must resolve,
with :func:`os.path.realpath`, inside one of those roots.

Three refusals, and the error names the rule it refused:

- a ``..`` segment whose resolution escapes every root,
- a symlink (or Windows junction) that points outside a root it starts in,
- an absolute path that lies outside every root from the start.

Realpath is the only authority: a path is accepted by where it resolves,
not by how it is written.
"""

import os
from typing import Iterable, List, Tuple

#: The kinds of refusal, as the words the tool error carries.
RULE_DOTDOT = "a '..' segment that escapes the allowed roots"
RULE_SYMLINK = "a symlink that resolves outside the allowed roots"
RULE_OUTSIDE = "an absolute path outside every allowed root"


class PathOutsideRootsError(ValueError):
    """A path that does not resolve inside any allowed root.

    The message names the rule that refused the path and lists the roots,
    so the client sees which confinement rule caught it and what is
    allowed.
    """


def _normcase(path: str) -> str:
    """The comparison form of ``path``: lowercase on Windows."""
    return os.path.normcase(path)


def _inside(candidate: str, roots: Iterable[str]) -> bool:
    """Whether ``candidate`` is a root itself or lies below one of them."""
    normed = _normcase(candidate)
    for root in roots:
        normed_root = _normcase(root)
        if normed == normed_root or normed.startswith(_normcase(root + os.sep)):
            return True
    return False


def startup_roots(allow_dirs: Iterable[str]) -> List[str]:
    """The roots fixed when the server starts: each ``--allow-dir``, else cwd.

    Every root is stored in its :func:`os.path.realpath` form, so a
    ``--allow-dir`` given through a symlink confines what it really points
    at, and an ``--allow-dir`` that does not exist confines nothing and is
    refused: a root that is not a directory would silently allow nothing
    or, worse, promise a directory the client cannot reach.
    """
    roots: List[str] = []
    for allow_dir in allow_dirs:
        resolved = os.path.realpath(allow_dir)
        if not os.path.isdir(resolved):
            raise PathOutsideRootsError(
                f"the --allow-dir {allow_dir} is not a directory that exists "
                f"(resolves to {resolved})"
            )
        roots.append(resolved)
    if not roots:
        roots.append(os.path.realpath(os.getcwd()))
    return roots


def effective_roots(startup: Iterable[str], client_roots: Iterable[str]) -> Tuple[str, ...]:
    """The roots a tool call is confined by: the startup roots plus the MCP
    roots the client announced.

    Client roots are additive, never a replacement: the person who started
    the server with ``--allow-dir`` does not lose that directory because a
    client connected with its own roots. A client root is stored in its
    realpath form like any other.
    """
    merged: List[str] = list(startup)
    for client_root in client_roots:
        resolved = os.path.realpath(client_root)
        if not any(_normcase(resolved) == _normcase(existing) for existing in merged):
            merged.append(resolved)
    return tuple(merged)


def _refusal_rule(raw_path: str, lexically_normed: str, roots: Tuple[str, ...]) -> str:
    """Which rule refused ``raw_path``, named the way the tool error prints it.

    A ``..`` in the written path is refused by the ``..`` rule even when a
    symlink shares the blame: the caller wrote an escape. A path that
    spells a location inside a root but resolves outside one went through a
    symlink or junction. Everything else lies outside the roots outright.
    """
    if ".." in raw_path.replace("\\", "/").split("/"):
        return RULE_DOTDOT
    if _inside(lexically_normed, roots):
        return RULE_SYMLINK
    return RULE_OUTSIDE


def confine(path: str, roots: Iterable[str]) -> str:
    """The realpath of ``path`` when it resolves inside one of ``roots``.

    Raises :class:`PathOutsideRootsError` otherwise, naming the rule the
    path broke. The roots are given in their realpath form, as
    :func:`startup_roots` and :func:`effective_roots` produce them.
    """
    roots_tuple = tuple(roots)
    if not roots_tuple:
        raise PathOutsideRootsError(
            f"refusing {path}: no allowed roots are configured"
        )
    if not path:
        raise PathOutsideRootsError(
            f"refusing an empty path: {RULE_OUTSIDE} (allowed roots: "
            f"{', '.join(roots_tuple)})"
        )
    resolved = os.path.realpath(path)
    if _inside(resolved, roots_tuple):
        return resolved
    # The written path with ``..`` collapsed lexically and symlinks left
    # alone: inside a root here but outside one after realpath means a
    # symlink or junction carried it out.
    lexically_normed = os.path.normpath(os.path.abspath(path))
    rule = _refusal_rule(str(path), lexically_normed, roots_tuple)
    raise PathOutsideRootsError(
        f"refusing {path}: {rule} "
        f"(it resolves to {resolved}; allowed roots: {', '.join(roots_tuple)})"
    )
