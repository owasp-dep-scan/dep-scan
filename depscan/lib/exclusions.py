"""The exclusion set of one scan, read from the patterns the user already
gives cdxgen.

``--cdxgen-args`` (or ``CDXGEN_ARGS``) may carry ``--exclude <glob>``
options. cdxgen applies them to its own walk of the scanned path; the walks
dep-scan starts itself (the blint binary review, the post-build target list,
the fallback golem, rusi, kosi and dosai runs) read the same patterns from
here, so a path the user excluded is not inventoried by one tool and ignored
by another.

Patterns reach cdxgen from three places and dep-scan reads the same ones
with cdxgen's precedence (the command line, then the ``CDXGEN_EXCLUDE``
environment variable, then the project config file in the working
directory): the first of them that sets any pattern is the whole set, as
with yargs arrays, which are replaced and never merged.

The patterns follow cdxgen: they are matched against the path relative to
the scanned path, anchored at its root and never at the working directory.
``*`` matches within one path segment, ``**`` matches any number of
segments, ``[...]`` and ``{a,b}`` (nested too) work as in a shell, and a
leading ``**/`` is needed to reach same-named directories nested below the
root. A pattern that names a directory excludes everything below it.
"""

import json
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

_EXCLUDE_FLAG = "--exclude"


def _segment_regex(segment: str) -> "re.Pattern[str]":
    """One path segment's glob (``*``, ``?``, ``[...]``) as a regex."""
    out = []
    i = 0
    while i < len(segment):
        char = segment[i]
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            end = segment.find("]", i + 2)
            if end == -1:
                out.append(re.escape(char))
            else:
                body = segment[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = end
        else:
            out.append(re.escape(char))
        i += 1
    return re.compile("".join(out) + r"\Z")


def _match_segments(pattern: Sequence["re.Pattern[str] | None"], parts: Sequence[str]) -> bool:
    """Match path segments against compiled pattern segments; ``None`` is a
    ``**`` segment that consumes zero or more path segments."""
    if not pattern:
        return not parts
    head = pattern[0]
    if head is None:
        rest = pattern[1:]
        return any(_match_segments(rest, parts[skip:]) for skip in range(len(parts) + 1))
    return bool(parts) and bool(head.match(parts[0])) and _match_segments(pattern[1:], parts[1:])


def _expand_braces(pattern: str) -> List[str]:
    """Expand ``{a,b}`` groups, nested ones included, into plain patterns.

    A group with one alternative (``{x}``) is literal text, as in a shell, and
    an unbalanced brace is left alone."""
    start = pattern.find("{")
    if start < 0:
        return [pattern]
    depth = 0
    parts: List[str] = []
    last = start + 1
    for index in range(start, len(pattern)):
        char = pattern[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                parts.append(pattern[last:index])
                head, tail = pattern[:start], pattern[index + 1 :]
                if len(parts) < 2:
                    return [head + "{" + parts[0] + "}" + t for t in _expand_braces(tail)]
                return [e for part in parts for e in _expand_braces(head + part + tail)]
        elif char == "," and depth == 1:
            parts.append(pattern[last:index])
            last = index + 1
    return [pattern]


def _normalise_pattern(pattern: str) -> str:
    pattern = pattern.strip().replace("\\", "/")
    while pattern.startswith("./"):
        pattern = pattern[2:]
    return pattern.strip("/")


def exclude_patterns_from_args(cdxgen_args: Optional[str]) -> List[str]:
    """The ``--exclude`` values in a cdxgen argument string, in order.

    The string is split the way the cdxgen invocation splits it, so a
    pattern means the same here as it does to cdxgen. ``--exclude=glob``
    and ``--exclude glob`` both count. An unparsable string yields no
    patterns; cdxgen reports its own argument errors.
    """
    if not cdxgen_args:
        return []
    try:
        tokens = shlex.split(cdxgen_args)
    except ValueError:
        return []
    patterns: List[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == _EXCLUDE_FLAG and index + 1 < len(tokens):
            patterns.append(tokens[index + 1])
            index += 1
        elif token.startswith(_EXCLUDE_FLAG + "="):
            patterns.append(token[len(_EXCLUDE_FLAG) + 1 :])
        index += 1
    return [p for p in patterns if _normalise_pattern(p)]


#: The project config files cdxgen reads from its working directory, in the
#: order it reads them; a later file replaces an earlier one.
CONFIG_FILENAMES = (".cdxgenrc", ".cdxgen.json", ".cdxgen.yml", ".cdxgen.yaml")
_CONFIG_KEYS = ("exclude", "excludeRegex", "exclude-regex")


def _config_file_patterns(cwd: str) -> Tuple[str, List[str]]:
    """The ``exclude`` patterns of the config file cdxgen would load from
    ``cwd``, with that file's path; nothing when none sets them.

    cdxgen takes the last existing file of :data:`CONFIG_FILENAMES` as the
    whole config. YAML is read when PyYAML is installed; a file that cannot be
    read or parsed gives no patterns (cdxgen reports its own config errors).
    """
    chosen = None
    for name in CONFIG_FILENAMES:
        candidate = os.path.join(cwd, name)
        if os.path.isfile(candidate):
            chosen = candidate
    if chosen is None:
        return "", []
    try:
        with open(chosen, encoding="utf-8") as handle:
            if chosen.endswith((".yml", ".yaml")):
                import yaml

                document = yaml.safe_load(handle)
            else:
                document = json.load(handle)
    except Exception:  # noqa: BLE001 - an unreadable config gives no patterns
        return "", []
    if not isinstance(document, dict):
        return "", []
    for key in _CONFIG_KEYS:
        value = document.get(key)
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            patterns = [v for v in value if isinstance(v, str) and _normalise_pattern(v)]
            if patterns:
                return chosen, patterns
    return "", []


@dataclass(frozen=True)
class ExclusionSet:
    """The patterns of one scan, matched against paths below a scan root."""

    patterns: Tuple[str, ...] = ()
    #: Where the patterns came from, for the line a scan logs about them.
    source: str = field(default="", compare=False)
    _compiled: Tuple[Tuple["re.Pattern[str] | None", ...], ...] = field(
        default=(), repr=False, compare=False
    )

    @classmethod
    def from_patterns(cls, patterns: Iterable[str], source: str = "") -> "ExclusionSet":
        expanded = [e for p in patterns for e in _expand_braces(p)]
        kept = tuple(
            dict.fromkeys(_normalise_pattern(p) for p in expanded if _normalise_pattern(p))
        )
        compiled = tuple(
            tuple(None if seg == "**" else _segment_regex(seg) for seg in pattern.split("/"))
            for pattern in kept
        )
        return cls(kept, source, compiled)

    @classmethod
    def from_options(cls, options, env=None, cwd=None) -> "ExclusionSet":
        """The set a scan's options define, with cdxgen's precedence.

        ``options`` carry the ``cdxgen_args`` string (``--cdxgen-args`` or
        ``CDXGEN_ARGS``). Without patterns there, ``CDXGEN_EXCLUDE`` (or its
        alias ``CDXGEN_EXCLUDE_REGEX``) in ``env`` and then the project
        config file in ``cwd`` are read, as cdxgen reads them. ``env`` and
        ``cwd`` default to the process environment and working directory.
        """
        args = None
        if options is not None:
            args = (
                options.get("cdxgen_args")
                if hasattr(options, "get")
                else getattr(options, "cdxgen_args", None)
            )
        from_args = exclude_patterns_from_args(args)
        if from_args:
            return cls.from_patterns(from_args, "--cdxgen-args")
        environment = os.environ if env is None else env
        for name in ("CDXGEN_EXCLUDE", "CDXGEN_EXCLUDE_REGEX"):
            value = environment.get(name)
            if value and _normalise_pattern(value):
                return cls.from_patterns([value], name)
        path, patterns = _config_file_patterns(os.getcwd() if cwd is None else cwd)
        if patterns:
            return cls.from_patterns(patterns, path)
        return cls()

    def describe(self) -> str:
        """One line naming the patterns a scan applied and where they came from."""
        return f"{', '.join(self.patterns)} (from {self.source or 'the scan options'})"

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def excludes(self, relative_path: str) -> bool:
        """Whether a path relative to the scan root is excluded, itself or
        through an ancestor directory the patterns name."""
        parts = [p for p in relative_path.replace("\\", "/").split("/") if p and p != "."]
        if not parts or not self._compiled:
            return False
        for end in range(1, len(parts) + 1):
            prefix = parts[:end]
            for pattern in self._compiled:
                if _match_segments(pattern, prefix):
                    return True
                # ``dir/**`` also removes the directory ``dir`` itself.
                if (
                    len(pattern) > 1
                    and pattern[-1] is None
                    and _match_segments(pattern[:-1], prefix)
                ):
                    return True
        return False

    def excludes_path(self, root: str, path: str) -> bool:
        """Whether an absolute or root-relative ``path`` below ``root`` is
        excluded. A path outside ``root`` is never excluded."""
        try:
            relative = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
        except ValueError:  # another drive on Windows
            return False
        if relative == os.curdir or relative.split(os.sep)[0] == os.pardir:
            return False
        return self.excludes(relative.replace(os.sep, "/"))


def walk_kept(
    root: str, exclusions: ExclusionSet, skip_dirs: Iterable[str] = ()
) -> Iterator[Tuple[str, List[str], List[str], bool]]:
    """Walk ``root`` top-down without entering excluded directories.

    Yields ``(directory, kept_dirs, kept_files, pruned)`` where ``pruned``
    says an excluded entry sits directly in this directory. ``skip_dirs``
    names directories never entered, whatever the patterns say.
    """
    skip = set(skip_dirs)
    for directory, dirs, files in os.walk(root):
        pruned = False
        kept_dirs = []
        for name in dirs:
            if name in skip:
                continue
            if exclusions.excludes_path(root, os.path.join(directory, name)):
                pruned = True
            else:
                kept_dirs.append(name)
        kept_files = []
        for name in files:
            if exclusions.excludes_path(root, os.path.join(directory, name)):
                pruned = True
            else:
                kept_files.append(name)
        dirs[:] = kept_dirs
        yield directory, kept_dirs, kept_files, pruned


def kept_targets(root: str, exclusions: ExclusionSet, skip_dirs: Iterable[str] = ()) -> List[str]:
    """The paths to hand a tool that walks directories itself, so that it
    reaches nothing the patterns exclude.

    The result is the scan root when nothing below it is excluded. Otherwise
    it is the largest set of directories (whole subtrees with no excluded
    entry) and single files that together cover every kept file, in a
    stable order. An empty list means every file is excluded.
    """
    root = os.path.abspath(root)
    if not exclusions or not os.path.isdir(root):
        return [root]
    dirty = set()
    entries = {}
    for directory, kept_dirs, kept_files, pruned in walk_kept(root, exclusions, skip_dirs):
        entries[directory] = (kept_dirs, kept_files)
        if pruned:
            dirty.add(directory)
    # A directory is dirty when it, or any kept directory below it, pruned.
    for directory in sorted(entries, key=len, reverse=True):
        if directory in dirty and directory != root:
            parent = os.path.dirname(directory)
            if parent in entries:
                dirty.add(parent)
    if root not in dirty:
        return [root]
    targets: List[str] = []

    def collect(directory: str) -> None:
        kept_dirs, kept_files = entries[directory]
        for name in sorted(kept_dirs):
            child = os.path.join(directory, name)
            if child in dirty:
                collect(child)
            else:
                targets.append(child)
        targets.extend(os.path.join(directory, name) for name in sorted(kept_files))

    collect(root)
    return targets


def project_roots(
    root: str,
    exclusions: ExclusionSet,
    markers: Sequence[str],
    skip_dirs: Iterable[str] = (),
) -> List[str]:
    """The topmost kept directories under ``root`` that hold one of the
    ``markers`` (a file name, or a ``*.ext`` suffix). The scan root counts
    when it holds one."""
    root = os.path.abspath(root)
    found: List[str] = []

    def has_marker(names: List[str]) -> bool:
        for marker in markers:
            if marker.startswith("*"):
                if any(n.endswith(marker[1:]) for n in names):
                    return True
            elif marker in names:
                return True
        return False

    for directory, kept_dirs, kept_files, _pruned in walk_kept(root, exclusions, skip_dirs):
        if any(directory == f or directory.startswith(f + os.sep) for f in found):
            kept_dirs[:] = []
            continue
        if has_marker(kept_files):
            found.append(directory)
            kept_dirs[:] = []
    return found
