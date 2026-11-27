"""Resolve and digest-check the inputs of the labelled corpus.

Each corpus item names where its input comes from. A repository item is a
clone at its pinned commit, checked by the digest of ``git archive``; a BOM
item is repo-test data pulled by digest under the test-data root; a fixture
item is a directory committed under ``contrib/corpus/fixtures/``, checked by
a digest over its committed files and scanned from a copy; an image item is
a reference that carries its digest. Every function returns (payload, None)
or (None, reason), and a reason makes the item not assessed.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))


def cache_dir(name: str) -> str:
    """A directory under the user cache for the corpus's clones, scans and
    pulled data: ``$XDG_CACHE_HOME/depscan/corpus/<name>``, with
    ``~/.cache`` standing in for an unset XDG_CACHE_HOME."""
    root = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(root, "depscan", "corpus", name)


def _ignored_patterns() -> list:
    """The patterns of contrib/corpus/fixtures/.gitignore: files a fixture's
    own scripts or a local build write, which the digest and the copy skip."""
    try:
        with open(os.path.join(_HERE, "fixtures", ".gitignore"), encoding="utf-8") as fp:
            return [line.strip().rstrip("/") for line in fp if line.strip() and line[0] != "#"]
    except OSError:
        return []


def fixture_files(directory: str) -> list:
    """The (relative path, path) pairs of a fixture's committed files, in
    sorted order: everything under the directory except what the fixtures'
    .gitignore names, by file or directory name, or by a path relative to
    contrib/corpus/fixtures when the pattern holds a slash."""
    patterns = _ignored_patterns()
    prefix = os.path.basename(os.path.normpath(directory)) + "/"
    entries = []
    for base, _dirs, files in os.walk(directory):
        for name in files:
            path = os.path.join(base, name)
            rel = os.path.relpath(path, directory).replace(os.sep, "/")
            parts = rel.split("/")
            if any(
                (prefix + rel).startswith(p + "/") or prefix + rel == p if "/" in p else p in parts
                for p in patterns
            ):
                continue
            entries.append((rel, path))
    return sorted(entries)


def fixture_bytes(path: str) -> bytes:
    """A fixture file's committed bytes. The fixtures are committed with LF
    line endings and ``-text``, but a checkout made before that attribute
    (or with core.autocrlf and a stale index) can still hold CRLF, so a text
    file, one without a NUL byte, reads with CRLF turned back into LF. A
    binary file reads as it is."""
    with open(path, "rb") as fp:
        data = fp.read()
    return data if b"\x00" in data else data.replace(b"\r\n", b"\n")


def fixture_digest(directory: str) -> str:
    """The digest of a fixture directory: SHA-256 over every committed
    file's relative path with forward slashes and its bytes
    (:func:`fixture_bytes`), in sorted path order."""
    digest = hashlib.sha256()
    for rel, path in fixture_files(directory):
        digest.update(rel.encode("utf-8") + b"\x00")
        digest.update(fixture_bytes(path))
    return digest.hexdigest()


def usable_bash():
    """The bash a fixture build script can run under, or None. On Windows
    the bash.exe in System32 or WindowsApps is the WSL launcher, which runs
    in another system (or answers with an error when none is installed), so
    it does not count."""
    path = shutil.which("bash")
    if path is None:
        return None
    lowered = path.replace("/", "\\").lower()
    if lowered.endswith("\\system32\\bash.exe") or "\\windowsapps\\" in lowered:
        return None
    return path


def process_text(data) -> str:
    """A tool's output as text: UTF-16 when it carries NUL bytes (as the
    WSL launcher writes), UTF-8 otherwise, with any NUL left removed."""
    if isinstance(data, str):
        return data.replace("\x00", "")
    data = data or b""
    text = data.decode("utf-16-le", errors="replace") if b"\x00" in data else ""
    if not text.strip("\x00").strip() or "\ufffd" in text:
        text = data.decode("utf-8", errors="replace")
    return text.replace("\x00", "")


def git(clone: str, *args, text=True):
    """Run one git command in ``clone`` and return the completed process. A
    host without git gets a failed process with that message, never an
    exception."""
    try:
        return subprocess.run(["git", "-C", clone, *args], capture_output=True, text=text)
    except OSError as exc:
        message = f"git could not run: {exc}"
        return subprocess.CompletedProcess(
            ["git"], 127, "" if text else b"", message if text else message.encode()
        )


def is_inside(path: str, root: str) -> bool:
    """Whether ``path`` lies inside ``root``. Paths on different drives
    (Windows) are never inside one another."""
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == (
            os.path.abspath(root)
        )
    except ValueError:
        return False


def resolve_repository(item: dict, corpus_root: str, fetch: bool = False):
    """The clone of a repository item at its pinned commit, digest-checked.

    With ``fetch`` a missing clone is fetched first: a blob-less clone, then
    a checkout of the pinned commit. Returns (clone, None), or (None, reason)
    when the clone is missing and fetching is off or the digest fails.
    """
    clone = os.path.join(corpus_root, item["name"])
    source, commit = item["source"].rsplit("@", 1)
    if shutil.which("git") is None:
        return None, "git is not on PATH, and a repository item is read through git"
    if not os.path.isdir(os.path.join(clone, ".git")):
        if not fetch:
            return None, (
                f"no clone at {clone}; clone {item['source']} there first, or "
                "run the scorer with --fetch"
            )
        os.makedirs(os.path.dirname(clone), exist_ok=True)
        cloned = subprocess.run(
            ["git", "clone", "-q", "--filter=blob:none", source, clone], capture_output=True
        )
        if cloned.returncode != 0:
            return None, f"cloning {source} failed: {cloned.stderr.decode(errors='replace')}"
    head = git(clone, "rev-parse", "HEAD").stdout.strip()
    if head != commit and fetch:
        git(clone, "fetch", "-q", "--filter=blob:none", "origin", commit)
        git(clone, "checkout", "-q", "--detach", commit)
        head = git(clone, "rev-parse", "HEAD").stdout.strip()
    if head != commit:
        return None, (
            f"the clone at {clone} is at {head[:12] or 'an unknown commit'}, "
            f"not the pinned {commit[:12]}"
        )
    tar = git(clone, "archive", "--format=tar", commit, text=False)
    if tar.returncode != 0:
        return None, f"git archive failed for {item['name']}"
    return _digest_checked(item, hashlib.sha256(tar.stdout).hexdigest(), clone)


def _digest_checked(item: dict, digest: str, payload):
    if digest == item["sha256"]:
        return payload, None
    note = item.get("digestNote", "")
    return None, (
        f"digest mismatch for {item['name']}: computed {digest}, the manifest pins "
        f"{item['sha256']}" + (f" ({note})" if note else "")
    )


def resolve_testdata(item: dict, testdata_root: str):
    """The pulled repo-test data of a BOM item, verified against its digest.

    The data root holds one directory per artifact plus the OCI manifest copy
    the pull keeps under ``.manifests``, the layout the repotests action
    pulls into.
    """
    testdata = item.get("testdata") or {}
    artifact = testdata.get("artifact")
    data_dir = os.path.join(testdata_root, artifact or "")
    if not artifact or not os.path.isdir(data_dir):
        return None, (
            f"the repo-test data for '{artifact or item['name']}' is not pulled "
            f"under {testdata_root}; pull it by digest with oras first"
        )
    manifest_copy = os.path.join(testdata_root, ".manifests", f"{artifact}.json")
    if not os.path.isfile(manifest_copy):
        return None, (
            f"the manifest copy of '{artifact}' is missing under {testdata_root}; "
            "pull the artifact the way .github/actions/repotests-data does"
        )
    sys.path.insert(0, os.path.join(_REPO_ROOT, "contrib"))
    from repotests import validate as repotests_validate

    try:
        repotests_validate.check_digests(
            data_dir, manifest_copy, manifest_digest=testdata["digest"]
        )
    except repotests_validate.ValidationFailure as exc:
        return None, f"the pulled data for '{artifact}' failed its digest check: {exc}"
    return data_dir, None


def resolve_fixture(item: dict, scans_root: str):
    """The committed fixture of a fixture item, digest-checked and copied.

    The fixture is scanned from a copy under ``scans_root``, after the
    item's ``build`` script (when it names one) ran in that copy, never from the
    repository tree: the corpus sits inside dep-scan's own uv workspace, and
    a scan of the committed directory would pick the workspace's environment
    up. The copy lands beside the scan directory, never inside it: a BOM
    directory scan reads its BOMs from the target, and a target inside the
    reports directory would have its BOMs skipped as scan outputs.
    """
    name = item["source"].split(":", 1)[1] if ":" in item["source"] else item["name"]
    directory = os.path.join(_HERE, "fixtures", name)
    if not os.path.isdir(directory):
        return None, f"the fixture '{name}' is not committed under contrib/corpus/fixtures."
    checked, reason = _digest_checked(item, fixture_digest(directory), directory)
    if checked is None:
        return None, reason
    copy_dir = os.path.abspath(os.path.join(scans_root, "payloads", item["name"]))
    if is_inside(copy_dir, _REPO_ROOT):
        return None, (
            f"the scans root {scans_root} is inside the dep-scan checkout, whose uv "
            "workspace a fixture scan would pick up; pass a --scans-root outside it"
        )
    bash = usable_bash() if item.get("build") else None
    if item.get("build") and bash is None:
        return None, (
            f"the fixture build ({item['build']}) needs bash and a Linux C compiler, "
            "and bash is not on PATH (a Windows WSL launcher does not count)"
        )
    shutil.rmtree(copy_dir, ignore_errors=True)
    for rel, path in fixture_files(directory):
        target = os.path.join(copy_dir, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fp:
            fp.write(fixture_bytes(path))
        shutil.copymode(path, target)
    if bash:
        # The fixture's own build script runs in the copy, so a built
        # artifact never reaches the committed tree or its digest.
        built = subprocess.run([bash, item["build"]], cwd=copy_dir, capture_output=True)
        if built.returncode != 0:
            detail = (
                process_text(built.stderr).strip() or process_text(built.stdout).strip()
            ).splitlines()
            return None, f"the fixture build ({item['build']}) failed: " + (
                detail[-1] if detail else f"exit {built.returncode}"
            )
    return copy_dir, None


def resolve_payload(item: dict, args):
    """The input an item's scan reads, as (payload, None) or (None, reason)."""
    kind = item.get("kind")
    if kind == "repository":
        return resolve_repository(item, args.corpus_root, args.fetch)
    if kind == "bom":
        return resolve_testdata(item, args.testdata_root)
    if kind in ("fixture", "binary"):
        return resolve_fixture(item, args.scans_root)
    if kind == "image":
        if f"sha256:{item['sha256']}" not in item["source"]:
            return None, (
                f"the image reference '{item['source']}' does not carry the digest "
                f"the item pins (sha256:{item['sha256']})"
            )
        return item["source"], None
    return None, f"unknown item kind '{kind}'"
