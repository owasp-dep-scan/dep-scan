"""Target kind detection for the ``depscan scan`` verb.

:func:`detect_kind` maps one target string to the inventory path the scan
uses for it: a package URL, a git URL, a container archive or reference, a
CycloneDX BOM file or directory, an app package, a binary, or a plain source
directory. Every result carries a short reason naming the evidence, which the
scan verb logs on stderr for each target.

The order is settled: existence checks for path kinds beat the reference
heuristics, and among path kinds the container archive and OCI layout come
first, then the BOM file, the BOM directory, the app extensions, the
executable header and finally the source fallback. A string that is both a
possible image reference and an existing path is the path, whatever kind the
path itself gives.
"""

import json
import os
import re
from typing import Optional, Tuple

#: The kinds a target can be detected as; also the values ``--target-kind``
#: uses to force one of them.
TARGET_KINDS = (
    "purl",
    "git",
    "container",
    "bom",
    "bom-dir",
    "binary",
    "android",
    "ios",
    "source",
)

#: The values ``--target-kind`` accepts beyond the detectable kinds. Firmware
#: has no inventory path in this version, so naming it is refused with exit 4
#: rather than scanned.
FORCE_TARGET_KINDS = TARGET_KINDS + ("firmware",)

#: The URL prefixes that make a target a remote source (the prefixes
#: ``is_remote_source`` in xbom_lib's cdxgen module treats as remote).
_GIT_URL_PREFIXES = ("http://", "https://", "git://", "ssh://", "git@")

#: Archive extensions: a URL ending in one of these names a file to fetch,
#: not a repository to clone.
_ARCHIVE_EXTENSIONS = (".tar", ".tar.gz", ".tgz", ".zip")

#: Files cdxgen or dep-scan writes beside the BOMs of a BOM directory, besides
#: the ``*.slices.json`` reachability slices.
_BOM_COMPANION_NAMES = ("depscan.manifest.json", "depscan.findings.json")

#: The four-byte headers of ELF, Mach-O (both byte orders, 32 and 64 bits)
#: and Mach-O universal files; PE files start with ``MZ``.
_EXECUTABLE_MAGICS = (
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)

# A registry/name reference as the distribution reference grammar spells it:
# an optional registry host (with an optional port), lowercase path
# components separated by single dots, underscores or dashes, and an
# optional tag. Paths such as ./app, /srv/app, ~/app or C:\app never match.
_PATH_REFERENCE_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]+)?/)?"
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$"
)

# An image digest reference, ``name@sha256:<64 hex>``.
_DIGEST_REFERENCE_RE = re.compile(r"^\S+@sha256:[0-9a-fA-F]{64}$")
# A bare ``name:tag`` reference without a registry slash. A single letter
# before the colon is a Windows drive, not a one-character repository name.
_TAG_REFERENCE_RE = re.compile(r"^(?![A-Za-z]:)[^\s/:@]+:[^\s/:@]+$")


def detect_kind(target: str) -> Tuple[str, str]:
    """Detect the kind of one target; returns ``(kind, reason)``.

    The reason names the evidence behind the kind, for the scan's per-target
    log line.
    """
    if target.startswith("pkg:"):
        return "purl", "starts with pkg:"
    if os.path.exists(target):
        return _detect_existing_path(target)
    git_reason = _git_url_reason(target)
    if git_reason:
        return "git", git_reason
    reference_reason = _image_reference_reason(target)
    if reference_reason:
        return "container", reference_reason
    return "source", "not an existing path and no more specific kind matched"


def _detect_existing_path(target: str) -> Tuple[str, str]:
    """Classify a target that exists on this machine."""
    if os.path.isfile(target):
        return _detect_existing_file(target)
    if os.path.isdir(target):
        return _detect_existing_directory(target)
    return "source", "an existing path that is neither a file nor a directory"


def _detect_existing_file(target: str) -> Tuple[str, str]:
    """Classify an existing file: archive, BOM, app package, executable."""
    lowered = target.lower()
    for extension in (".tar.gz", ".tar"):
        if lowered.endswith(extension):
            return "container", f"an existing {extension} archive file"
    if _is_cyclonedx_document(target):
        return "bom", "an existing file whose JSON document is CycloneDX"
    # The app extensions run before the executable check: the extension names
    # a more specific inventory path and the executable bit is noisy.
    for extension in (".apk", ".aab"):
        if lowered.endswith(extension):
            return "android", f"an existing {extension} file"
    if lowered.endswith(".ipa"):
        return "ios", "an existing .ipa file"
    if _has_executable_header(target):
        return "binary", "an existing file with an ELF, PE or Mach-O header"
    return "source", "an existing file no more specific kind names"


def _detect_existing_directory(target: str) -> Tuple[str, str]:
    """Classify an existing directory: OCI layout, BOM directory, source."""
    if os.path.isfile(os.path.join(target, "oci-layout")):
        return "container", "a directory holding an oci-layout file"
    json_files = [path for path in _direct_json_files(target) if not _is_bom_companion(path)]
    if json_files and all(_is_cyclonedx_document(path) for path in json_files):
        return "bom-dir", "a directory whose JSON files are all CycloneDX documents"
    return "source", "an existing directory"


def _direct_json_files(target: str) -> list:
    """The JSON files directly inside ``target``, as absolute paths."""
    return [
        os.path.join(target, entry)
        for entry in sorted(os.listdir(target))
        if entry.endswith(".json") and os.path.isfile(os.path.join(target, entry))
    ]


def _is_bom_companion(path: str) -> bool:
    """Whether the file is one cdxgen or dep-scan writes next to its BOMs.

    Reachability slices and dep-scan's own manifest and findings files sit
    beside the BOMs in a directory cdxgen or an earlier scan produced; they
    are not CycloneDX documents and must not make the directory a source
    directory.
    """
    name = os.path.basename(path)
    return name.endswith(".slices.json") or name in _BOM_COMPANION_NAMES


def _has_executable_header(path: str) -> bool:
    """Whether the file starts with an ELF, PE or Mach-O header.

    The header decides rather than the executable bit, which every file has
    on Windows and which shell scripts carry elsewhere. A Java class file
    shares the Mach-O universal magic, so ``.class`` files never count.
    """
    if path.lower().endswith(".class"):
        return False
    try:
        with open(path, "rb") as fp:
            header = fp.read(4)
    except OSError:
        return False
    return header.startswith(b"MZ") or header in _EXECUTABLE_MAGICS


def _is_cyclonedx_document(path: str) -> bool:
    """Whether the file parses as a JSON document with a CycloneDX format.

    A file that cannot be read or parsed is simply not a BOM; detection never
    fails on an unreadable candidate.
    """
    try:
        with open(path, "rb") as fp:
            document = json.load(fp)
    except (OSError, ValueError):
        return False
    return isinstance(document, dict) and document.get("bomFormat") == "CycloneDX"


def _git_url_reason(target: str) -> Optional[str]:
    """Why the target is a git URL, or None when it is not one."""
    prefix = next((p for p in _GIT_URL_PREFIXES if target.startswith(p)), None)
    if prefix is None:
        return None
    if target.lower().endswith(_ARCHIVE_EXTENSIONS):
        return None
    return f"starts with {prefix} and does not name an archive file"


def _image_reference_reason(target: str) -> Optional[str]:
    """Why the target looks like a container image reference, or None."""
    if _DIGEST_REFERENCE_RE.match(target):
        return "no path and carries a sha256 digest"
    if _TAG_REFERENCE_RE.match(target):
        return "no path and looks like name:tag"
    if "/" in target and _PATH_REFERENCE_RE.match(target):
        return "no path and looks like registry/name"
    return None
