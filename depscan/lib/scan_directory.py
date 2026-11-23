"""The scan directory: the manifest and the findings file a scan writes.

A scan directory is the reports directory with a documented layout. The
BOM, VDR and slices files keep the names and places they have always had;
this module adds ``depscan.manifest.json`` and ``depscan.findings.json`` at
the top of the directory and moves the raw reports that dep-scan itself runs
a tool to produce under ``analysis/<producer>/``. Files that cdxgen writes,
or that the user passed in, stay where they are.

The manifest is written last, after every other file, through a temporary
file and a rename: an interrupted scan never leaves a manifest that lists
files that do not exist. A scan that stops partway still writes one, with
the failed stage and its reason.

Nothing outside ``inputs`` may carry an absolute path, a username or a
hostname. Paths in ``files`` are relative to the directory. Options that can
hold a secret are recorded as ``<redacted>``.
"""

import contextlib
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from custom_json_diff.lib.utils import json_load

from depscan.lib import doctor as doctor_lib
from depscan.lib.doctor import DoctorReport

#: The version of the ``depscan.findings.json`` document shape. Version 2
#: drops the Pressure axis from exploitability and adds its sources.
FINDINGS_SCHEMA_VERSION = "2"

#: The scan directory layout this version writes and reads. Layout 2 is
#: the evidence store layout: a manifest whose major is 1 predates the
#: evidence files and is refused on load.
LAYOUT_VERSION = "2.0"

#: The major version this code accepts when loading a manifest.
LAYOUT_MAJOR = 2

MANIFEST_FILE = "depscan.manifest.json"
FINDINGS_FILE = "depscan.findings.json"

#: Named in the layout and in the enrichment stage's outputs. The store is
#: written once per project type after the adapters run, and the index is
#: written last, after the findings exist, so both carry finished content.
EVIDENCE_FILE = "evidence.jsonl"
EVIDENCE_INDEX_FILE = "evidence.index.json"

#: The directory under which dep-scan's own tool runs keep their raw reports.
ANALYSIS_DIR = "analysis"

#: The value recorded for an option that was set and can hold a secret.
REDACTED = "<redacted>"

#: Option names whose value is treated as a secret: the name rule below plus
#: the free-form arguments and the two URLs, which a user may credentialed.
_SECRET_NAME_PARTS = ("key", "token", "password", "secret", "credential")
_SECRET_OPTIONS = ("cdxgen_args", "vdb_image", "cdxgen_server")

#: Path-valued options. They are recorded in ``inputs`` (as the user gave
#: them) instead of ``options``, so no absolute path appears outside inputs.
_PATH_OPTIONS = (
    "src_dir",
    "reports_dir",
    "src_dir_image",
    "bom",
    "bom_dir",
    "custom_data",
    "report_template",
    "server_allowed_paths",
    "html_report_file",
    "txt_report_file",
    "llm_prompt_file",
    "config",
    "exploitability_rules",
)

#: The suffixes of the cdxgen slice files, for role and project type parsing.
_SLICE_KINDS = ("deps", "usages", "callsites", "data-flow", "reachables", "semantics")

#: The reachables slices dep-scan's earlier versions wrote from a plugin's
#: raw report. Nothing writes them any more; the names stay so a stale file
#: keeps its true producer, kosi's included.
_LANGUAGE_REACHABLES = ("rust", "go", "dotnet", "kosi")

#: A converted reachables slice of an earlier dep-scan version, split parts
#: (``.slices_1.json``, ``.slices-1.json``) included. The other slices of
#: those prefixes, such as ``dotnet-usages.slices.json`` or the
#: ``rust-semantics.slices.json`` raw report, are cdxgen's.
_LANGUAGE_REACHABLES_RE = re.compile(
    r"^(?:%s)-reachables\.slices(?:[_-]\d+)?\.json$" % "|".join(_LANGUAGE_REACHABLES)
)

#: Files the rendering stages write, named for their role.
_REPORT_FILES = {
    "depscan.html",
    "depscan.txt",
    "depscan-prompts.md",
    "depscan.toml.sample",
    "csaf.toml.sample",
    "rendered.report",
}

_LIFECYCLE_PREFIXES = ("prebuild", "build", "postbuild", "container", "operations")


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: str) -> str:
    """The SHA-256 hex digest of a file's bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for block in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def option_is_set(value: Any) -> bool:
    """Whether an option carries a value, as opposed to its unset form."""
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    if isinstance(value, (list, tuple, dict, set)) and not value:
        return False
    return True


def option_holds_secret(name: str) -> bool:
    """Whether an option's name says it can hold a secret.

    The rule is a name containing key, token, password, secret or
    credential, plus the free-form cdxgen arguments and the two URLs, where
    credentials are legal parts of the value.
    """
    lowered = name.lower()
    return any(part in lowered for part in _SECRET_NAME_PARTS) or lowered in _SECRET_OPTIONS


def redact_options(options: Dict[str, Any]) -> Dict[str, Any]:
    """The parsed options for the manifest, with secrets removed.

    Secret-capable options become ``<redacted>`` when they were set and null
    when they were not, so the manifest shows that a secret was configured
    without recording it. Path-valued options are dropped; ``inputs`` records
    those paths as the user gave them.
    """
    out: Dict[str, Any] = {}
    for name, value in sorted(options.items()):
        if name in _PATH_OPTIONS:
            continue
        if option_holds_secret(name):
            out[name] = REDACTED if option_is_set(value) else None
        else:
            out[name] = value
    return out


def git_state(path: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """The git commit and dirty flag of a work tree, or None.

    Runs ``git rev-parse HEAD`` and ``git status --porcelain`` in ``path``
    with a timeout, and never runs anything else in the scanned project. The
    two invocations carry ``-c core.fsmonitor=false`` and
    ``--no-optional-locks`` so a scanned repository's own configuration can
    neither start a monitor process nor take index locks while the scan
    reads it. Any failure, including a directory that is not a work tree,
    leaves no git information behind.
    """
    argv = ["git", "-c", "core.fsmonitor=false", "--no-optional-locks"]

    def run(args: List[str]) -> Optional[subprocess.CompletedProcess]:
        try:
            return subprocess.run(
                [*argv, *args],
                cwd=path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            return None

    commit = run(["rev-parse", "HEAD"])
    if commit is None or commit.returncode != 0:
        return None
    status = run(["status", "--porcelain"])
    if status is None:
        return None
    return {"commit": commit.stdout.strip(), "dirty": bool(status.stdout.strip())}


def input_entries(options: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every input the scan read, as the user gave the paths.

    A file input carries its SHA-256 digest; a directory input carries its
    git state when the directory is a work tree. A purl search records the
    purl and nothing else, because nothing was read from disk.
    """
    entries: List[Dict[str, Any]] = []
    seen = set()

    def add(entry: Dict[str, Any]) -> None:
        key = (entry.get("type"), entry.get("path"))
        if key not in seen:
            seen.add(key)
            entries.append(entry)

    if options.get("search_purl"):
        add({"type": "purl", "path": str(options["search_purl"])})
    if options.get("bom"):
        bom = str(options["bom"])
        if os.path.isfile(bom):
            add({"type": "file", "path": bom, "sha256": sha256_file(bom)})
        else:
            add({"type": "file", "path": bom})
    if options.get("bom_dir"):
        add(_dir_input(str(options["bom_dir"])))
    if not (options.get("bom") or options.get("bom_dir") or options.get("search_purl")):
        add(_dir_input(str(options.get("src_dir") or ".")))
    if options.get("custom_data"):
        custom = str(options["custom_data"])
        if os.path.isdir(custom):
            add(_dir_input(custom))
        elif os.path.isfile(custom):
            add({"type": "file", "path": custom, "sha256": sha256_file(custom)})
        else:
            add({"type": "file", "path": custom})
    if options.get("exploitability_rules"):
        rules = str(options["exploitability_rules"])
        if os.path.isfile(rules):
            add({"type": "file", "path": rules, "sha256": sha256_file(rules)})
        else:
            add({"type": "file", "path": rules})
    if options.get("report_template"):
        template = str(options["report_template"])
        if os.path.isfile(template):
            add({"type": "file", "path": template, "sha256": sha256_file(template)})
        else:
            add({"type": "file", "path": template})
    return entries


def _dir_input(path: str) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"type": "dir", "path": path}
    git = git_state(path) if os.path.isdir(path) else None
    if git:
        entry["git"] = git
    return entry


def _parse_bom_project_type(stem: str) -> Optional[str]:
    """The project type a BOM name carries, for example python in
    ``sbom-python`` and ``sbom-postbuild-python``."""
    if not stem.startswith("sbom-"):
        return None
    remainder = stem[len("sbom-") :]
    for prefix in _LIFECYCLE_PREFIXES:
        if remainder.startswith(prefix + "-"):
            return remainder[len(prefix) + 1 :] or None
    return remainder or None


def _parse_slice_project_type(name: str) -> Optional[str]:
    """The project type a slices or openapi file name carries."""
    for kind in _SLICE_KINDS:
        suffix = f"-{kind}.slices"
        if name.endswith(suffix):
            return name[: -len(suffix)] or None
    if "-openapi" in name:
        return name.split("-openapi", 1)[0] or None
    return None


def classify_file(relative_path: str, is_cyclonedx=None) -> Dict[str, Any]:
    """One ``files`` entry: role, producer and project type of a file.

    ``relative_path`` uses forward slashes and never starts with a slash.
    ``is_cyclonedx`` is the parsed document when the caller has one, used to
    tell a user's BOM apart from other JSON the directory may hold. The
    manifest itself is never classified; callers leave it out.
    """
    name = os.path.basename(relative_path)
    parts = relative_path.split("/")
    stem = name[: -len(".json")] if name.endswith(".json") else None
    entry: Dict[str, Any] = {"path": relative_path}
    if len(parts) > 1 and parts[0] == ANALYSIS_DIR and len(parts) == 3:
        entry.update(role="raw-report", producer=parts[1])
        return entry
    if name == FINDINGS_FILE:
        entry.update(role="findings", producer="dep-scan")
        return entry
    if name == EVIDENCE_FILE or name == EVIDENCE_INDEX_FILE:
        entry.update(role="evidence", producer="dep-scan")
        return entry
    if name.endswith(".vdr.json"):
        project_type = None
        vdr_stem = name[: -len(".vdr.json")]
        if vdr_stem.startswith("sbom-"):
            project_type = _parse_bom_project_type(vdr_stem)
        if project_type:
            entry.update(role="vdr", producer="dep-scan", projectType=project_type)
        else:
            entry.update(role="vdr", producer="dep-scan")
        return entry
    if name.endswith(".csaf.json"):
        entry.update(role="csaf", producer="dep-scan")
        return entry
    if ".slices" in name and name.endswith(".json"):
        prefix = _parse_slice_project_type(name[: -len(".json")])
        producer = "dep-scan" if _LANGUAGE_REACHABLES_RE.match(name) else "cdxgen"
        if prefix:
            entry.update(role="slices", producer=producer, projectType=prefix)
        else:
            entry.update(role="slices", producer=producer)
        return entry
    if stem and stem.endswith("-openapi"):
        entry.update(role="other", producer="cdxgen", projectType=stem[: -len("-openapi")])
        return entry
    if name.endswith(".cdx.json") and stem:
        bom_stem = name[: -len(".cdx.json")]
        project_type = _parse_bom_project_type(bom_stem)
        if project_type is not None:
            producer = "blint" if bom_stem.startswith("sbom-postbuild-") else "cdxgen"
            entry.update(role="bom", producer=producer, projectType=project_type)
        else:
            entry.update(role="bom", producer="user")
        return entry
    if name in _REPORT_FILES or name.startswith("depscan-risk-") or name.startswith("license-"):
        entry.update(role="report", producer="dep-scan")
        return entry
    if name.endswith(".json") and is_cyclonedx is not None:
        # A BOM the user dropped here keeps its name and its place.
        if is_cyclonedx.get("bomFormat") == "CycloneDX":
            role = "vdr" if "vulnerabilities" in is_cyclonedx else "bom"
            entry.update(role=role, producer="user")
            return entry
    entry.update(role="other", producer="unknown")
    return entry


def walk_files(reports_dir: str) -> List[Dict[str, Any]]:
    """The files of the scan directory except the manifest, with digests.

    The scan directory is the top level of the reports directory plus the
    ``analysis/`` tree, which is everything a scan writes. Other
    subdirectories are not walked: the reports directory can be a BOM
    directory the user passed, or a directory inside the scanned project,
    and hashing a source tree would be slow and would list files no scan
    wrote. Paths are relative to the directory, always with forward
    slashes, so a manifest written on any platform reads the same
    everywhere.
    """
    entries = []
    analysis_root = os.path.join(reports_dir, ANALYSIS_DIR)
    for root, dirs, names in os.walk(reports_dir):
        if root == reports_dir:
            dirs[:] = [name for name in dirs if name == ANALYSIS_DIR]
        elif not root.startswith(analysis_root):
            dirs[:] = []
            continue
        for name in sorted(names):
            if name == MANIFEST_FILE:
                continue
            absolute = os.path.join(root, name)
            if not os.path.isfile(absolute):
                continue
            relative = os.path.relpath(absolute, reports_dir).replace(os.sep, "/")
            entry = classify_file(relative)
            try:
                entry["sha256"] = sha256_file(absolute)
            except OSError:
                continue
            entries.append(entry)
    entries.sort(key=lambda entry: entry["path"])
    return entries


def analyzer_entries(
    report: Optional[DoctorReport],
    project_types: List[str],
    adapter_results: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """The reachability analyzer entries for the enrichment stage, from the
    adapters' results.

    Every analyzer this scan could have used gets an entry, and the entry
    says what the adapters actually made of the reports. ``completed`` means
    the analyzer's adapter found and read a report: the BOM step handed one
    over, or a BOM-directory adapter found and read one, because the
    analysis ran when the data was generated. Anything else is
    ``not-assessed``: the reason is the adapter's own whenever an adapter
    result exists (a BOM-directory scan reads the reports the directory
    holds, so a damaged report is named as damaged even on a machine without
    the tool), and the doctor's capability reason stands in only when there
    is no result or it gave no reason, so a tool being installed is never
    reported as an analysis that ran. The producer-level
    caveats of a completed result are carried on the entry as ``caveats``.

    atom applies to every scan; a language analyzer applies when the scan's
    project types cover it, which a BOM directory or universal scan always
    does, because such a scan may hold packages of any language.
    """
    from depscan.lib.bom import reachability_analyzers_for_types

    tools_by_name = report.tools_by_name() if report else {}
    data = report.data if report else {}
    entries = []
    for name in reachability_analyzers_for_types(project_types):
        capability = doctor_lib.ANALYZER_CAPABILITIES[name]
        entry: Dict[str, Any] = {"name": name, "capability": capability}
        result = (adapter_results or {}).get(name)
        if result is not None and result.status == "completed":
            entry["status"] = "completed"
            if result.caveats:
                entry["caveats"] = [
                    {"kind": caveat.kind, "detail": caveat.detail} for caveat in result.caveats
                ]
        else:
            reason = result.reason if result is not None and result.reason else None
            if not reason:
                reason = doctor_lib.capability_unavailable_reason(capability, tools_by_name, data)
            if not reason:
                reason = f"no {name} report was produced or given for this scan"
            entry.update(
                status="not-assessed",
                reason=reason,
            )
        entries.append(entry)
    return entries


def home_relative(path: Optional[str]) -> Optional[str]:
    """A path with the user's home replaced by ``~``, or the path unchanged.

    The manifest may be shared, so it never carries the home directory or
    the username behind it; the doctor's tool and database paths are the
    machine's, and this keeps them readable without identifying anyone.
    Paths outside the home are machine locations such as ``/opt``, which
    name no user and are kept as they are.
    """
    if not path:
        return path
    home = os.path.expanduser("~")
    if home != "~" and (path == home or path.startswith(home + os.sep)):
        # Forward slashes, so the manifest reads the same on every platform.
        return "~" + path[len(home) :].replace(os.sep, "/")
    return path


def _sanitize_doctor_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = dict(entry)
    if sanitized.get("path"):
        sanitized["path"] = home_relative(str(sanitized["path"]))
    return sanitized


class ScanDirectory:
    """The manifest builder one scan fills in as its stages run."""

    def __init__(
        self,
        reports_dir: str,
        *,
        depscan_version: str,
        doctor_report: Optional[DoctorReport] = None,
    ):
        self.reports_dir = reports_dir
        self.depscan_version = depscan_version
        self.doctor_report = doctor_report
        self.started_utc = _utcnow()
        self.stages: List[Dict[str, Any]] = []

    def record_stage(
        self,
        name: str,
        status: str,
        *,
        project_type: Optional[str] = None,
        reason: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        analyzers: Optional[List[Dict[str, Any]]] = None,
        outputs: Optional[List[Dict[str, Any]]] = None,
        notAssessed: Optional[List[str]] = None,
    ) -> None:
        """Append one stage entry, in the order the stages ran."""
        entry: Dict[str, Any] = {
            "name": name,
            "status": status,
            "capabilities": list(capabilities or []),
        }
        if project_type:
            entry["projectType"] = project_type
        if reason:
            entry["reason"] = reason
        if analyzers is not None:
            entry["analyzers"] = analyzers
        if outputs is not None:
            entry["outputs"] = outputs
        if notAssessed:
            entry["notAssessed"] = list(notAssessed)
        self.stages.append(entry)

    def build(
        self,
        *,
        options: Dict[str, Any],
        database_flavor: Optional[str],
        shards_used: List[str],
    ) -> Dict[str, Any]:
        """Assemble the manifest document.

        The file walk happens here, at write time, so the ``files`` list
        names exactly the files that exist.
        """
        manifest: Dict[str, Any] = {
            "layoutVersion": LAYOUT_VERSION,
            "depscanVersion": self.depscan_version,
            "startUtc": self.started_utc,
            "endUtc": _utcnow(),
            "inputs": input_entries(options),
            "stages": self.stages,
            "options": redact_options(options),
            "files": walk_files(self.reports_dir),
            "database": {
                "vulnerabilityDatabase": {},
                "flavorUsed": database_flavor,
                "shardsUsed": list(shards_used or []),
            },
        }
        if self.doctor_report is not None:
            report_doc = self.doctor_report.to_dict()
            manifest["tools"] = [_sanitize_doctor_entry(tool) for tool in report_doc["tools"]]
            manifest["platform"] = report_doc["platform"]
            manifest["capabilities"] = report_doc["capabilities"]
            database = dict(report_doc["data"]["vulnerabilityDatabase"])
            database["directory"] = home_relative(database.get("directory"))
            manifest["database"]["vulnerabilityDatabase"] = database
        return manifest


def atomic_write_json(path: str, document: Any) -> None:
    """Write a JSON document through a temporary file and a rename.

    A reader of ``path`` therefore sees either the previous content or the
    complete new one, never a half-written document.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=directory,
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
        delete=False,
    )
    try:
        with tmp as fp:
            json.dump(document, fp, indent=2)
            fp.write("\n")
        os.replace(tmp.name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp.name)
        raise


def write_manifest(scan_dir: ScanDirectory, manifest: Dict[str, Any]) -> None:
    """Write the manifest into the scan directory, last of every file."""
    atomic_write_json(os.path.join(scan_dir.reports_dir, MANIFEST_FILE), manifest)


def write_findings(
    reports_dir: str,
    vulnerabilities: List[Dict[str, Any]],
    depscan_version: str,
    exploitability: Optional[Dict[Any, Any]] = None,
    blint_reviews: bool = False,
    evidence_records: Optional[Iterable[Any]] = None,
    usage_not_assessed: Optional[Dict[str, str]] = None,
):
    """Write ``depscan.findings.json`` from the scan's VDR entries and the
    blint binary review.

    A scan with no vulnerabilities writes the file with an empty findings
    array, so a reader can tell an assessed-empty scan from a directory
    nobody scanned. ``exploitability`` is the (advisory id, affects ref) ->
    Exploitability map the scan graded; each vulnerability finding records
    its assessment from it. ``blint_reviews`` says this scan asked for
    blint's review; without it the blint records among ``evidence_records``
    are not this scan's findings and are ignored. The binary-hardening
    findings are built from the blint records this scan's adapter produced,
    with the producer version the records carry. ``usage_not_assessed``
    maps a comparable purl to the reason usage evidence of that package in
    a BOM of the scan was not assessed; every vulnerability finding of
    that package that carries an exploitability assessment names the
    reason in its coverage, proven presence included.
    Returns the document written.
    """
    from analysis_lib.findings.blint_convert import findings_from_blint_records
    from analysis_lib.findings.vdr_convert import findings_from_vdr

    findings = findings_from_vdr(
        vulnerabilities,
        producer_version=depscan_version,
        exploitability=exploitability,
        usage_not_assessed=usage_not_assessed,
    )
    if blint_reviews:
        findings.extend(findings_from_blint_records(evidence_records))
    document = {
        "schemaVersion": FINDINGS_SCHEMA_VERSION,
        "findings": [finding.to_dict() for finding in findings],
    }
    atomic_write_json(os.path.join(reports_dir, FINDINGS_FILE), document)
    return document


def output_path(reports_dir: str, relative: str) -> str:
    """The file a manifest output names, joined under ``reports_dir``.

    Manifest outputs are scan-directory-relative paths with ``/``
    separators. One that resolves outside the scan directory (a ``..``
    segment, or a symlink that leads out) raises ValueError naming it, so a
    hand-edited or hostile manifest cannot make a reader open a file
    elsewhere.
    """
    path = os.path.join(str(reports_dir), *str(relative).split("/"))
    root = os.path.realpath(str(reports_dir))
    resolved = os.path.realpath(path)
    if resolved != root and not resolved.startswith(root.rstrip(os.sep) + os.sep):
        raise ValueError(
            f"The manifest output '{relative}' resolves outside the scan "
            f"directory '{reports_dir}'."
        )
    return path


def read_manifest(reports_dir: str) -> Optional[Dict[str, Any]]:
    """The manifest of a scan directory, or None when there is none.

    A manifest that exists but cannot be parsed raises, because a reader
    must not fall back to the older layout and present a broken directory
    as a valid scan.
    """
    path = os.path.join(str(reports_dir), MANIFEST_FILE)
    if not os.path.isfile(path):
        return None
    document = json_load(path)
    if not isinstance(document, dict):
        raise ValueError(f"The manifest at '{path}' is not a JSON object.")
    return document


def read_findings(reports_dir: str) -> Optional[Dict[str, Any]]:
    """The findings document of a scan directory, or None when absent.

    A file that exists but is not valid JSON raises: the error names the
    file and the parse failure, because a corrupted findings document must
    never read back as a scan with no findings.
    """
    path = os.path.join(str(reports_dir), FINDINGS_FILE)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fp:
            document = json.load(fp)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"The findings file at '{path}' is unreadable: it is not valid JSON ({exc})."
        ) from exc
    if not isinstance(document, dict):
        raise ValueError(f"The findings file at '{path}' is not a JSON object.")
    return document


def check_layout_version(manifest: Dict[str, Any]) -> None:
    """Refuse a manifest whose layout major this reader does not know.

    A reader accepts any minor version of a major it knows; anything else
    raises with both versions named.
    """
    version = str(manifest.get("layoutVersion") or "")
    try:
        major = int(version.split(".", 1)[0])
    except ValueError as exc:
        raise ValueError(
            f"The manifest carries an unreadable layoutVersion {version!r}; "
            f"this dep-scan reads layout {LAYOUT_VERSION}."
        ) from exc
    if major != LAYOUT_MAJOR:
        raise ValueError(
            f"The manifest carries layout version {version}, which this "
            f"dep-scan ({LAYOUT_VERSION}) does not support."
        )


def matching_completed_types(manifest: Dict[str, Any]) -> List[str]:
    """The project types whose matching stage completed, in scan order.

    This is what lets a manifest-backed type with no VDR file load as a
    result with no vulnerabilities: its matching stage ran and found
    nothing. A type whose matching stage was skipped, failed or never
    recorded must not load as clean.
    """
    types: List[str] = []
    for stage in manifest.get("stages") or []:
        if stage.get("name") != "matching" or stage.get("status") != "completed":
            continue
        project_type = stage.get("projectType")
        if project_type and project_type not in types:
            types.append(project_type)
    return types


#: The schema objects the documentation documents as field tables, in page
#: order. The top-level manifest fields come first.
_DOCUMENTED_DEFS = ("input", "database", "stage", "analyzer", "stageOutput", "file")


def _field_table(properties: Dict[str, Any]) -> List[str]:
    """One markdown table of field names and descriptions, from the schema."""
    lines = ["| Field | What it holds |", "| --- | --- |"]
    for name, spec in properties.items():
        description = str(spec.get("description") or "").strip()
        lines.append(f"| `{name}` | {description} |")
    return lines


def manifest_fields_markdown() -> str:
    """The manifest schema's fields as the markdown tables the docs embed.

    The documentation page carries the output of this function, so the
    published tables cannot drift from the schema.
    """
    from analysis_lib.findings.schemas import load_schema

    schema = load_schema("depscan-manifest")
    lines = ["### Manifest fields", ""]
    lines += _field_table(schema["properties"])
    for def_name in _DOCUMENTED_DEFS:
        definition = schema["$defs"][def_name]
        lines += ["", f"### {def_name} fields", ""]
        lines += _field_table(definition["properties"])
    return "\n".join(lines)


def project_types(manifest: Dict[str, Any]) -> List[str]:
    """The project types the manifest recorded, in the order they ran."""
    types = []
    for stage in manifest.get("stages") or []:
        project_type = stage.get("projectType")
        if project_type and project_type not in types:
            types.append(project_type)
    return types


def stage_outputs(manifest: Dict[str, Any], name: str, status: str = "completed") -> List[Any]:
    """The (project type, file path) pairs a completed stage recorded with
    the given output status.

    The inventory stage records the BOM document it settled on and the vdr
    stage records the VDR it wrote, which maps each file to the project type
    that produced it; the file name alone does not always carry the type.
    """
    outputs = []
    for stage in manifest.get("stages") or []:
        if stage.get("name") != name or stage.get("status") != "completed":
            continue
        for output in stage.get("outputs") or []:
            if output.get("file") and output.get("status") == status:
                outputs.append((stage.get("projectType"), output["file"]))
    return outputs
