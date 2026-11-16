"""The repo-test data validator of contrib/repotests.

The staleness checks refuse data that dep-scan would scan without finding
anything: BOMs from a cdxgen older than 13.8.0, reachables slices in the
atom 2 shape (a ``{"reachables": [...]}`` object, which the slice reader
silently skips because it is not a bare JSON array), and slices without a
single ``pkg:`` purl. The assert checks run the same reachability analyzers
the repo tests use and compare the reached purls against the project's
recorded minimum and mustReach names. The digest checks verify a pulled OCI
artifact file by file, and the lock builder turns the generation records
into testdata.lock.json.
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VALIDATE_PATH = REPO_ROOT / "contrib" / "repotests" / "validate.py"
PROJECTS_PATH = REPO_ROOT / "contrib" / "repotests" / "projects.json"
ATOM4_FIXTURE = REPO_ROOT / "test" / "data" / "atom4"


def load_validator():
    spec = importlib.util.spec_from_file_location("repotests_validate", VALIDATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(name="validator")
def validator_fixture():
    return load_validator()


def write_bom(path, cdxgen_version="13.8.0"):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "group": "@cdxgen",
                        "name": "cdxgen",
                        "version": cdxgen_version,
                    }
                ]
            }
        },
        "components": [],
    }
    path.write_text(json.dumps(bom), encoding="utf-8")


def write_reachables(path, flows):
    path.write_text(json.dumps(flows), encoding="utf-8")


def flow(purls=None):
    return {
        "flows": [{"id": "1", "label": "CALL", "tags": None}],
        "purls": purls or [],
    }


def test_staleness_accepts_the_atom4_fixture(validator):
    entry = {"name": "fixture", "minReachablePurls": 4, "mustReach": []}
    summary = validator.check_staleness(ATOM4_FIXTURE, entry)
    # The fixture keeps five flows, four of which carry pkg: purls (its README
    # lists them: quart at two versions, rich, custom-json-diff).
    assert summary == {
        "bomFiles": 1,
        "sliceFiles": 1,
        "flows": 5,
        "flowsWithPurl": 4,
    }


def test_staleness_rejects_an_old_cdxgen(validator, tmp_path):
    write_bom(tmp_path / "sbom-java.cdx.json", cdxgen_version="11.2.7")
    write_reachables(
        tmp_path / "java-reachables.slices.json", [flow(["pkg:maven/org.junit/junit@4.13"])]
    )
    with pytest.raises(validator.ValidationFailure, match=r"11\.2\.7.*13\.8"):
        validator.check_staleness(tmp_path, {"minReachablePurls": 1})


def test_staleness_names_cdxgen_version_from_a_legacy_tools_list(validator, tmp_path):
    # CycloneDX 1.5 and earlier write metadata.tools as a plain list.
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"tools": [{"name": "cdxgen", "version": "11.2.6"}]},
    }
    (tmp_path / "sbom-js.cdx.json").write_text(json.dumps(bom), encoding="utf-8")
    write_reachables(tmp_path / "js-reachables.slices.json", [flow(["pkg:npm/left-pad@1.3.0"])])
    with pytest.raises(validator.ValidationFailure, match="11.2.6"):
        validator.check_staleness(tmp_path, {"minReachablePurls": 1})


def test_staleness_rejects_atom2_slices(validator, tmp_path):
    write_bom(tmp_path / "sbom-js.cdx.json")
    # atom 2 wrapped the same flow objects in a top-level dict; dep-scan's
    # slice reader skips such files entirely, which is how a whole generation
    # of test data used to scan as if it held nothing.
    (tmp_path / "js-reachables.slices.json").write_text(
        json.dumps({"reachables": [flow(["pkg:npm/left-pad@1.3.0"])]}), encoding="utf-8"
    )
    with pytest.raises(validator.ValidationFailure, match="not a bare JSON array"):
        validator.check_staleness(tmp_path, {"minReachablePurls": 1})


def test_staleness_rejects_flows_without_purl_evidence(validator, tmp_path):
    write_bom(tmp_path / "sbom-js.cdx.json")
    write_reachables(tmp_path / "js-reachables.slices.json", [flow(), flow(["not-a-purl"])])
    with pytest.raises(validator.ValidationFailure, match="no flow with a pkg: purl"):
        validator.check_staleness(tmp_path, {"minReachablePurls": 1})


def test_staleness_accepts_purl_free_slices_of_a_c_project(validator, tmp_path):
    # C and C++ slices carry no purls in any atom version; a project with
    # minReachablePurls 0 records that and needs flows, not purls.
    write_bom(tmp_path / "sbom-c.cdx.json")
    write_reachables(tmp_path / "c-reachables.slices.json", [flow(), flow()])
    summary = validator.check_staleness(tmp_path, {"minReachablePurls": 0})
    assert summary["flows"] == 2
    assert summary["flowsWithPurl"] == 0


def test_staleness_rejects_slices_without_any_flow(validator, tmp_path):
    write_bom(tmp_path / "sbom-c.cdx.json")
    # An empty array is a valid atom 4 file; it just holds no flow.
    write_reachables(tmp_path / "c-reachables.slices.json", [])
    with pytest.raises(validator.ValidationFailure, match="no flow at all"):
        validator.check_staleness(tmp_path, {"minReachablePurls": 0})


def test_staleness_rejects_missing_boms_and_slices(validator, tmp_path):
    write_bom(tmp_path / "sbom-js.cdx.json")
    with pytest.raises(validator.ValidationFailure, match="no reachables slice"):
        validator.check_staleness(tmp_path, {"minReachablePurls": 1})
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(validator.ValidationFailure, match="no BOM files"):
        validator.check_staleness(empty, {"minReachablePurls": 1})


def test_assert_counts_reached_purls_of_the_atom4_fixture(validator, tmp_path):
    entry = {"name": "fixture", "minReachablePurls": 4, "mustReach": ["quart", "rich"]}
    summary = validator.check_assert(ATOM4_FIXTURE, entry, "SemanticReachability")
    # SemanticReachability over the fixture reaches exactly the four purls its
    # README records; this is also the positive control that the analyzer
    # itself ran rather than the check passing on empty input.
    assert summary["reachedPurls"] == 4
    assert summary["analyzer"] == "SemanticReachability"


def test_assert_fails_below_the_recorded_minimum(validator, tmp_path):
    entry = {"name": "fixture", "minReachablePurls": 99, "mustReach": []}
    with pytest.raises(validator.ValidationFailure, match="at least 99"):
        validator.check_assert(ATOM4_FIXTURE, entry, "SemanticReachability")


def test_assert_fails_when_a_must_reach_package_is_missing(validator, tmp_path):
    entry = {"name": "fixture", "minReachablePurls": 1, "mustReach": ["nonexistent"]}
    with pytest.raises(validator.ValidationFailure, match="nonexistent was not reached"):
        validator.check_assert(ATOM4_FIXTURE, entry, "SemanticReachability")


def test_assert_matches_scoped_package_names(validator):
    # A scoped npm name matches by its last segment and by scope/name.
    names = validator.purl_package_names("pkg:npm/%40types/node@20.1.0")
    assert "node" in names
    assert "@types/node" in names


def test_staleness_rejects_a_truncated_slice(validator, tmp_path):
    # cdxgen killed while atom writes leaves a valid prefix. The slice reader
    # would keep the flows before the cut and drop the rest silently.
    write_bom(tmp_path / "sbom-js.cdx.json")
    whole = json.dumps([flow(["pkg:npm/left-pad@1.3.0"]), flow(["pkg:npm/react@18.3.1"])])
    (tmp_path / "js-reachables.slices.json").write_text(
        whole[: len(whole) // 2 + 20], encoding="utf-8"
    )
    with pytest.raises(
        validator.ValidationFailure, match="js-reachables.slices.json: (malformed|truncated)"
    ):
        validator.check_staleness(tmp_path, {"minReachablePurls": 1})


def test_staleness_rejects_an_unterminated_slice(validator, tmp_path):
    write_bom(tmp_path / "sbom-js.cdx.json")
    whole = json.dumps([flow(["pkg:npm/left-pad@1.3.0"])])
    (tmp_path / "js-reachables.slices.json").write_text(whole[:-1], encoding="utf-8")
    with pytest.raises(validator.ValidationFailure, match="truncated"):
        validator.check_staleness(tmp_path, {"minReachablePurls": 1})


def make_manifest(dir_path, filenames):
    layers = []
    for name in filenames:
        blob = (dir_path / name).read_bytes()
        layers.append(
            {
                "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
                "annotations": {"org.opencontainers.image.title": name},
            }
        )
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": layers,
    }


def test_digests_accept_a_pulled_artifact(validator, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "sbom-js.cdx.json").write_text("{}", encoding="utf-8")
    (data_dir / "js-reachables.slices.json").write_text("[]", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(make_manifest(data_dir, ["sbom-js.cdx.json", "js-reachables.slices.json"])),
        encoding="utf-8",
    )
    assert validator.check_digests(data_dir, manifest) == {"verifiedFiles": 2}


def test_digests_reject_tampered_missing_and_extra_files(validator, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "sbom-js.cdx.json").write_text("{}", encoding="utf-8")
    (data_dir / "js-reachables.slices.json").write_text("[]", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(make_manifest(data_dir, ["sbom-js.cdx.json", "js-reachables.slices.json"])),
        encoding="utf-8",
    )

    (data_dir / "sbom-js.cdx.json").write_text('{"tampered": true}', encoding="utf-8")
    (data_dir / "extra.json").write_text("{}", encoding="utf-8")
    (data_dir / "js-reachables.slices.json").unlink()
    with pytest.raises(validator.ValidationFailure) as excinfo:
        validator.check_digests(data_dir, manifest)
    message = str(excinfo.value)
    assert "does not match" in message
    assert "not pulled" in message
    assert "extra.json" in message


def test_digests_check_the_manifest_against_the_pinned_digest(validator, tmp_path):
    # The action keeps the manifest in the cache beside the files. A manifest
    # that does not hash to the lock file's digest cannot vouch for them.
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "sbom-js.cdx.json").write_text("{}", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(make_manifest(data_dir, ["sbom-js.cdx.json"])), encoding="utf-8"
    )
    pinned = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert validator.check_digests(data_dir, manifest, pinned) == {"verifiedFiles": 1}

    other = "sha256:" + "0" * 64
    with pytest.raises(validator.ValidationFailure, match="is not the pinned"):
        validator.check_digests(data_dir, manifest, other)
    assert (
        validator.main(["digests", str(data_dir), "--manifest", str(manifest), "--digest", other])
        == 1
    )


def test_lock_writes_one_entry_per_generated_project(validator, tmp_path):
    data_root = tmp_path / "out"
    project = data_root / "rustpad"
    project.mkdir(parents=True)
    generation = {
        "name": "rustpad",
        "git": "https://example.invalid/rustpad.git",
        "commit": "a" * 40,
        "types": ["rust", "js"],
        "cdxgenArgs": ["--profile", "research"],
        "cdxgenVersion": "13.8.0",
        "atomVersion": "4.0.2",
        "cdxgenPluginsVersion": "4.3.1",
        "generated": "2026-11-16T10:00:00Z",
        "tag": "rustpad-cdxgen13.8.0-20261116",
    }
    (project / "generation.json").write_text(json.dumps(generation), encoding="utf-8")
    (project / "descriptor.json").write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + "b" * 64,
                "size": 1024,
            }
        ),
        encoding="utf-8",
    )
    lock_out = tmp_path / "testdata.lock.json"
    summary = validator.write_lock(data_root, lock_out, "ghcr.io/owasp-dep-scan/depscan-testdata")
    assert summary == {"projects": ["rustpad"]}
    lock = json.loads(lock_out.read_text(encoding="utf-8"))
    assert lock["registry"] == "ghcr.io/owasp-dep-scan/depscan-testdata"
    entry = lock["projects"]["rustpad"]
    assert entry["manifestDigest"] == "sha256:" + "b" * 64
    assert entry["tag"] == "rustpad-cdxgen13.8.0-20261116"
    assert entry["generators"] == {"cdxgen": "13.8.0", "atom": "4.0.2", "cdxgenPlugins": "4.3.1"}
    assert entry["source"]["commit"] == "a" * 40


def test_lock_refuses_a_generation_without_a_pushed_descriptor(validator, tmp_path):
    project = tmp_path / "out" / "rustpad"
    project.mkdir(parents=True)
    (project / "generation.json").write_text(json.dumps({"name": "rustpad"}), encoding="utf-8")
    with pytest.raises(validator.ValidationFailure, match="descriptor.json"):
        validator.write_lock(tmp_path / "out", tmp_path / "lock.json", "registry")


def test_projects_json_is_well_formed():
    projects = json.loads(PROJECTS_PATH.read_text(encoding="utf-8"))["projects"]
    assert projects, "projects.json must declare at least one project"
    names = [p["name"] for p in projects]
    assert len(names) == len(set(names)), "project names must be unique"
    for entry in projects:
        assert set(entry) >= {
            "name",
            "directory",
            "git",
            "commit",
            "types",
            "cdxgenArgs",
            "minReachablePurls",
            "mustReach",
        }, entry["name"]
        assert entry["git"].startswith("https://"), entry["name"]
        # A full commit SHA only: a branch or tag name would move under the
        # project and make generations irreproducible.
        assert len(entry["commit"]) == 40 and all(
            c in "0123456789abcdef" for c in entry["commit"]
        ), entry["name"]
        assert entry["types"] and all(isinstance(t, str) for t in entry["types"]), entry["name"]
        assert isinstance(entry["minReachablePurls"], int) and entry["minReachablePurls"] >= 0, (
            entry["name"]
        )
        for must in entry["mustReach"]:
            # Package name without version: a purl, an @version or a space
            # would silently never match.
            assert (
                isinstance(must, str)
                and must
                and "@" not in must
                and " " not in must
                and not must.startswith("pkg:")
            ), entry["name"]


def test_main_reports_failures_on_stderr_with_exit_code_one(validator, capsys, tmp_path):
    write_bom(tmp_path / "sbom-js.cdx.json", cdxgen_version="11.2.7")
    write_reachables(tmp_path / "js-reachables.slices.json", [flow(["pkg:npm/left-pad@1.3.0"])])
    projects = tmp_path / "projects.json"
    projects.write_text(
        json.dumps({"projects": [{"name": "js", "directory": "js"}]}), encoding="utf-8"
    )
    code = validator.main(
        ["staleness", str(tmp_path), "--projects", str(projects), "--name", "js"]
    )
    assert code == 1
    assert "FAILED staleness" in capsys.readouterr().err


def test_main_rejects_an_unknown_project(validator, tmp_path):
    projects = tmp_path / "projects.json"
    projects.write_text(json.dumps({"projects": []}), encoding="utf-8")
    code = validator.main(
        ["staleness", str(tmp_path), "--projects", str(projects), "--name", "ghost"]
    )
    assert code == 1


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="publish.sh and its oras stub are bash scripts; the publish job runs on Linux only",
)
def test_publish_pushes_every_project_and_writes_the_lock(tmp_path):
    """publish.sh drives oras once per project and writes the lock file.

    The oras on PATH is a stub that records its arguments and answers the
    descriptor fetch; the recording is the positive control that the real
    script reached oras with the provenance annotations.
    """
    import hashlib
    import os
    import subprocess

    data_root = tmp_path / "out"
    for name in ("rustpad", "depscan"):
        project = data_root / name
        project.mkdir(parents=True)
        (project / "sbom-js.cdx.json").write_text("{}", encoding="utf-8")
        (project / "js-reachables.slices.json").write_text("[]", encoding="utf-8")
        (project / "generation.json").write_text(
            json.dumps(
                {
                    "name": name,
                    "git": f"https://example.invalid/{name}.git",
                    "commit": "a" * 40,
                    "types": ["js"],
                    "cdxgenArgs": ["--profile", "research"],
                    "cdxgenVersion": "13.8.0",
                    "atomVersion": "4.0.2",
                    "cdxgenPluginsVersion": "4.3.1",
                    "generated": "2026-11-16T10:00:00Z",
                    "tag": f"{name}-cdxgen13.8.0-20261116",
                }
            ),
            encoding="utf-8",
        )
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    record = tmp_path / "oras-calls.txt"
    stub = stub_bin / "oras"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "$@" >> "{record}"\n'
        'if [ "$1" = "manifest" ] && [ "$2" = "fetch" ]; then\n'
        '  ref="$(echo "$@" | grep -o "ghcr.io[^ ]*")"\n'
        '  digest="sha256:$(printf %s "$ref" | shasum -a 256 | cut -d" " -f1)"\n'
        f'  printf \'{{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "%s", "size": 1024}}\\n\' "$digest"\n'
        "fi\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    env = dict(os.environ, PATH=f"{stub_bin}:{os.environ['PATH']}")
    summary = tmp_path / "summary.md"
    env["GITHUB_STEP_SUMMARY"] = str(summary)
    lock_out = data_root / "testdata.lock.json"

    result = subprocess.run(
        [
            str(REPO_ROOT / "contrib" / "repotests" / "publish.sh"),
            str(data_root),
            "ghcr.io/owasp-dep-scan/depscan-testdata",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr

    calls = record.read_text(encoding="utf-8").splitlines()
    pushes = [c for c in calls if c.startswith("push")]
    assert len(pushes) == 2
    # Every provenance field of decision 1 rides along as an annotation.
    for annotation in (
        "org.opencontainers.image.source=https://example.invalid/rustpad.git",
        "org.opencontainers.image.revision=" + "a" * 40,
        "org.opencontainers.image.created=2026-11-16T10:00:00Z",
        "io.owasp-dep-scan.testdata.project=rustpad",
        "io.owasp-dep-scan.testdata.cdxgen-version=13.8.0",
        "io.owasp-dep-scan.testdata.atom-version=4.0.2",
        "io.owasp-dep-scan.testdata.cdxgen-plugins-version=4.3.1",
        "io.owasp-dep-scan.testdata.cdxgen-args=--profile research",
    ):
        assert any(annotation in c for c in pushes), annotation
    # Each file is its own layer; generation.json never becomes one.
    rustpad_push = next(c for c in pushes if "rustpad" in c)
    assert "./sbom-js.cdx.json:application/json" in rustpad_push
    assert "./js-reachables.slices.json:application/json" in rustpad_push
    assert "generation.json" not in rustpad_push

    lock = json.loads(lock_out.read_text(encoding="utf-8"))
    entry = lock["projects"]["rustpad"]
    ref = "ghcr.io/owasp-dep-scan/depscan-testdata:rustpad-cdxgen13.8.0-20261116"
    assert entry["manifestDigest"] == "sha256:" + hashlib.sha256(ref.encode()).hexdigest()
    assert "| rustpad |" in summary.read_text(encoding="utf-8")
