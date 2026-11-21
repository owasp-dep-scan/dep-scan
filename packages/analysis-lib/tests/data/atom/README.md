# atom evidence adapter fixtures

Two recording sets of atom's native output: one from the current cdxgen
`master` with atom 4.0.3, one from the pinned repotests data. The adapter
tests read both; this README says how each was made and what was kept.

## python-*.slices.json: recorded for this repository with the latest tools

Recorded with cdxgen `13.9.0` (master build `af131a30`, installed by
`harness/tools-latest.sh`, run as `~/.local/bin/cdxgen`), which bundles atom
`4.0.3` and atom-parsetools `2.0.0`. The scanned project was this
repository's own checkout (read only; the recording was written elsewhere):

```console
$ export DOTNET_ROOT=$HOME/.dotnet PATH=$HOME/.dotnet:$PATH
$ export ATOM_TOOLS_WORK_DIR=<recording-dir> ATOM_TOOLS_OPENAPI_FILENAME=python-openapi.json
$ cdxgen -t python -o <recording-dir>/sbom-python.cdx.json --profile research \
    --reachables-slices-file <recording-dir>/python-reachables.slices.json \
    --usages-slices-file <recording-dir>/python-usages.slices.json \
    --callsites-slices-file <recording-dir>/python-callsites.slices.json \
    <dep-scan checkout>
```

The BOM the run wrote names cdxgen 13.9.0 in `metadata.tools`; the atom
version is the one that cdxgen master bundles and invokes (4.0.3). The run
produced 770 reachables flows over seven distinct pypi purls, 5105 callsites
and 28775 usage slices. No OpenAPI document was produced (this scan carries
no HTTP endpoints), so the `x-atom-usages` coverage lives in
`test/data/atom4/python-openapi.json`.

What was kept, everything whole and in order:

- `python-reachables.slices.json`: six whole flow objects, chosen to cover
  six distinct pypi purls including quart at two versions (the second
  version of one package), one multi-purl flow, one flow whose node tags
  interleave a purl, a `comp-desc:framework` token and a second purl (the
  atom 4 withPurls-style order), and one flow whose nodes name no purls.
- `python-callsites.slices.json`: 34 whole callsite entries covering every
  kind the recording carries (`call`, `ref`, `arg`, `decltype`, `extends`,
  `decorator`), most with a purl, several without.
- `python-usages.slices.json`: eight whole `objectSlices` entries, six with
  invoked calls and two without, plus two whole `userDefinedTypes` entries.

## java-*.slices.json: the pinned repotests recordings

Trimmed from the pinned repotests data, pulled by the digests in
`contrib/repotests/testdata.lock.json` (the `java-sec-code` entry, manifest
`sha256:8588e97394786ef18f6616c6f3bf18ce24b4c66d27e4daf26a0ad7b9d65eeec1`,
scanning github.com/HooliCorp/java-sec-code at commit `7f7f02a`), which the
evidence deliverable allows as a recording source. Tool versions as the data
names them: cdxgen `13.8.0`, atom `4.0.2`, cdxgen plugins `4.3.1`.

They are kept beside the current-release recordings for one reason: atom's
Java tagger emits the bare service tags (`web`, `framework`) the service
attribution is exercised on, and the recordings the latest tools produced on
this machine do not carry them (a Python scan of this repository tags nodes
`framework-input`/`cli-source`/`comp-desc:framework`, none of which is a
bare service tag; one JS web project failed under atom 4.0.3 outright, and
a second carried only `library-call` tags). The Java runs could not be
repeated here: the project needs its Maven build, which this machine does
not have.

- `java-reachables.slices.json`: thirteen whole flow objects covering
  thirteen distinct maven purls and both of atom's tag orders, including
  flows whose node tags carry service tags, one where a service tag sits on
  a node that names no purl of its own, and one flow with no purls.
- `java-usages.slices.json`: eleven whole `objectSlices` entries plus two
  whole `userDefinedTypes` entries.
- `java-callsites.slices.json`: sixteen whole callsite entries covering
  every call-site kind the recording carries across fifteen distinct purls.

File names inside every object are the scanned repository's own relative
paths (the `org.joychou` package structure and its source snippets for the
java set, this repository's `depscan/` and `packages/` tree for the python
set), not paths from the machine the recording was made on. No absolute
paths, usernames, hostnames or secrets appear in any file.
