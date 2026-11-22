# dosai evidence recordings

Two recordings of current dosai releases, trimmed for the evidence-adapter
tests in `../test_evidence_dosai.py`. Both are combined reports in the shape
dep-scan assembles in `depscan/lib/bom.py` (a dict with `Metadata`, `methods`
and `dataflows`), with the sections the dosai evidence adapter consumes kept
whole and the bulk sections no consumer reads dropped.

Neither file contains local absolute paths, usernames, hostnames or
timestamps: `Metadata.InputPath` was replaced with a stable relative
placeholder (`./reachable-app`, `./unreachable-app`), and `GeneratedAt` and
`InputFullPath` were removed. The `methods` `Metadata` block keeps its
`TargetFrameworks` lists. Every file location inside the sections (`Path`,
`FileName`) is already relative to the scanned app in dosai's own output and
was left untouched.

## dosai-v5.0.0-reachable-combined.json

The dosai 5.0.0 release binary over the committed `reachable-app` fixture
(`test/data/dosai/repos/reachable-app`, the Newtonsoft.Json deserialization
app). The binary was obtained by downloading the self-contained release
asset over plain HTTPS,

```console
$ curl -L -o Dosai-osx-arm64-full \
    https://github.com/owasp-dep-scan/dosai/releases/download/v5.0.0/Dosai-osx-arm64-full
```

and it prints `--version` as `5.0.0+0c35f375fbcf81cf4d221c043373e8eadcf098b8`,
the build string of the published dosai 5.0.0 release.
Recording commands, run from a scratch directory outside the repository
(the app was passed by its real absolute path; the placeholder stands in
here):

```console
$ Dosai-osx-arm64-full dataflows --path <repos>/reachable-app --o dataflows.json
$ Dosai-osx-arm64-full methods --path <repos>/reachable-app --o methods.json
```

The binary reports `Metadata.AnalyzerVersion` `5.0.0.0` (`AnalyzerBuild`
`5.0.0+0c35f375...`) and, despite the 5.0.0 release name, writes
`Metadata.SchemaVersion` `5.1.0`.

Kept whole from the recording: `dataflows` `Statistics`, `Diagnostics`,
`Slices`, `Nodes`, `PackageReachability`, `ExploitChains`, `AttackSurface`,
`EntryPoints`, `SanitizedFlows`, `WeaknessCandidates`,
`DangerousApiReachability`; `methods` `PackageReachability`,
`EntryPoints`, `ApiEndpoints`, `Services`, `DeadCode`, `Reachability`,
`Diagnostics`, `Metadata`; the combined `Metadata` block. The `methods`
`PackageReachability` entries carry the `ExternalCallGraphNode` kind at
High confidence for all three packages, the evidence kind that master's
flow projection dropped (dep-scan issue 561). The app produces no
`SanitizedFlows`, `ApiEndpoints`, `Services` or `DeadCode` entries, so
those sections are present and empty; the `methods.Reachability` list
carries the 13 unreachable node entries that exercise the dead-code
records.

Dropped (no consumer reads them): `dataflows` `Edges`, `MethodSummaries`,
`Patterns`; `methods` `AiComponents`, `AssemblyInformation`,
`CallGraph`, `Constructors`, `Dependencies`, `Events`, `Fields`,
`Frameworks`, `Methods`, `MethodCalls`, `Properties`, `RecursionClusters`,
`SecurityFindings`, `SourceAssemblyMapping`. The `Methods` section was the
only other place the recording carried absolute paths (assembly paths under
`bin/Debug`).

`WeaknessCandidates` (6 entries) and `DangerousApiReachability` (8 entries)
were added later, whole, from a second run of the dosai 5.0.0 release
build (`--version` prints the same `5.0.0+0c35f375...` string) over a copy of
`reachable-app`, with the same two commands. That run's other sections are identical to the ones above, so
the added entries refer to the same slices, nodes and entry points. Neither
section carries an absolute path (their locations read `Program.cs:12:19`),
so nothing in them was rewritten.

## dosai-main-unreachable-combined.json

The dosai main-branch build at commit `0d4c331` over the committed
`unreachable-app` fixture (`test/data/dosai/repos/unreachable-app`, the app
whose Newtonsoft.Json dependency is present but never reached). The binary
was built from a throwaway detached worktree of the dosai checkout at that
commit,

```console
$ git -C <dosai-checkout> worktree add --detach /tmp/dosai-main 0d4c331
$ cd /tmp/dosai-main
$ dotnet publish ./Dosai/ -c Release -r osx-arm64 \
    --property:PublishDir=<dir> -p:PublishSingleFile=true \
    --no-self-contained /p:UseAppHost=true /p:AssemblyName=dosai-main
```

with the .NET SDK 11.0.100 (`DOTNET_ROOT` pointing at its install
directory).
The built binary prints `--version` as
`5.0.0+0d4c3317aa54df99e532ac2bdfa46becbb92c8b0` and records this fixture
only. Recording commands as above, with `unreachable-app` in place of
`reachable-app`. It writes `Metadata.SchemaVersion` `5.1.0` and
`Metadata.AnalyzerVersion` `5.0.0.0` (`AnalyzerBuild`
`5.0.0+0d4c331...`).

Kept and dropped sections are the same lists as above, except that this
recording does not carry `WeaknessCandidates` or `DangerousApiReachability`.
This recording has
3 dataflow slices (one of them, `dfs2`, names no package purls, which
exercises the record-skipped caveat), `ExternalCallGraphNode` entries for
both packages, 3 exploit chains, and no `SanitizedFlows`, `ApiEndpoints`,
`Services` or `DeadCode` entries; all 6 `methods.Reachability` nodes are
reachable, so this file carries no dead-code negatives.

## Section shapes the recordings do not carry

The two apps are console apps: neither produces `SanitizedFlows`,
`ApiEndpoints`, `Services` or `DeadCode` entries, and current releases
state an explicit `Confidence` on every `PackageReachability` entry. The
adapter paths for sanitizer records, API-endpoint records, service records,
dead-code `DeadCode` entries, and entries without an explicit confidence
are exercised in the tests with reports built from the sections of the real
recordings plus shapes taken from the checked-in samples of older dosai
releases (`dosai-exploit-chains.sample.json`, schema 4.1.0) and, for the
issue 561 reproducer, from the issue's quoted report description.
