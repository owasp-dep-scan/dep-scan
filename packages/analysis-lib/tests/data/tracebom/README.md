# tracebom recordings

Trace BOMs recorded as adapter test input. The tests in
`test_evidence_tracebom.py` read them.

## How they were made

`tracebom` is the command the cdxgen 13.9.0 package installs; it prints
`CycloneDX Generator 13.9.0` (cdxgen master `af131a30`).

Both recordings ran in a temporary directory (deleted afterwards, spelled
`<recording-dir>` below). The traced workload built one shared library and
served two local endpoints, both bound to loopback only, no external
network and no credentials:

```bash
clang -shared -o libtrace-demo.dylib trace-demo.c        # int trace_demo_add(int, int)
python3 -m http.server 8471                              # plain HTTP
openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout key.pem -out cert.pem
openssl s_server -accept 8472 -www -key key.pem -cert cert.pem
```

The traced command loaded the local library with ctypes and fetched both
endpoints with curl (`fetch-demo.py` was
`ctypes.CDLL("<recording-dir>/libtrace-demo.dylib")` plus one call to
`trace_demo_add`):

```bash
tracebom -d <recording-dir> \
  --cmd "sh -c 'python3 <recording-dir>/fetch-demo.py; \
curl -s --noproxy \"\" http://localhost:8471/; \
curl -sk --noproxy \"\" https://localhost:8472/'" \
  --proxy-egress --allow-host localhost --allow-port 8471,8472 \
  --timeout 60000 -o tracebom.json
```

The `--noproxy ""` and the host name `localhost` (not the `127.0.0.1`
literal) are what the egress proxy needs to observe the fetches. The
dry-run recording used one command that wrote a file and fetched two
localhost URLs, with every side effect denied:

```bash
tracebom --sandbox-dry-run \
  --cmd "sh -c 'echo traced > out.txt; curl -s http://localhost:8473/; \
curl -sk https://localhost:8474/'" \
  -d <recording-dir> --timeout 30000 -o tracebom-dry-run.json
```

## What each file holds

`tracebom.json` holds four `cryptographic-asset` components (three
algorithms and the TLSv1.3 protocol with its cipher suite, seen in the TLS
handshake to the https endpoint) and two services, one per endpoint, each
with `cdx:dynamic:egressDecision` `allowed`.

It holds no library components: on macOS the safer-exec runtime
(`@cdxgen/safer-exec-darwin-arm64` 1.3.0) reports library loads only as
`file-read` violation events and never emits the `lib-load` events cdxgen
collects, so tracebom on this platform writes no component with a
`cdx:dynamic:filePath` property. The tests add library components in the
two shapes `lib/inventory/dynamic.js` writes: a generic purl whose subpath
is the loaded file's absolute path (the shape cdxgen's own tests assert,
including the Windows DLL spelling `C:\Windows\System32\bcrypt.dll`),
and a file the OS package manager owns, named by that package's purl with
its `arch` and `distro` qualifiers (the purls `osPackageResolver.poku.js`
asserts, such as `pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9`). The services an
eBPF HTTP trace builds on Linux (only `cdx:service:httpMethod`, and the
`urn:service:dynamic:` bom-ref) are added the same way, from
`traceRunner.js`.

`tracebom-dry-run.json` holds no components and no services, only the ten
`cdx:dynamic:dryRun*` metadata properties with the attempted-operation
counts a denied run leaves (file reads, file writes, exec and fork
attempts; only counts are recorded, never the paths or targets).

## What was cut

Nothing. Both recordings are small and carry no path, user name or host
name of the recording machine: the components describe algorithms, the
endpoints name `localhost`, the dry run records counts only, and the
private key never left the temporary directory. The metadata timestamps
and the random serial numbers are what tracebom printed.
