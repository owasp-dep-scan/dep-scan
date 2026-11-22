# tracebom recording

A trace BOM recorded as adapter test input. The tests in
`test_evidence_tracebom.py` read it.

## How it was made

`tracebom` is the one shipped inside the cdxgen package
(`~/.local/bin/tracebom`); it prints `CycloneDX Generator 13.9.0`
(cdxgen master `af131a30`).

In a temporary directory (`/tmp/tracebom-rec`, deleted afterwards) the
recording built one shared library and served two local endpoints, both
bound to loopback only, no external network and no credentials:

```bash
clang -shared -o libtrace-demo.dylib trace-demo.c        # int trace_demo_add(int, int)
python3 -m http.server 8471                              # plain HTTP
openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout key.pem -out cert.pem
openssl s_server -accept 8472 -www -key key.pem -cert cert.pem
```

The traced command loaded the local library with ctypes and fetched both
endpoints with curl:

```bash
~/.local/bin/tracebom -d /tmp/tracebom-rec \
  --cmd "sh -c '/usr/bin/python3 /tmp/tracebom-rec/fetch-demo.py; \
/usr/bin/curl -s --noproxy \"\" http://localhost:8471/; \
/usr/bin/curl -sk --noproxy \"\" https://localhost:8472/'" \
  --proxy-egress --allow-host localhost --allow-port 8471,8472 \
  --timeout 60000 -o tracebom.json
```

`fetch-demo.py` was `ctypes.CDLL("/tmp/tracebom-rec/libtrace-demo.dylib")`
plus one call to `trace_demo_add`. The `--noproxy ""` and the host name
`localhost` (not the `127.0.0.1` literal) are what the egress proxy needs
to observe the fetches.

## What the BOM holds

Four `cryptographic-asset` components (three algorithms and the TLSv1.3
protocol with its cipher suite, seen in the TLS handshake to the https
endpoint) and two services, one per endpoint, each with
`cdx:dynamic:egressDecision` `allowed`.

It holds no library components: on macOS the safer-exec runtime
(`@cdxgen/safer-exec-darwin-arm64` 1.3.0) reports library loads only as
`file-read` violation events and never emits the `lib-load` events cdxgen
collects, so tracebom on this platform writes no component with a
`cdx:dynamic:filePath` property. The tests add one library component in
the exact shape `lib/inventory/dynamic.js` writes (the shape cdxgen's own
tests assert, including the Windows DLL spelling
`C:\Windows\System32\bcrypt.dll`) to cover the file path relativisation.

## What was cut

Nothing. The recording is 2.4 KB and carries no path, user name or host
name of the recording machine: the components describe algorithms, the
endpoints name `localhost`, and the private key never left the temporary
directory. The metadata timestamp and the random serial number are what
tracebom printed.
