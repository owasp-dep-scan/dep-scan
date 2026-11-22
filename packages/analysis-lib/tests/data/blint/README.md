# blint recordings

Raw blint 4.0.1 output kept as adapter test input: the three reports a
blint review writes plus the SBOM its sbom mode writes, over the two ELF
corpus binaries of the blint test suite. The tests in
`test_evidence_blint.py` and `test_blint_convert.py` read them.

## How they were made

blint comes from the repository virtual environment (the lockfile pin).
blint 4.0.1 has no `--version` flag, so the version is the installed
package's own:

```bash
uv run python -c "from importlib.metadata import version; print(version('blint'))"
4.0.1
```

The two corpus files were copied from a blint checkout's
`tests/data/plain-libc-demo.elf` and `tests/data/fortified-libc-demo.elf`
into a fresh temporary directory `corpus/`, so the recording never touched
the checkout. The reports are the ones dep-scan's own runner writes,
produced from the repository root:

```bash
uv run python -c "import sys; sys.path.insert(0, 'packages/xbom-lib/src'); \
from xbom_lib.blint import run_blint_reviews; \
r = run_blint_reviews(['<recording-dir>/corpus'], '<recording-dir>/out', deep=True); \
print(r.success, r.files)"
```

That wrote `analysis-coverage.json`, `findings.json` and `reviews.json`
under `<recording-dir>/out`. The SBOM is blint's own sbom mode over one
corpus binary, the file the adapter's producer version is read from:

```bash
uv run blint sbom -i <recording-dir>/corpus/plain-libc-demo.elf \
  -o <recording-dir>/out/sbom-blint.json
```

## What the recording holds

- `findings.json`: three findings, `CHECK_CANARY` and two `CHECK_ABI_FLOOR`
  entries, one per corpus binary.
- `reviews.json`: one review, `FORTIFIED_LIBC_IN_USE`, whose evidence
  lists the `__fprintf_chk` fortified symbol.
- `analysis-coverage.json`: two attempted, two succeeded units, nothing
  failed or skipped.
- `sbom-blint.json`: specVersion 1.7, `metadata.tools.components` naming
  blint 4.0.1, the plain binary as the metadata component and the loader
  and libc as library components.

## What was cut

- Every finding and review `description` was cut to its first sentence.
- Every occurrence of the recording directory was rewritten so the binary
  paths read `corpus/<name>.elf`; in the reports that is `filename` and
  `exe_name`, in the SBOM the `evidence.identity.methods[].value` entries
  and the `internal:srcFile` properties.
- Nothing else was changed: every finding and review entry is otherwise
  whole, key order and the compact one-line form are blint's own, and the
  SBOM keeps its pretty-printed form. `scan_id`, `created` and the SBOM's
  `serialNumber` and `metadata.timestamp` are the recording's own values;
  they never reach an evidence record.

The recording carries no usernames, hostnames or secrets.
