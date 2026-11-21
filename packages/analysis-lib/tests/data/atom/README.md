# atom evidence adapter fixtures

Recordings of atom's own native output for the java-sec-code project, trimmed
from the pinned repotests data. The recordings were not made for this
repository's tests; they were pulled by the digests in
`contrib/repotests/testdata.lock.json` (the `java-sec-code` entry,
manifest `sha256:8588e97394786ef18f6616c6f3bf18ce24b4c66d27e4daf26a0ad7b9d65eeec1`,
scanning github.com/HooliCorp/java-sec-code at commit `7f7f02a`) and copied
into this directory from a local checkout of that pinned data.

Tool versions, as the tools name them in the recording: cdxgen `13.8.0`
(the version the scanned project's own BOM, `sbom-java.cdx.json`, carries in
`metadata.tools`), atom `4.0.2`, cdxgen plugins `4.3.1` (the `generators`
block of the lock entry above). cdxgen was obtained as the published npm
package `@cdxgen/cdxgen@13.8.0`; atom is the version that cdxgen release
bundles and invokes. The slices are current atom 4 output; no re-recording
was made for these fixtures.

Every file keeps whole report objects verbatim, in their original order;
everything cut is cut whole and nothing inside the kept objects was edited.

- `java-reachables.slices.json`: thirteen whole flow objects out of the
  recording's 398, chosen to cover thirteen distinct maven purls and both of
  atom's tag orders: purls interleaved with free-form tags on one node, and
  callee purls appended after a call's own tags (the atom 4 `withPurls`
  order). Flows whose node tags carry service tags and flows without any are
  both present, including one where a service tag sits on a node that names
  no purl of its own, so the tag falls back to the flow's own purls. Every
  flow carries at least one purl.
- `java-usages.slices.json`: eleven whole `objectSlices` entries covering
  usages with invoked calls, usages as call arguments, an entry with many
  usage entries and entries with none, plus two whole `userDefinedTypes`
  entries.
- `java-callsites.slices.json`: sixteen whole callsite entries covering every
  call-site kind the recording carries (`extends`, `annotation`,
  `decltype`, `call`, `ref`, `new`) across fifteen distinct purls; one entry
  names no purl, which exercises the no-purl callsite record.

File names inside the objects are the repository-relative paths of the
scanned java-sec-code checkout (its own `org.joychou` package structure and
its own source snippets), not paths from the machine the recording was made
on. No absolute paths, usernames, hostnames or secrets appear in any file.
