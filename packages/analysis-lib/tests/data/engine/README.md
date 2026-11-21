# reachability engine fixtures

The BOM half of the pinned-data input the reachability engine tests run on.
The slice half is the recorded atom output in the ``../atom`` directory next
to this one; its README describes how those recordings were cut.

- `sbom-java.cdx.json`: the BOM of the same `java-sec-code` scan, trimmed to
  the thirteen components the thirteen recorded reachables flows reach
  (matched by purl, kept verbatim, occurrences included). The document
  metadata is cut back to its `lifecycles` entry (the recording carries a
  single `build` phase, so no post-build component list is derived from it).

File names inside the components are the repository-relative paths of the
scanned java-sec-code checkout. No absolute paths, usernames, hostnames or
secrets appear in any file.
