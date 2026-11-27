"""dep-scan defects the corpus scorer measured, pinned as tests.

A strict xfail test shows a defect that is still open: it fails today, and
the day the defect is fixed it passes and the strict marker fails the run,
so the marker and the corpus floor are updated in the same change.
"""

from types import SimpleNamespace

import pytest

from analysis_lib.findings.vdr_convert import finding_category
from depscan.lib import pipeline


@pytest.mark.xfail(
    strict=True,
    reason=(
        "the supply-chain check requests only the package-integrity and "
        "dependency-source audit packs for a GitHub Actions scan, so cdx-audit's "
        "ci-permission rules (CI-001, an unpinned action in a write-permission "
        "workflow) never run; the corpus item supply-chain-fixture misses CI-001"
    ),
)
def test_github_actions_scans_request_the_ci_permission_pack():
    ctx = SimpleNamespace(project_types=["github"])
    scan = SimpleNamespace(project_type="github")
    bom = SimpleNamespace(container=False, purl_types={"github"})
    assert "ci-permission" in pipeline._audit_categories(ctx, scan, bom)


def test_malicious_package_advisories_are_malware_findings():
    # The corpus measured MAL-2024-1000 reporting under the vulnerability
    # category; dep-scan#707 gave malware advisories their own category, and
    # the malware-fixture labels and floor rely on it.
    assert finding_category({"id": "MAL-2024-1000"}) == "malware"
    assert finding_category({"id": "CVE-2021-44228"}) == "vulnerability"
