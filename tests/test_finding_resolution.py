import json

import httpx
import respx
from httpx import ASGITransport, AsyncClient

from app.main import app

VULNERABLE_SBOM = {
    "bomFormat": "CycloneDX",
    "components": [
        {"type": "library", "name": "pyyaml", "version": "5.3", "purl": "pkg:pypi/pyyaml@5.3"},
    ],
}

FIXED_SBOM = {
    "bomFormat": "CycloneDX",
    "components": [
        {"type": "library", "name": "pyyaml", "version": "6.0", "purl": "pkg:pypi/pyyaml@6.0"},
    ],
}


@respx.mock
async def test_finding_resolves_across_a_later_submission(db_session_factory):
    """Simulates the real CI flow: one commit's SBOM shows a vulnerable
    dependency, a later commit's SBOM (after the fix) shows it clean.
    These are two separate submissions with two separate Package rows --
    this test exists specifically to prove a finding from the first
    submission gets marked resolved when the second submission's scan no
    longer reports it, even though the two scans never share a package_id.
    """
    route = respx.post("https://api.osv.dev/v1/querybatch")
    route.side_effect = [
        httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-8q59-q68h-6hv4"}]}]},
        ),
        httpx.Response(200, json={"results": [{"vulns": []}]}),
    ]
    respx.get("https://api.osv.dev/v1/vulns/GHSA-8q59-q68h-6hv4").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "GHSA-8q59-q68h-6hv4",
                "summary": "PyYAML full_load arbitrary code execution",
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            },
        )
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First commit: vulnerable pyyaml==5.3, scanned and found.
        upload_1 = await client.post(
            "/sboms",
            files={"file": ("sbom.json", json.dumps(VULNERABLE_SBOM), "application/json")},
        )
        submission_1_id = upload_1.json()["id"]
        await client.post(f"/sboms/{submission_1_id}/scan")

        findings_1 = await client.get(f"/sboms/{submission_1_id}/findings")
        assert findings_1.json()["findings"][0]["vuln_id"] == "GHSA-8q59-q68h-6hv4"
        assert findings_1.json()["findings"][0]["resolved_at"] is None

        # Second commit: dependency bumped to pyyaml==6.0, a brand-new
        # submission and brand-new Package row -- not the same package_id
        # as the first scan.
        upload_2 = await client.post(
            "/sboms",
            files={"file": ("sbom.json", json.dumps(FIXED_SBOM), "application/json")},
        )
        submission_2_id = upload_2.json()["id"]
        await client.post(f"/sboms/{submission_2_id}/scan")

        # The original finding, viewed from either submission, should now
        # show resolved -- proving resolution isn't scoped to one
        # submission's package rows.
        findings_1_after = await client.get(f"/sboms/{submission_1_id}/findings")
        assert findings_1_after.json()["findings"][0]["resolved_at"] is not None

        findings_2 = await client.get(f"/sboms/{submission_2_id}/findings")
        assert findings_2.json()["findings"] == []
