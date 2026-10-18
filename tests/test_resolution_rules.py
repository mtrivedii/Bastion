import respx

from tests.helpers import client, mock_osv, sbom, upload, upload_and_scan

VULN = "GHSA-8q59-q68h-6hv4"
CRITICAL_RECORD = {
    "id": VULN,
    "summary": "PyYAML arbitrary code execution",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
}


async def findings(c, submission_id, state="all"):
    response = await c.get(f"/sboms/{submission_id}/findings", params={"state": state})
    assert response.status_code == 200
    return response.json()["findings"]


@respx.mock
async def test_upgrade_resolves_as_fixed(db_session_factory):
    mock_osv({("pyyaml", "5.3"): [VULN]}, {VULN: CRITICAL_RECORD})
    async with client() as c:
        first = await upload_and_scan(c, sbom(("pyyaml", "5.3")))
        second = await upload_and_scan(c, sbom(("pyyaml", "6.0")))

        old = await findings(c, first)
        assert old[0]["resolved_at"] is not None
        assert old[0]["resolution"] == "fixed"
        assert old[0]["severity"] == "CRITICAL"
        assert old[0]["cvss_score"] == 9.8
        assert await findings(c, second) == []


@respx.mock
async def test_removing_the_package_resolves_as_removed(db_session_factory):
    mock_osv({("pyyaml", "5.3"): [VULN]}, {VULN: CRITICAL_RECORD})
    async with client() as c:
        first = await upload_and_scan(c, sbom(("pyyaml", "5.3"), ("requests", "2.32.0")))
        await upload_and_scan(c, sbom(("requests", "2.32.0")))

        old = await findings(c, first)
        assert len(old) == 1
        assert old[0]["resolved_at"] is not None
        assert old[0]["resolution"] == "removed"


@respx.mock
async def test_a_finding_that_persists_stays_open_and_keeps_discovery_time(db_session_factory):
    mock_osv({("pyyaml", "5.3"): [VULN]}, {VULN: CRITICAL_RECORD})
    async with client() as c:
        first = await upload_and_scan(c, sbom(("pyyaml", "5.3")))
        discovered = (await findings(c, first))[0]["discovered_at"]
        second = await upload_and_scan(c, sbom(("pyyaml", "5.3")))

        current = await findings(c, second, state="open")
        assert len(current) == 1
        assert current[0]["discovered_at"] == discovered
        assert current[0]["resolution"] is None


@respx.mock
async def test_projects_do_not_affect_each_other(db_session_factory):
    mock_osv({("pyyaml", "5.3"): [VULN]}, {VULN: CRITICAL_RECORD})
    async with client() as c:
        app_a = await upload_and_scan(c, sbom(("pyyaml", "5.3")), project="app-a")
        # Project B does not use pyyaml at all. It must not resolve A's finding.
        await upload_and_scan(c, sbom(("requests", "2.32.0")), project="app-b")

        assert (await findings(c, app_a))[0]["resolved_at"] is None


@respx.mock
async def test_state_filter(db_session_factory):
    mock_osv({("pyyaml", "5.3"): [VULN]}, {VULN: CRITICAL_RECORD})
    async with client() as c:
        first = await upload_and_scan(c, sbom(("pyyaml", "5.3")))
        assert len(await findings(c, first, "open")) == 1
        await upload_and_scan(c, sbom(("pyyaml", "6.0")))
        assert await findings(c, first, "open") == []
        assert len(await findings(c, first, "resolved")) == 1


@respx.mock
async def test_scanning_an_older_submission_is_refused(db_session_factory):
    mock_osv({})
    async with client() as c:
        old = (await upload(c, sbom(("requests", "2.32.0")))).json()["id"]
        await upload(c, sbom(("requests", "2.32.1")))
        response = await c.post(f"/sboms/{old}/scan")
        assert response.status_code == 409
        assert "newer" in response.json()["detail"]


@respx.mock
async def test_a_running_scan_cannot_be_started_twice(db_session_factory):
    mock_osv({})
    async with client() as c:
        submission = (await upload(c, sbom(("requests", "2.32.0")))).json()["id"]
        # Put the submission into "scanning" the way an in-flight scan would.
        from datetime import UTC, datetime

        from app.db import SBOMSubmission

        async with db_session_factory() as db:
            row = await db.get(SBOMSubmission, submission)
            row.scan_status = "scanning"
            row.scan_started_at = datetime.now(UTC)
            await db.commit()

        assert (await c.post(f"/sboms/{submission}/scan")).status_code == 409


@respx.mock
async def test_a_stale_scan_can_be_started_again(db_session_factory, monkeypatch):
    mock_osv({})
    monkeypatch.setenv("DRYDOCK_SCAN_STALE_SECONDS", "0")
    async with client() as c:
        submission = (await upload(c, sbom(("requests", "2.32.0")))).json()["id"]
        from datetime import UTC, datetime

        from app.db import SBOMSubmission

        async with db_session_factory() as db:
            row = await db.get(SBOMSubmission, submission)
            row.scan_status = "scanning"
            row.scan_started_at = datetime.now(UTC)
            await db.commit()

        assert (await c.post(f"/sboms/{submission}/scan")).status_code == 202


@respx.mock
async def test_unqueryable_packages_are_stored_but_not_scanned(db_session_factory):
    mock_osv({})
    document = sbom(("requests", "2.32.0"))
    document["components"].append({"type": "library", "name": "busybox", "version": "1.36", "purl": "pkg:apk/busybox@1.36"})
    async with client() as c:
        submission = await upload_and_scan(c, document)
        report = (await c.get(f"/sboms/{submission}/findings")).json()
        assert report["scan_status"] == "completed"
        assert report["findings"] == []
