from datetime import UTC, datetime, timedelta

import respx
from sqlalchemy import select

from app.db import Finding
from app.services import metrics
from tests.helpers import client, mock_osv, sbom, upload_and_scan

CRIT = "GHSA-crit"
LOW = "GHSA-low"
DETAILS = {
    CRIT: {"id": CRIT, "summary": "c", "database_specific": {"severity": "CRITICAL"}},
    LOW: {"id": LOW, "summary": "l", "database_specific": {"severity": "LOW"}},
}


async def set_times(factory, mapping):
    """mapping: vuln_id -> (discovered_at, resolved_at)."""
    async with factory() as db:
        for finding in (await db.execute(select(Finding))).scalars().all():
            discovered, resolved = mapping[finding.vuln_id]
            finding.discovered_at = discovered
            finding.resolved_at = resolved
        await db.commit()


@respx.mock
async def test_summary_counts_and_remediation_times(db_session_factory):
    mock_osv({("a", "1"): [CRIT], ("b", "1"): [LOW]}, DETAILS)
    async with client() as c:
        await upload_and_scan(c, sbom(("a", "1"), ("b", "1")), project="demo")

    start = datetime(2026, 1, 1, tzinfo=UTC)
    now = start + timedelta(days=10)
    await set_times(
        db_session_factory,
        {
            CRIT: (start, start + timedelta(hours=1)),  # resolved after 1 hour
            LOW: (start, None),  # still open, 10 days old
        },
    )
    # Mark the critical one as removed rather than fixed to cover both reasons.
    async with db_session_factory() as db:
        for finding in (await db.execute(select(Finding).where(Finding.vuln_id == CRIT))).scalars():
            finding.resolution = "removed"
        await db.commit()
        summary = await metrics.summarise(db, "demo", now=now)

    assert summary["open_findings"] == 1
    assert summary["open_by_severity"]["LOW"] == 1
    assert summary["open_by_severity"]["CRITICAL"] == 0
    assert summary["resolved_findings"] == 1
    assert summary["resolved_by_reason"] == {"fixed": 0, "removed": 1}
    assert summary["mean_time_to_remediate_seconds"] == 3600
    assert summary["median_time_to_remediate_seconds"] == 3600
    assert summary["oldest_open_finding_age_seconds"] == 10 * 86400


@respx.mock
async def test_summary_with_no_findings_has_no_averages(db_session_factory):
    mock_osv({})
    async with client() as c:
        await upload_and_scan(c, sbom(("a", "1")), project="clean")
        body = (await c.get("/projects/clean/summary")).json()
    assert body["open_findings"] == 0
    assert body["mean_time_to_remediate_seconds"] is None
    assert body["oldest_open_finding_age_seconds"] is None
    assert body["submissions"] == 1


async def test_summary_for_unknown_project_is_404(db_session_factory):
    async with client() as c:
        assert (await c.get("/projects/nothing/summary")).status_code == 404


@respx.mock
async def test_projects_list(db_session_factory):
    mock_osv({})
    async with client() as c:
        await upload_and_scan(c, sbom(("a", "1")), project="zeta")
        await upload_and_scan(c, sbom(("a", "1")), project="alpha")
        assert (await c.get("/projects")).json() == ["alpha", "zeta"]


@respx.mock
async def test_prometheus_output(db_session_factory):
    mock_osv({("a", "1"): [CRIT]}, DETAILS)
    async with client() as c:
        await upload_and_scan(c, sbom(("a", "1")), project="demo")
        response = await c.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    text = response.text
    assert '# TYPE drydock_open_findings gauge' in text
    assert 'drydock_open_findings{project="demo",severity="CRITICAL"} 1' in text
    assert 'drydock_open_findings{project="demo",severity="LOW"} 0' in text
    assert 'drydock_submissions{status="completed"} 1' in text
    assert "drydock_last_scan_timestamp_seconds{" in text
    # No remediation yet, so the mean must be absent rather than zero.
    assert "drydock_mean_time_to_remediate_seconds{" not in text


async def test_label_values_are_escaped():
    assert metrics._label('a"b\\c\nd') == 'a\\"b\\\\c d'
