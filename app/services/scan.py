import asyncio
import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import Finding, Package, SBOMSubmission, Vulnerability
from app.osv_client import OSVClient
from app.services.severity import extract_severity

logger = logging.getLogger("drydock.scan")

# How many vulnerability records are fetched from OSV.dev at the same time.
HYDRATE_CONCURRENCY = 8


async def _hydrate_new_vulns(
    db: AsyncSession, osv_client: OSVClient, vuln_ids: set[str], now: datetime
) -> None:
    """Fetches and caches every vulnerability ID that is not in the local cache yet."""
    missing = [vid for vid in sorted(vuln_ids) if await db.get(Vulnerability, vid) is None]
    if not missing:
        return

    semaphore = asyncio.Semaphore(HYDRATE_CONCURRENCY)

    async def fetch(vuln_id: str) -> tuple[str, dict]:
        async with semaphore:
            return vuln_id, await osv_client.get_vuln_details(vuln_id)

    for vuln_id, details in await asyncio.gather(*(fetch(v) for v in missing)):
        severity = extract_severity(details)
        db.add(
            Vulnerability(
                id=vuln_id,
                summary=(details.get("summary") or "")[:2000],
                severity=severity.rating,
                cvss_score=severity.score,
                cvss_vector=severity.vector[:200] if severity.vector else None,
                fetched_at=now,
            )
        )
    await db.flush()


async def run_scan(submission_id: int, db: AsyncSession, osv_client: OSVClient) -> None:
    """Scans one submission and updates the findings of its whole project.

    Findings are matched by (package name, ecosystem, vulnerability id) within
    the project, not by package row. Every SBOM upload creates new Package rows,
    so a package row cannot identify "the same dependency" across two scans on
    different days. Matching on name and ecosystem lets a finding first
    recorded against an older submission resolve when a later submission no
    longer reports it.

    A finding is resolved in two cases:
    - "fixed": the package is still in the SBOM but OSV.dev no longer reports
      the vulnerability for the version that is there now.
    - "removed": the package is no longer in the SBOM at all.

    This assumes the submission being scanned is the newest one in its project.
    The API enforces that, because scanning an older submission would reopen or
    resolve findings based on out-of-date data.

    Known limit: if one SBOM lists the same package twice with different
    versions, the findings of both versions are treated as one set.
    """
    submission = await db.get(SBOMSubmission, submission_id)
    if submission is None:
        return

    now = datetime.now(UTC)
    submission.scan_status = "scanning"
    submission.scan_started_at = now
    await db.commit()
    logger.info("scan started submission=%s project=%s", submission_id, submission.project)

    try:
        result = await db.execute(
            select(Package).where(Package.submission_id == submission_id)
        )
        packages = list(result.scalars().all())

        # Packages whose purl didn't map to a known OSV.dev ecosystem can't
        # be queried -- they're stored but skipped here.
        queryable = [p for p in packages if p.ecosystem]

        vuln_id_lists = await osv_client.query_batch(
            [
                {"name": p.name, "version": p.version, "ecosystem": p.ecosystem}
                for p in queryable
            ]
        )
        if len(vuln_id_lists) != len(queryable):
            raise RuntimeError(
                f"OSV.dev returned {len(vuln_id_lists)} results for {len(queryable)} queries"
            )

        # What this submission says is vulnerable right now, per dependency.
        current: dict[tuple[str, str], tuple[Package, set[str]]] = {}
        for package, vuln_ids in zip(queryable, vuln_id_lists, strict=True):
            key = (package.name, package.ecosystem)
            if key in current:
                current[key][1].update(vuln_ids)
            else:
                current[key] = (package, set(vuln_ids))

        all_vuln_ids = {vid for _, ids in current.values() for vid in ids}
        await _hydrate_new_vulns(db, osv_client, all_vuln_ids, now)

        # Every finding that is open anywhere in this project.
        open_result = await db.execute(
            select(Finding, Package)
            .join(Package, Finding.package_id == Package.id)
            .join(SBOMSubmission, Package.submission_id == SBOMSubmission.id)
            .where(
                SBOMSubmission.project == submission.project,
                Finding.resolved_at.is_(None),
            )
        )
        open_by_key: dict[tuple[str, str], dict[str, Finding]] = {}
        for finding, package in open_result.all():
            key = (package.name, package.ecosystem)
            open_by_key.setdefault(key, {})[finding.vuln_id] = finding

        for key, (package, found_ids) in current.items():
            existing = open_by_key.get(key, {})
            for vuln_id in found_ids:
                if vuln_id in existing:
                    # Still open. Point it at this scan's package row so it shows up
                    # in this submission's report. discovered_at stays as it was.
                    existing[vuln_id].package_id = package.id
                else:
                    db.add(
                        Finding(package_id=package.id, vuln_id=vuln_id, discovered_at=now)
                    )
            for vuln_id, finding in existing.items():
                if vuln_id not in found_ids:
                    finding.resolved_at = now
                    finding.resolution = "fixed"

        for key, existing in open_by_key.items():
            if key not in current:
                for finding in existing.values():
                    finding.resolved_at = now
                    finding.resolution = "removed"

        submission.scan_status = "completed"
        submission.last_scanned_at = now
        await db.commit()
        logger.info("scan completed submission=%s", submission_id)
    except Exception:
        await db.rollback()
        submission = await db.get(SBOMSubmission, submission_id)
        if submission is not None:
            submission.scan_status = "failed"
            await db.commit()
        logger.exception("scan failed submission=%s", submission_id)
        raise
