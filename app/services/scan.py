from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import Finding, Package, SBOMSubmission, Vulnerability
from app.osv_client import OSVClient


def _extract_severity(details: dict) -> Optional[str]:
    # OSV records list severity as [{"type": "CVSS_V3", "score": "..."}].
    # Taking the first entry is a simplification -- good enough to show a
    # number in the findings report, not a substitute for real CVSS parsing.
    severities = details.get("severity")
    if severities:
        return severities[0].get("score")
    return None


async def run_scan(submission_id: int, db: AsyncSession, osv_client: OSVClient) -> None:
    submission = await db.get(SBOMSubmission, submission_id)
    if submission is None:
        return

    submission.scan_status = "scanning"
    await db.commit()

    try:
        result = await db.execute(
            select(Package).where(Package.submission_id == submission_id)
        )
        packages = list(result.scalars().all())

        # Packages whose purl didn't map to a known OSV.dev ecosystem can't
        # be queried -- they're stored but silently skipped here.
        queryable = [p for p in packages if p.ecosystem]

        vuln_id_lists = await osv_client.query_batch(
            [
                {"name": p.name, "version": p.version, "ecosystem": p.ecosystem}
                for p in queryable
            ]
        )

        now = datetime.now(timezone.utc)

        for package, vuln_ids in zip(queryable, vuln_id_lists):
            found_ids = set(vuln_ids)

            for vuln_id in found_ids:
                cached = await db.get(Vulnerability, vuln_id)
                if cached is None:
                    details = await osv_client.get_vuln_details(vuln_id)
                    db.add(
                        Vulnerability(
                            id=vuln_id,
                            summary=details.get("summary", ""),
                            severity=_extract_severity(details),
                            fetched_at=now,
                        )
                    )

            existing_result = await db.execute(
                select(Finding).where(
                    Finding.package_id == package.id,
                    Finding.resolved_at.is_(None),
                )
            )
            existing_findings = {f.vuln_id: f for f in existing_result.scalars().all()}

            for vuln_id in found_ids - existing_findings.keys():
                db.add(
                    Finding(package_id=package.id, vuln_id=vuln_id, discovered_at=now)
                )

            for vuln_id, finding in existing_findings.items():
                if vuln_id not in found_ids:
                    finding.resolved_at = now

        submission.scan_status = "completed"
        submission.last_scanned_at = now
        await db.commit()
    except Exception:
        submission.scan_status = "failed"
        await db.commit()
        raise
