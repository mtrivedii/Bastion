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

            # Findings are matched by (package name, ecosystem, vuln_id),
            # not by raw package_id. This matters because every SBOM
            # upload creates brand-new Package rows -- package_id alone
            # can't identify "the same real-world dependency" across two
            # scans taken on different days (e.g. a CI run before a fix
            # and another CI run after it). Matching on name+ecosystem
            # instead lets a finding first recorded against one
            # submission's package correctly resolve when a *later*
            # submission's scan of the same dependency no longer reports
            # it.
            #
            # Known limitation: this only checks packages present in the
            # submission being scanned right now. If a vulnerable
            # dependency is removed entirely (not upgraded, just deleted)
            # in a later SBOM, its finding never gets visited again and
            # stays open forever. Not handled yet -- acceptable gap for
            # now, worth fixing before relying on this for real metrics.
            #
            # This also assumes a single project is being tracked over
            # time. A multi-project version of this app would need an
            # explicit project_id to stop unrelated projects' identical
            # package names from being matched to each other.
            existing_result = await db.execute(
                select(Finding)
                .join(Package, Finding.package_id == Package.id)
                .where(
                    Package.name == package.name,
                    Package.ecosystem == package.ecosystem,
                    Finding.resolved_at.is_(None),
                )
            )
            existing_findings = {f.vuln_id: f for f in existing_result.scalars().all()}

            for vuln_id in found_ids:
                if vuln_id in existing_findings:
                    # Still open -- re-point it at this scan's package row
                    # so it shows up when *this* submission's findings are
                    # queried, while discovered_at stays at its original
                    # value.
                    existing_findings[vuln_id].package_id = package.id
                else:
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
