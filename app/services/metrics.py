"""Security metrics computed from the findings table.

Time to remediate is measured from the moment Drydock first saw a finding
(`discovered_at`) to the scan that stopped reporting it (`resolved_at`). It is
not measured from the day the vulnerability was published.
"""

import statistics
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import Finding, Package, SBOMSubmission, Vulnerability
from app.services.severity import RATINGS


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes. Everything here is stored as UTC."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


async def _finding_rows(db: AsyncSession, project: str | None):
    query = (
        select(
            SBOMSubmission.project,
            Vulnerability.severity,
            Finding.discovered_at,
            Finding.resolved_at,
            Finding.resolution,
        )
        .select_from(Finding)
        .join(Package, Finding.package_id == Package.id)
        .join(SBOMSubmission, Package.submission_id == SBOMSubmission.id)
        .join(Vulnerability, Finding.vuln_id == Vulnerability.id)
    )
    if project is not None:
        query = query.where(SBOMSubmission.project == project)
    return (await db.execute(query)).all()


async def project_names(db: AsyncSession) -> list[str]:
    result = await db.execute(select(SBOMSubmission.project).distinct().order_by(SBOMSubmission.project))
    return [row[0] for row in result.all()]


async def summarise(db: AsyncSession, project: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    rows = [r for r in await _finding_rows(db, project)]

    by_severity = dict.fromkeys(RATINGS, 0)
    resolved_by_reason = {"fixed": 0, "removed": 0}
    open_ages: list[float] = []
    remediation_times: list[float] = []

    for _, severity, discovered_at, resolved_at, resolution in rows:
        discovered = _aware(discovered_at)
        resolved = _aware(resolved_at)
        if resolved is None:
            by_severity[severity if severity in by_severity else "UNKNOWN"] += 1
            open_ages.append((now - discovered).total_seconds())
        else:
            remediation_times.append((resolved - discovered).total_seconds())
            reason = resolution if resolution in resolved_by_reason else "fixed"
            resolved_by_reason[reason] += 1

    submissions = (
        await db.execute(
            select(func.count(SBOMSubmission.id), func.max(SBOMSubmission.last_scanned_at)).where(
                SBOMSubmission.project == project
            )
        )
    ).one()

    return {
        "project": project,
        "submissions": submissions[0],
        "last_scanned_at": _aware(submissions[1]),
        "open_findings": sum(by_severity.values()),
        "open_by_severity": by_severity,
        "resolved_findings": len(remediation_times),
        "resolved_by_reason": resolved_by_reason,
        "mean_time_to_remediate_seconds": (
            statistics.fmean(remediation_times) if remediation_times else None
        ),
        "median_time_to_remediate_seconds": (
            statistics.median(remediation_times) if remediation_times else None
        ),
        "oldest_open_finding_age_seconds": max(open_ages) if open_ages else None,
    }


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


async def render_prometheus(db: AsyncSession) -> str:
    """Prometheus text exposition format, one set of series per project."""
    lines: list[str] = []

    def header(name: str, help_text: str, kind: str = "gauge") -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")

    summaries = [await summarise(db, project) for project in await project_names(db)]

    header("drydock_open_findings", "Open findings by severity.")
    for s in summaries:
        for severity, count in s["open_by_severity"].items():
            lines.append(
                f'drydock_open_findings{{project="{_label(s["project"])}",severity="{severity}"}} {count}'
            )

    header("drydock_resolved_findings", "Findings that were resolved, by reason.")
    for s in summaries:
        for reason, count in s["resolved_by_reason"].items():
            lines.append(
                f'drydock_resolved_findings{{project="{_label(s["project"])}",reason="{reason}"}} {count}'
            )

    header(
        "drydock_mean_time_to_remediate_seconds",
        "Mean seconds from first sighting to resolution. Absent until something is resolved.",
    )
    for s in summaries:
        if s["mean_time_to_remediate_seconds"] is not None:
            lines.append(
                f'drydock_mean_time_to_remediate_seconds{{project="{_label(s["project"])}"}} '
                f'{s["mean_time_to_remediate_seconds"]:.3f}'
            )

    header("drydock_oldest_open_finding_age_seconds", "Age of the oldest open finding.")
    for s in summaries:
        if s["oldest_open_finding_age_seconds"] is not None:
            lines.append(
                f'drydock_oldest_open_finding_age_seconds{{project="{_label(s["project"])}"}} '
                f'{s["oldest_open_finding_age_seconds"]:.3f}'
            )

    header("drydock_last_scan_timestamp_seconds", "Unix time of the last completed scan.")
    for s in summaries:
        if s["last_scanned_at"] is not None:
            lines.append(
                f'drydock_last_scan_timestamp_seconds{{project="{_label(s["project"])}"}} '
                f'{s["last_scanned_at"].timestamp():.0f}'
            )

    status_rows = (
        await db.execute(
            select(SBOMSubmission.scan_status, func.count(SBOMSubmission.id)).group_by(
                SBOMSubmission.scan_status
            )
        )
    ).all()
    header("drydock_submissions", "Submissions by scan status.")
    for status, count in status_rows:
        lines.append(f'drydock_submissions{{status="{_label(status)}"}} {count}')

    return "\n".join(lines) + "\n"
