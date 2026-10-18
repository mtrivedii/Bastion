from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SBOMSubmissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project: str
    filename: str
    uploaded_at: datetime
    package_count: int
    scan_status: str
    last_scanned_at: datetime | None = None


class ScanTriggerOut(BaseModel):
    submission_id: int
    scan_status: str


class FindingOut(BaseModel):
    package_name: str
    package_version: str
    vuln_id: str
    summary: str
    # CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN
    severity: str
    cvss_score: float | None
    discovered_at: datetime
    resolved_at: datetime | None
    # "fixed", "removed", or None while the finding is open
    resolution: str | None


class FindingsReportOut(BaseModel):
    submission_id: int
    project: str
    scan_status: str
    last_scanned_at: datetime | None
    findings: list[FindingOut]


class ProjectSummaryOut(BaseModel):
    project: str
    submissions: int
    last_scanned_at: datetime | None
    open_findings: int
    open_by_severity: dict[str, int]
    resolved_findings: int
    resolved_by_reason: dict[str, int]
    mean_time_to_remediate_seconds: float | None
    median_time_to_remediate_seconds: float | None
    oldest_open_finding_age_seconds: float | None
