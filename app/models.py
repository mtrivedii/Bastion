from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class SBOMSubmissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    uploaded_at: datetime
    package_count: int
    scan_status: str


class ScanTriggerOut(BaseModel):
    submission_id: int
    scan_status: str


class FindingOut(BaseModel):
    package_name: str
    package_version: str
    vuln_id: str
    summary: str
    severity: Optional[str]
    discovered_at: datetime
    resolved_at: Optional[datetime]


class FindingsReportOut(BaseModel):
    submission_id: int
    scan_status: str
    last_scanned_at: Optional[datetime]
    findings: list[FindingOut]
