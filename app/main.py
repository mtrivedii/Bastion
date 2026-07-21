from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import Finding, Package, SBOMSubmission, Vulnerability, get_db, init_db
from app.models import FindingOut, FindingsReportOut, SBOMSubmissionOut, ScanTriggerOut
from app.osv_client import OSVClient
from app.services.scan import run_scan
from app.services.sbom import InvalidSBOMError, parse_cyclonedx

osv_client = OSVClient()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await osv_client.close()


app = FastAPI(title="Drydock Dependency Watchdog", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/sboms", response_model=SBOMSubmissionOut, status_code=201)
async def upload_sbom(
    file: UploadFile = File(...), db: AsyncSession = Depends(get_db)
):
    raw = await file.read()
    try:
        parsed_packages = parse_cyclonedx(raw)
    except InvalidSBOMError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    submission = SBOMSubmission(filename=file.filename, package_count=len(parsed_packages))
    db.add(submission)
    await db.flush()  # assigns submission.id before packages reference it

    for pkg in parsed_packages:
        db.add(
            Package(
                submission_id=submission.id,
                name=pkg["name"],
                version=pkg["version"],
                ecosystem=pkg["ecosystem"],
                purl=pkg["purl"],
            )
        )

    await db.commit()
    await db.refresh(submission)
    return submission


async def _run_scan_in_background(submission_id: int) -> None:
    # Imported here rather than at module level: a fresh session,
    # independent of the request-scoped one, since this runs after the
    # response has already been sent -- and importing it late means tests
    # can swap in a different session factory via app.db.AsyncSessionLocal.
    from app.db import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await run_scan(submission_id, db, osv_client)


@app.post("/sboms/{submission_id}/scan", response_model=ScanTriggerOut, status_code=202)
async def trigger_scan(
    submission_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    submission = await db.get(SBOMSubmission, submission_id)
    if submission is None:
        raise HTTPException(status_code=404, detail="submission not found")

    background_tasks.add_task(_run_scan_in_background, submission_id)
    return ScanTriggerOut(submission_id=submission_id, scan_status="scanning")


@app.get("/sboms/{submission_id}/findings", response_model=FindingsReportOut)
async def get_findings(submission_id: int, db: AsyncSession = Depends(get_db)):
    submission = await db.get(SBOMSubmission, submission_id)
    if submission is None:
        raise HTTPException(status_code=404, detail="submission not found")

    result = await db.execute(
        select(Finding, Package, Vulnerability)
        .join(Package, Finding.package_id == Package.id)
        .join(Vulnerability, Finding.vuln_id == Vulnerability.id)
        .where(Package.submission_id == submission_id)
    )

    findings = [
        FindingOut(
            package_name=package.name,
            package_version=package.version,
            vuln_id=vuln.id,
            summary=vuln.summary,
            severity=vuln.severity,
            discovered_at=finding.discovered_at,
            resolved_at=finding.resolved_at,
        )
        for finding, package, vuln in result.all()
    ]

    return FindingsReportOut(
        submission_id=submission_id,
        scan_status=submission.scan_status,
        last_scanned_at=submission.last_scanned_at,
        findings=findings,
    )
