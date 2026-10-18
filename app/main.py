import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import Finding, Package, SBOMSubmission, Vulnerability, get_db, init_db
from app.models import (
    FindingOut,
    FindingsReportOut,
    ProjectSummaryOut,
    SBOMSubmissionOut,
    ScanTriggerOut,
)
from app.osv_client import OSVClient
from app.security import rate_limit, require_api_key
from app.services import metrics
from app.services.sbom import InvalidSBOMError, SBOMTooLargeError, parse_cyclonedx
from app.services.scan import run_scan

logging.basicConfig(
    level=os.environ.get("DRYDOCK_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

osv_client = OSVClient()

PROJECT_PATTERN = r"^[A-Za-z0-9._-]{1,100}$"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await osv_client.close()


app = FastAPI(title="Drydock Dependency Watchdog", lifespan=lifespan)

# Everything except /health needs the API key (when one is configured).
api = APIRouter(dependencies=[Depends(require_api_key)])


@app.get("/health")
async def health():
    return {"status": "ok"}


def _check_declared_size(request: Request) -> None:
    """Refuse obviously oversized uploads before reading the body."""
    declared = request.headers.get("content-length")
    # A little headroom for the multipart envelope around the file.
    if declared and declared.isdigit() and int(declared) > get_settings().max_upload_bytes + 4096:
        raise HTTPException(status_code=413, detail="upload too large")


@api.post(
    "/sboms",
    response_model=SBOMSubmissionOut,
    status_code=201,
    dependencies=[Depends(rate_limit), Depends(_check_declared_size)],
)
async def upload_sbom(
    file: UploadFile = File(...),
    project: str = Query("default", pattern=PROJECT_PATTERN),
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    raw = await file.read(settings.max_upload_bytes + 1)
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="upload too large")
    try:
        parsed_packages = parse_cyclonedx(raw, max_packages=settings.max_packages)
    except SBOMTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except InvalidSBOMError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    filename = os.path.basename(file.filename or "") or "upload.json"
    submission = SBOMSubmission(
        project=project, filename=filename[:255], package_count=len(parsed_packages)
    )
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


@api.get("/sboms", response_model=list[SBOMSubmissionOut])
async def list_sboms(
    project: str | None = Query(None, pattern=PROJECT_PATTERN),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    query = select(SBOMSubmission).order_by(SBOMSubmission.id.desc()).limit(limit)
    if project is not None:
        query = query.where(SBOMSubmission.project == project)
    return list((await db.execute(query)).scalars().all())


async def _run_scan_in_background(submission_id: int) -> None:
    # Imported here rather than at module level: a fresh session,
    # independent of the request-scoped one, since this runs after the
    # response has already been sent -- and importing it late means tests
    # can swap in a different session factory via app.db.AsyncSessionLocal.
    from app.db import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await run_scan(submission_id, db, osv_client)


@api.post(
    "/sboms/{submission_id}/scan",
    response_model=ScanTriggerOut,
    status_code=202,
    dependencies=[Depends(rate_limit)],
)
async def trigger_scan(
    submission_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    submission = await db.get(SBOMSubmission, submission_id)
    if submission is None:
        raise HTTPException(status_code=404, detail="submission not found")

    now = datetime.now(UTC)
    if submission.scan_status == "scanning" and submission.scan_started_at is not None:
        started = submission.scan_started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=UTC)
        if now - started < timedelta(seconds=get_settings().scan_stale_seconds):
            raise HTTPException(status_code=409, detail="a scan is already running")

    newest_id = (
        await db.execute(
            select(func.max(SBOMSubmission.id)).where(SBOMSubmission.project == submission.project)
        )
    ).scalar_one()
    if newest_id != submission_id:
        raise HTTPException(
            status_code=409,
            detail=(
                f"submission {newest_id} is newer for project '{submission.project}'; "
                "scan the newest submission so findings are compared in order"
            ),
        )

    submission.scan_status = "scanning"
    submission.scan_started_at = now
    await db.commit()

    background_tasks.add_task(_run_scan_in_background, submission_id)
    return ScanTriggerOut(submission_id=submission_id, scan_status="scanning")


@api.get("/sboms/{submission_id}/findings", response_model=FindingsReportOut)
async def get_findings(
    submission_id: int,
    state: Literal["all", "open", "resolved"] = "all",
    db: AsyncSession = Depends(get_db),
):
    submission = await db.get(SBOMSubmission, submission_id)
    if submission is None:
        raise HTTPException(status_code=404, detail="submission not found")

    query = (
        select(Finding, Package, Vulnerability)
        .join(Package, Finding.package_id == Package.id)
        .join(Vulnerability, Finding.vuln_id == Vulnerability.id)
        .where(Package.submission_id == submission_id)
        .order_by(Finding.discovered_at, Finding.id)
    )
    if state == "open":
        query = query.where(Finding.resolved_at.is_(None))
    elif state == "resolved":
        query = query.where(Finding.resolved_at.is_not(None))
    result = await db.execute(query)

    findings = [
        FindingOut(
            package_name=package.name,
            package_version=package.version,
            vuln_id=vuln.id,
            summary=vuln.summary,
            severity=vuln.severity,
            cvss_score=vuln.cvss_score,
            discovered_at=finding.discovered_at,
            resolved_at=finding.resolved_at,
            resolution=finding.resolution,
        )
        for finding, package, vuln in result.all()
    ]

    return FindingsReportOut(
        submission_id=submission_id,
        project=submission.project,
        scan_status=submission.scan_status,
        last_scanned_at=submission.last_scanned_at,
        findings=findings,
    )


@api.get("/projects", response_model=list[str])
async def list_projects(db: AsyncSession = Depends(get_db)):
    return await metrics.project_names(db)


@api.get("/projects/{project}/summary", response_model=ProjectSummaryOut)
async def project_summary(project: str, db: AsyncSession = Depends(get_db)):
    if project not in await metrics.project_names(db):
        raise HTTPException(status_code=404, detail="project not found")
    return await metrics.summarise(db, project)


@api.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics(db: AsyncSession = Depends(get_db)):
    body = await metrics.render_prometheus(db)
    return PlainTextResponse(body, media_type="text/plain; version=0.0.4")


app.include_router(api)
