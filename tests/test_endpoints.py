import json

import httpx
import respx
from httpx import ASGITransport, AsyncClient

from app.main import app

SAMPLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
    ],
}


async def test_upload_sbom_creates_submission(db_session_factory):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/sboms",
            files={"file": ("sbom.json", json.dumps(SAMPLE_SBOM), "application/json")},
        )
    assert response.status_code == 201
    body = response.json()
    assert body["filename"] == "sbom.json"
    assert body["package_count"] == 2
    assert body["scan_status"] == "pending"


async def test_upload_invalid_sbom_returns_400(db_session_factory):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/sboms",
            files={"file": ("bad.json", "not json", "application/json")},
        )
    assert response.status_code == 400


async def test_findings_for_unknown_submission_returns_404(db_session_factory):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/sboms/999/findings")
    assert response.status_code == 404


async def test_scan_trigger_for_unknown_submission_returns_404(db_session_factory):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/sboms/999/scan")
    assert response.status_code == 404


@respx.mock
async def test_scan_trigger_returns_202_and_scanning_status(db_session_factory):
    # The scan endpoint's background task calls out to OSV.dev -- mocked
    # here since this test is checking the endpoint's contract (202,
    # scanning status), not real OSV.dev connectivity.
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}, {"vulns": []}]})
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        upload = await client.post(
            "/sboms",
            files={"file": ("sbom.json", json.dumps(SAMPLE_SBOM), "application/json")},
        )
        submission_id = upload.json()["id"]
        response = await client.post(f"/sboms/{submission_id}/scan")
    assert response.status_code == 202
    assert response.json() == {"submission_id": submission_id, "scan_status": "scanning"}


async def test_findings_empty_before_scan_runs(db_session_factory):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        upload = await client.post(
            "/sboms",
            files={"file": ("sbom.json", json.dumps(SAMPLE_SBOM), "application/json")},
        )
        submission_id = upload.json()["id"]
        response = await client.get(f"/sboms/{submission_id}/findings")
    assert response.status_code == 200
    body = response.json()
    assert body["findings"] == []
    assert body["scan_status"] == "pending"


async def test_health_check():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
