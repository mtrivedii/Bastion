import json

import httpx
import respx
from httpx import ASGITransport, AsyncClient

from app.main import app

OSV = "https://api.osv.dev"


def sbom(*components: tuple[str, str], ecosystem: str = "pypi") -> dict:
    """Builds a small CycloneDX document from (name, version) pairs."""
    return {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:{ecosystem}/{name}@{version}",
            }
            for name, version in components
        ],
    }


def mock_osv(vulns: dict[tuple[str, str], list[str]], details: dict[str, dict] | None = None):
    """Registers fake OSV.dev routes with respx.

    vulns maps (name, version) to the vulnerability IDs OSV.dev should report.
    details maps a vulnerability ID to the record /v1/vulns/<id> should return.
    """
    details = details or {}

    def querybatch(request: httpx.Request) -> httpx.Response:
        queries = json.loads(request.content)["queries"]
        results = []
        for query in queries:
            key = (query["package"]["name"], query["version"])
            results.append({"vulns": [{"id": vid} for vid in vulns.get(key, [])]})
        return httpx.Response(200, json={"results": results})

    respx.post(f"{OSV}/v1/querybatch").mock(side_effect=querybatch)

    def vuln(request: httpx.Request) -> httpx.Response:
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        record = details.get(vuln_id, {"id": vuln_id, "summary": f"summary of {vuln_id}"})
        return httpx.Response(200, json=record)

    respx.get(url__regex=rf"{OSV}/v1/vulns/.+").mock(side_effect=vuln)


def client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def upload(c: AsyncClient, document: dict, project: str | None = None, **kwargs):
    params = {"project": project} if project else None
    return await c.post(
        "/sboms",
        params=params,
        files={"file": ("sbom.json", json.dumps(document), "application/json")},
        **kwargs,
    )


async def upload_and_scan(c: AsyncClient, document: dict, project: str | None = None) -> int:
    response = await upload(c, document, project)
    assert response.status_code == 201, response.text
    submission_id = response.json()["id"]
    scan = await c.post(f"/sboms/{submission_id}/scan")
    assert scan.status_code == 202, scan.text
    return submission_id
