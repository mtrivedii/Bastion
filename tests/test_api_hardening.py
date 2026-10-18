import json

import respx

from tests.helpers import client, mock_osv, sbom, upload


async def test_health_is_open_even_with_an_api_key(db_session_factory, monkeypatch):
    monkeypatch.setenv("DRYDOCK_API_KEY", "s3cret")
    async with client() as c:
        assert (await c.get("/health")).status_code == 200


async def test_endpoints_need_the_api_key_when_one_is_set(db_session_factory, monkeypatch):
    monkeypatch.setenv("DRYDOCK_API_KEY", "s3cret")
    async with client() as c:
        for method, path in [("get", "/sboms"), ("get", "/projects"), ("get", "/metrics"), ("post", "/sboms/1/scan"), ("get", "/sboms/1/findings")]:
            assert (await getattr(c, method)(path)).status_code == 401, path
        assert (await upload(c, sbom(("requests", "2.32.0")))).status_code == 401


async def test_wrong_key_is_rejected_and_right_key_accepted(db_session_factory, monkeypatch):
    monkeypatch.setenv("DRYDOCK_API_KEY", "s3cret")
    async with client() as c:
        assert (await c.get("/sboms", headers={"X-API-Key": "nope"})).status_code == 401
        assert (await c.get("/sboms", headers={"X-API-Key": "s3cret"})).status_code == 200
        assert (await c.get("/metrics", headers={"Authorization": "Bearer s3cret"})).status_code == 200
        assert (await upload(c, sbom(("requests", "2.32.0")), headers={"X-API-Key": "s3cret"})).status_code == 201


async def test_no_key_configured_means_open_access(db_session_factory, monkeypatch):
    monkeypatch.delenv("DRYDOCK_API_KEY", raising=False)
    async with client() as c:
        assert (await c.get("/sboms")).status_code == 200


async def test_upload_over_the_size_limit_is_refused(db_session_factory, monkeypatch):
    monkeypatch.setenv("DRYDOCK_MAX_UPLOAD_BYTES", "200")
    async with client() as c:
        response = await upload(c, sbom(*[(f"pkg{i}", "1.0.0") for i in range(30)]))
        assert response.status_code == 413


async def test_too_many_components_is_refused(db_session_factory, monkeypatch):
    monkeypatch.setenv("DRYDOCK_MAX_PACKAGES", "3")
    async with client() as c:
        assert (await upload(c, sbom(*[(f"pkg{i}", "1.0.0") for i in range(4)]))).status_code == 413
        assert (await upload(c, sbom(*[(f"pkg{i}", "1.0.0") for i in range(3)]))).status_code == 201


async def test_components_that_are_not_a_list_are_a_400_not_a_crash(db_session_factory):
    async with client() as c:
        response = await c.post(
            "/sboms",
            files={"file": ("x.json", json.dumps({"components": {"a": 1}}), "application/json")},
        )
        assert response.status_code == 400


async def test_garbage_components_are_skipped(db_session_factory):
    document = {"components": ["text", 5, None, {"name": "ok", "version": "1.0", "purl": "pkg:pypi/ok@1.0"}, {"name": 7, "version": "1"}]}
    async with client() as c:
        response = await c.post(
            "/sboms", files={"file": ("x.json", json.dumps(document), "application/json")}
        )
        assert response.status_code == 201
        assert response.json()["package_count"] == 1


async def test_binary_upload_is_a_400(db_session_factory):
    async with client() as c:
        response = await c.post("/sboms", files={"file": ("x.json", b"\xff\xfe\x00\x01", "application/json")})
        assert response.status_code == 400


async def test_project_name_is_validated(db_session_factory):
    async with client() as c:
        assert (await upload(c, sbom(("requests", "2.32.0")), project="bad name!")).status_code == 422
        assert (await upload(c, sbom(("requests", "2.32.0")), project="good-name_1.0")).status_code == 201


async def test_filename_is_reduced_to_its_base_name(db_session_factory):
    async with client() as c:
        response = await c.post(
            "/sboms",
            files={"file": ("../../etc/passwd.json", json.dumps(sbom(("a", "1"))), "application/json")},
        )
        assert response.json()["filename"] == "passwd.json"


async def test_write_requests_are_rate_limited(db_session_factory, monkeypatch):
    monkeypatch.setenv("DRYDOCK_RATE_LIMIT_PER_MINUTE", "3")
    async with client() as c:
        codes = [(await upload(c, sbom(("requests", "2.32.0")))).status_code for _ in range(5)]
        assert codes == [201, 201, 201, 429, 429]
        # Reading is not limited.
        assert (await c.get("/sboms")).status_code == 200


async def test_rate_limit_can_be_turned_off(db_session_factory, monkeypatch):
    monkeypatch.setenv("DRYDOCK_RATE_LIMIT_PER_MINUTE", "0")
    async with client() as c:
        codes = {(await upload(c, sbom(("requests", "2.32.0")))).status_code for _ in range(5)}
        assert codes == {201}


@respx.mock
async def test_a_failed_osv_call_marks_the_scan_failed(db_session_factory):
    import httpx

    respx.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(400, json={"error": "bad"}))
    async with client() as c:
        submission = (await upload(c, sbom(("requests", "2.32.0")))).json()["id"]
        try:
            await c.post(f"/sboms/{submission}/scan")
        except Exception:
            pass
        report = (await c.get(f"/sboms/{submission}/findings")).json()
        assert report["scan_status"] == "failed"


@respx.mock
async def test_list_sboms_filters_by_project_and_newest_first(db_session_factory):
    mock_osv({})
    async with client() as c:
        await upload(c, sbom(("a", "1")), project="one")
        await upload(c, sbom(("b", "1")), project="two")
        await upload(c, sbom(("c", "1")), project="one")
        everything = (await c.get("/sboms")).json()
        assert [s["id"] for s in everything] == [3, 2, 1]
        only_one = (await c.get("/sboms", params={"project": "one"})).json()
        assert [s["id"] for s in only_one] == [3, 1]
