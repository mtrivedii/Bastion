import httpx
import pytest
import respx

from app.osv_client import OSVClient, OSVServerError


@respx.mock
async def test_query_batch_returns_vuln_ids_per_package():
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-aaaa"}, {"id": "GHSA-bbbb"}]},
                    {"vulns": []},
                ]
            },
        )
    )
    client = OSVClient()
    result = await client.query_batch(
        [
            {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
            {"name": "safe-pkg", "version": "1.0.0", "ecosystem": "PyPI"},
        ]
    )
    await client.close()
    assert result == [["GHSA-aaaa", "GHSA-bbbb"], []]


@respx.mock
async def test_get_vuln_details_returns_full_record():
    respx.get("https://api.osv.dev/v1/vulns/GHSA-aaaa").mock(
        return_value=httpx.Response(200, json={"id": "GHSA-aaaa", "summary": "test vuln"})
    )
    client = OSVClient()
    details = await client.get_vuln_details("GHSA-aaaa")
    await client.close()
    assert details["summary"] == "test vuln"


@respx.mock
async def test_retries_on_server_error_then_succeeds():
    route = respx.post("https://api.osv.dev/v1/querybatch")
    route.side_effect = [
        httpx.Response(500),
        httpx.Response(200, json={"results": [{"vulns": []}]}),
    ]
    client = OSVClient()
    result = await client.query_batch([{"name": "x", "version": "1", "ecosystem": "PyPI"}])
    await client.close()
    assert result == [[]]
    assert route.call_count == 2


@respx.mock
async def test_gives_up_after_max_retries():
    respx.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(500))
    client = OSVClient()
    with pytest.raises(OSVServerError):
        await client.query_batch([{"name": "x", "version": "1", "ecosystem": "PyPI"}])
    await client.close()


@respx.mock
async def test_client_error_is_not_retried():
    route = respx.post("https://api.osv.dev/v1/querybatch")
    route.mock(return_value=httpx.Response(400, json={"error": "bad request"}))
    client = OSVClient()
    with pytest.raises(httpx.HTTPStatusError):
        await client.query_batch([{"name": "x", "version": "1", "ecosystem": "PyPI"}])
    await client.close()
    assert route.call_count == 1
