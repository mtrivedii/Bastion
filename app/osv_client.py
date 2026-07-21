import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

OSV_BASE_URL = "https://api.osv.dev"

# Hard limit enforced by OSV.dev's own API for a single /v1/querybatch call.
MAX_QUERIES_PER_BATCH = 1000


class OSVServerError(Exception):
    """Raised for 5xx responses from OSV.dev. These are treated as
    transient and retried; 4xx responses (bad request) are not retried
    since retrying an invalid query wastes calls without changing the
    outcome.
    """


def _is_retryable(exc: BaseException) -> bool:
    return isinstance(exc, (httpx.TimeoutException, OSVServerError))


class OSVClient:
    def __init__(self, base_url: str = OSV_BASE_URL, timeout: float = 15.0):
        # 15s timeout: OSV.dev's own published SLO allows up to ~6s P95 on
        # /v1/querybatch, so this leaves real headroom before giving up.
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def close(self) -> None:
        await self._client.aclose()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type((httpx.TimeoutException, OSVServerError)),
        reraise=True,
    )
    async def _post(self, path: str, json_body: dict) -> dict:
        response = await self._client.post(path, json=json_body)
        if response.status_code >= 500:
            raise OSVServerError(f"{response.status_code} from POST {path}")
        response.raise_for_status()
        return response.json()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type((httpx.TimeoutException, OSVServerError)),
        reraise=True,
    )
    async def _get(self, path: str) -> dict:
        response = await self._client.get(path)
        if response.status_code >= 500:
            raise OSVServerError(f"{response.status_code} from GET {path}")
        response.raise_for_status()
        return response.json()

    async def query_batch(self, packages: list[dict]) -> list[list[str]]:
        """Query OSV.dev for known vulnerabilities affecting each package.

        packages: list of {"name": str, "version": str, "ecosystem": str}
        Returns a list of vulnerability ID lists, same order and length as
        the input.

        Note: /v1/querybatch only returns bare vulnerability IDs, not full
        details -- call get_vuln_details() to hydrate any ID you haven't
        seen before. Also note: OSV.dev paginates further results per
        query via page_token if a single package has an unusually large
        number of vulnerabilities; that pagination isn't handled here, so
        an extremely vulnerable package could show a truncated list. Fine
        for this project's scale, worth knowing if reused elsewhere.
        """
        results: list[list[str]] = []
        for start in range(0, len(packages), MAX_QUERIES_PER_BATCH):
            chunk = packages[start : start + MAX_QUERIES_PER_BATCH]
            queries = [
                {
                    "version": pkg["version"],
                    "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
                }
                for pkg in chunk
            ]
            data = await self._post("/v1/querybatch", {"queries": queries})
            for result in data.get("results", []):
                results.append([v["id"] for v in result.get("vulns", [])])
        return results

    async def get_vuln_details(self, vuln_id: str) -> dict:
        return await self._get(f"/v1/vulns/{vuln_id}")
