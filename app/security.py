"""API key check and a small in-memory rate limiter."""

import hmac
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from app.config import get_settings


def _presented_key(request: Request) -> str | None:
    header = request.headers.get("x-api-key")
    if header:
        return header
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


async def require_api_key(request: Request) -> None:
    """Rejects the request unless it carries the configured API key.

    Does nothing when DRYDOCK_API_KEY is not set, so local development works
    without extra setup. Accepts `X-API-Key: <key>` or `Authorization: Bearer <key>`
    (the second form is what a Prometheus scrape config can send).
    """
    expected = get_settings().api_key
    if expected is None:
        return
    presented = _presented_key(request)
    if presented is None or not hmac.compare_digest(presented.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="missing or invalid API key")


class _SlidingWindow:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > window_seconds:
            hits.popleft()
        if not hits:
            # Forget addresses that went quiet so the table cannot grow forever.
            self._hits.pop(key, None)
            hits = self._hits[key]
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


limiter = _SlidingWindow()


async def rate_limit(request: Request) -> None:
    """Limits write requests per client address. State is per process."""
    limit = get_settings().rate_limit_per_minute
    if limit <= 0:
        return
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client, limit):
        raise HTTPException(
            status_code=429,
            detail="too many requests",
            headers={"Retry-After": "60"},
        )
