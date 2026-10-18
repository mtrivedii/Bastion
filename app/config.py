"""Runtime settings, read from environment variables.

Read on every call (not cached at import) so tests and deployments can change
them without reloading the module.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Reject uploads larger than this many bytes.
    max_upload_bytes: int
    # Reject SBOMs with more components than this.
    max_packages: int
    # When set, every endpoint except /health needs this key.
    api_key: str | None
    # Requests per minute per client address for write endpoints. 0 turns it off.
    rate_limit_per_minute: int
    # A scan stuck in "scanning" for longer than this many seconds may be started again.
    scan_stale_seconds: int


def get_settings() -> Settings:
    return Settings(
        max_upload_bytes=int(os.environ.get("DRYDOCK_MAX_UPLOAD_BYTES", 5_000_000)),
        max_packages=int(os.environ.get("DRYDOCK_MAX_PACKAGES", 20_000)),
        api_key=os.environ.get("DRYDOCK_API_KEY") or None,
        rate_limit_per_minute=int(os.environ.get("DRYDOCK_RATE_LIMIT_PER_MINUTE", 60)),
        scan_stale_seconds=int(os.environ.get("DRYDOCK_SCAN_STALE_SECONDS", 900)),
    )
