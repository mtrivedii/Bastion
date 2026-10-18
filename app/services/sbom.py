import json

# Maps a purl "type" segment (pkg:<type>/...) to the ecosystem name OSV.dev
# expects in query requests. Only ecosystems OSV.dev actually indexes are
# listed here; anything else is stored but skipped during scanning rather
# than sent to OSV.dev as a guess.
PURL_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "composer": "Packagist",
    "nuget": "NuGet",
}


class InvalidSBOMError(Exception):
    """Raised when the uploaded file isn't a parseable CycloneDX SBOM."""


class SBOMTooLargeError(InvalidSBOMError):
    """Raised when an SBOM has more components than the configured limit."""


def _ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    # purl format: pkg:type/namespace/name@version?qualifiers#subpath
    remainder = purl[len("pkg:") :]
    purl_type = remainder.split("/", 1)[0]
    return PURL_ECOSYSTEM_MAP.get(purl_type.lower())


def _clean(value: object, limit: int) -> str | None:
    """Returns a stripped string cut to the column size, or None if it is not usable text."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


def parse_cyclonedx(raw: bytes, max_packages: int | None = None) -> list[dict]:
    """Parse a CycloneDX JSON SBOM into a flat list of package dicts.

    Each dict has: name, version, purl (may be None), ecosystem (may be
    None if the purl type isn't one OSV.dev indexes). Components missing
    a name or version are skipped rather than raising, since a partially
    incomplete SBOM shouldn't block the whole upload. Components that are
    not JSON objects are skipped for the same reason.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise InvalidSBOMError(f"not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or "components" not in data:
        raise InvalidSBOMError("missing 'components' field, not a CycloneDX SBOM")
    components = data["components"]
    if not isinstance(components, list):
        raise InvalidSBOMError("'components' must be a list")
    if max_packages is not None and len(components) > max_packages:
        raise SBOMTooLargeError(
            f"SBOM has {len(components)} components, the limit is {max_packages}"
        )

    packages = []
    for component in components:
        if not isinstance(component, dict):
            continue
        name = _clean(component.get("name"), 255)
        version = _clean(component.get("version"), 100)
        if not name or not version:
            continue
        purl = _clean(component.get("purl"), 500)
        packages.append(
            {
                "name": name,
                "version": version,
                "purl": purl,
                "ecosystem": _ecosystem_from_purl(purl),
            }
        )
    return packages
