import json
from typing import Optional

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


def _ecosystem_from_purl(purl: Optional[str]) -> Optional[str]:
    if not purl or not purl.startswith("pkg:"):
        return None
    # purl format: pkg:type/namespace/name@version?qualifiers#subpath
    remainder = purl[len("pkg:") :]
    purl_type = remainder.split("/", 1)[0]
    return PURL_ECOSYSTEM_MAP.get(purl_type.lower())


def parse_cyclonedx(raw: bytes) -> list[dict]:
    """Parse a CycloneDX JSON SBOM into a flat list of package dicts.

    Each dict has: name, version, purl (may be None), ecosystem (may be
    None if the purl type isn't one OSV.dev indexes). Components missing
    a name or version are skipped rather than raising, since a partially
    incomplete SBOM shouldn't block the whole upload.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidSBOMError(f"not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or "components" not in data:
        raise InvalidSBOMError("missing 'components' field, not a CycloneDX SBOM")

    packages = []
    for component in data["components"]:
        name = component.get("name")
        version = component.get("version")
        if not name or not version:
            continue
        purl = component.get("purl")
        packages.append(
            {
                "name": name,
                "version": version,
                "purl": purl,
                "ecosystem": _ecosystem_from_purl(purl),
            }
        )
    return packages
