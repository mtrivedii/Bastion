import json

import pytest

from app.services.sbom import InvalidSBOMError, parse_cyclonedx


def test_parses_component_with_known_ecosystem():
    sbom = {
        "components": [
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
        ]
    }
    packages = parse_cyclonedx(json.dumps(sbom).encode())
    assert packages == [
        {
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "ecosystem": "PyPI",
        }
    ]


def test_unknown_purl_type_gives_none_ecosystem():
    sbom = {
        "components": [{"name": "weird-pkg", "version": "1.0", "purl": "pkg:conan/weird-pkg@1.0"}]
    }
    packages = parse_cyclonedx(json.dumps(sbom).encode())
    assert packages[0]["ecosystem"] is None


def test_component_missing_version_is_skipped():
    sbom = {"components": [{"name": "no-version"}]}
    packages = parse_cyclonedx(json.dumps(sbom).encode())
    assert packages == []


def test_component_missing_purl_gives_none_ecosystem():
    sbom = {"components": [{"name": "mystery-pkg", "version": "1.0"}]}
    packages = parse_cyclonedx(json.dumps(sbom).encode())
    assert packages[0]["ecosystem"] is None
    assert packages[0]["purl"] is None


def test_invalid_json_raises():
    with pytest.raises(InvalidSBOMError):
        parse_cyclonedx(b"not json at all")


def test_missing_components_key_raises():
    with pytest.raises(InvalidSBOMError):
        parse_cyclonedx(json.dumps({"foo": "bar"}).encode())
