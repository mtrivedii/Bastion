import pytest

from app.services.severity import cvss3_base_score, extract_severity, rating_from_score


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # Reference scores from the FIRST CVSS v3.1 specification examples and NVD.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_cvss3_base_score_matches_reference_values(vector, expected):
    assert cvss3_base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "not a vector",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # unknown value
    ],
)
def test_cvss3_base_score_rejects_what_it_cannot_score(vector):
    assert cvss3_base_score(vector) is None


@pytest.mark.parametrize(
    ("score", "rating"),
    [(10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"), (6.9, "MEDIUM"), (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, "UNKNOWN")],
)
def test_rating_boundaries(score, rating):
    assert rating_from_score(score) == rating


def test_vector_in_osv_record_gives_score_and_rating():
    record = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    result = extract_severity(record)
    assert (result.rating, result.score) == ("CRITICAL", 9.8)
    assert result.vector.startswith("CVSS:3.1/")


def test_plain_number_score_is_accepted():
    result = extract_severity({"severity": [{"type": "CVSS_V3", "score": "7.5"}]})
    assert (result.rating, result.score) == ("HIGH", 7.5)


def test_database_label_is_used_when_there_is_no_scorable_vector():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    record = {"severity": [{"type": "CVSS_V4", "score": v4}], "database_specific": {"severity": "MODERATE"}}
    result = extract_severity(record)
    assert (result.rating, result.score) == ("MEDIUM", None)
    assert result.vector == v4


def test_label_only_record():
    assert extract_severity({"database_specific": {"severity": "high"}}).rating == "HIGH"


def test_no_information_is_unknown():
    assert extract_severity({}).rating == "UNKNOWN"
    assert extract_severity({"database_specific": {"severity": 5}}).rating == "UNKNOWN"
