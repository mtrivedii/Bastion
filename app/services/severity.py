"""Turns the severity data in an OSV record into a score and a rating.

OSV records carry severity in two places:
- `severity`: a list of {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."} entries
  (the score field holds the vector string, not a number)
- `database_specific.severity`: a label such as "HIGH" or "MODERATE" (GitHub advisories)

A CVSS v3 vector is scored here with the formula from the CVSS v3.1 specification.
CVSS v4 vectors are kept as text but not scored, because v4 needs lookup tables
that this app does not carry. For those records the rating falls back to the
database label if there is one.
"""

import math
from dataclasses import dataclass

RATINGS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


@dataclass(frozen=True)
class Severity:
    rating: str
    score: float | None = None
    vector: str | None = None


def _roundup(value: float) -> float:
    """Round up to one decimal place, as defined in CVSS v3.1 (Appendix A)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score for a CVSS:3.0 or CVSS:3.1 vector, or None if it cannot be parsed."""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics = {}
    for part in parts[1:]:
        key, _, value = part.partition(":")
        metrics[key] = value
    try:
        changed = metrics["S"] == "C"
        if metrics["S"] not in ("U", "C"):
            return None
        pr_table = _PR_CHANGED if changed else _PR_UNCHANGED
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr_table[metrics["PR"]] * _UI[metrics["UI"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    except KeyError:
        return None

    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def rating_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _normalise_label(label: object) -> str | None:
    if not isinstance(label, str):
        return None
    value = label.strip().upper()
    if value == "MODERATE":
        value = "MEDIUM"
    return value if value in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else None


def extract_severity(details: dict) -> Severity:
    vector: str | None = None
    score: float | None = None

    for entry in details.get("severity") or []:
        raw = str(entry.get("score", "")).strip()
        if not raw:
            continue
        if raw.startswith("CVSS:3"):
            vector = raw
            score = cvss3_base_score(raw)
            break
        # Some records give a plain number instead of a vector.
        try:
            number = float(raw)
        except ValueError:
            if vector is None:
                vector = raw  # for example a CVSS v4 vector, kept as text
            continue
        if 0.0 <= number <= 10.0:
            score = number
            break

    if score is not None:
        return Severity(rating=rating_from_score(score), score=score, vector=vector)

    label = _normalise_label((details.get("database_specific") or {}).get("severity"))
    if label:
        return Severity(rating=label, score=None, vector=vector)
    return Severity(rating="UNKNOWN", score=None, vector=vector)
