"""CVSS v3.1 base-vector validation and scoring."""

from __future__ import annotations

import math

_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _round_up(value: float) -> float:
    return math.ceil((value - 1e-10) * 10) / 10


def calculate_cvss_v31(vector: str) -> dict:
    """Calculate an analyst-provided CVSS v3.1 base vector, without inference."""
    if not isinstance(vector, str) or len(vector) > 200:
        raise ValueError("CVSS v3.1 vector must be a string of at most 200 characters")
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError("Only CVSS:3.1 base vectors are supported")
    metrics: dict[str, str] = {}
    for item in parts[1:]:
        pair = item.split(":", 1)
        if len(pair) != 2 or pair[0] in metrics:
            raise ValueError("CVSS vector contains a malformed or duplicate metric")
        metrics[pair[0]] = pair[1]
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if set(metrics) != required:
        raise ValueError("CVSS v3.1 vector must contain exactly the eight base metrics")
    scope = metrics["S"]
    if scope not in {"U", "C"}:
        raise ValueError("CVSS S must be U or C")
    for name in ("AV", "AC", "UI"):
        if metrics[name] not in _VALUES[name]:
            raise ValueError(f"Unsupported CVSS {name} metric value")
    for name in ("C", "I", "A"):
        if metrics[name] not in _VALUES["CIA"]:
            raise ValueError(f"Unsupported CVSS {name} metric value")
    pr_values = _VALUES[f"PR_{scope}"]
    if metrics["PR"] not in pr_values:
        raise ValueError("Unsupported CVSS PR metric value")

    impact_sub = 1 - ((1 - _VALUES["CIA"][metrics["C"]])
                      * (1 - _VALUES["CIA"][metrics["I"]])
                      * (1 - _VALUES["CIA"][metrics["A"]]))
    impact = (6.42 * impact_sub if scope == "U" else
              7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15)
    exploitability = (8.22 * _VALUES["AV"][metrics["AV"]]
                      * _VALUES["AC"][metrics["AC"]]
                      * pr_values[metrics["PR"]]
                      * _VALUES["UI"][metrics["UI"]])
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _round_up(min(impact + exploitability, 10))
    else:
        score = _round_up(min(1.08 * (impact + exploitability), 10))
    canonical = "CVSS:3.1/" + "/".join(
        f"{name}:{metrics[name]}" for name in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"))
    severity = ("None" if score == 0 else "Low" if score <= 3.9 else
                "Medium" if score <= 6.9 else "High" if score <= 8.9 else "Critical")
    return {"version": "3.1", "vector": canonical, "base_score": score,
            "severity": severity, "score_type": "BASE",
            "source": "analyst_supplied_vector"}
