"""Explainable, deliberately non-numeric finding prioritization policy."""

from dataclasses import dataclass

MODEL_VERSION = "apisentinel-risk-v1"
SEVERITY_RANK = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


@dataclass(frozen=True)
class RiskAnalysis:
    severity: str
    confidence: str
    priority: str
    confidence_rationale: str
    priority_rationale: str
    details: dict


def analyze_finding(*, severity: str, confidence: str = "UNASSESSED",
                    confidence_rationale: str = "", check_id: str | None = None,
                    owasp_categories: list[str] | None = None,
                    taxonomy_version: str | None = None) -> RiskAnalysis:
    """Normalize taxonomy and assign review priority without invented impact scores."""
    canonical_severity = next((item for item in SEVERITY_RANK if item.lower() == severity.lower()), None)
    if canonical_severity is None:
        raise ValueError("Unsupported technical severity")
    allowed_confidence = {"LOW", "MEDIUM", "HIGH", "UNASSESSED"}
    if confidence not in allowed_confidence:
        raise ValueError("Unsupported confidence classification")

    if canonical_severity == "Critical":
        priority = "P0" if confidence == "HIGH" else "P1"
        rationale = ("Critical technical severity with high-confidence evidence." if confidence == "HIGH"
                     else "Critical severity is unverified or has less than high confidence; prioritize validation urgently.")
    elif canonical_severity == "High":
        priority = "P1"
        rationale = ("High technical severity; prioritize review." if confidence != "LOW"
                     else "High severity with low-confidence evidence; prioritize validation before remediation decisions.")
    elif canonical_severity == "Medium":
        priority, rationale = "P2", "Medium technical severity; normal remediation review priority."
    elif canonical_severity == "Low":
        priority, rationale = "P3", "Low technical severity; standard backlog priority."
    else:
        priority, rationale = "P4", "Informational observation; analyst review is required before any risk claim."

    if confidence == "UNASSESSED" and not confidence_rationale:
        confidence_rationale = "Confidence has not been assessed from structured evidence."
    elif not confidence_rationale:
        confidence_rationale = f"{confidence} confidence is assigned by the documented check evidence policy; this is not statistical calibration."
    details = {
        "model_version": MODEL_VERSION,
        "technical_severity": canonical_severity,
        "confidence": confidence,
        "priority": priority,
        "priority_rationale": rationale,
        "numerical_score": None,
        "score_status": "NOT_SCORED_MISSING_IMPACT_CONTEXT",
        "remediation_guidance_type": "UNAVAILABLE",
        "factors": {
            "check_id": check_id,
            "owasp_categories": list(owasp_categories or []),
            "taxonomy_version": taxonomy_version,
            "business_criticality": None,
            "exploitability": None,
            "impact": None,
        },
        "limitations": [
            "No numerical risk score is calculated because exploitability, impact, and business context are not configured.",
            "Priority is a review order, not a severity or vulnerability confirmation.",
        ],
    }
    return RiskAnalysis(canonical_severity, confidence, priority,
                        confidence_rationale, rationale, details)
