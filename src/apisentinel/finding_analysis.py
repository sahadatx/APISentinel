"""Normalization helpers for candidate finding metadata."""

import hashlib
import json

from .risk_analysis import analyze_finding
from .test_registry import REGISTRY

OWASP_API_2023 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}


def finding_analysis_fields(*, assessment_id: int, endpoint_id: int | None,
                            test_id: str | None, test_version: str | None,
                            category: str, severity: str,
                            confidence: str = "UNASSESSED",
                            confidence_rationale: str = "",
                            remediation_guidance_type: str = "UNAVAILABLE") -> dict:
    definition = REGISTRY.get(test_id or "")
    manual_category = category.strip().split(" ", 1)[0]
    owasp_categories = (list(definition.owasp_categories) if definition else
                        [manual_category] if manual_category in OWASP_API_2023 else [])
    taxonomy_version = (definition.taxonomy_version if definition else
                        "OWASP API Security Top 10 2023" if owasp_categories else "")
    if definition and not confidence_rationale:
        confidence_rationale = (
            "LOW confidence: one bounded observation produced an indicator; "
            "the check limitations require analyst validation and do not establish exploitability."
        )
    risk = analyze_finding(
        severity=severity, confidence=confidence,
        confidence_rationale=confidence_rationale,
        check_id=test_id, owasp_categories=owasp_categories,
        taxonomy_version=taxonomy_version or None,
    )
    if remediation_guidance_type not in {"CHECK_SPECIFIC", "GENERIC", "ANALYST_PROVIDED", "UNAVAILABLE"}:
        raise ValueError("Unsupported remediation guidance provenance")
    risk_details = {**risk.details, "remediation_guidance_type": remediation_guidance_type}
    correlation_key = ""
    if endpoint_id is not None and test_id:
        canonical = {
            "assessment_id": assessment_id,
            "endpoint_id": endpoint_id,
            "test_id": test_id,
            "test_version": test_version or "",
            "category": category,
        }
        correlation_key = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    return {
        "vulnerability_category": category,
        "owasp_categories": owasp_categories,
        "taxonomy_version": taxonomy_version,
        "confidence": confidence,
        "confidence_rationale": risk.confidence_rationale,
        "remediation_guidance_type": remediation_guidance_type,
        "priority": risk.priority,
        "priority_rationale": risk.priority_rationale,
        "risk_analysis": risk_details,
        "correlation_key": correlation_key,
    }
