"""Version-pinned manual assessment checklists.

These controls are analyst workflows, not executable probes. The catalog is
deliberately explicit about that distinction so coverage never implies that a
control was tested just because it exists here.
"""

FRAMEWORKS = {
    "OWASP_WEB_2025": {
        "name": "OWASP Top 10:2025 · Web Application",
        "source": "https://top10.owasp.org/2025/",
        "controls": [
            ("A01:2025", "Broken Access Control", "Review server-side authorization, tenant boundaries, object access, and privileged actions against an approved role matrix."),
            ("A02:2025", "Security Misconfiguration", "Review deployment settings, security headers, error handling, exposed services, and environment-specific configuration."),
            ("A03:2025", "Software Supply Chain Failures", "Review dependency provenance, lockfiles, build pipeline permissions, artifact integrity, and known dependency advisories."),
            ("A04:2025", "Cryptographic Failures", "Review sensitive-data handling, transport protections, key management, and cryptographic configuration."),
            ("A05:2025", "Injection", "Review input flows, parameterized data access, output encoding, and approved non-destructive test evidence. No payload is sent by this checklist."),
            ("A06:2025", "Insecure Design", "Review threat models, trust boundaries, abuse cases, business rules, and compensating controls."),
            ("A07:2025", "Authentication Failures", "Review login, session lifecycle, recovery, MFA, lockout, and identity-verification behavior against documented policy."),
            ("A08:2025", "Software or Data Integrity Failures", "Review deserialization, update and build integrity, signatures, and trust in client-controlled data."),
            ("A09:2025", "Security Logging and Alerting Failures", "Review security event coverage, sensitive-data exclusion, access to logs, alerting, and retention policy."),
            ("A10:2025", "Mishandling of Exceptional Conditions", "Review failure paths, resource cleanup, safe error responses, transaction consistency, and retry behavior."),
        ],
    },
    "OWASP_API_2023": {
        "name": "OWASP API Security Top 10:2023",
        "source": "https://api-security.owasp.org/editions/2023/en/0x11-t10/",
        "controls": [
            ("API1:2023", "Broken Object Level Authorization", "Compare object access for client-provisioned synthetic records and documented owners; do not use real-user IDs."),
            ("API2:2023", "Broken Authentication", "Review authentication, token lifecycle, recovery, and lockout policy. Automated checks do not test brute force or credential attacks."),
            ("API3:2023", "Broken Object Property Level Authorization", "Compare response properties with the approved data-classification and role matrix."),
            ("API4:2023", "Unrestricted Resource Consumption", "Review documented quotas and limits; any active verification needs an explicitly bounded sandbox plan."),
            ("API5:2023", "Broken Function Level Authorization", "Compare endpoint access with the client-provided role and function authorization matrix."),
            ("API6:2023", "Unrestricted Access to Sensitive Business Flows", "Review business rules with synthetic data and a client-approved reset plan; do not exercise real transactions."),
            ("API7:2023", "Server Side Request Forgery", "Review URL-fetch boundaries and egress policy; use only client-owned sandbox callbacks if authorized."),
            ("API8:2023", "Security Misconfiguration", "Review API transport, headers, error behavior, configuration, and deployment defaults."),
            ("API9:2023", "Improper Inventory Management", "Reconcile imported operations against the client's authoritative inventory and lifecycle policy."),
            ("API10:2023", "Unsafe Consumption of APIs", "Review third-party contracts, schema validation, trust boundaries, and failure handling without probing providers."),
        ],
    },
    "CWE_TOP_25_2025": {
        "name": "MITRE CWE Top 25:2025",
        "source": "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25",
        "controls": [
            ("CWE-79", "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)", "Review output contexts, encoding, templates, and approved safe test evidence."),
            ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)", "Review query construction and parameterization; do not send destructive injection payloads."),
            ("CWE-352", "Cross-Site Request Forgery (CSRF)", "Review browser session protections, origin validation, and state-changing request design."),
            ("CWE-862", "Missing Authorization", "Review required authorization checks for each sensitive operation."),
            ("CWE-787", "Out-of-bounds Write", "Review applicable native components, memory-safe boundaries, and static-analysis evidence."),
            ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", "Review file path handling, canonicalization, and storage boundaries."),
            ("CWE-416", "Use After Free", "Review applicable native or unsafe-language components and memory-safety evidence."),
            ("CWE-125", "Out-of-bounds Read", "Review applicable native components and memory-safe access patterns."),
            ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)", "Review process invocation, argument handling, and use of safe APIs."),
            ("CWE-94", "Improper Control of Generation of Code (Code Injection)", "Review dynamic code generation and untrusted template or expression evaluation."),
            ("CWE-120", "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)", "Review applicable native components, bounds checks, and static-analysis evidence."),
            ("CWE-434", "Unrestricted Upload of File with Dangerous Type", "Review upload type validation, storage isolation, execution prevention, and size limits."),
            ("CWE-476", "NULL Pointer Dereference", "Review applicable native or unsafe-language components and error-path handling."),
            ("CWE-121", "Stack-based Buffer Overflow", "Review applicable native components, bounds checks, and memory-safe alternatives."),
            ("CWE-502", "Deserialization of Untrusted Data", "Review deserialization formats, type restrictions, integrity checks, and trust boundaries."),
            ("CWE-122", "Heap-based Buffer Overflow", "Review applicable native components, bounds checks, and memory-safety evidence."),
            ("CWE-863", "Incorrect Authorization", "Review authorization decisions for role, resource, tenant, and context correctness."),
            ("CWE-20", "Improper Input Validation", "Review validation at trust boundaries, canonicalization, and type/range checks."),
            ("CWE-284", "Improper Access Control", "Review access-control policy enforcement and default-deny behavior."),
            ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor", "Review data classification, response fields, logs, error messages, and access policy."),
            ("CWE-306", "Missing Authentication for Critical Function", "Review authentication requirements for sensitive and administrative functions."),
            ("CWE-918", "Server-Side Request Forgery (SSRF)", "Review outbound request allowlists and URL parsing; do not target internal or third-party systems."),
            ("CWE-77", "Improper Neutralization of Special Elements used in a Command (Command Injection)", "Review command construction and use of safe process APIs."),
            ("CWE-639", "Authorization Bypass Through User-Controlled Key", "Review object-key authorization using synthetic records and documented ownership."),
            ("CWE-770", "Allocation of Resources Without Limits or Throttling", "Review quotas and bounded resource controls; do not conduct load or denial-of-service tests."),
        ],
    },
}


def public_catalog() -> list[dict]:
    return [
        {
            "framework_id": framework_id,
            "name": framework["name"],
            "source": framework["source"],
            "mode": "MANUAL_ONLY",
            "controls": [
                {"control_id": control_id, "name": name, "review_prompt": prompt}
                for control_id, name, prompt in framework["controls"]
            ],
        }
        for framework_id, framework in FRAMEWORKS.items()
    ]


def control_for(framework_id: str, control_id: str) -> dict | None:
    framework = FRAMEWORKS.get(framework_id)
    if framework is None:
        return None
    for current_id, name, prompt in framework["controls"]:
        if current_id == control_id:
            return {"control_id": current_id, "name": name, "review_prompt": prompt}
    return None
