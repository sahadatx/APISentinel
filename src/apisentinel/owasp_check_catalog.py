"""OWASP API 2023 review catalog, including prerequisites for non-automated checks.

Entries distinguish bounded automation, passive inventory analysis, and manual work.
Only registered checks with an enabled server evaluator can reach the HTTP runner.
"""

OWASP_CHECK_CATALOG = {
    "API1:2023": {
        "check_id": "authorization.bola.synthetic_pair",
        "name": "Object-level authorization with synthetic records",
        "mode": "PARTIAL_AUTOMATION",
        "prerequisites": [
            "Current approved GET endpoint with a declared required object path parameter",
            "Two encrypted, client-provisioned disposable bearer identities",
            "Two existing synthetic records with known owners",
        ],
        "expected_behavior": "Both identities can read their own synthetic record and receive a denial or not-found status for the other identity's record.",
        "safety": "Runs up to four GET requests against only the supplied synthetic IDs, and skips cross-identity requests if either owner control fails. Tokens are encrypted; response bodies and completed-job object IDs are not retained. No real-user IDs or write requests are accepted.",
    },
    "API2:2023": {
        "check_id": "authentication.unauthenticated_access",
        "name": "Unauthenticated access observation and identity policy review",
        "mode": "PARTIAL_AUTOMATION",
        "prerequisites": ["Written authorization", "Client-provisioned disposable test identities", "Documented session, token expiry, and lockout expectations"],
        "expected_behavior": "A contract-protected read endpoint rejects one request sent without credentials. Broader token lifecycle and role behavior follow the documented policy.",
        "safety": "The registered check sends one unauthenticated GET or HEAD to a currently approved endpoint explicitly marked auth required. Token lifecycle, recovery, brute force, credential stuffing, and token theft remain untested.",
    },
    "API3:2023": {
        "check_id": "authorization.sensitive_property_observation",
        "name": "Sensitive-property observation and schema authorization review",
        "mode": "PARTIAL_AUTOMATION",
        "prerequisites": ["Current approved unauthenticated GET endpoint", "Client-approved response schema and sensitivity policy"],
        "expected_behavior": "The read-only heuristic records only fixed categories of sensitive-looking JSON property names; the client schema and role matrix establish whether each property is authorized.",
        "safety": "The registered check inspects one successful unauthenticated JSON response and never stores response values. It does not write properties or validate role-based property access.",
    },
    "API4:2023": {
        "check_id": "resource.rate_limit_observation",
        "name": "Rate-limit observation and resource policy review",
        "mode": "PARTIAL_AUTOMATION",
        "prerequisites": ["Written authorization", "Client-provided rate/size/page limits", "Explicit request ceiling and stop conditions", "Sandbox or mocked endpoint for any active verification"],
        "expected_behavior": "Observed quota metadata is compared with the documented limit and input-size policy; this suite sends one normal request only.",
        "safety": "The registered check inspects one response and does not generate repeated requests, large payloads, uncontrolled pagination, load, or denial of service. Enforcement still requires a client-defined safe test plan.",
    },
    "API5:2023": {
        "check_id": "authorization.function_role_pair",
        "name": "Function-level authorization with test roles",
        "mode": "PARTIAL_AUTOMATION",
        "prerequisites": ["Current approved GET endpoint", "Two encrypted client-provisioned disposable bearer identities", "Client-confirmed allow/deny expectation for this endpoint"],
        "expected_behavior": "The client-designated allowed identity receives success and the denied identity receives a denial or not-found status.",
        "safety": "Runs two GET requests against one endpoint and retains status codes only. It does not infer roles, probe admin routes, or send mutations.",
    },
    "API6:2023": {
        "check_id": "business_flow.synthetic_transaction_review",
        "name": "Sensitive business-flow abuse-control review",
        "mode": "MANUAL_ONLY",
        "prerequisites": ["Written authorization", "Documented business rules and abuse controls", "Sandbox with synthetic accounts/transactions", "Client-approved low-volume test cases and reset procedure"],
        "expected_behavior": "The service enforces documented eligibility, sequencing, quotas, and idempotency rules for synthetic transactions.",
        "safety": "No real purchases, refunds, balances, bookings, or irreversible state changes. No automated request is currently available.",
    },
    "API7:2023": {
        "check_id": "ssrf.client_owned_callback_review",
        "name": "Server-side URL-fetch boundary review",
        "mode": "MANUAL_ONLY",
        "prerequisites": ["Written authorization explicitly covering URL-fetch behavior", "Client-owned sandbox callback endpoint", "Documented egress allowlist and stop conditions", "No internal, link-local, cloud metadata, or third-party destinations"],
        "expected_behavior": "URL-fetch functionality accepts only approved schemes/destinations and cannot reach internal or non-allowlisted networks.",
        "safety": "No SSRF payload execution is implemented. Validate with mocks or a client-owned callback only after a dedicated safe evaluator exists.",
    },
    "API8:2023": {
        "check_id": "configuration.response_policy_observation",
        "name": "Bounded response security-policy observations",
        "mode": "REGISTERED_CHECKS",
        "prerequisites": ["Current authorization and reviewed in-scope endpoint", "Supported safe method", "Active checks enabled by local policy", "HTTPS for HSTS evaluation"],
        "expected_behavior": "Each registered evaluator records its own bounded evidence and returns PASS, candidate, inconclusive, error, or not-run; no result alone proves exploitability.",
        "safety": "Only server-registered checks shown in Security Testing can run. Coverage includes only enabled and method/scheme-compatible checks.",
    },
    "API9:2023": {
        "check_id": "inventory.authoritative_reconciliation_review",
        "name": "Passive inventory review and source-of-truth reconciliation",
        "mode": "PASSIVE_INVENTORY_REVIEW",
        "prerequisites": ["Written authorization", "Client-provided authoritative endpoint/version inventory", "Known deprecation and ownership policy", "Assessment-specific exclusions"],
        "expected_behavior": "The snapshot flags unresolved, deprecated, stale, duplicate, versionless, or import-warning inventory records for analyst reconciliation.",
        "safety": "The review reads imported database records only and sends no target requests. It cannot prove inventory completeness without a client-provided source of truth.",
    },
    "API10:2023": {
        "check_id": "integration.third_party_contract_review",
        "name": "Third-party API consumption contract review",
        "mode": "MANUAL_ONLY",
        "prerequisites": ["Written authorization for the consuming application", "Client-provided dependency/API contracts", "Mocked third-party responses or client-owned sandbox", "Expected schema and failure-handling policy"],
        "expected_behavior": "Responses are schema-validated, errors are handled safely, and trust boundaries match the documented integration contract.",
        "safety": "Do not probe third-party providers. No automated request is currently available.",
    },
}
