# Client API assessment playbook

This playbook adapts common API penetration-testing topics to APISentinel's authorization, scope, evidence, finding, and remediation workflow. It is a manual review guide, not a claim that the registered runner automates every OWASP category.

## Before testing

1. Create the client and assessment; record objectives, exclusions, environment, target, and deliverables.
2. Record current written client authorization and review the exact hosts, paths, methods, and testing window.
3. Import the client-provided OpenAPI/Postman/Burp/HAR inventory. For GraphQL, import a client-provided introspection JSON export. Imports are passive and do not send requests; GraphQL imports retain only schema names, types, fields, arguments and root operations.
4. Compare imported inventory with the client's approved endpoint/version list. Review scope, then approve only endpoints that meet the assessment's safety policy.
5. Obtain client-provided test accounts, synthetic records, role expectations, and a non-production environment for authorization or business-logic checks. Do not use another customer's or a public user's data.
6. Run only enabled registered checks after the platform confirms the authorization and scope gates. Record other assessment work as analyst findings with sanitized evidence and an OWASP category.

## OWASP API Security Top 10 review map

| Category | Safe assessment focus | Prerequisites / evidence |
|---|---|---|
| API1 Broken Object Level Authorization | Verify object ownership rules using two client-provided test identities and synthetic records. Confirm the documented owner/role can access the record and another test identity cannot. Never access real third-party records. | Two authorized test identities, synthetic records, expected ownership policy, sanitized request/response comparison. |
| API2 Broken Authentication | Review documented authentication requirements, token/session lifetime and storage configuration, recovery policy, and server-side enforcement. Use only provisioned test accounts; do not attempt account takeover or password reset against a real user. | Client authentication policy, test account, sanitized configuration or response evidence. |
| API3 Broken Object Property Level Authorization | Compare writable/readable properties with the approved schema and role policy. Validate on disposable synthetic records and avoid privilege-changing properties unless the client explicitly provides a resettable fixture and expected result. | Data schema, property allowlist, role expectations, before/after fixture state. |
| API4 Unrestricted Resource Consumption | Review documented quotas, pagination limits, upload/response limits, and throttling configuration. If authorized, use only a pre-agreed low-volume limit check. Do not load test, flood, or cause service exhaustion. | Written request budget, staging/lab target, expected limits, bounded timestamps/statuses. |
| API5 Broken Function Level Authorization | Compare endpoint/action permissions with the client role matrix using provisioned test roles and non-destructive operations. | Role matrix, test users, safe read-only or resettable fixture action. |
| API6 Unrestricted Access to Sensitive Business Flows | Review business rules and abuse controls using synthetic records in a sandbox. Do not place orders, issue refunds, redeem value, or alter production state. | Business owner-approved scenarios, sandbox, synthetic accounts/transactions, expected invariants. |
| API7 Server-Side Request Forgery | Review URL-fetching features, destination allowlists, redirect handling, and egress policy. Use a client-owned controlled callback in a lab if explicitly approved. Never probe internal networks, cloud metadata, or third-party hosts. | Feature inventory, allowed destination policy, isolated callback, egress/network evidence. |
| API8 Security Misconfiguration | Review response security headers, CORS policy, error disclosure, TLS/deployment settings, caching, and version configuration. The current automated runner only implements its enabled narrow checks; a result on one response does not prove route-wide posture. | Approved origins, deployment configuration, route samples, redacted headers/errors. |
| API9 Improper Inventory Management | Compare imported endpoints, app/API versions, and deprecation policy with the client's authoritative inventory. The import only represents supplied sources and cannot prove that no hidden API exists. | Client-owned endpoint/version list, source and import provenance, deprecation records. |
| API10 Unsafe Consumption of APIs | Review third-party API contracts, response schema validation, dependency configuration, and trust boundaries using documentation or mocks. Do not send malformed payloads to a live vendor. | Dependency list, API contracts, mocks or sandbox responses, sanitized validation evidence. |

## Recording a result

- Use **Coverage** to see which endpoints/checks have an actual registered outcome and which OWASP API categories lack enabled automation.
- Use **Security Testing** only for an enabled check on an endpoint approved for the current authorization and scope.
- Use **Coverage → Manual security review** to record analyst status and evidence references for the version-pinned OWASP Web Top 10:2025, OWASP API Security Top 10:2023, and MITRE CWE Top 25:2025 checklists. `NO_ISSUE_OBSERVED` and `ISSUE_FOUND` require a note and at least one evidence reference. An absent review row remains unreviewed; `NO_ISSUE_OBSERVED` is an analyst observation, not proof that a control is secure.
- If a manual review identifies a weakness, create an assessment finding with the expected behavior, observed behavior, impact, sanitized evidence, severity, and remediation recommendation. Then link that finding from the checklist control using `ISSUE_FOUND`.
- A manually entered finding starts as a candidate and requires validation. A test result or missing prerequisite is not automatically a confirmed vulnerability or a fix.
- Use remediation and retesting only after a documented change and a fresh authorization/scope check. Reports should describe tested coverage and limitations honestly.

## Web application and CWE review scope

The manual checklist supports evidence tracking for the current OWASP Web Top 10:2025 and MITRE CWE Top 25:2025 versions. The OWASP list is an awareness framework, while the CWE list contains software weakness categories; checklist entry does not mean each weakness was dynamically tested. In the gig wording, “SANS 25” is represented as the versioned MITRE CWE Top 25, which is the official current list name. Relevant references: [OWASP Top 10:2025](https://top10.owasp.org/2025/) and [MITRE CWE Top 25:2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25).

XSS, SQL injection, GraphQL authorization, custom-protocol behavior, browser execution, and other injection or exploit scenarios require a separate authorized methodology, client-owned fixtures, and safe verification. APISentinel does not send exploit payloads or claim those categories are automatically tested. The API import path accepts OpenAPI 3.0/3.1, Postman Collection v2.1, documented structured Burp HTTP-history JSON, Browser HAR and client-provided GraphQL introspection JSON. GraphQL is schema inventory only: it does not probe operations or test authorization. Target crawling and arbitrary custom protocols are unsupported.

## Current automation limits

The current registry has two enabled safe response-header checks: X-Content-Type-Options and Strict-Transport-Security (HTTPS only). Other OWASP categories are manual-review areas unless a future check is explicitly designed with the needed client-owned fixtures, expected-behavior oracle, bounded request policy, and non-destructive verification. APISentinel does not currently provide general fuzzing, brute-force, injection exploitation, account takeover, destructive business-flow testing, or denial-of-service testing.
