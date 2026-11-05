# Narrow service scope and controlled-pilot checklist

## Current honest service description

**Draft scope:** “Authorized, bounded read-only API assessment using supplied API inventory and explicitly approved scope. The registry contains narrow API1–API5/API8 observations, including synthetic-identity BOLA/BFLA comparisons where the client provides disposable accounts, existing test data, and an expected access policy. API9 inventory reconciliation is passive. Results are candidates or observations for analyst review, not a comprehensive penetration test.”

Use this description only when the actual work is limited to the implemented checks and authorized endpoints. Do not market the current build as a full API penetration test, OWASP API audit, comprehensive vulnerability scanner, authorization test, or exploitability assessment.

## Included in the present implementation

- Analyst-owned client and assessment records.
- Recording and reviewing an authorization attestation bound to assessment scope, allowed methods, and validity period.
- Local OpenAPI 3.0.x/3.1.x JSON import without fetching servers or remote references.
- Explicit review and approval of imported endpoints.
- Ten bounded read-only registered checks across API1–API5/API8, a passive API9 inventory review, and a bounded HTTP transport path.
- Assessment-bound encrypted disposable bearer identities for one-endpoint BOLA/BFLA GET comparisons; raw tokens are never returned, and test object IDs and response bodies are not retained.
- Candidate finding review, linked retest records, coverage summaries, and versioned JSON/HTML reports.

## Explicit exclusions

- Token lifecycle and session authentication tests; broad or route-wide IDOR/BOLA/BFLA coverage; injection, fuzzing, business logic, destructive methods, source-code review, browser exploitability, load/performance testing, and broad OWASP coverage.
- Verification of a client's legal authority or authenticity of an authorization document.
- PDF/signature generation and platform-mediated client delivery.
- Multi-analyst collaboration and tamper-proof audit storage.

## Client intake requirements before any real engagement

Obtain and manually verify the system owner's written authorization outside APISentinel. Record the client, exact hostnames, paths, environment, permitted methods, exclusions, testing window and time zone, request ceiling, emergency contact, stop conditions, and evidence-retention/delivery terms. Confirm the authorization covers the actual client account and target. For BOLA/BFLA, provision two disposable identities and synthetic records, confirm their roles/owners and expected access policy, then configure their bearer tokens as assessment-bound encrypted test identities. Never put client tokens, cookies, or credentials in ordinary assessment notes, OpenAPI files, issue text, or report evidence.

The backend must show an active, current scope-bound authorization and current endpoint approval before any request. `APISENTINEL_ALLOW_ACTIVE_TESTS` remains a separate default-off operator gate. Review the report and evidence before delivery; do not treat `COMPLETED` transport as a positive security result.

## Pilot gate

Do not accept a client target until all of the following are true:

- The local browser workflow passes from login through report export and evidence-linked retest.
- The chosen deployment has a verified backup/restore procedure, restricted network binding, HTTPS/Secure cookies, explicit CORS origins, and protected database/secret files.
- A named operator verifies and records source authorization and scope; APISentinel's attestation is not legal verification.
- Scope is limited to explicitly registered read-only checks and client-provided disposable identity comparisons; each target endpoint must still be authorized, approved, and covered by the active-test operator gate.
- SQLite deployments use one controlled worker; DB-backed rate/concurrency reservations coordinate workers sharing a database, but stale `RUNNING` TestRun recovery and multi-process stress tests remain outstanding.
- A human checks scope, exclusions, tested and skipped items, candidate/confirmed distinctions, limitations, redaction, and retest provenance in every report.

This checklist does not certify marketplace policy compliance or replace professional/legal review. Keep the product classified as a local assessment workspace until a controlled pilot is separately reviewed.
