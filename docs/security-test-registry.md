# Security test registry and result contract

`GET /api/v1/testing/registry` lists server-implemented checks, their version, category, purpose, method support, authentication needs, evidence, limitations, safety prerequisites, and whether they are enabled. `APISENTINEL_ENABLED_SECURITY_TESTS` is a comma-separated server-side allowlist. Unknown and disabled identifiers are rejected. The client cannot provide code, a URL, an arbitrary method, a raw payload, or request-policy overrides. Request values must match the approved endpoint's declared parameters.

## Registered check: `response.header.content_type_options` v1.0.0

This check sends a no-payload GET to the approved endpoint through the bounded HTTP runner, so it is classified as an active network check even though it only observes response metadata. It inspects the response `Content-Type` and `X-Content-Type-Options` headers. Supported media types are `text/html`, `application/xhtml+xml`, `application/json`, and `text/plain`.

- `NO_ISSUE_OBSERVED`: the supported response declares `X-Content-Type-Options: nosniff`.
- `CANDIDATE_FOUND`: a supported response omits the header. APISentinel creates a low-confidence `Candidate` finding for analyst review.
- `INCONCLUSIVE`: the response lacks a supported Content-Type or has an unrecognized header value.
- `ERROR`: transport did not complete, except blocked/skipped/cancelled/auth-unavailable requests which are `NOT_RUN`.

The candidate means only that the observed response omitted the policy header. It does not prove exploitable MIME sniffing; browser consumption, response content, and route context are outside this check. It does not use payloads, infer from HTTP status, or confirm findings automatically. It recommends only a generic header configuration and still requires analyst review.

Transport outcome remains in `TestRun.status`; security-test outcome is separate in `TestRun.security_outcome`. A transport-only request has `test_id` empty and security outcome `NOT_RUN`. No transport outcome becomes a security verdict. Findings are linked to assessment, endpoint, and originating TestRun; new candidates start in `Candidate` status. Existing finding status review is performed through the authenticated finding workflow.

Coverage reports current endpoint inventory review, HTTP transport completion, registered security-test execution, and review of check-generated candidates separately. Only `NO_ISSUE_OBSERVED` and `CANDIDATE_FOUND` count as evaluated security-test coverage. Blocked, skipped, errored, cancelled, inconclusive, and not-run outcomes do not count. A candidate is an evaluated check result, not a confirmed vulnerability. Finding review coverage counts a candidate after its status leaves the initial `Candidate` state; this records analyst triage, not confirmation.

## Read-only identity comparisons

`authorization.bola.synthetic_pair` (API1) and `authorization.function_role_pair` (API5) run only through the durable queue against approved GET endpoints marked as authentication-required. Configure two client-provisioned disposable bearer identities in Assessment Details. Tokens are encrypted and never returned; revoking an identity disables it and clears its stored token.

BOLA requires two existing synthetic object IDs with known owners and a declared required path parameter. It sends up to four GET requests: both identities must first read their own object, then each identity is checked against the other's object. Cross-identity requests are skipped if either owner control fails. BFLA requires the client to designate which identity is allowed for the selected endpoint; it checks the allowed identity first and sends the denied identity's GET only if the allow control succeeds. Redirects are disabled. Only identity labels/roles, expected relation, and status codes are retained in results. Tokens stay encrypted in identity profiles; request parameters, including object IDs, are encrypted while jobs are pending/running and cleared on completion, cancellation, or failed lease recovery. Response bodies are not persisted.

The client-provided ownership/role expectation is the oracle. These comparisons cover one endpoint only and do not validate route-wide policy, role inference, sensitive response values, token lifecycle, or mutation behavior. A success from a denied identity is a low-confidence candidate for analyst review.

All active checks require their server allowlist entry, current assessment authorization, current endpoint approval, and the independent `APISENTINEL_ALLOW_ACTIVE_TESTS` gate. GET is assumed to be safe, but server-side side effects cannot be ruled out by the client. The suite remains a narrow local-workspace tool, not a comprehensive scanner or evidence of a complete client engagement assessment.
