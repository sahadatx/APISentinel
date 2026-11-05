# Assessment authorization records

The legacy `authorization_confirmed` Boolean and `authorization_reference` string are retained for compatibility. They are not sufficient to permit execution. Existing assessments are migrated to `REVIEW_REQUIRED` without changing their legacy values or inventing authorization evidence.

## Lifecycle

- `REVIEW_REQUIRED`: no complete, scope-bound record has been reviewed, the record is incomplete, or its stored scope fingerprint no longer matches current assessment settings.
- `RECORDED`: an authenticated assessment owner recorded the authorizing party, reference, validity period, permitted methods, reason, and acknowledged the current server-displayed scope.
- `ACTIVE`: an authenticated reviewer reviewed the record, party, validity, and exact scope and recorded a review rationale; a sole active client member may instead complete the explicit self-review acknowledgement and rationale. Self-review is audited as `AUTHORIZATION_SELF_REVIEWED` and is not an independent second-person check. Both paths remain operator attestations; APISentinel does not verify the legal authenticity of the source document.
- `SCHEDULED`: an active record is valid but its `valid_from` time or configured testing-window start is in the future.
- `WINDOW_CLOSED`: the configured testing-window end has been reached. The authorization record may remain valid, but execution is blocked until a new window is recorded and reviewed.
- `EXPIRED`: the record expiry has passed.
- `REVOKED`: an analyst explicitly revoked the record with a reason.

`POST /api/v1/assessments/{id}/authorization/record`, `/review`, and `/revoke` are authenticated and client-scoped. Each mutation requires the current `expected_version`; state and canonical `ExecutionAuditEvent` are committed in one transaction. Stale versions return 409. Review and revoke require a rationale. Review also requires an acknowledgement that the authorizing party, evidence fingerprint, scope, and validity were inspected. A recorder reviewing their own record must explicitly acknowledge solo-operator self-review; the action is retained in audit history. Audit metadata contains a hash of the authorization reference rather than the reference itself.

The authorization snapshot is generated server-side from the assessment's environment, hosts, allowed paths, exclusions, request ceiling, testing-window fields, and explicitly selected methods. Testing-window start and end must both be supplied as timezone-aware ISO 8601 timestamps; the start is inclusive and the end is exclusive. Empty values leave the window unrestricted. The record API does not accept replacement hosts or paths. A mismatch blocks execution and requires a newly recorded and reviewed authorization. Permitted methods are limited to GET, HEAD, and OPTIONS and further intersect with the runner policy.

The endpoint approval step remains separate and must be current for the imported endpoint definition. Before each HTTP request, including each redirect hop, the runner reloads the owned assessment and verifies that the authorization version and scope fingerprint are unchanged and that the record remains active, within its validity period and testing window, and permits the method. DNS lookups are bounded by the overall request deadline. Existing destination, redirect, TLS, response, rate, and concurrency controls remain in force.

For production/staging, attach a PDF through `POST /api/v1/assessments/{id}/authorization/evidence` before recording the authorization. The upload accepts a bounded PDF, records its SHA-256, sanitized filename and size in the assessment and audit log, then discards the bytes. Uploading changed evidence clears prior reviewer approval and returns the record to `REVIEW_REQUIRED`. Reviewers should compare the displayed fingerprint against their separately obtained source document. This is provenance metadata and a consistency check only: APISentinel does not retain the document, validate a digital signature, establish signer identity, or prove legal authenticity. Operators must verify authority and rules of engagement independently.
