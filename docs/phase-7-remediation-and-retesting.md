# Phase 7 remediation and retesting

## Remediation

The canonical Finding stores owner analyst ID, optional target date, remediation notes, proposed fix, supplied change reference, reviewer notes, and remediation status. Update through `PATCH /api/v1/findings/{id}/remediation` with a required reason. The API verifies an assigned analyst is an active member of the finding's client. Reviewer-only decisions include accepted risk, verified fix, closure, and reopening. Optimistic locking and `ExecutionAuditEvent` preserve concurrent updates and history.

States used by this workflow: `OPEN`, `IN_PROGRESS`, `READY_FOR_RETEST`, `FIXED_PENDING_VERIFICATION`, `VERIFIED_FIXED`, `REOPENED`, `ACCEPTED_RISK`, and `CLOSED`. Legacy `PENDING_RETEST` and `RESOLVED` remain readable and transitionable for compatibility. A developer/status update never proves a fix. `VERIFIED_FIXED` requires a latest evidence-bearing successful/manual retest, reviewer membership, and a rationale of at least ten characters. It is the only remediation state that changes the triage status to `Resolved`.

## Retesting

`POST /api/v1/findings/{id}/retests/request` requires an `Idempotency-Key`, finding eligibility, original endpoint/TestRun/check provenance, and an unchanged enabled check version. It delegates request creation to the Phase 5 job queue. The queue rechecks assessment membership, authorization validity/method/scope, current endpoint approval and definition, check prerequisites, parameter declaration, request budget, rate limit, and cancellation. Callers must resupply parameter values; encrypted queue storage/redaction behavior is inherited from Phase 5.

Queued retests are linked to their original Finding and TestRun. The worker or cancellation route records one classified conclusion and sanitized new evidence while preserving original finding evidence. Classifications are `CONFIRMED_PERSISTENCE`, `NO_ISSUE_OBSERVED`, `INCONCLUSIVE`, `ERROR`, `BLOCKED`, and `NOT_APPLICABLE`. A successful-looking result becomes `FIXED_PENDING_VERIFICATION`, not `VERIFIED_FIXED`. Errors, blocks, inconclusive and not-applicable outcomes remain open/pending. A persistent observation after a prior fix decision moves the finding to `REOPENED`; earlier decisions remain in audit history.

Manual retest evidence is allowed for analyst documentation, but only a reviewer can approve it as a verified closure. Automated no-issue conclusions require a registered compatible TestRun and structured evidence. No retest is started by report creation, remediation edits, or finding creation.

## Limitations

Only current registered checks are eligible for automatic retest. PDF, bulk retesting, retest execution against authenticated-only registered checks, external issue links beyond a supplied reference, and production deployment validation are not implemented.
