# Finding lifecycle and analyst triage

`ExecutionAuditEvent` is the canonical audit source. It records finding creation, candidate generation, triage decisions, and retest outcomes, including the finding link, authenticated actor, event timestamp, prior and new state, reason, and available test/endpoint provenance. Each event and finding update commit in one database transaction. `GET /api/v1/findings/{id}/history` returns linked audit events plus any legacy history; missing legacy attribution remains unavailable rather than being synthesized.

The `findings` table retains its assessment foreign key and adds nullable endpoint/TestRun links plus an optimistic `triage_version`. Legacy/manual findings can have no endpoint or TestRun provenance. The status column remains a string without a database CHECK constraint; the allowed state machine is enforced by the authenticated API. Every finding route requires a session and resolves ownership through the assessment's client. Other analysts receive the same 404 behavior as an unknown finding.

## States and transitions

Finding review now tracks three independent dimensions alongside the legacy triage status:

- **Validation** (`PENDING_VALIDATION`, `NEEDS_REVIEW`, `VALIDATED`, `REJECTED`, `INCONCLUSIVE`) is recorded through the reviewer-only validation endpoint with a separate audit event. `VALIDATED` requires usable evidence and, for registered checks, a completed originating TestRun with matching assessment, endpoint, check/version, candidate outcome, and structured security evidence. Confirmation and accepted-risk triage require `VALIDATED`; false-positive triage requires `REJECTED`.
- **Remediation** (`OPEN`, `IN_PROGRESS`, `PENDING_RETEST`, `RESOLVED`) follows triage and retest events without changing the validation decision. Retest outcomes update remediation status from the authoritative new evidence.
- **Confidence and priority** are first-class fields with rationales. Automated registered-check observations begin at LOW confidence and do not become confirmed findings automatically. P0–P4 is an explainable review order, separate from technical severity. No numeric risk score is produced until impact, exploitability, and business-criticality inputs are configured.

Assessment-scoped correlation keys identify repeat registered observations without replacing the canonical finding or overwriting original evidence. `first_detected_at` is preserved and `last_observed_at` advances on a duplicate observation. The API offers tenant-scoped filters, summary counts, and pagination headers; report snapshots carry the validation, priority, confidence, remediation, taxonomy, and correlation metadata.

New automated findings start as `Candidate`; checks cannot confirm them. Allowed analyst transitions are:

| Current state | Allowed next state(s) |
| --- | --- |
| Candidate | Needs Review |
| Needs Review | Confirmed, False Positive, Accepted Risk, Remediation In Progress, Closed |
| Confirmed | Accepted Risk, Remediation In Progress, Retest Required, Closed |
| False Positive | Needs Review (explicit reopen) |
| Accepted Risk | Needs Review (reopen), Remediation In Progress, Retest Required, Closed |
| Remediation In Progress | Accepted Risk, Retest Required, Closed |
| Retest Required | Accepted Risk, Remediation In Progress, Closed |
| Resolved | Retest Required (reopen) |
| Closed | Needs Review (reopen) |

Transitions to `Resolved` are accepted only through the retest endpoint, with new evidence and notes. A resolved status cannot be set by a normal triage PATCH. Legacy `Fixed` and `Retested` records remain readable and have explicit transitions into the new lifecycle; no old rows are rewritten by migration.

Every triage action requires a reason. Confirmation, false-positive, and accepted-risk decisions require at least 10 non-whitespace characters. Other changes require at least 5. Repeated or invalid transitions return 409; missing/short rationale returns 422. The authenticated session supplies the actor; clients cannot send actor IDs, history, or evidence changes in the triage request. Concurrent updates use `triage_version` optimistic locking and return 409 if the record changed during the request.

## Provenance and evidence

The original finding evidence is not part of the triage update contract. Automated candidates retain their assessment, endpoint, TestRun, check ID/version, and endpoint-definition hash where available. Manual findings record that automated provenance was not supplied. Triage events record the provenance that remains available at decision time.

Evidence and history read serialization applies recursive credential/body-key redaction and common inline secret redaction. The runner still stores no raw response body. Legacy history may not have an actor or reliable timestamp; the API returns those fields as unavailable in the canonical history view. Audit records are not editable through analyst APIs. Database administrators remain able to alter local database files.

Findings and audit history are only visible to the analyst who owns the assessment's client. No finding deletion route is provided.

## Retest provenance

New retests store a nullable assessment, TestRun, endpoint, analyst, test ID/version, and endpoint-definition hash. The assessment is copied from the owned finding by the server. A linked TestRun must be a new execution completed after the finding was recorded, belong to that assessment and the finding's endpoint, use the same registered check/version that produced the finding, and reference the endpoint's current approved definition. One TestRun can be linked to at most one retest. The server ignores client-supplied evidence/outcome when a TestRun is linked and derives the result from its persisted security outcome; transport-only completion therefore cannot resolve a finding. Evidence is copied from the check's sanitized evidence, never from a raw response body.

Linked `CANDIDATE_FOUND` is recorded as `CONFIRMED_PERSISTENCE` (the observation persisted, not that exploitability is confirmed); `NO_ISSUE_OBSERVED` can resolve only with registered-check evidence; inconclusive, error, and not-executed outcomes leave the finding open. Without a linked run, the API supports an explicitly manual analyst decision; manual `Resolved` is stored as `MANUALLY_RESOLVED` and must include evidence and notes, and is distinct from an automated no-issue result. Legacy outcomes remain unchanged. Audit events include the actor, reason, state transition, retest ID, and available execution provenance in the same transaction.

Migration `0008_retest_execution_provenance` adds nullable links and empty-default provenance fields. It deliberately does not backfill historical retests, which remain unlinked. No lifecycle status constraint is added: the database may contain legacy state strings, and API transition validation remains authoritative. Existing values are preserved rather than reinterpreted during upgrade.
