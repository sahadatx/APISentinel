# Phase 7 reports, retesting, and remediation gap analysis

## Audit disposition

| Area | Before Phase 7 | Current disposition |
| --- | --- | --- |
| Canonical reports | Versioned JSON snapshots and tenant-scoped JSON/HTML/CSV export existed | **COMPLETE** for these formats; snapshots now carry type, inclusion policy, source revision and generation time |
| PDF | Previously listed as unsupported in this gap note | **IMPLEMENTED**: access-controlled PDF export renders the saved report snapshot with ReportLab. This document's prior PDF row was stale. |
| Report types/filters | One all-data snapshot, no validated configuration | **COMPLETE** for executive, technical, remediation and retest/closure configuration, validation/severity filters and evidence inclusion |
| HTML safety | Escaping existed for current tables; no CSP or full evidence detail rendering | **COMPLETE** for escaped static HTML, no external resources/scripts, restrictive CSP and secret-sanitized report content |
| Report access | Tenant-scoped list/export | **COMPLETE** with tenant-scoped detail/export, pagination on list and access/export audit events |
| Retest records | Manual results or linking an already completed TestRun | **COMPLETE** for explicit requests through the existing safe job queue, persisted asynchronous result classification, and existing manual evidence review path |
| Retest safety | Existing queue rechecked scope/authorization; manual retest could set triage Resolved immediately | **COMPLETE** for queue revalidation and cancellation mapping; retest success now remains pending reviewer verification |
| Remediation workflow | Basic OPEN/IN_PROGRESS/PENDING_RETEST/RESOLVED state | **COMPLETE** for expanded auditable state transitions, owner, due date, notes, proposed fix, and change reference |
| Finding closure | Retest could mark Resolved without separate reviewer approval | **COMPLETE** with evidence-backed reviewer-only VERIFIED_FIXED decision; failed, blocked, inconclusive, and non-applicable results cannot satisfy it |
| E2E | Local browser workflow covered manual TestRun linking, remediation review and JSON/HTML | **PARTIAL**: local browser E2E passed for report export, remediation and evidence-linked review; queued retest is covered by API/worker integration, but browser automation does not yet exercise the new request/poll/cancel UI path |

## Existing architecture reused

- `Report` remains the sole immutable report snapshot model; its content stores report configuration, generated time, data revision and persisted source data.
- `Finding` remains canonical for validation, triage, remediation ownership/notes/status and closure.
- `Retest` remains canonical for original/new evidence and registered TestRun provenance.
- Phase 5 `TestRun` queue, worker, cancellation, request budgets, endpoint approval and authorization checks are reused. No new HTTP engine or evidence table was added.
- `ExecutionAuditEvent` remains the audit system for remediation changes, report generation/access/export, and retest request/completion.

## Remaining limitations

- DOCX, external delivery, issue tracker synchronization, localization, and automated report-generation jobs are not implemented. PDF rendering is implemented in the API export path; deployments still need the ReportLab dependency installed.
- Report lifecycle is synchronous (`Completed`/stored snapshot); QUEUED/GENERATING/FAILED states are not needed for this local synchronous generator.
- Retest parameter values are not copied from original runs. An operator must supply them again; queued values remain encrypted by the existing request queue.
- Registered checks are limited to the current registry and safe GET/HEAD/OPTIONS execution policy. A changed check version blocks automated retest and requires manual review.
- Assessment completion dates, business impact, and assigned owner names are not configured in the source model, so reports display the known start date/owner identifier and leave completion unknown.
- The repository provides local fixture validation; production database, hosted CI, external storage, and release approval were not exercised.

## Verification record

Commands and results are recorded in `phase-7-reports-requirements-traceability.md`. `pytest -q` completed with 124 passed and 1 skipped; Ruff, Python compile, dashboard build, disposable SQLite migration check, and local browser E2E passed. The skipped test and warning are noted in the traceability record. No live client target was used.
