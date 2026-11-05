# Phase 3 Assessments Management gap analysis

Reviewed 2026-10-18 against the Phase 3 Assessments Management prompt.

## Existing foundation reused

- `Assessment` already belonged to a tenant-owned `Client`; access uses the established client membership predicate and role checks.
- `WEB_API`, `ANDROID_API`, and `BOTH`, authorization records/review/revoke, scope fingerprints, a single encrypted assessment bearer profile, Android metadata/APK parsing, API imports, endpoint inventory review, test runs, audit events, and reports already existed.
- Assessment creation never started an HTTP request. Actual requests already require current reviewed authorization, endpoint approval, enabled server policy, in-scope method/path/host, and the shared runner.
- The dashboard already had an Assessments route and connected API client, but it was a selection/card view with a create modal; there was no update API, configuration revision, assessment-level activity reader, or archive action.

## Addressed in this increment

- Added assessment description, per-platform descriptive target configuration, creator attribution, configuration revision, and update timestamp with an additive Alembic migration.
- Added typed URL validation (no embedded credentials/query/fragment; production target URLs must use HTTPS), platform/type compatibility checks, server-side list filters/pagination, optimistic revision checks, draft edits, audit history, and non-destructive archive.
- Scope edits change the canonical authorization snapshot inputs; the existing authorization fingerprint then evaluates to `REVIEW_REQUIRED`. Editing or archiving is blocked while a request is queued or running. Archived assessments fail the existing authorization execution gate.
- Added an assessment list with search, type/environment filters, 30-row pagination, portfolio counts, selected-assessment details, configuration editing, authorization summary, activity and archive controls.
- Existing imports, endpoint inventory, findings, coverage, reports, auth profiles, authorization flow, and tenant policy remain the source of truth; no duplicate subsystem was added.

## Remaining product boundaries

- Assessment lifecycle remains deliberately conservative: records stay Draft while authorization status is shown separately; the existing product has no assessment-level execution job/state machine. The management API does not fabricate Ready, Running, Completed, Failed, or Cancelled states. Individual test-run jobs retain their own lifecycle.
- Target URLs are metadata only. They do not populate approved hosts or become executable scope. A reviewer must record/review authorization against the explicit `allowed_hosts`/paths/methods, and endpoints still need their existing inventory approval.
- The current single bearer credential profile is assessment-wide, not separately bound to the Web and Android source configurations. The management UI reuses this profile and does not claim separate source credentials.
- There is no dedicated assessment detail route with every proposed tab; the selected workspace links to/reuses the existing discovery, testing, findings, coverage, and reports pages. Empty/future workflow pages are not invented.
- Hosted CI, production infrastructure, and PostgreSQL migration behavior depend on external environments. The migration was applied to the configured local SQLite database; local PostgreSQL validation remains environment-gated.

See [requirements traceability](phase-3-assessments-requirements-traceability.md) and [management guide](phase-3-assessments-management.md).
