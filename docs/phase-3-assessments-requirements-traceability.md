# Phase 3 Assessments Management requirements traceability

Scope: existing APISentinel repository and configured local SQLite database. Statuses reflect implemented behavior and tests; they are not a release certification.

| ID | Requirement | Status | Implementation | Verification / remaining limit |
|---|---|---|---|---|
| ASM-01 | Reuse existing tenant-owned Assessment and Client domain | COMPLETE | `models.Assessment`, `owned_assessment_or_404`, `client_access_filter` | `tests/test_auth_isolation.py` |
| ASM-02 | Web, Android, combined types | COMPLETE | Existing type field plus source-key validation and separate `target_configs.web_api` / `android_api` | `tests/test_auth_isolation.py::test_assessment_management_configuration_history_archive_and_tenant_isolation` |
| ASM-03 | Description, creator, timestamps, revision | COMPLETE | Additive model fields and migration 0020 | Migration regression; API management test |
| ASM-04 | Safe target URL validation and no implicit authorization | COMPLETE | Pydantic URL/type checks; target metadata never changes allowed host scope or executes requests | `test_assessment_target_validation_is_typed_and_non_authorizing`; creation audit asserts no execution |
| ASM-05 | Existing authorization/scope record and review | COMPLETE | Existing versioned authorization service and scope fingerprint reused | `tests/test_authorization_lifecycle.py`, `tests/test_auth_isolation.py` |
| ASM-06 | List, tenant filters, search, server pagination | COMPLETE | `GET /assessments` accepts client/type/environment/status/search/limit/offset; `X-Total-Count` | New management test; existing tenant isolation suite |
| ASM-07 | Edit with concurrency/revalidation | PARTIAL | `PATCH /assessments/{id}` requires expected configuration revision, locks/reloads, blocks queued/running jobs, audits changes; scope edits invalidate the existing authorization fingerprint | New management test. No immutable per-field config revision table; each execution retains its existing policy snapshot. |
| ASM-08 | Archive without deleting evidence | COMPLETE | `POST /assessments/{id}/archive`; blocked for queued/running jobs, records canonical audit event; archived records are read-only and execution gate blocks them | New management test; existing runner/authorization tests |
| ASM-09 | Assessment activity/history | COMPLETE | `GET /assessments/{id}/history` reads canonical `execution_audit_events` under tenant access | New management test |
| ASM-10 | Bearer credential references | PARTIAL | Existing encrypted assessment-bound bearer profile reused. Only one profile per assessment; not source-specific and only bearer supported. | Existing credential tests; source-specific profiles remain future work. |
| ASM-11 | Assessment lifecycle transitions | PARTIAL | Draft and Archived are persisted; scope state remains the existing derived authorization status. No synthetic assessment-level execution lifecycle was added because execution is represented by TestRuns/jobs. | Invalid state transitions to Ready/Running are impossible through assessment API; assessment-level state machine remains absent. |
| ASM-12 | Dashboard assessment management | PARTIAL | Search, type/environment filters, 30 per page, counts, selected details, edit, authorization summary, audit history and archive | `npm run build` and `python tests/e2e_browser_workflow.py` pass. The assessment list is fetched from the tenant-filtered API (maximum 500 rows per call); current UI filtering is client-side. Full tabbed detail layout is not implemented. |
| ASM-13 | Existing discovery, findings, coverage and reports reused | COMPLETE | Existing assessment-scoped APIs/pages remain canonical | Existing integration and E2E workflows |
| ASM-14 | Additive migration preserves existing records | COMPLETE (local SQLite) | Migration 0020 adds nullable/backfilled creator/timestamps and non-null defaulted fields; no table/data removal | `tests/test_migration_authorization.py` verifies upgrade defaults and downgrade preserves legacy authorization/status; local `alembic upgrade head` and `alembic check` |
| ASM-15 | Hosted CI, PostgreSQL upgrade, production deployment proof | BLOCKED | Not available in this local environment | PostgreSQL URL and hosted CI/deployment evidence are external prerequisites. |

## Safety gates retained

- Creation and editing make no HTTP requests.
- Target base URLs are descriptive. Only the separately recorded/reviewed scope authorizes hosts, paths, methods and time window; discovered/imported endpoints still require endpoint approval.
- Cross-client reads and writes return not-found/forbidden according to existing membership policy.
- Credentials remain in the existing encrypted credential profile; no target config or audit event accepts a credential field.
- Scope or environment changes invalidate the current authorization scope fingerprint; authorization must be re-recorded/reviewed before execution.

## Verification results

- `pytest -q`: 116 passed, 1 skipped; one Starlette/httpx deprecation warning. The skip is the existing environment-gated PostgreSQL test.
- Focused management/security regression: `pytest -q tests/test_auth_isolation.py tests/test_authorization_lifecycle.py tests/test_execution_integration.py` — 22 passed.
- Migration regression: `pytest -q tests/test_migration_authorization.py tests/test_auth_isolation.py` — 18 passed, including preservation/default backfill through revision 0020.
- `ruff check src tests`: passed.
- `alembic check`: passed, no new upgrade operations detected.
- Local configured database: `alembic upgrade head` applied `0019 -> 0020`; `alembic current` reports `0020_assessment_configuration`.
- `npm run build` in `dashboard/`: passed.
- `python tests/e2e_browser_workflow.py`: passed against isolated local fixtures; no third-party target was contacted.
