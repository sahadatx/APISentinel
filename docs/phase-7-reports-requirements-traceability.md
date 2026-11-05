# Phase 7 requirements traceability

| Requirement | Implementation | Status / verification |
| --- | --- | --- |
| Use persisted, authorized assessment data | `make_report` loads owned assessment, canonical findings, endpoints, runs, retests and Android metadata in one DB unit of work | COMPLETE; report API and isolation tests |
| Report types and validated inclusion policy | `ReportCreate`; executive defaults to VALIDATED findings; optional validation/severity filters and evidence inclusion | COMPLETE; `test_report_type_and_inclusion_policy_are_snapshotted` |
| Consistent immutable versioned snapshot | Report source revision hash, generation timestamp, next version under assessment row lock | COMPLETE locally; concurrent PostgreSQL generation not stress-tested |
| JSON, HTML, CSV, PDF exports | JSON/CSV retained; HTML uses escaped content and restrictive CSP; PDF rendered from sanitized snapshot with ReportLab and no external resources | COMPLETE; PDF export endpoint smoke/integration test and frontend build |
| Report list/detail/access/audit | Tenant-scoped list/detail/export and `REPORT_GENERATED`, `REPORT_ACCESSED`, `REPORT_EXPORTED` events | COMPLETE; `test_auth_isolation.py` |
| Remediation ownership and details | Fields on canonical Finding and PATCH `/findings/{id}/remediation`; active client membership validation | COMPLETE; finding lifecycle tests |
| Auditable, concurrent remediation updates | Shared Finding optimistic version and same-transaction audit event | COMPLETE; API transition tests |
| Explicit authorized retest request | POST `/findings/{id}/retests/request` delegates to `/testing/jobs` queue with original registered check; caller supplies fresh parameters | COMPLETE; execution integration test |
| Scope/auth revalidation, budgets, cancellation | Existing queue performs these checks; queued cancellation finalizes linked retest as BLOCKED | COMPLETE by reuse; queue and authorization integration coverage |
| Result classification and evidence preservation | Retest outcomes: NO_ISSUE_OBSERVED, CONFIRMED_PERSISTENCE, INCONCLUSIVE, ERROR, BLOCKED, NOT_APPLICABLE; original Finding evidence remains immutable | COMPLETE; execution integration test |
| Reviewer closure/reopening | `FIXED_PENDING_VERIFICATION` requires evidence; reviewer-only `VERIFIED_FIXED`; persistent later result reopens and preserves history | COMPLETE; lifecycle and queued-ret test coverage |
| Frontend report/remediation/retest actions | Type/filter report modal, report type/version list, remediation editor, retest status/progress, cancellation and explicit retest request | PARTIAL; local browser E2E covers report export, remediation update and evidence-linked review; queued retest API/worker is integration-tested, but the new request/poll/cancel UI path is not yet browser-E2E exercised |
| Database migration | `0024_phase7_remediation_workflow` adds fields and client-owner FK without rewriting old finding decisions | COMPLETE; migration compatibility test and disposable DB upgrade |
| PDF support | ReportLab dependency and access-controlled PDF export added; report includes scope, summary, findings, execution, retest history, limitations, and page numbering | COMPLETE; PDF output verified by `%PDF-` signature and sanitized-secret regression assertion |

## Actual verification

- Baseline before edits: `pytest -q tests/test_finding_lifecycle.py tests/test_auth_isolation.py tests/test_execution_integration.py tests/test_migration_finding_triage.py` — **34 passed**.
- After edits: `pytest -q tests/test_finding_lifecycle.py` — **14 passed**.
- Final full suite: `pytest -q` — **124 passed, 1 skipped, 1 deprecation warning** (Starlette TestClient/httpx compatibility notice).
- Final quality checks: `ruff check src tests` — passed; `python -m compileall -q src/apisentinel` — passed.
- Dashboard: `npm run build` — passed.
- Migration: disposable SQLite `alembic upgrade head` and `alembic check` — passed; no schema drift.
- `python tests/e2e_browser_workflow.py` — passed for local fixture auth/ownership, inventory approval, registry checks, finding triage, compatible evidence-linked retesting, coverage, and JSON/HTML exports. It does not yet exercise the new queued-ret request/poll/cancel UI path.
- Baseline before edits: `pytest -q tests/test_finding_lifecycle.py tests/test_auth_isolation.py tests/test_execution_integration.py tests/test_migration_finding_triage.py` — **34 passed**.
