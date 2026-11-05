# Phase 8 requirements traceability

Statuses describe implementation and local verification, not production certification.

| Requirement | Implementation | Status / evidence |
| --- | --- | --- |
| Audit repository before implementation | Existing routes/models/access/docs/tests inspected; baseline auth/core/finding tests run | **COMPLETE**; baseline `39 passed` |
| Authoritative dashboard aggregates | `/dashboard`, `DashboardRead`; counts from client-scoped Assessment, current Endpoint, canonical Finding, Retest, TestRun, Report and audit rows | **COMPLETE**; empty and populated workspace, client isolation, repeated-test deduplication covered |
| Lifecycle, assessment type, severity, validation and triage metrics | group counts over existing labels; separate open/resolved/validated/unvalidated counts | **COMPLETE**; API integration tests |
| Remediation/retest integration | remediation state, overdue count and retest outcome counts from Phase 7 canonical rows | **COMPLETE**; no dashboard-triggered test jobs |
| Date filtering/time zone | Optional ISO datetime filters; timezone required; UTC `[start,end)` applied to tables with persisted `created_at` | **COMPLETE** for timestamped sources; **PARTIAL** for endpoint inventory because Endpoint has no timestamp, disclosed in response |
| Audit list/detail/filter/pagination | `GET /audit/events` and `GET /audit/events/{event_id}` filter time, actor, action, outcome, client, assessment and typed target; bounded page 1–200 | **COMPLETE**; invalid filters, sanitized detail, cross-client denial, pagination and immutability tests |
| Audit access and safe metadata | Authenticated route; accessible-client join before filtering; recursive `sanitize_evidence`; no write/delete route | **COMPLETE** for application-level controls; not tamper-evident against privileged database access |
| Creation audit event | `CLIENT_CREATED` persisted in same transaction as client record; assessment lifecycle already audited | **COMPLETE**; transaction pattern inspected; no separate audit table |
| Activity & Audit UI | Real paginated API table, event/client/assessment/date filters and empty/error/loading states | **IMPLEMENTED**; dashboard production build passes; browser E2E not added |
| Existing remediation/retest pages retained | Existing Finding/Retest UI and Phase 5 request route retained | **COMPLETE** by regression suite; no automatic execution added |
| Machine-readable release gate | `python scripts/release_gate.py` emits JSON checks with PASS/FAIL/WARN/BLOCKED/NOT_RUN, evidence, remediation and block flag | **COMPLETE** locally; script tests cover result distinctions; actual release decision is blocked on external requirements |
| Backend start, lint, compile, tests, frontend build, E2E and disposable migrations | Gate runs import, Ruff, compileall, pytest, local browser workflow, dashboard build and Alembic upgrade/check in temporary SQLite | **COMPLETE** locally; external/production gates remain blocked |
| PostgreSQL multiprocess / backup restore / production egress / KMS | Requires disposable PostgreSQL and production cloud/network services | **BLOCKED** when dependencies/evidence unavailable; no false pass is emitted |
| Database schema | No Phase 8 fields required | **NOT_APPLICABLE**; no migration added |

## Actual verification record

Final verification record:

- Baseline before Phase 8 edits: `pytest -q tests/test_auth_isolation.py tests/test_core.py tests/test_finding_lifecycle.py` — **39 passed, 1 warning**.
- Final full suite: `pytest -q` — **128 passed, 1 skipped, 1 warning** in 36.27s. The warning is the existing Starlette TestClient/httpx deprecation. The skipped test is PostgreSQL multiprocess limits/recovery, which requires the disposable PostgreSQL test URL.
- Focused Phase 8 integration and release-gate unit tests: `pytest -q tests/test_auth_isolation.py tests/test_release_gate.py` — **22 passed, 1 warning**.
- `ruff check src migrations tests scripts` — **passed**; `python -m compileall -q src migrations tests scripts` — **passed**.
- `npm run build` in `dashboard/` — **passed**.
- `python tests/e2e_browser_workflow.py` — **passed** with dashboard aggregation/date filter and activity audit in the local loopback flow.
- `python scripts/release_gate.py` — **BLOCKED**; **9 PASS, 0 FAIL, 1 WARN, 5 BLOCKED, 1 NOT_RUN**. Details are in `docs/phase-8-release-readiness.md`.

The single Starlette/httpx deprecation warning seen in the existing test environment is not a test failure. Skipped tests are represented separately as NOT_RUN in the release gate.
