# APISentinel release-readiness gap analysis

> Historical review: the observations below reflect the code at the time of that review. Follow-up work has added assessment-bound encrypted bearer profiles, database-backed execution reservations, loopback/non-root Docker defaults, and migration `0011`. See [the current Phase 1 matrix](phase1-implementation-matrix.md) for current status.

**Review date:** 2026-10-17 (updated after Phase 4 Task 2)
**Repository:** `/home/kali/Projects/APISentinel`
**Disposition:** Keep classified as a local assessment workspace. This review does not establish readiness for client-facing or production use.

## 1. Executive summary

The current code implements a local workflow: analyst login with server-side sessions, single-owner client isolation, scope-bound authorization record/review/revocation, OpenAPI inventory review, endpoint approval, a bounded HTTP runner, two narrowly scoped response-header checks, candidate triage, execution audit records, evidence-linked retesting, coverage summaries, and JSON/HTML/CSV export code. The latest local revalidation is recorded in the Phase 4 Task 2 addendum below. This does not establish production or client readiness.

The system is not ready for a controlled client pilot yet. The most consequential limitations are that authorization is an operator attestation, not legal verification; authenticated API endpoints cannot be tested because there is no configured secret vault/resolver; runner rate and concurrency limits are partly process-local; and the Docker example publishes development-mode services on all interfaces. The registry contains only two metadata checks and does not evaluate API authorization or business logic. A reproducible loopback-only local demo now exercises report scope in HTML and exports synthetic JSON/HTML artifacts, but does not test deployment or report delivery operations.

No Critical finding was established from this bounded review. “High” means the issue blocks a safe or honest pilot under the stated client-assessment goal; it is not a claim of a remotely exploitable vulnerability.

## 2. Review method and evidence labels

- **Code evidence** identifies behavior visible in the current implementation.
- **Test evidence** identifies behavior exercised by a test that ran during this review.
- **Inference** identifies operational or release consequences derived from that evidence.
- **Implemented, tested** means the behavior exists and a relevant test ran; it does not imply independent security certification.
- **Implemented, partially tested** means only selected paths or layers are covered.
- **Untested / missing** means this review found no direct current test or implementation.

The repository has no `.git` metadata, so this review could not establish a diff or prior change history. The configured database was inspected read-only; it was not reset or migrated during this review.

## 3. Current capability inventory

| Area | Current state | Code evidence | Test evidence and limits |
|---|---|---|---|
| Analyst authentication | Implemented, partially validated. Argon2id password hashes, opaque server-side sessions, session expiry/revocation, HttpOnly session cookie, CSRF cookie/header, explicit credentialed CORS origins, TOTP MFA and account-level login throttling. | `src/apisentinel/auth.py`, `src/apisentinel/cli.py`, `src/apisentinel/config.py`, `src/apisentinel/main.py` | `tests/test_auth_isolation.py` covers login/logout, bad/disabled users, expiry, CSRF, origin/CORS, and protected access. The current throttle lacks direct regression coverage; password recovery and session administration UI are absent. |
| Ownership isolation | Implemented, tested for listed API paths. Client-scoped reads and mutations use owner joins/helpers and generally return 404 for inaccessible resources. | `src/apisentinel/api.py` (`owned_client_or_404`, `owned_assessment_or_404`, `owned_finding_or_404`) | `test_all_client_scoped_routes_hide_foreign_and_unowned_legacy_records` and same-owner cross-assessment endpoint test in `tests/test_auth_isolation.py`; additional triage/retest checks in `tests/test_finding_lifecycle.py`. Single-owner model only; no team sharing/RBAC. |
| Authorization record | Implemented and locally tested as a scope-bound lifecycle: `REVIEW_REQUIRED`, `RECORDED`, `ACTIVE`, `SCHEDULED`, `EXPIRED`, `REVOKED`. Legacy Boolean/reference fields are preserved but do not authorize execution. | `src/apisentinel/authorization.py`, `src/apisentinel/models.py`, `src/apisentinel/api.py`, `src/apisentinel/runner.py`, migration `0009_assessment_authorization_lifecycle.py` | `tests/test_authorization_lifecycle.py`, `tests/test_migration_authorization.py`, `tests/test_execution_integration.py`, and `tests/e2e_browser_workflow.py`. The operator must independently verify the source document and signer authority. |
| Scope and destination safety | Implemented, substantially tested. Server derives request URL; runner validates owner, authorization, methods/host/path/ports, resolves and pins destination IP, checks peer, verifies TLS hostname, disables environment proxies, manually validates bounded redirects, strips credentials on origin change, limits time/body, and uses per-assessment in-process limits. | `src/apisentinel/safety.py`, `src/apisentinel/runner.py`, `src/apisentinel/api.py` | `tests/test_runner.py` directly covers actual local TCP peer/TLS SNI/Host, DNS changes, private destinations, redirects, proxy settings, timeouts, size limits, cancellation, and rate/concurrency. HTTPX/httpcore use private internals and exact pins (`pyproject.toml`); their upgrade requires renewed integration validation. Limits do not coordinate workers. |
| OpenAPI import and endpoint approval | Implemented, tested for a documented JSON subset. OpenAPI 3.0.x/3.1.x imports local JSON paths/operations, parameters, schemas, tags, security declarations, and local refs; remote refs are not fetched. Changed definitions invalidate stale approval. | `src/apisentinel/discovery.py`, `src/apisentinel/api.py`, `src/apisentinel/models.py`, `docs/openapi-import.md` | `tests/test_openapi_inventory.py` covers versions/errors, size/duplicate keys, refs, parameters, server scope review, traversal, reimport and stale approval. Postman, YAML and complete OpenAPI compatibility are not established. |
| TestRun and HTTP execution | Implemented, tested. TestRun selects an owned assessment and same-assessment endpoint, approved current definition, server registry ID or transport-only mode; request URL/policy are server-derived. Active execution has a separate default-off gate. | `src/apisentinel/api.py`, `src/apisentinel/runner.py`, `src/apisentinel/models.py` | `tests/test_execution_integration.py`, `tests/test_core.py`, `tests/test_runner.py`; Playwright workflow verifies local endpoint approval/execution gate. This does not establish safe behavior for every deployment topology. Crash during an active run may leave `RUNNING`; API cancellation is not exposed. |
| Registered security checks | Implemented, tested as two metadata observations only: `response.header.content_type_options` and `response.header.strict_transport_security`, both v1.0.0. Registry defines purpose, supported method/scheme, prerequisites, gates, evidence and outcome text. | `src/apisentinel/test_registry.py`, `src/apisentinel/config.py`, `docs/first-check-quality.md`, `docs/hsts-check.md`, `docs/security-test-registry.md` | `tests/test_test_registry.py` covers parser/outcome cases, evidence allowlist, HSTS values and registry disabled/unknown behavior. E2E covers both cards/check IDs against loopback HTTP. No browser exploitability or authenticated API behavior is tested. The checks do not prove exploitability or assess authorization/business logic. |
| Findings and triage | Implemented, tested. Automated findings start as candidates; explicit transitions and rationale requirements are validated; SQLAlchemy version column rejects stale concurrent updates; no deletion API. | `src/apisentinel/api.py`, `src/apisentinel/models.py`, `src/apisentinel/schemas.py`, `docs/finding-lifecycle.md` | `tests/test_finding_lifecycle.py` covers candidate provenance, transitions, reasons, spoofed actor/history, retest decisions, rollback/audit consistency and concurrent updates. Sanitizer masks common secret keys, but cannot guarantee removal of arbitrary secrets embedded in free text. |
| Audit | Implemented, tested at application level. `ExecutionAuditEvent` stores actor, resource IDs, event type, outcome, metadata and timestamp; state change plus event commit together in covered paths. | `src/apisentinel/models.py`, `src/apisentinel/api.py` | Lifecycle, execution and endpoint-approval tests assert audit behavior. It is append-only by application convention, not tamper-proof against a database administrator. No external sink, retention policy or integrity signature. |
| Retesting | Implemented, tested for linked registered checks and manual analyst entries. Linked TestRun must be newer, same assessment/endpoint/check/version and current approved definition; API derives linked outcome/evidence. Legacy retests remain unlinked. | `src/apisentinel/api.py`, `src/apisentinel/models.py`, `docs/finding-lifecycle.md`, `docs/coverage-model.md` | `tests/test_finding_lifecycle.py` and Playwright workflow exercise compatible runs, stale/transport-only cases and audit consistency. No independent client fix verification beyond the applicable registered check; manual retest is analyst-attested. |
| Coverage | Implemented, tested. Separate inventory review, transport completion, registered check completion and candidate review. Only interpreted check outcomes count as completed security-test coverage. | `src/apisentinel/api.py` (`build_coverage`), `docs/coverage-model.md` | `tests/test_core.py`, `tests/test_execution_integration.py`, `tests/test_test_registry.py`, plus browser workflow. Retest outcomes are records, not a percentage metric. Coverage means workflow activity, not assurance. |
| Reports | JSON/HTML/CSV export code and immutable-by-API snapshots implemented. Scope, enabled methodology/check limitations, transport/security outcomes, findings, coverage and retest provenance are included in the current report path. | `src/apisentinel/api.py` (`make_report`, `/reports`, `/reports/{id}/export`), `src/apisentinel/models.py`, `docs/report-versioning.md` | Local browser workflow checks JSON/HTML scope, limitations, retest linkage, and secret absence. CSV still needs focused direct export regression coverage. No PDF, signature, release approval or delivery receipt. |
| Migrations and persistence | Current migration head is `0009_assessment_authorization_lifecycle`; the user's configured DB remains at `0008_retest_execution_provenance`. | `migrations/versions/0001_initial.py` through `0009_assessment_authorization_lifecycle.py`, `migrations/env.py`, `src/apisentinel/models.py` | `tests/test_migration_authorization.py` verifies a representative legacy assessment retains its Boolean/reference but becomes `REVIEW_REQUIRED` with no fabricated event. Disposable `alembic upgrade head` and `alembic check` passed; the configured DB was not upgraded. |
| Dashboard and browser workflow | Implemented, partially tested. SPA includes login, clients, assessments, discovery, testing, coverage, findings, reports, retesting, settings and sign out. | `dashboard/src/App.tsx`, `dashboard/src/index.css`, `dashboard/src/main.tsx`, `tests/e2e_browser_workflow.py`, `docs/browser-e2e.md` | The local Playwright/Chromium script passed and checks login/logout, access denial, client/assessment creation, import/review/approval, both checks, triage, compatible retest, coverage and JSON/HTML exports. It does not cover Settings changes, all API error branches, responsive/mobile layouts, HTTPS browser behavior or accessibility. |
| Install and operations | Local install/Docker instructions exist; API container runs migrations at startup and Docker Compose persists SQLite in a volume. | `README.md`, `Dockerfile`, `docker-compose.yml`, `dashboard/Dockerfile`, `.env.example`, `pyproject.toml` | Current checks prove build and schema behavior only. No CI workflow files were found. No documented tested backup/restore procedure or retention procedure was found. Python requirements are ranged except pinned HTTPX/httpcore; frontend package manifest uses `latest` ranges despite a lockfile, and Docker runs `npm install` rather than `npm ci`. |

## 4. Prioritized gaps

### Critical

None established by this review. The application is explicitly treated as a local workspace, active requests default off, and no live target was used. This is not a statement that no critical defect can exist.

### High

#### H1 — Authorization is an operator attestation, not independently established

- **Code evidence:** `src/apisentinel/authorization.py` and `src/apisentinel/api.py` require a complete, time-bounded, scope-bound record and separate authenticated review. The application does not ingest or validate signed documents or signer identity. Legacy Boolean/reference fields cannot open the runner gate.
- **Test evidence:** `tests/test_authorization_lifecycle.py`, `tests/test_migration_authorization.py`, `tests/test_execution_integration.py`, and `tests/e2e_browser_workflow.py` cover lifecycle, legacy review requirement, execution blocking, and local workflow. They do not authenticate real client authority.
- **Inference:** Before any client target is tested, an operator must verify source authorization and rules of engagement outside APISentinel. A non-empty reference is not legal proof.

#### H2 — Authenticated API endpoints cannot be assessed with the current credential path

- **Code evidence:** `runner.py` defines a bearer reference adapter interface, but the TestRun API does not inject a trusted resolver. OpenAPI endpoints requiring authentication fail closed with `AUTH_UNAVAILABLE`.
- **Test evidence:** `tests/test_runner.py::test_unavailable_bearer_reference_fails_without_request`; registry and E2E tests exercise no authenticated client API.
- **Inference:** Most private client APIs require credentials. A pilot must either be explicitly limited to unauthenticated endpoints and state that limitation, or wait for controlled secret resolution, access controls and redaction tests. Do not pass tokens through normal assessment/TestRun fields.

#### H3 — Docker example is development-mode and network exposed

- **Code evidence:** `docker-compose.yml` publishes `8000:8000` and `5173:80` without loopback binding and sets only the database and active-test gate. `Dockerfile` launches Uvicorn on `0.0.0.0`; settings default to `environment=development` and `cookie_secure=false`.
- **Test evidence:** configuration tests reject insecure production settings (`tests/test_auth_isolation.py`), but no deployment/network exposure test exists.
- **Inference:** The sample stack is appropriate only on a trusted local host/network. Before a pilot, bind ports to loopback or supply and validate a production deployment configuration behind HTTPS with secure cookies, explicit origins, protected secrets, and a network boundary. Keep active execution disabled unless the approved pilot runbook enables it.

### Medium

#### M1 — Two header checks do not support broad API security claims

- **Code evidence:** `src/apisentinel/test_registry.py` contains only the Content-Type-Options and HSTS checks. HSTS applies only to the final HTTPS response; both checks are metadata observations and candidates require analyst review.
- **Test evidence:** `tests/test_test_registry.py` validates deterministic response/header outcomes. E2E exercises the narrow workflow with a loopback fixture. No authorization/IDOR, input validation, business-logic or browser behavior check exists.
- **Inference:** Limit client-facing scope and report language to these exact checks. Do not present the platform as a comprehensive API security assessment engine.

#### M2 — Rate/concurrency controls are per-process and active-run recovery is manual

- **Code evidence:** runner limiter state is module-local; a partial unique index coordinates a running request per assessment endpoint, but not aggregate rate/concurrency across workers. API execution is synchronous. Process interruption can leave a `RUNNING` record; cancellation cannot immediately interrupt a socket blocked until read timeout.
- **Test evidence:** `tests/test_runner.py::test_rate_and_concurrency_limits_are_enforced_before_transport`, `test_cancellation_during_stream_closes_response`; `tests/test_core.py::test_database_prevents_duplicate_active_http_run_for_same_endpoint` tests same-endpoint concurrency.
- **Inference:** A pilot must run a single controlled worker and define operator handling for stale `RUNNING` records. Distributed deployments require shared coordination and an interruption recovery design.

#### M3 — CSV is not a full engagement report and has narrower E2E verification

- **Code evidence:** CSV export is a finding-row projection; it is not a full structured engagement report like JSON/HTML.
- **Test evidence:** The browser workflow checks JSON/HTML scope, limitations, retest linkage, and secret absence. It does not exercise CSV through the browser.
- **Inference:** Do not treat CSV as the complete client deliverable. Add focused CSV export, redaction, and spreadsheet formula-safety checks before using it standalone.

#### M4 — CSV and migration data preservation have narrower direct coverage

- **Code evidence:** CSV export is a finding-row projection; retest provenance remains nullable and migration `0008` does not backfill old rows.
- **Test evidence:** Current E2E validates JSON/HTML, not CSV. The legacy migration test covers the `0007` finding-triage migration; this review's disposable empty-database upgrade verifies the chain, not a populated pre-0008 upgrade.
- **Inference:** Add populated legacy fixture migration tests and CSV assertions for formula-like values, redaction, and expected omissions before relying on these paths for delivery.

#### M5 — Account login throttling is implemented; session administration remains absent

- **Code evidence:** eight failed password or MFA attempts within a 15-minute window place an account in a 15-minute lockout; successful login clears the counter. Logout revokes the current session; no session list/revoke-all UI/API was found.
- **Test evidence:** the existing authentication test inventory covers invalid credentials and logout, but this throttle has not received direct regression coverage in this update.
- **Inference:** Keep deployment exposure controls and MFA. Add direct throttle verification and a tested account/session revocation runbook before a shared-network pilot.

#### M6 — Audit and evidence are not protected from local database administrators

- **Code evidence:** audit rows are ordinary SQLAlchemy records with JSON metadata and no database trigger, signature, external sink, or retention policy. The docs describe append-only as an application convention. Evidence sanitizer masks known key names, not arbitrary secret text.
- **Test evidence:** tests verify application writes and common-field redaction; no privileged DB-tampering or arbitrary free-text secret test exists.
- **Inference:** The audit log supports workflow traceability but not tamper-evident compliance evidence. Use restricted filesystem/database access, encrypted backups and a defined retention policy; add external immutable audit storage only if the pilot's assurance requirements need it.

### Low

#### L1 — Operational documentation was stale (corrected in this update)

- **Code evidence:** `README.md`, `docs/roadmap.md`, and `docs/architecture.md` now describe authorization, bounded execution, the two-check limit, report formats, and the local-only disposition. `docs/local-demo-workflow.md` documents the isolated reproduction path.
- **Test evidence:** The updated browser workflow and report-artifact export are re-run as part of this task.
- **Inference:** Current-status documentation is improved, but it does not replace operational backup, deployment, and human authorization checks.

#### L2 — CI and reproducible frontend installation are not present

- **Code evidence:** no `.github/workflows` files are present; `dashboard/package.json` declares `latest` for runtime/dev dependencies; `dashboard/Dockerfile` runs `npm install`, though `package-lock.json` exists.
- **Test evidence:** Local build passed. No CI execution or clean container build was run for this review.
- **Inference:** Add CI and use lockfile-enforcing installation (`npm ci`) before pilot releases so a clean build is reproducible and regressions are caught after changes.

#### L3 — Browser workflow omits some operational/user paths

- **Code evidence:** `docs/browser-e2e.md` explicitly excludes Settings workflows, every API validation branch, mobile layouts and a full HTTPS browser target.
- **Test evidence:** Local Chromium E2E passed only for documented scenarios; backend HTTPS peer/SNI is covered separately by `tests/test_runner.py`.
- **Inference:** These omissions are acceptable for a local prototype but should be covered according to actual pilot use, particularly permission-denied and user-visible recovery states.

## 5. Required before a controlled client pilot

1. Keep status documentation aligned with actual behavior and train operators using the local demo workflow. Core README, roadmap, architecture, and demo instructions now reflect current behavior.
2. Define and rehearse a written operator authorization and rules-of-engagement checklist. Verify system-owner authority, exact hosts/paths/methods, environment, test account, rate ceiling, exclusions, time window, emergency contact and stop conditions before switching on active requests.
3. Decide whether the pilot includes authenticated endpoints. If yes, implement a trusted secret resolver/vault and prove credential masking and origin-change behavior. If no, explicitly exclude auth-required endpoints and disclose coverage limitations.
4. Do not expose the current Compose sample to a client/shared network as-is. Use loopback binding for local use or a reviewed HTTPS deployment with secure cookies, explicit CORS, protected secrets and restricted network access.
5. Keep active requests off by default; use one worker and local-like staging targets only until shared limits and interrupted-run recovery are designed and validated.
6. Add CSV export regression tests and human report QA. JSON/HTML scope and limitations are exercised locally; QA must still confirm exclusions, candidate-vs-confirmed status, limitations, and retest provenance.
7. Document and test database backup/restore, file permissions, retention, account disablement and stale `RUNNING` run handling. Verify a restore before storing client records.
8. Add a CI workflow that installs locked dependencies and runs backend, migration, frontend and local E2E checks. Pin frontend build dependencies and use `npm ci` in Docker.
9. Perform a human review of each candidate and each final report. Treat audit rows as traceability, not tamper-proof evidence.

## 6. Deferred enhancements

- **MFA, password recovery and session UI:** can wait for a loopback-only, single-analyst pilot if strong local account handling and account-disable procedures are documented. Reassess before shared-network access.
- **Team roles and client sharing:** can wait while one analyst owns all clients; current database model does not support collaborative ownership safely.
- **Postman/YAML import and broader OpenAPI compatibility:** can wait if the pilot supplies supported OpenAPI JSON and parser limitations are disclosed.
- **PDF export, delivery receipts and cryptographic report signing:** can wait if JSON/HTML/CSV satisfy the pilot contract and reports are delivered through an approved channel with manual version QA.
- **Distributed rate limiting and cancellation:** can wait only while single-worker operation, bounded read timeout and stale-run recovery are enforced.
- **More security checks:** deferred until the existing two checks, evidence, applicability, retesting and report claims are operationally reliable. No new checks are proposed by this review.
- **Mobile-specific dashboard and Settings editing:** can wait for a desktop local workflow; do not imply policy settings can be changed through the UI unless implemented.

## 7. Proposed implementation order

1. Keep the browser workflow and synthetic report export reproducible; review artifacts manually after material changes.
2. Add CSV export regression coverage, especially secret redaction and spreadsheet formula safety.
3. Document and exercise backup/restore, permissions, retention, account disablement, and stale TestRun recovery.
4. Prepare a pilot-specific locked deployment profile: HTTPS, secure cookies, explicit origins, restricted bind/network, one worker, active gate off by default, and operator-controlled enablement.
5. If authenticated routes are in scope, implement trusted secret storage and resolver before the pilot; otherwise formally exclude those routes.
6. Add account/session revocation operations appropriate to the deployment exposure and regression coverage for login throttling.
7. Add CI and a clean installation/build job, then repeat the local end-to-end workflow and human report QA.
8. Reassess readiness against a written pilot checklist; do not broaden product claims based only on passing tests.

## 8. Verification performed

Commands executed from `/home/kali/Projects/APISentinel` during this review:

| Command | Result |
|---|---|
| `rg --files ...` / targeted `nl`, `cat`, `rg` inspections | Inspected repository sources, docs, tests, config, frontend and migrations. |
| `git status --short --branch` | Could not run: repository has no `.git` directory. No Git cleanup or mutation was attempted. |
| Read-only SQLite query of `apisentinel.db` | Revision `0008_retest_execution_provenance`; 12 tables; one analyst and zero client/assessment/test/finding/report/retest/audit rows at inspection time. File remained unchanged. |
| `alembic history --verbose` | Confirmed linear migration chain `0001` through `0008`. |
| `pytest -q` | **72 passed**, 1 warning, 21.94s. Warning: Starlette deprecation that `httpx` with `starlette.testclient` is deprecated and recommends `httpx2`. |
| `ruff check src migrations tests` | Passed: “All checks passed!”. |
| `python -m compileall -q src migrations tests` | Passed, no output. |
| `npm --prefix dashboard run build` | Passed: TypeScript build and Vite 8.3.4 production bundle. |
| `alembic check` (configured DB) | Passed: “No new upgrade operations detected.” No upgrade was run against the configured database. |
| `alembic upgrade head` and `alembic check` with `APISENTINEL_DATABASE_URL` set to a temporary disposable SQLite file | Both passed; migration chain reached `0008_retest_execution_provenance`; no schema drift. Temporary directory was removed after the check. |
| `python tests/e2e_browser_workflow.py` | Passed on local Playwright/Chromium with temporary DB and loopback fixture: auth/ownership, inventory approval, both registry checks, finding triage, compatible retesting, coverage, JSON/HTML exports. |

No live network target, configured client target, browser HTTPS target, CSV browser export, backup/restore drill, or CI workflow was exercised. `alembic check` inspected the configured DB without applying migrations; the read-only revision and data-count query was separate. No claim is made that this review independently verifies prior reports beyond the commands listed here.

## 9. Files inspected

- Root/config/operations: `README.md`, `.env.example`, `pyproject.toml`, `alembic.ini`, `Makefile`, `Dockerfile`, `docker-compose.yml`, `dashboard/Dockerfile`, `dashboard/package.json`, `dashboard/package-lock.json`.
- Backend: `src/apisentinel/api.py`, `auth.py`, `cli.py`, `config.py`, `db.py`, `discovery.py`, `main.py`, `models.py`, `runner.py`, `safety.py`, `schemas.py`, `test_registry.py`.
- Migrations: `migrations/env.py`, `migrations/script.py.mako`, and `migrations/versions/0001_initial.py` through `0008_retest_execution_provenance.py`.
- Tests: `tests/test_auth_isolation.py`, `test_core.py`, `test_execution_integration.py`, `test_finding_lifecycle.py`, `test_migration_finding_triage.py`, `test_openapi_inventory.py`, `test_runner.py`, `test_test_registry.py`, `e2e_browser_workflow.py`, and `tests/fixtures/tls/localhost-cert.pem` / `localhost-key.pem`.
- Dashboard: `dashboard/src/App.tsx`, `index.css`, `main.tsx`, `vite.config.ts`, `tsconfig.json`, `index.html`.
- Documentation: `docs/architecture.md`, `browser-e2e.md`, `client-workflow.md`, `coverage-model.md`, `finding-lifecycle.md`, `first-check-quality.md`, `hsts-check.md`, `openapi-import.md`, `report-versioning.md`, `roadmap.md`, `security-model.md`, `security-test-registry.md`.

`docs/release-readiness-gap-analysis.md` is the review artifact and was created after the inspection and verification described above.

## 10. Phase 4 Task 2 follow-up verification

The following follow-up revalidated the authorization lifecycle and a report-producing local workflow after migration `0009_assessment_authorization_lifecycle` was added. This supersedes the older status and test-count statements above where they conflict.

| Command / inspection | Result |
|---|---|
| `python tests/e2e_browser_workflow.py --artifacts-dir /tmp/apisentinel-client-demo-artifacts.nb4dv9` | Passed. Uses fresh temporary SQLite DB, temporary local services, synthetic authorization, and a loopback-only HTTP fixture. JSON and HTML files were saved to the named `/tmp` artifact directory. |
| Inspect generated JSON/HTML artifacts | Scope was `127.0.0.1` and `/api/**`; authorization said `ACTIVE` while `legal_authenticity_verified=false`; runs distinguished `BLOCKED_SCOPE`, `CANDIDATE_FOUND`, `INCONCLUSIVE`, and `NO_ISSUE_OBSERVED`; finding was `Resolved` only after linked v1.0.0 `NO_ISSUE_OBSERVED` retest; synthetic cookie marker was absent. |
| `tests/test_migration_authorization.py` via `pytest -q` | Passed; preserved legacy Boolean/reference values and did not fabricate authorization review/audit events. |
| Disposable `alembic upgrade head` and `alembic check` | Passed at revision `0009_assessment_authorization_lifecycle`, no schema drift. |
| Configured SQLite DB read-only inspection | Remained at `0008_retest_execution_provenance`, zero assessment rows, original modification time unchanged. It was not upgraded. |

Follow-up limitations: no public/client target, client credentials, external authorization evidence, production deployment, database restore, or marketplace interaction was used. The Playwright workflow is automated and local; every client report still requires human review.

## Phase 8 follow-up (2026-10-18)

This section supersedes earlier statements above where later implementation changed the repository. The canonical Phase 8 review is [phase-8-gap-analysis.md](phase-8-gap-analysis.md), with requirement evidence in [phase-8-requirements-traceability.md](phase-8-requirements-traceability.md).

- `/api/v1/dashboard` now returns typed, tenant-scoped aggregation for persisted clients, assessments, endpoint review state, canonical findings and lifecycle, remediation, retests, executions, reports, recent findings and audit events. Optional UTC date filters use `[start,end)` for sources with creation timestamps. Endpoint inventory is current/all-time because Endpoint has no creation timestamp; this is labeled in the response.
- `/api/v1/audit/events` and `/api/v1/audit/events/{event_id}` provide bounded, access-filtered, sanitized, read-only audit querying. The canonical `ExecutionAuditEvent` table is reused. Client creation now emits a transactionally persisted event. Existing append-only application behavior is not cryptographic tamper evidence.
- The Overview and Activity & Audit pages read actual API data. Date filters, pagination, loading/error/empty states are connected. They do not trigger scans or retests.
- `python scripts/release_gate.py` runs local backend, full pytest, loopback browser E2E, frontend build and temporary SQLite migration checks, and emits machine-readable per-check results. A local pass does not establish deployment readiness.
- The release gate explicitly blocks on a non-production environment, unavailable/skipped tests, KMS/IAM proof, host/VPC egress review, production HTTPS/ingress review, and a production-like restore drill. The dependency advisory query is warned/not run in offline mode. No production environment or data was contacted or changed.

See `docs/phase-8-release-readiness.md` for the latest exact release-gate result. Its final result is **BLOCKED** until all environment-specific checks are verified by an authorized operator.
