# Phase 5 API Security Testing Gap Analysis

## Status

**Historical snapshot, superseded in part by the current Phase 3/5 catalogs.** The earlier audit found no identity/ownership oracles. The current implementation adds a narrow status-only BOLA/BFLA workflow with encrypted disposable identities and client-provided synthetic data/role expectations. The Phase 5 definition of done is still **PARTIAL**: token lifecycle, property authorization, injection, SSRF, rate-limit enforcement, and business-flow checks remain manual or uncovered.

## Existing capabilities reused

| Area | State | Existing implementation |
| --- | --- | --- |
| Assessment and endpoint inventory | COMPLETE | `Assessment`, `Endpoint`, import provenance and scope classification in discovery |
| Authorization and endpoint approval | COMPLETE | Reviewed authorization records and endpoint execution approval |
| Bounded HTTP runner | COMPLETE | Scope revalidation, DNS/IP restrictions, redirect checks, TLS verification, cancellation hook, request/time/response limits |
| Registered checks | PARTIAL | Ten narrow read-only checks across API1–API5/API8; all use the bounded runner |
| Results and findings | PARTIAL | `TestRun`, sanitized metadata, audit events, candidate finding lifecycle and coverage integration |
| Frontend | PARTIAL | Catalog, endpoint selection, queued one-check execution, outcomes, history, coverage and job cancellation |
| Assessment-level orchestration | MISSING | No profile/assessment-wide execution plan or multi-check job lifecycle |
| Registered-check cancellation | PARTIAL | Explicit one-check runs can use the existing durable queue and cancellation flow; synchronous compatibility endpoint remains available |
| Controlled auth/ownership fixtures | PARTIAL | Encrypted assessment-bound identities and client-supplied synthetic objects/role expectation support one-endpoint GET comparisons; no token lifecycle or property policy model |
| Hosted CI / production validation | BLOCKED | Requires configured hosted CI and an authorized production environment; not run here |

## Changes in this implementation

- Evaluator exceptions and malformed evaluator output now become a safe `ERROR` check outcome. They do not alter the independent transport status, create a candidate finding, or expose exception text.
- Check results validate outcome type, JSON-safe evidence, a 64 KiB evidence cap, and bounded result text. The API sanitizes the result before persistence.
- Endpoint URL construction uses the imported server origin only when the endpoint is explicitly `IN_SCOPE`, preventing the previous fallback to the first assessment host for multi-server imports. The normal approval validator and runner still revalidate target scope.
- Registered checks can now be explicitly queued in the existing persistent HTTP job queue. The worker revalidates check enablement, assessment type, method, authorization and endpoint approval, applies check budgets, evaluates with isolated errors, stores redacted results, links candidate findings, and supports the queue's active cancellation path. The Security Testing UI now queues checks and offers cancellation while queued/running.

## Remaining blockers and risks

- BOLA/BFLA support only one-endpoint GET comparisons. Authentication token lifecycle, property authorization, injection, rate-limit enforcement, SSRF and business-logic tests require additional policy oracles and target-side fixtures.
- The existing synchronous `/testing/runs` compatibility route cannot be cancelled after dispatch. The UI uses the cancelable queue path; clients that call the synchronous route directly retain this limitation.
- Assessment-wide profiles, batch execution budgets, and partial multi-check recovery remain unimplemented.
- API1–API5/API8 have narrow registered checks and API9 has a passive inventory review. API6, API7 and API10 remain manual or uncovered; no category is fully tested.
- Full UI/browser E2E, hosted CI, production egress and recovery drills are not evidenced by this local code change.

## Baseline and verification

The verification records below are historical results for an earlier revision and do not cover the later API1/API5 identity workflows or migrations 0030–0031. Those latest changes were not tested or built in the current task.

- Baseline before edits: `pytest -q tests/test_test_registry.py tests/test_runner.py tests/test_execution_integration.py` — **42 passed**.
- Focused queue/execution suite: `pytest -q tests/test_job_queue_recovery.py tests/test_execution_integration.py tests/test_test_registry.py` — **15 passed**.
- Full suite: `pytest -q` — **121 passed, 1 skipped**.
- Lint: `ruff check src/apisentinel/api.py src/apisentinel/job_queue.py src/apisentinel/test_registry.py src/apisentinel/schemas.py tests/test_execution_integration.py tests/test_job_queue_recovery.py tests/test_test_registry.py` — **passed**.
- Dashboard build: `npm run build` from `dashboard/` — **passed**.
- Hosted CI, browser E2E, production egress, database stress and recovery drills were not run.
- One Starlette/httpx deprecation warning remains; one pre-existing test is skipped.
- Hosted CI, browser E2E, production egress, database stress and recovery drills were not run.
