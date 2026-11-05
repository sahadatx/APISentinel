# Phase 3 testing and validation

All networked tests use loopback fixtures; no public, customer, internal infrastructure, cloud metadata, or third-party target was used.

## Baseline before this increment

- Command: `pytest -q`
- Result: **107 passed, 1 skipped**, one Starlette/httpx deprecation warning, 31.16 seconds.
- Skip: environment-gated PostgreSQL validation.

## Focused coverage

- `tests/test_test_registry.py`: registry metadata, fail-closed lookup, response header interpretation, Set-Cookie value removal, CORS/session-cookie observations, bounded verbose-error indicator, and six-state classification.
- `tests/test_runner.py`: reviewed scope, pinned DNS, redirect and destination restrictions, request limits, cancellation, TLS, and per-check time/response/redirect caps.
- `tests/test_execution_integration.py`: authenticated local owner/reviewer flow, imports, authorization, endpoint approval, execution, candidate/dedup/triage, cancellation, audit, evidence privacy, coverage and reports.
- `tests/e2e_browser_workflow.py`: local browser workflow; Playwright is an optional dependency and availability must be reported.

## Final commands and results

These are historical results from the earlier repository revision, before the current API1/API5 identity workflows and migrations 0030–0031. They are not verification of the current increment; the historical browser flow reported API1 as uncovered because the BOLA workflow had not yet been implemented.

- `pytest -q`: **114 passed, 1 skipped**, one Starlette/httpx deprecation warning, 30.35 seconds.
- Focused regression `pytest -q tests/test_test_registry.py tests/test_runner.py tests/test_execution_integration.py`: **39 passed**, one deprecation warning.
- `ruff check src tests`: **passed**.
- `alembic check`: **passed**, no new upgrade operations detected.
- `npm run build` in `dashboard/`: **passed** (`tsc -b` and Vite production build).
- Browser E2E `python tests/e2e_browser_workflow.py`: **passed**. Verified auth/ownership, passive inventory and approval, both enabled registered checks, candidate triage, compatible retesting, coverage (including an explicitly uncovered API1 category), and JSON/HTML report exports against isolated loopback fixtures.

## Limits of local verification

A passing local suite cannot prove live AWS KMS/IAM behavior, host/VPC egress controls, multi-host production recovery, hosted CI execution, or authorization to test any real application. Those remain external deployment/release gates. The new verbose-error test uses synthetic response bytes and proves only the implemented signature logic and redaction behavior.
