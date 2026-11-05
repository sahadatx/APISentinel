# Phase 8 release readiness

## Local release gate

Run from the repository root:

```sh
python scripts/release_gate.py
```

The command emits one JSON object with schema version, release decision, counts and per-check records (`check_id`, category, `PASS`/`FAIL`/`WARN`/`BLOCKED`/`NOT_RUN`, evidence, explanation, suggested remediation, and `blocks_release`). It runs backend import validation, Ruff, Python compilation, `pytest -q`, loopback-only browser E2E, dashboard production build, and migration upgrade/drift check against a disposable temporary SQLite database. It does not migrate the configured application database, deploy, contact assessment targets, access cloud KMS, or change production data.

Options `--skip-tests`, `--skip-dashboard-build` and `--skip-e2e` exist for diagnostics only; skipped steps are `NOT_RUN` and block release. Pytest skips are separately emitted as NOT_RUN checks and never treated as a pass.

## Gate semantics

No readiness percentage is calculated. Any blocking result other than PASS makes `release_decision` `BLOCKED`. Local automated checks can pass while production readiness remains blocked.

Production-like `APISENTINEL_*` settings are validated without printing credential values. The gate reports environment validation only; it does not prove credentials work or cloud key policy is correct. KMS/IAM reachability, actual host/VPC egress ACLs and target ranges, production HTTPS/ingress, and a production-like backup/restore drill are explicitly BLOCKED until independently verified. Dependency advisory database queries are not attempted by the offline-safe gate and appear as WARN.

## Current result

Latest `python scripts/release_gate.py` run: **release_decision=BLOCKED**; **9 PASS, 0 FAIL, 1 WARN, 5 BLOCKED, 1 NOT_RUN**. The gate process exited nonzero as intended because blocking evidence is outstanding.

Passing checks: backend app import, Ruff, Python compile, backend pytest command (**128 passed, 1 skipped**), local loopback browser E2E, dashboard build, disposable SQLite migration upgrade and Alembic drift check, and the active execution gate being disabled in the supplied local configuration. The one skipped test is the PostgreSQL multiprocess limits/recovery test; the test suite also emitted one existing Starlette TestClient/httpx deprecation warning.

Blocking checks:

- `skipped-tests` — one pytest skipped test was NOT_RUN: PostgreSQL multiprocess limits/recovery requires `APISENTINEL_TEST_POSTGRES_URL` pointing to a disposable PostgreSQL service. It was not counted as a pass.
- `production-config` — current local configuration is development; no production profile was provided.
- `managed-kms-iam` — actual KMS/IAM connectivity and key policy were not checked.
- `host-egress-acl` — production host/VPC egress ACL and approved target ranges were not inspected.
- `backup-restore-drill` — no production-like database restore was performed.
- `production-https` — ingress/TLS/cookie behavior was not exercised in a deployment environment.

Warning: `dependency-advisory-scan` — remote advisory lookup was intentionally omitted by the offline-safe gate. No external service was contacted. The gate output includes command evidence for local checks and keeps environment checks distinct from code/build status. A local build/test pass does not establish production readiness.

## Operations and recovery

Existing database operation and deployment notes remain authoritative: [database operations](database-operations.md), [deployment egress](deployment-egress.md), and [release-readiness gap analysis](release-readiness-gap-analysis.md). Verify backup retention, restore correctness, migration recovery, TLS/cookie/CORS settings, secret-management policy, ingress/egress policy, shutdown behavior, and health/readiness semantics in the actual deployment environment before client data is used.

## Release and operations follow-up (2026-10-19)

The CI workflow now seeds a synthetic audit event in a fresh PostgreSQL backup source and verifies that both the Alembic revision and the persisted audit row survive dump/restore. A local disposable PostgreSQL 16 drill passed with matching-major client tools. See [operations readiness evidence](operations-readiness-evidence.md) for exact boundaries.

The hosted workflow definition is present, but no hosted run was observable from this checkout (no `.git` metadata or GitHub CLI/connection). Production KMS/IAM, deployment secret injection, host/VPC egress ACLs, TLS/ingress, production restore acceptance, and the organization's audit retention period remain unverified or undecided. Application audit history has no purge job and remains append-only through the API; do not claim a retention schedule until the organization approves one.
