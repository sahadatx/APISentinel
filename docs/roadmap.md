# Implementation status

APISentinel is a local API assessment workspace, not a comprehensive scanner or client-ready service. The following status is based on the current code and local test workflow; it is not a security certification.

## Implemented and locally exercised

- FastAPI/SQLAlchemy/Alembic backend and React/TypeScript dashboard with analyst login, owner-managed client memberships, and `viewer`/`analyst`/`reviewer` permissions.
- Scope-bound authorization record lifecycle: `REVIEW_REQUIRED`, `RECORDED`, `ACTIVE`, `SCHEDULED`, `WINDOW_CLOSED`, `EXPIRED`, and `REVOKED`; configured testing windows gate execution. Legacy Boolean/reference values are preserved but cannot authorize execution.
- OpenAPI 3.0.x/3.1.x, Postman Collection v2.1, and structured Burp HTTP-history JSON import, endpoint inventory review, explicit endpoint approval, and source-specific import versioning.
- Bounded HTTP runner with per-request scope/destination checks, TLS verification, manual redirects, response/time caps, and distinct transport outcomes.
- Ten narrow read-only registered checks share one scope-gated engine across API1–API5/API8; API1 BOLA and API5 BFLA comparisons use encrypted disposable identities, synthetic records, and client-declared expectations. The API9 inventory review is passive. The newly added identity workflows have not been tested in this task.
- Candidate finding review, canonical audit events, evidence-linked retesting, separate automated/manual coverage, JSON/HTML/CSV/PDF report exports, and integrity-checked non-overwriting SQLite backup/restore commands.
- Version-pinned analyst review checklists for OWASP Web Top 10:2025, OWASP API Security Top 10:2023, and MITRE CWE Top 25:2025. Reviews are stored with status, notes, evidence references, actor, and an optional linked finding; reports snapshot these records separately from automated outcomes.
- TOTP MFA supports one-time recovery codes and account login throttling; authorization activation requires a separate reviewer except for an explicitly acknowledged sole-member self-review. A local Playwright workflow exercises the end-to-end owner/reviewer flow against loopback fixtures. Run `python tests/e2e_browser_workflow.py`.

## Remaining Phase 1 validation and product gaps

- Authorization evidence upload stores a PDF SHA-256, sanitized filename and size, then discards bytes. Reviewers can compare a separately obtained document. Signer identity and legal authenticity remain human-verified; no evidence vault or digital-signature verification exists.
- AWS KMS envelope encryption is implemented, but live cloud KMS/IAM/workload identity validation needs a configured AWS environment. Production also needs host/VPC egress firewall rules; runner CIDRs are application-layer enforcement only.
- APK manifest parsing runs in a bounded, non-root, network-isolated container. It does not verify publisher signatures, device provenance, or app behavior; isolation shares the host kernel.
- PostgreSQL multiprocess rate reservations and 16-process queue claims were validated locally against disposable PostgreSQL 16; the workflow also runs migration and dump/restore checks, but hosted CI has not run in this workspace. True multi-host fault injection and restored-service acceptance still need deployment infrastructure.
- Phase 3 remains partial: ten bounded read-only observations cover narrow API1–API5/API8 signals and a passive API9 inventory review is persisted. BOLA/BFLA only compare two client-provisioned identities on one approved GET endpoint; object-property access, injection, rate-limit enforcement, SSRF behavior, and business logic remain uncovered or manual. See the [Phase 3 traceability](phase-3-requirements-traceability.md) and [check catalog](phase-3-security-check-catalog.md) for the exact implementation boundaries and fixture prerequisites. Password reset, global administrator/user lifecycle, session administration, and audit retention/tamper evidence also remain absent.
- The suite imports client-provided GraphQL introspection JSON as sanitized offline schema metadata, but does not execute GraphQL operations or test GraphQL authorization. Arbitrary custom protocols and browser-based web application checks, XSS/SQLi payloads, fuzzing, writes, rate-limit stress, and business-flow mutations remain unsupported. Manual checklists record analyst work but do not implement those dynamic tests.
- Browser DevTools export formats and raw Burp XML are unsupported; imported traffic has no verified mobile app/device provenance. PDF rendering is implemented; human QA and controlled delivery remain necessary. NDA signature/execution is an engagement process outside this application.
- Production deployment, operational firewall configuration, live KMS validation, hosted-CI evidence, an administrator-run recovery drill against a restored PostgreSQL service, an operational runbook, and an authorized pilot review are still required.

Use [the local demo workflow](local-demo-workflow.md) to validate the current narrow product behavior. Do not use it to test public or client targets or describe it as a full API penetration test.
