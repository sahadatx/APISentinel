# Phase 8 dashboard, activity, audit, and release-readiness gap analysis

**Audit date:** 2026-10-18
**Repository:** APISentinel existing implementation
**Disposition:** Local implementation work completed for the gaps listed below. Production release remains **BLOCKED** by environment-specific checks.

## Audit findings before edits

| Area | Existing implementation | Gap found | Phase 8 disposition |
| --- | --- | --- | --- |
| Backend and app entry | FastAPI app and versioned router in `src/apisentinel/main.py` and `api.py` | Existing `/dashboard` returned only totals and recent assessments | **IMPLEMENTED** richer persisted-data metrics; no new domain table |
| Frontend | React/Vite SPA, authenticated shell, Overview and assessment history | Overview calculated open findings from a partial browser payload; no global Activity & Audit page | **IMPLEMENTED** backend metrics, date controls, and audit page |
| Access control | Server-side analyst authentication and client membership/owner predicates | Aggregates and global audit list needed explicit tenant-bound queries | **IMPLEMENTED** client-access predicates for all dashboard and audit queries |
| Audit source | `ExecutionAuditEvent` with actor/client/assessment/run/finding, event, outcome, safe JSON metadata and timestamp | Only per-assessment/per-finding history reads existed; client creation lacked its event | **IMPLEMENTED** paginated `/audit/events`, filters, sanitization and `CLIENT_CREATED` event |
| Remediation/retest | Canonical Finding/Retest rows, Phase 5 queue, Phase 7 reviewer closure and audit events | No summary integration in Overview | **IMPLEMENTED** counts by canonical remediation state and persisted retest outcome |
| Database | Existing migrations through Phase 7; `Endpoint` has no `created_at` field | No Phase 8 schema field was required; endpoint discovery time cannot be filtered | **NOT_APPLICABLE** migration; endpoint metric explicitly remains current all-time inventory |
| Release checks | CI workflow and build/test tooling existed; prior release review documented operational gaps | No machine-readable local release gate | **IMPLEMENTED** offline-safe JSON gate; production-specific evidence remains **BLOCKED** |

## Canonical sources reused

- `Assessment`, `Endpoint`, `Finding`, `Retest`, `TestRun`, and `Report` are authoritative dashboard sources.
- `ExecutionAuditEvent` remains the single audit source. No duplicate event table was added.
- `client_access_filter` is applied in the database query before aggregation, audit filtering, or pagination.
- Remediation and retest remain Phase 7 workflows. Dashboard loading issues no write request and starts no test job.

## Remaining limitations and gaps

- Authentication/session events without a client context are not exposed in the tenant activity feed; there is no existing global audit permission contract to safely authorize those events. No new global role or permission was invented.
- Existing events are append-only through ordinary application APIs, but are not cryptographically tamper-evident against a database administrator.
- Several historical action types have no event because they were not recorded at the time; no historical events are fabricated. New client and assessment lifecycle events continue using the canonical table.
- `Endpoint` records lack a creation timestamp, so endpoint inventory is current/all-time rather than date-filtered.
- The release gate reports KMS/IAM reachability, host/VPC egress rules, production HTTPS/ingress and a production backup restore drill as **BLOCKED** until environment evidence is supplied. It does not contact cloud services or production systems.
- Automated browser E2E for the audit UI and real production TLS, external dependency advisory scans, and production deployment were not performed as part of code implementation.

## Evidence and tests

The final test/build/gate commands and exact results are recorded in [Phase 8 traceability](phase-8-requirements-traceability.md). No production data, client target, external destination, deployment, or configured database migration was used by the Phase 8 work.
