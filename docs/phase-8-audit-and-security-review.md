# Phase 8 audit and security review

## Canonical audit model

`ExecutionAuditEvent` is reused with the existing actor/client/assessment/TestRun/Finding references, event type, outcome, sanitized metadata and timestamp. Events are created in the same database transaction as their corresponding changes in covered paths. Client creation now writes `CLIENT_CREATED`; assessment creation/update/archive and the existing endpoint, authorization, execution, finding, remediation, retest, and report paths already emit their events. No new audit model or migration was needed.

## Read API

`GET /api/v1/audit/events` is analyst-authenticated and read-only. Filters: timezone-aware `start_at`/`end_at` in UTC, actor ID, event type, outcome, accessible client ID, accessible assessment ID, and a target type/ID pair (`client`, `assessment`, `test_run`, `finding`). `limit` is bounded to 1–200; `offset` is nonnegative. Client and assessment filters are independently authorized; the query itself is also joined through accessible clients before pagination. Cross-tenant resources return 404. `GET /api/v1/audit/events/{event_id}` provides the same sanitized, tenant-scoped event detail. Metadata is sanitized recursively before serialization.

The audit endpoint has no create, update, delete, or export route. The dashboard's recent activity uses the same sanitized data source and accessible-client predicate. Audit reads do not recursively create more audit rows.

## Security and limitations

- Application users cannot modify/delete audit rows through ordinary API routes.
- This is append-only by application behavior, not cryptographically tamper-evident against direct database/filesystem administrators. There is no hash chain or external immutable sink.
- Authentication/session events without a client context are not included. The existing role contract has no global audit permission; the implementation does not invent one or expose global identity activity to every tenant user.
- Historical activity is not reconstructed. Missing historical events remain missing.
- Sanitization redacts known credential-shaped fields and embedded secret patterns; arbitrary prose can still contain sensitive data. Callers must keep metadata allowlisted and avoid raw request/response bodies.
- Storage failures during action and audit persistence remain in the same transaction for covered paths; the action does not return success when that commit fails.

## Review evidence

Tenant isolation, metadata redaction, bounded pagination, invalid date order, client/assessment authorization, and read-only behavior have dedicated tests in `tests/test_auth_isolation.py`. Database-level tamper resistance, production retention, remote log delivery, and global authentication event visibility remain unverified/out of scope.
