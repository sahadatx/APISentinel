# Assessment management

## Domain and safety model

An assessment belongs to one client workspace and supports `WEB_API`, `ANDROID_API`, or `BOTH`. A combined assessment may store different descriptive base URLs and API/app metadata under `target_configs.web_api` and `target_configs.android_api`. The existing `AndroidApplication` and import records remain the detailed metadata/inventory source.

Target configuration does not grant permission to test. `allowed_hosts`, `allowed_paths`, excluded paths, permitted methods, authorization record/review, server execution policy, and per-endpoint approval remain separate execution gates. Creating or editing assessment metadata never sends a request.

Only HTTP(S) target URLs without embedded credentials, query, or fragment are accepted; production metadata must use HTTPS. The existing bearer credential profile is assessment-wide and encrypted. The current profile is not source-specific and is not returned by status APIs.

## API

- `POST /api/v1/assessments`: create a draft under a client the analyst may edit.
- `GET /api/v1/assessments`: tenant-filtered list; optional `client_id`, `search`, `assessment_type`, `environment`, `status`, `authorization_status_filter`, `limit` (1–500), and `offset`; `X-Total-Count` reports the accessible result count.
- `GET /api/v1/assessments/{id}`: detail under existing client RBAC.
- `PATCH /api/v1/assessments/{id}`: draft configuration update with `expected_configuration_version`; stale revisions return 409. Changes are rejected while queued/running requests exist. Scope changes cause the existing authorization fingerprint to no longer match.
- `GET /api/v1/assessments/{id}/history`: paginated view of canonical audit events, maximum 200 per page.
- `POST /api/v1/assessments/{id}/archive`: archives without deleting inventory or history; queued/running jobs must first finish or be cancelled.
- Existing authorization, credential, Android metadata, import, endpoint, finding, coverage, and report routes remain in use.

## Audit and history

Creation, configuration edits, and archival use `execution_audit_events`. Configuration events record the revision, changed field names, whether scope fields changed, and the required authorization revalidation; they do not record raw target configuration or credential values. Each test execution already stores its effective policy and now also captures the assessment configuration revision.

## Lifecycle boundary

Assessment records begin in `Draft`. Authorization review state is derived by the existing authorization service and shown separately. The current product has no assessment-level execution job, so the assessment API does not manufacture `Ready`, `Running`, `Completed`, `Failed`, or `Cancelled`. HTTP test jobs retain their own real lifecycle. `Archived` is persisted and prevents later edits or execution.

## Migration and verification

Migration `0020_assessment_configuration` adds description, per-platform target metadata, configuration revision, creator attribution, and `updated_at`. Existing rows receive safe empty/default values and their existing authorization fields are unchanged. The configured local SQLite database was upgraded from `0019` to `0020`.

Verified commands/results for this increment are recorded in the final task report and `docs/phase-3-assessments-requirements-traceability.md`.
