# Phase 8 dashboard and metrics

## API

`GET /api/v1/dashboard?start_at=<ISO-8601>&end_at=<ISO-8601>` returns a typed `DashboardRead` object. Date filters must include a timezone; values are normalized to UTC and use the half-open interval `created_at >= start_at AND created_at < end_at`. Without filters, all persisted timestamped records visible to the analyst are included.

Metrics include accessible clients and assessments; assessment lifecycle and `WEB_API`/`ANDROID_API`/`BOTH`; current endpoint review state; canonical findings by severity, validation, triage and remediation; open, verified-fixed, validated, rejected and unvalidated counts; accepted-risk and overdue remediation; persisted retest outcome; transport status separately from security outcome; report count/status; recent assessments, findings and sanitized audit events.

Queries use `client_access_filter` before counting or grouping. Findings are counted from the canonical Finding rows exactly once regardless of the number of TestRuns or Retests. Raw TestRun outcomes remain separate from finding validation/triage. An accepted-risk item is represented by the existing triage/remediation labels and excluded from the open count. “Resolved” count means `VERIFIED_FIXED`; accepted risk and rejected/false-positive findings are not claimed as fixed.

Endpoint inventory is a current-state metric and is not date-filtered: the existing Endpoint schema has no creation timestamp. The response identifies this limitation. Empty groupings return `{}` and scalar counts return zero.

## UI

The Overview page uses backend-provided metrics; it no longer computes open finding totals from the client-side finding page. Start/end date controls reload the backend dashboard. End date includes that UTC calendar day. Cards link to existing detail pages. Recent activity is read-only, sanitized audit data; the dashboard does not generate reports, modify remediation, or enqueue tests.

The Activity & Audit page reads the paginated endpoint and supports event type, accessible client/assessment and UTC date filters. It includes loading, error, empty and next/previous page states.

## Known limits

There is no dedicated charting dependency; the overview uses accessible numeric summaries and existing severity bars. No metric claims product effectiveness, vulnerability pass rate or release readiness score. Endpoint discovery timing and a globally authorized identity audit view require future schema/permission decisions.
