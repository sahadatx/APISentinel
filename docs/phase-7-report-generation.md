# Phase 7 report generation

## Supported output

The API creates an immutable, synchronous JSON snapshot. It supports JSON, static HTML, CSV, and PDF exports. DOCX, public links, email delivery, and hosted artifact storage are not implemented. Reports are stored in the existing database `reports` table; no separate storage service is used.

## Types and inclusion

`POST /api/v1/reports?assessment_id={id}` accepts a strict `ReportCreate` body:

```json
{
  "report_type": "TECHNICAL",
  "validation_states": ["VALIDATED", "NEEDS_REVIEW"],
  "severities": ["Critical", "High"],
  "include_evidence": true
}
```

Supported types are `EXECUTIVE_SUMMARY`, `TECHNICAL`, `REMEDIATION`, and `RETEST_CLOSURE`. A blank validation filter includes all states except that an executive summary defaults to validated findings only. Blank severity means all severities. Evidence is included by default after canonical secret redaction; it may be omitted. A new request creates a new per-assessment version and never runs a security check.

Each snapshot records its type, inclusion policy, UTC generation timestamp, source revision fingerprint, assessment/client reference, scope/exclusions, authorization state, methodology, coverage, outcomes, findings, remediation data, retests and Android metadata when present. Missing assessment completion dates and unavailable impact facts remain unknown.

## Access and safety

`GET /api/v1/reports` is tenant-scoped and paginated (`limit`, `offset`, `X-Total-Count`, `X-Next-Offset`). `GET /api/v1/reports/{id}` and `/export?format=json|html|csv|pdf` use the same client-role access checks. Generation, detail access, and export create audit events. HTML uses escaped user content, contains no scripts or external resource links, and sets a restrictive Content-Security-Policy. PDF is generated from the same sanitized persisted snapshot using ReportLab (no network resources are loaded), with repeated table headers, page numbers, scope, evidence, limitations, and report version metadata. CSV cells that can be interpreted as formulas are prefixed safely.

Report rows are immutable snapshots; later changes require a new version. The report generator reuses `make_report` and the canonical models and does not store rendered files on disk.
