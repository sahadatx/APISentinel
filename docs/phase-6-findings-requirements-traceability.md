# Phase 6 findings requirements traceability

| Requirement | Implementation evidence | Verification |
| --- | --- | --- |
| Preserve canonical findings and history | Existing `Finding` and `ExecutionAuditEvent` remain authoritative | `tests/test_finding_lifecycle.py` |
| Separate validation from analyst triage | `PATCH /api/v1/findings/{id}/validation`; reviewer role, transition checks, evidence gates, audit event | Validation lifecycle tests |
| Do not let automation confirm vulnerability | Candidate creation sets pending validation; confirmation requires `VALIDATED` | Lifecycle and queue tests |
| Separate technical severity, confidence, and review priority | `risk_analysis.py`; persisted and serialized fields | Risk policy unit tests |
| Avoid invented numeric score | Null score plus `NOT_SCORED_MISSING_IMPACT_CONTEXT` and explicit limitations | Risk policy unit tests and report schema |
| Track remediation independently | `remediation_status` lifecycle; retest updates state | Lifecycle/retest tests |
| Explain taxonomy/guidance provenance | OWASP categories, taxonomy version, guidance type | API response and report snapshot tests |
| Filter and summarize findings safely | Tenant-scoped `/findings` filters, pagination headers, `/findings/summary` | API authorization/filter tests |
| Display review context and actions | Findings table/detail with validation, triage, remediation, rationale, evidence and audit history | Dashboard build and browser workflow |
| Preserve and correlate repeat observations | Assessment-scoped correlation key; repeated run updates `last_observed_at` | Candidate deduplication tests |
| Carry the complete analysis to exports | Versioned report snapshot includes risk/validation/priority/remediation fields | Report snapshot/export tests |

## Acceptance status

Implementation coverage is present for the requirements above. Phase sign-off remains conditional on migration verification in the supported deployment database, reviewer acceptance, and configuring the domain policies listed in `phase-6-findings-gap-analysis.md`. Unconfigured scoring inputs are represented as unknown and never inferred.
