# Phase 6 findings, risk analysis, and validation gap analysis

## Scope and disposition

This phase extends the existing Finding record and its audit, deduplication, retest, and immutable report flows. It does not replace historical records or claim that automated observations prove exploitability. Findings remain tenant-scoped and analyst decisions remain attributable to authenticated users.

The local implementation now provides distinct validation, triage, and remediation states; confidence and priority rationales; taxonomy and remediation-guidance provenance; time-bounded observation metadata; scoped correlation keys; summary/filter APIs; a review UI; and report snapshots carrying these fields. Phase 6 still requires operational acceptance and domain-specific policy configuration before it can be called complete: confidence is not statistically calibrated, numerical risk scoring is deliberately disabled until impact/exploitability/business context is configured, and accepted-risk expiry/owner policy is not configured.

## Existing capabilities retained

- Canonical `Finding` rows, the existing triage state machine, optimistic concurrency, tenant checks, and `ExecutionAuditEvent` history.
- Registered-check candidate creation with endpoint/TestRun/check-version provenance and non-destructive duplicate correlation.
- Retest evidence and immutable report version snapshots.
- Secret-redacted evidence serialization and role-gated reviewer decisions.

## Gaps addressed

| Gap | Implementation |
| --- | --- |
| Validation mixed with triage | `validation_state` and rationale with a separate audited reviewer transition API. Confirmation, false-positive, and accepted-risk triage require the matching validation outcome. |
| Priority could be mistaken for severity | Technical severity remains distinct; deterministic P0–P4 review ordering carries rationale and is explicitly not a vulnerability verdict. |
| Unsupported numeric risk claims | `risk_analysis` records model/policy version, factors, limitations, and a null numeric score with a reason. |
| Confidence buried in evidence | First-class confidence and rationale fields are exposed through API, list/detail UI, filters, and reports. Automated registered-check candidates are low confidence until reviewed. |
| Remediation lifecycle conflated with triage | Separate remediation status is set by triage/retest and included in filters, summaries, UI, and reports. |
| Weak list/report visibility | Tenant-scoped filtering, summary counts, stable pagination headers, priority ordering, and expanded report snapshot fields. |
| Observation lineage | First/last observed timestamps and a deterministic assessment-scoped correlation key; duplicate candidates update observation time while preserving original evidence. |
| Legacy rows | Migration preserves original records and maps only explicit legacy states; unknown/unreviewed states remain pending validation. |

## Remaining acceptance work

1. Calibrate confidence against an approved labeled evidence set and document check-specific decision thresholds.
2. Configure approved impact, exploitability, and business-criticality inputs before enabling a numerical risk model.
3. Define accepted-risk owner, expiry, renewal, and escalation policy.
4. Run the migration against each supported production database version and verify report/API compatibility in the deployment pipeline.
5. Obtain reviewer acceptance of the validation policy and taxonomy mapping.

These items are policy or environment-dependent; the implementation does not fabricate their values.
