# Phase 4 Discovery Requirements Traceability

Status terms: COMPLETE means implemented and locally verified; PARTIAL means only the documented subset exists; BLOCKED requires external infrastructure/evidence; NOT_APPLICABLE means excluded by the Phase 4 prompt or current product boundary.

| Requirement | Existing implementation / change | Status | Verification |
|---|---|---|---|
| Repository and baseline audit | Existing docs, models, migrations, routes, importers, UI, tests inspected; no `.git` metadata in checkout | COMPLETE | Manual repository audit |
| Assessment-scoped endpoint inventory | `Endpoint.assessment_id`; access-filtered APIs | COMPLETE | `tests/test_auth_isolation.py` |
| OpenAPI 3.0/3.1 JSON parsing | Strict JSON, duplicate-key rejection, size cap, local refs only, bounded schema filtering | COMPLETE | `tests/test_openapi_inventory.py` |
| Swagger 2 / OpenAPI YAML | Not supported; no parser integration claimed | NOT_APPLICABLE | Documented unsupported format |
| Postman v2.1 | Passive converter strips values and records parameter/auth metadata | COMPLETE | `tests/test_openapi_inventory.py` |
| Burp structured history, HAR 1.2, Android capture v1 | Supported converters; no replay; sanitized metadata | COMPLETE | `tests/test_openapi_inventory.py` |
| APK, arbitrary Burp/DevTools variants, GraphQL, XML | Out of scope/unsupported for Phase 4 inventory import | NOT_APPLICABLE | Docs identify supported formats |
| Stable endpoint metadata | Added origin, scope result/reason, API title/version, description, deprecation, request/response content types, response schemas, last discovered | COMPLETE | OpenAPI inventory tests and migration tests |
| URL/origin normalization | IDNA lowercase hostname, default-port removal in traffic imports; no DNS/HTTP calls | COMPLETE | Import tests; same-path different-origin regression |
| Assessment-scoped deduplication/provenance | Reconciliation identity includes method/path/origin within assessment; import/source hashes retained | COMPLETE | Existing idempotency/reimport tests plus origin identity regression |
| Scope enforcement | Imported hosts never modify approved hosts; candidate classification persisted; execution approval still revalidates authorization and target | COMPLETE | Existing scope/authorization regression tests plus classification regression |
| Out-of-scope/excluded approval guard | Server rejects candidates classified out of scope/excluded | COMPLETE | API/inventory suite |
| Review/audit workflow | Existing backend approval route/audit event retained; added access-scoped review-history API and UI details | COMPLETE | API history cross-tenant test and browser E2E |
| Discovery coverage | Added `/api/v1/discovery/coverage`, source/review/scope/error/missing metadata counts and qualification text | COMPLETE | New access/filter test; route verified through API test suite |
| Filtering/pagination/tenant isolation | Validated scope filter added; existing search/method/source/review and pagination retained | COMPLETE | New test plus existing auth isolation suite |
| Frontend inventory/details | Scope and review filters, 30 records per page, detail/provenance, metadata and coverage KPIs | COMPLETE | Dashboard production build and browser E2E where available |
| Parser and execution boundary safety | No network resolution/replay; secrets/examples omitted; authorization rechecked at approval/execution | COMPLETE | Existing security regressions and OpenAPI tests |
| Migration compatibility | Additive `0021_phase4_endpoint_inventory` and `0022_phase4_api_title`; legacy records receive fail-safe unresolved classification | COMPLETE | Alembic upgrade/check and migration test |
| Hosted CI / production egress proof | Requires project remote, hosted CI and target infrastructure evidence | BLOCKED | Not available in this environment |
| Complete API coverage | Imports cannot establish all deployed endpoints | NOT_APPLICABLE | UI/API coverage caveat explicitly states this |

## Test evidence

Exact commands and results are recorded in `docs/phase-4-api-discovery-and-inventory.md` after the implementation run. This matrix must be updated if those results change.
