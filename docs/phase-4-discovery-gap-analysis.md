# Phase 4 API Discovery & Endpoint Inventory — Gap Analysis

## Audit baseline

Repository audit completed before changes. The project already had an assessment-scoped `Endpoint` model, `OpenAPIDocument` import batches, bounded OpenAPI JSON parsing, Postman v2.1/Burp structured history/HAR 1.2/Android capture converters, source provenance, import version reconciliation, audit events, client-access checks, scope validation at endpoint execution approval, a passive import UI, and an execution boundary that only permits explicitly approved safe methods. These components were retained.

The repository has no Git metadata in this checkout. Phase 3 docs and database migrations through `0020_assessment_configuration` were present. Existing database records and API routes were preserved.

## Gaps found and changes made

| Area | Baseline | Phase 4 change |
|---|---|---|
| Endpoint contract | Origin, explicit scope result, API title/version, operation description/deprecation, request/response media types, response schemas, and discovery timestamp were not persisted | Added endpoint metadata and additive migrations `0021_phase4_endpoint_inventory` and `0022_phase4_api_title` |
| Scope classification | Import-time server warnings existed but lacked a stable classification | Imports now record `IN_SCOPE`, `OUT_OF_SCOPE`, `UNRESOLVED`, or `EXCLUDED` plus a reason; imported hosts do not alter assessment scope |
| Deduplication identity | Method/path identity could conflate same path on distinct origins | Canonical reconciliation key now includes assessment (query boundary), method, path, and normalized origin |
| Coverage | No dedicated discovery coverage endpoint | Added assessment-access-checked coverage API with raw import candidate, unique current, historical, source, review, scope, error, and missing-metadata counts |
| Inventory API | Search/method/source/review filters existed | Added validated scope filter; existing pagination and access checks remain |
| UI | Inventory list and basic approve/reject existed | Added scope/review filters, 30-row paging, endpoint detail/provenance/scope reason, API contract metadata, coverage metrics, and explicit coverage caveat |
| Documentation | No Phase 4 requirement docs | Added this analysis, traceability matrix, and API/inventory guide |

## Verified limitations

- OpenAPI input is JSON only. YAML is not claimed as supported; the request envelope and parser currently intentionally use strict JSON.
- Swagger 2.0, XML, GraphQL formats beyond client-provided introspection JSON metadata, browser/Burp formats beyond the documented converters, dynamic crawling, APK reverse engineering, and network discovery are unsupported.
- OpenAPI and traffic imports are passive. They do not fetch servers, resolve remote references, replay requests, execute scripts, or expand authorized scope.
- Endpoint coverage means only records found in supplied files/captures. It cannot prove complete API coverage.
- Request bodies and raw traffic values are intentionally discarded; response schema metadata is retained after safe schema filtering that omits examples/defaults.
- State-changing methods and required path parameters remain inventory-only for the current execution policy.
- Hosted CI, production firewall/eBPF/VPC egress enforcement and external authorization cannot be validated from this local checkout.

## Status

Local Phase 4 implementation requirements are implemented as documented in the traceability matrix. Environment-dependent production validation is **BLOCKED** and unsupported parsers/features remain **NOT_APPLICABLE** to this release. No claim is made that externally hosted validation or complete target API coverage has occurred.
