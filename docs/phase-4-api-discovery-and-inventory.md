# Phase 4 API Discovery & Endpoint Inventory

## Supported sources

| Source | Supported format | Notes |
|---|---|---|
| OpenAPI | JSON OpenAPI 3.0.x and 3.1.x | Local JSON Pointer references only; no remote fetching |
| Postman | Collection v2.1 JSON | Request values, environment values and bodies are not retained |
| Burp | APISentinel's documented structured HTTP history JSON shape | Not every Burp export variant |
| Browser | HAR 1.2 JSON | Sanitized origin/capture metadata only |
| Android | APISentinel Android HTTP capture v1 JSON | Client-supplied traffic; package/version provenance is retained only when supplied |

OpenAPI YAML, Swagger 2.0, XML, GraphQL, arbitrary DevTools/Burp exports, target crawling and APK reverse engineering are not supported by this inventory flow.

## Import and security behavior

Import is assessment-access checked, size and JSON nesting bounded, parsed in-process without outbound requests, and persisted with source hash, import batch and audit attribution. Malformed/unsupported documents return validation errors. Imported server declarations are data only: they neither prove permission nor change assessment scope. Remote `$ref` values are rejected. Examples/defaults and raw request values/bodies are omitted from retained schemas/traffic metadata. Imported requests are never replayed.

## Identity, scope and review

Candidates are grouped by `(assessment_id, normalized origin, uppercase method, path template)`. Host names are IDNA-normalized and lowercase; default HTTP/HTTPS ports are omitted; path case is preserved. Different origins and assessment IDs remain separate. Exact definition hashes coalesce across sources and add provenance. Conflicting definitions remain separate current inventory records so metadata is not silently overwritten; a changed definition from the same source makes its prior record historical and invalidates approval. The system does not collapse path templates with different literal spelling.

Each imported candidate carries `IN_SCOPE`, `OUT_OF_SCOPE`, `UNRESOLVED`, or `EXCLUDED` plus a reason. Only explicit single-server declarations are classified against the existing approved host/path scope. Missing or multiple server declarations remain unresolved. Scope is never expanded from an import. Approval and later execution also revalidate the current authorization and target through existing safety checks. Out-of-scope and excluded candidates cannot be approved.

Review history is recorded in the existing execution audit event stream and read through `GET /api/v1/discovery/endpoints/{endpoint_id}/history`, which enforces client access and returns only whitelisted audit details. Changed endpoint definitions invalidate previous approval. Source provenance records source type, import ID, artifact SHA-256 and sanitized source metadata.

## Coverage definition

`GET /api/v1/discovery/coverage?assessment_id=...` reports raw candidate references across import batches, unique current endpoints, historical endpoint records, current endpoint counts by source/review/scope, reviewed/approved/excluded/out-of-scope/unresolved counts, import warnings, parser errors, and endpoints missing an operation ID or summary. Invalid documents return a structured 4xx and are not persisted as successful import batches, so the coverage API reports zero persisted parser errors; import-time scope/review warnings are counted separately. These are counts of supplied artifacts only, not evidence of complete API coverage.

`GET /api/v1/discovery/endpoints` supports assessment ID, search, method, source, review state, scope status, limit and offset. The UI presents endpoint details, parameters, content types, response schema keys, provenance and scope explanation without exposing raw credentials or payloads.

The synchronous import response includes raw candidate count, unique endpoints, deduplications, rejected/unresolved/out-of-scope/excluded counts, per-scope totals and warning count. Malformed documents produce a structured error and do not create a misleading successful import batch.

## Database

Migrations `0021_phase4_endpoint_inventory` and `0022_phase4_api_title` add endpoint origin, explicit scope result/reason, API title/version, description, deprecated flag, request/response content types, sanitized response schemas and last-discovered timestamp. They are additive. Existing endpoint rows are preserved and receive `UNRESOLVED` plus a revalidation reason; this fails safe and does not grant execution eligibility. No assessment/client data is copied.

## Validation evidence

Commands run for this implementation:

- `pytest -q` — 119 passed, 1 skipped, 1 warning.
- `pytest -q tests/test_openapi_inventory.py` — 20 passed.
- `ruff check src tests` — passed.
- `alembic upgrade head` — applied through `0022_phase4_api_title` to the local SQLite database; `alembic check` — passed.
- `npm run build` in `dashboard/` — passed.
- `python tests/e2e_browser_workflow.py` — passed (authorization/access, inventory approval, registered checks, finding/retest, coverage, report exports).

Hosted CI and production firewall/VPC egress validation remain external and are not represented as completed.
