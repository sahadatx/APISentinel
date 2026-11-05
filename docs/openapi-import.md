# OpenAPI import and endpoint review

## Supported input

The authenticated `POST /api/v1/discovery/openapi` endpoint accepts a JSON envelope containing `assessment_id`, `source`, and a JSON `document`. `source` is `inline_json` (default), `postman_v2.1`, or `burp_http_history`. The entire request is streamed and capped at `APISENTINEL_OPENAPI_MAX_DOCUMENT_BYTES` (1 MiB by default, configurable up to 5 MiB) before the JSON document is fully parsed. Duplicate JSON object keys and non-JSON numeric constants are rejected. YAML and Swagger 2.0 are not supported. The importer supports the structural subset of OpenAPI 3.0.x and 3.1.x needed for endpoint inventory; it is not a full official OpenAPI conformance validator.

### Postman Collection v2.1

Select `postman_v2.1` and provide a Postman Collection v2.1 JSON object with its standard `info.schema` marker and nested `item` arrays. Folder depth and total collection entries are bounded. URLs must be resolved absolute HTTP(S) URLs; unresolved `{{variables}}` and unsafe URL/path forms are rejected. The importer never runs collection scripts, auth helpers, pre-request hooks, or tests. It discards request bodies, parameter values, header values, and examples; it retains endpoint path, method, query parameter names, and an authentication-required signal. Collections are passive inventory only and do not confer target authorization.

### Burp structured HTTP history JSON

Select `burp_http_history` and provide a JSON object with an `items` or `log` array. Each entry must include a structured `request` object (or be the request object) with `method`, absolute `url`, and optional `headers`; alternatively the item may provide `host`, `protocol`, `port`, and `path`. Raw request bytes/base64 exports and arbitrary Burp project files are not supported. The importer discards headers' values, request/response bodies, and query values, and stores only normalized inventory metadata. This intentionally limited format must not be mistaken for support for every Burp export version.

Supported inventory details include paths and standard HTTP operations; path, query, header, and cookie parameters; operation IDs; tags; request-body media types and schemas; declared security requirements; and local `#/...` JSON Pointer references. Local referenced parameter, request-body, and schema definitions are validated and safely summarized. Recursive local schema references are represented with a recursion marker. Remote references, unresolved references, malformed references, malformed path templates, conflicting path templates, duplicate operation IDs, mismatched path parameters, and unsupported specification versions are rejected. The importer never fetches a URL or reference.

Schema examples, defaults, enum values, and other free-form payload values are not retained. Descriptions, summaries, tags, and operation IDs are bounded and common inline credential patterns are redacted. Only parsed inventory fields, the stable SHA-256 content hash, server declarations, and import/change metadata are persisted; the uploaded document is not stored or logged. This does not provide a guarantee against every secret embedded in arbitrary prose, so source documents should still be reviewed before import.

## Server declarations and scope

OpenAPI `servers` are treated as untrusted metadata. Absolute server URLs are parsed without DNS resolution or network access. Userinfo, query strings, fragments, invalid ports, malformed paths, and encoded paths are rejected. A server's scheme, host, port, and base path are checked against the assessment's current scope and runner policy. Relative server URLs and server-variable templates are outside the supported subset.

Server declarations never alter `Assessment.allowed_hosts`, path scope, ports, or allowed methods. A single in-scope server can contribute its base path to the stored endpoint representation if the composed path remains in scope. Multiple declarations, out-of-scope hosts/ports/schemes, server templates, or path mismatches produce review issues; the endpoint remains unapproved and its usable server base path is cleared. An analyst can explicitly approve or reject with a reason. Even after acknowledgement, the runner builds the request host from the assessment's approved host list and revalidates the composed endpoint path, destination, DNS answers, and redirects immediately before transmission.

Percent-encoded paths, encoded separators, dot segments, backslashes, query strings embedded in path keys, and malformed braces are rejected to avoid normalization ambiguity. The assessment path scope is not widened by an import.

## Endpoint lifecycle and re-import

New safe-method endpoints begin `IMPORTED`; endpoints with server review issues begin `NEEDS_REVIEW`; methods outside GET, HEAD, and OPTIONS are retained as inventory-only `REJECTED` records. No import starts a request. An analyst must explicitly approve or reject each current endpoint through the authenticated endpoint review route with a reason. Approval also requires the assessment's authorization confirmation/reference and an endpoint target that validates against the current scope. The global `APISENTINEL_ALLOW_ACTIVE_TESTS` gate remains separate.

Every imported definition has a SHA-256 fingerprint over the operation, path-level details, local-reference targets, security scheme definitions, and effective server declarations. A content hash identifies the canonical JSON document. Re-importing the same definition reuses the existing endpoint and does not change its decision. A changed or removed definition supersedes the old record, clears its execution approval, marks it `REJECTED` and not current, records the analyst and time that invalidated it, creates an audit event, and creates a fresh unapproved row when applicable. Import records retain version hash, actor, server declarations, endpoint IDs, issues, and added/changed/unchanged/removed counts.

Legacy endpoints are migrated to `NEEDS_REVIEW`, remain linked to no invented import, and are not automatically approved. Review/import audit events are stored in `execution_audit_events`, which has no ordinary analyst update route; database administrators can still alter database records.

## Limits

This workflow does not support Swagger 2.0, YAML, webhooks, callbacks, external references, remote schema resolution, server URL templates, full OpenAPI schema validation, or every OpenAPI extension. It does not validate target reachability, credentials, or endpoint behavior. HTTP transport completion remains a transport outcome, not a vulnerability result. APISentinel remains a local assessment workspace.
