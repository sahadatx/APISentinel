# Safe HTTP execution jobs

The async job API queues one explicitly approved `GET`, `HEAD`, or `OPTIONS` endpoint at a time. Import never queues a request. Callers may supply declared path, query, and header parameter values. Values must match the endpoint's imported parameter metadata; reserved headers, undeclared names, control characters, ambiguous path separators, and out-of-scope resolved URLs are rejected. The pure builder performs no network activity. The worker rechecks current authorization, endpoint approval, scope, and destination using the shared Phase 1 runner immediately before transmission.

## API

- `POST /api/v1/testing/jobs` with assessment/endpoint IDs and optional `path_parameters`, `query_parameters`, and `header_parameters` objects, plus a unique `Idempotency-Key` header (8–200 characters). Example: `{ "assessment_id": 1, "endpoint_id": 2, "path_parameters": { "user_id": "abc" }, "query_parameters": { "active": true }, "header_parameters": { "X-Trace": "opaque-id" } }`. The key is stored only as a SHA-256 digest scoped to the analyst and assessment; nonempty parameter payloads are encrypted at rest with purpose `http-job-parameters` and must not be echoed into logs or status responses.
- `GET /api/v1/testing/jobs?assessment_id=1&limit=100&offset=0` lists the caller's jobs.
- `GET /api/v1/testing/jobs/{job_id}` retrieves the sanitized lifecycle state.
- `POST /api/v1/testing/jobs/{job_id}/cancel` cancels queued work or requests cancellation of a running request. The runner checks the cancellation signal while connecting and streaming the bounded response.

States are `QUEUED`, `RUNNING`, a runner outcome such as `COMPLETED` or `BLOCKED_SCOPE`, and `CANCELLED`. Running cancellation is polled by a worker watcher and delivered to the runner while connecting or consuming response bytes. The worker does not retry ordinary failures. An expired worker lease can be reclaimed once; only the read-only methods admitted to the queue can be replayed. A second lease expiry fails the job. Local unit tests cover in-flight cancellation and both recovery branches; a 16-process claim stress test runs against disposable PostgreSQL 16.

Parameter serialization supports scalar values and repeated query values (as arrays). OpenAPI `style`/`explode` serialization variants, request bodies, and state-changing methods are not currently supported. Production host/VPC egress firewall ACLs and hosted GitHub Actions execution require external environment access and are not proven by local tests.

## Start a worker

For a local process, run `apisentinel worker --worker-id workstation-1`. Docker Compose includes a separately constrained `worker` service that uses the same database volume and environment as the API. Start services only after configuring the approved database and network egress policy. The worker has no published port. The Phase 1 runner remains the only HTTP transport path.

Response bodies and credentials are not persisted in job records. Job status, safe response headers, attempt count, and lifecycle audit events are retained.
