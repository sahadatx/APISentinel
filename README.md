# APISentinel

APISentinel is a local, single-workspace API assessment dashboard and API. It organizes client engagements, records scope, imports API specifications, tracks analyst-reviewed findings and retests, supports versioned manual security reviews, and creates immutable JSON/HTML/CSV/PDF report snapshots.

> **Current implementation boundary:** this is an authenticated local assessment workspace, not a comprehensive or client-ready scanner. TestRun can send bounded HTTP requests to an owned assessment's explicitly approved endpoint only when authorization is current and `APISENTINEL_ALLOW_ACTIVE_TESTS=true`; active execution is disabled by default. The registry contains ten bounded read-only HTTP checks across API1–API5 and API8, plus a passive API9 inventory-review snapshot. BOLA and BFLA require two client-provisioned disposable identities and run only on one approved GET endpoint; BOLA additionally requires two existing synthetic object IDs with known owners, and BFLA requires a client-confirmed allow/deny expectation. Only status codes and identity labels/roles are retained; tokens are encrypted, object IDs are encrypted only while jobs are pending or running and discarded at completion/cancellation, and response bodies are not retained. The Coverage page now stores analyst-entered reviews against OWASP Web Top 10:2025, OWASP API Security Top 10:2023, and MITRE CWE Top 25:2025. These controls are manual records, not automated test results; injection payloads, active GraphQL probing, writes, load tests, business-flow mutations, and broad exploit testing are not implemented. Assessment-bound bearer secrets and TOTP seeds support local Fernet in development and AWS KMS envelope encryption in configured deployments. Android APK manifest static observations and iOS IPA `Info.plist` metadata can be parsed in a resource-limited, network-isolated sidecar; application bytes are not retained or executed. These observations are not a full Android/iOS security analysis. MobSF, Frida and device runtime analysis are not integrated. OpenAPI 3.0/3.1, Postman v2.1 and a structured Burp HTTP-history JSON subset can be imported passively. Client-provided GraphQL introspection JSON can be imported as sanitized schema metadata; no GraphQL operation is sent. Arbitrary custom protocols, target crawling, and general web-browser testing are not supported. Use local fixtures or specifically authorized lab/staging targets only.

## Start locally

Requirements: Python 3.11+, Node.js 20+ and npm.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
# For a new disposable/local database only; back up and review an existing DB before migrating it.
alembic upgrade head
apisentinel create-user analyst@example.test
apisentinel serve
```

In another terminal:

```bash
cd dashboard
npm install
npm run dev
```

`npm run dev` reuses a ready local API or starts it on `127.0.0.1:8001`, starts one local queue worker, then starts the dashboard. Keep this terminal open while using the local UI. The worker consumes explicitly queued jobs from the configured database; it does not bypass authorization, endpoint approval, or server execution policy. Browser API calls use the same-origin `/api/v1` path and Vite proxies them to the API, so browser CORS and hostname differences do not break sign-in. For a fresh database, run `alembic upgrade head` before starting the UI. Open <http://127.0.0.1:5174>. API documentation is at <http://127.0.0.1:8001/docs>.

Active HTTP execution remains off unless the operator explicitly sets `APISENTINEL_ALLOW_ACTIVE_TESTS=true` for a controlled, authorized environment. With the default `false` setting, queued jobs are consumed and recorded as `SKIPPED` without sending a request. If `APISENTINEL_API_PROXY` points to another API, run `apisentinel worker` beside that API using its same database configuration; the dashboard dev script intentionally does not start a worker for an external/custom proxy.

The CLI prompts twice for a password and stores only an Argon2id password hash. User provisioning and password resets are local operator actions; there is no public registration, self-service password reset, or administrator bootstrap route. Use `apisentinel reset-password [login]` on the trusted local host to set a new password; it revokes existing sessions and clears login lockout state. It does not disable MFA. Authenticated users can enroll TOTP MFA from Settings when the encryption key is configured; one-time recovery codes are displayed once. Client owners can grant `viewer`, `analyst`, or `reviewer` membership. Existing clients without an owner remain unassigned and hidden until explicitly assigned through controlled database administration.

The SQLite database is created at the configured `APISENTINEL_DATABASE_URL`. For PostgreSQL, set that variable to a suitable SQLAlchemy URL and run migrations. Keep `.env` private. The app defaults to loopback binding and active checks off. Development uses an HttpOnly session cookie with `Secure=false` for plain HTTP on loopback; staging and production require `APISENTINEL_COOKIE_SECURE=true` and HTTPS. Generate a private Fernet-key file with `apisentinel generate-credential-key --path /private/location/apisentinel-credentials.env`; load it through a trusted environment/secret mechanism. Keep the dashboard and API on the same hostname in development so SameSite=Lax cookies work. The default local CORS allowlist includes `http://127.0.0.1:5173` and `http://127.0.0.1:5174`; configure explicit origins only when deployment requires them.

To store bearer credentials, provision a Fernet key in `APISENTINEL_CREDENTIAL_ENCRYPTION_KEY` through a protected secret store. Keep it outside the repository, restrict access, and back it up separately from the database. See [credential management](docs/credential-management.md) for rotation and recovery. The API request rate and concurrency limits use the configured shared database, so all workers for an installation must point to the same database.

## Workflow

1. Create a client and a `WEB_API`, `ANDROID_API`, or `BOTH` assessment. For Android-capable assessments, upload an APK to the isolated manifest parser; the service stores only sanitized metadata and its SHA-256.
2. Record authorization metadata and acknowledge the assessment's exact server-derived scope. A separate analyst review is required before the record becomes active. APISentinel records operator attestations; it does not verify the legal authenticity of the source authorization.
3. Import OpenAPI 3.0.x/3.1.x JSON, Postman Collection v2.1 JSON, the documented structured Burp HTTP-history JSON subset, Browser HAR, Android capture, or a client-provided GraphQL introspection JSON export. Imports are passive; request values/bodies are discarded, GraphQL schema descriptions/default values are not retained, and HTTP endpoints need explicit review and approval.
4. Execute only enabled registered checks for approved endpoints after the authorization and `APISENTINEL_ALLOW_ACTIVE_TESTS` gates pass. The runner currently supports only bounded GET, HEAD, and OPTIONS requests. Active execution is disabled by default.
5. Review candidate findings; an automated observation does not confirm a vulnerability. The read-only registry includes limited BOLA and BFLA comparisons with client-provisioned identities, synthetic objects, and an explicit allow/deny expectation, plus unauthenticated access, sensitive-looking JSON property-name, and one-response rate-limit observations. It does not validate route-wide role policy, data values, or quota enforcement. Use Coverage to save a passive API inventory review and record evidence-backed manual control reviews.
6. Generate a report version and export JSON, HTML, CSV, or PDF. Reports distinguish manual review statuses from automated outcomes. Review scope, methodology, limitations, outcomes, evidence, and coverage before delivery. See the [client API assessment playbook](docs/client-api-assessment-playbook.md) for safe review prerequisites and evidence guidance.
7. Retest only with new evidence from an applicable registered check, or record a clearly labeled manual analyst retest. A transport-only request is not a successful security retest.

For a fully isolated demonstration of login through report export and linked retesting, follow [the local demo workflow](docs/local-demo-workflow.md). It uses a disposable database and loopback fixture, not the configured database or any client target.

For a truthful current service boundary and controlled-pilot gate, see [service scope and pilot checklist](docs/service-scope-and-pilot-checklist.md). GraphQL import behavior is documented in [GraphQL schema import](docs/graphql-schema-import.md).

Security-tool integrations and their verified limits are listed in [tooling capability boundaries](docs/security-tooling-capabilities.md). Mobile artifact handling is documented in [mobile static metadata workflow](docs/mobile-static-analysis-and-ipa-metadata.md) and the staged [dynamic analysis environment](docs/mobile-dynamic-analysis-environment.md), including the Android lab setup script and current device prerequisites. Analyst-entered findings may include a CVSS v3.1 base vector; this is reported separately from validation and technical severity.

## API

All routes use `/api/v1`. The generated OpenAPI spec at `/docs` is the current source of truth. Core routes include `clients`, `assessments`, `discovery/openapi`, `discovery/graphql-schemas`, `discovery/endpoints`, `testing/runs`, `coverage/{assessment_id}`, `findings`, `reports`, and finding retests.

## Database migrations

Alembic migration scripts live in `migrations/`.

```bash
alembic upgrade head
alembic revision --autogenerate -m "describe change"
alembic downgrade -1
```

See [database backup and restore procedures](docs/database-operations.md), [APK import boundaries](docs/android-apk-import.md), [mobile static/IPA metadata boundaries](docs/mobile-static-analysis-and-ipa-metadata.md), [runner egress controls](docs/deployment-egress.md), and [credential/KMS management](docs/credential-management.md). Production requires PostgreSQL, AWS KMS, an explicit runner egress allowlist and the private mobile artifact parser service. PostgreSQL backup/restore and multiprocess verification run in CI against a disposable PostgreSQL service; hosted CI evidence remains pending a CI run.

## Project map

```text
src/apisentinel/     FastAPI API, ORM models, discovery and scope helpers
migrations/          Alembic environment and initial relational schema
dashboard/src/       React/TypeScript dark dashboard
docs/                Architecture, safety, coverage and workflow notes
```

See [docs/roadmap.md](docs/roadmap.md) for implementation status and the remaining phases.

Phase 3 currently uses the shared registry for ten bounded read-only observations across API1–API5/API8 plus a passive API9 inventory snapshot. Results separate transport state, security outcomes, candidate findings, and OWASP API Security Top 10 2023 coverage. This remains a partial suite: injection, rate-limit enforcement, SSRF behavior, business-flow abuse, and unsafe third-party consumption need explicit safe fixtures and policies. See the [Phase 3 traceability](docs/phase-3-requirements-traceability.md), [security-check catalog](docs/phase-3-security-check-catalog.md), and [testing/validation notes](docs/phase-3-testing-and-validation.md).

## Docker

Start the stack with `docker compose up --build`, then provision the first analyst using `docker compose exec api apisentinel create-user analyst@example.test`. The API container runs Alembic migrations before starting the service. The dashboard sends `/api/` requests through nginx to the API on the same origin. Host ports bind to loopback, containers run without root and with dropped capabilities, and API/database writes are limited to the persistent volume. Set the encryption key in the host environment before starting the stack if bearer profiles are needed.
