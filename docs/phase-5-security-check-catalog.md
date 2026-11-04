# Phase 5 Security Check Catalog

The runtime source of truth is `src/apisentinel/test_registry.py`; this page summarizes current checks. All checks are explicit, server-registered checks and use the approved bounded runner through the durable queue. A candidate is not a confirmed vulnerability.

| Check ID | Category / OWASP | Inputs and applicability | Observation and limits |
| --- | --- | --- | --- |
| `authorization.bola.synthetic_pair` | Authorization / API1:2023 | Approved GET endpoint, two encrypted disposable identities, two existing synthetic object IDs, and a declared path parameter | Four status-only comparisons cover two own-object controls and two cross-identity reads on this endpoint only. |
| `authentication.unauthenticated_access` | Authentication / API2:2023 | Approved GET/HEAD endpoint explicitly marked auth-required | Sends one unauthenticated request and records status only; does not test login, token lifecycle, recovery, or lockout. |
| `authorization.sensitive_property_observation` | Authorization / API3:2023 | Approved unauthenticated GET returning bounded JSON | Records fixed sensitive-property categories, never values or raw property names; does not prove disclosure or property authorization. |
| `resource.rate_limit_observation` | Resource consumption / API4:2023 | Approved GET/HEAD endpoint; one ordinary response | Records quota-header names and 429 status; always inconclusive and sends no repeated requests. |
| `authorization.function_role_pair` | Authorization / API5:2023 | Approved GET endpoint, two encrypted disposable identities, client-declared allowed identity | Sends two status-only requests to one endpoint; does not infer roles or test other routes or mutations. |
| `response.header.cors_policy` | Misconfiguration / API8:2023 | Approved unauthenticated endpoint; documented supported method and one request | Flags only the narrow wildcard-origin plus credentials combination; browser origin/context is not fully modeled. |
| `response.cookie.session_flags` | Misconfiguration / API8:2023 | Endpoint response with cookie metadata; no raw cookie value retained | Checks observed cookie flags from runner metadata only; cannot prove session-cookie identity or full route coverage. |
| `response.header.content_type_options` | Misconfiguration / API8:2023 | Successful 2xx response with supported media type | Missing `nosniff` is a low-confidence candidate; does not establish browser exploitability. |
| `response.header.strict_transport_security` | Misconfiguration / API8:2023 | Successful final HTTPS response | Parses one HSTS header; does not test browser, certificate, subdomain readiness, preload, or policy requirements. |
| `server.error.verbose_exception` | Misconfiguration / API8:2023 | Controlled 5xx response preferred; examines at most 65,536 bytes | Stores signature names and bounded metadata only, never raw response text; signatures are indicators, not proof. |

All current checks declare Web API, Android API and combined assessment applicability in metadata. That shared engine support does not mean APK internals, device storage, pinning, or mobile runtime behavior are tested.

## Remaining checks that need controlled oracles

The BOLA/BFLA entries above cover only explicit, client-provided read-only oracles. Token lifecycle, route-wide and property-level authorization, SQL/NoSQL/command/template injection, mass assignment, SSRF confirmation, rate-limit threshold behavior, and business-flow checks remain manual or uncovered. They are not represented as passing checks or dispatched.

## OWASP API Security Top 10 review catalog

`src/apisentinel/owasp_check_catalog.py` is the source for per-category review specifications exposed in the assessment coverage response. Each category has a stable review-check ID, mode, prerequisites, expected behavior, and a safety boundary. API1–API5 and API8 link to narrow registered observations; API9 has a separate passive imported-inventory review. API6, API7, and API10 remain manual-only. Manual-only entries never appear as runnable checks in Security Testing and do not contribute to the registered-check coverage percentage.

For BOLA (API1), the client supplies two encrypted disposable identities and existing synthetic records with known owners. For BFLA (API5), the client designates which identity is allowed for the endpoint. Migrations 0030–0031 persist passive inventory snapshots and encrypted identity profiles; tokens are never returned, and object IDs and response bodies are not retained.

Coverage UI shows these specifications alongside actual registered outcomes. A manual specification or missing prerequisite is not an automated test result and never counts as passed or executed.
