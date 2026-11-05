# Strict-Transport-Security registered check

## Contract

- **Identifier/version:** `response.header.strict_transport_security` v1.0.0.
- **Purpose:** observe the `Strict-Transport-Security` header on one successful, final HTTPS response from a currently approved endpoint.
- **Execution:** server-registered GET only; authenticated assessment owner, recorded authorization, endpoint execution approval, the active-test server gate, and the existing bounded/scope-aware runner are still required. Import or approval never executes a request.
- **Data observed:** final scheme, status code, and the allowlisted HSTS header value. The evaluator never reads the response body. The shared runner still performs its normal bounded read and records only retained-byte count, not body bytes.

## Parsing and outcomes

Header-name matching is case-insensitive. Only final `2xx` HTTPS responses are interpreted. Directives are split on semicolons, trimmed, and directive names are case-insensitive. Exactly one decimal `max-age` is required. Its value is limited to 20 decimal digits by this parser. Duplicate directives, duplicate field values, comma-combined values, empty/malformed directives, invalid tokens, a valued `includeSubDomains`/`preload`, missing or invalid `max-age`, and unsupported numeric range are inconclusive. Unknown syntactically valid extension directives are ignored. A positive `max-age` produces `NO_ISSUE_OBSERVED`; `max-age=0` produces a low-confidence candidate because it disables stored HSTS for the host. An absent header on a final successful HTTPS response produces a low-confidence candidate. Any final HTTP response, non-2xx response, or missing status is `INCONCLUSIVE`. Blocked/skipped/cancelled/auth-unavailable transport is `NOT_RUN`; transport errors, timeouts, oversized or incomplete responses are `ERROR`.

The runner's existing redirect policy evaluates the final response only; every redirect is independently scope/destination checked. A blocked redirect yields no security conclusion. No new redirect or transport behavior is introduced by this check.

`includeSubDomains` and `preload` are recorded when present but are not required for a positive observation. Whether to use them, and what `max-age` meets policy, depends on subdomain readiness, organizational requirements, and deployment context. This check does not establish browser acceptance, certificate quality, HTTPS availability across routes, downgrade exploitability, preload eligibility, or overall policy compliance.

## Evidence, findings, retests, and coverage

Evidence is limited to the final scheme, status, HSTS value and parsed directives, passed through the existing evidence sanitizer. An absent header or zero age may create a low-confidence candidate using the existing finding and audit path; repeated active observations use the existing duplicate suppression. The check does not confirm or resolve findings. Retesting uses existing same-assessment, same-endpoint, registered-test/version and current-definition provenance rules; transport completion by itself cannot establish a successful retest. A newer applicable HSTS run with `NO_ISSUE_OBSERVED` is still a single-response observation, not proof of remediation across the deployment.

Security-check coverage plans HSTS only when the server-derived target for the current approved endpoint is HTTPS. `INCONCLUSIVE`, `NOT_RUN`, `ERROR`, disabled checks, and HTTP-inapplicable endpoints do not increase completed security-test coverage. HTTP transport coverage remains separate.
