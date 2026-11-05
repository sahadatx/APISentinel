# First registered check: detection rules and limits

`response.header.content_type_options` v1.0.0 examines only the final response metadata returned by the bounded runner. It does not inspect response bodies, browser behavior, or exploitability.

## Outcome rules

- A completed 2xx response with exactly one supported `Content-Type` (`text/html`, `application/xhtml+xml`, `application/json`, or `text/plain`) and exactly one case-insensitive `X-Content-Type-Options: nosniff` value produces `NO_ISSUE_OBSERVED` for that response only.
- The same supported 2xx response with the security header absent produces a low-confidence `CANDIDATE_FOUND`. This is an observation, not proof of a vulnerability.
- Unsupported/missing media types, duplicate or comma-combined relevant headers, unexpected security-header values, missing status codes, and non-2xx responses produce `INCONCLUSIVE`.
- Redirects are handled by the runner first. A permitted redirect is evaluated only at its final response. A blocked redirect produces no security conclusion; transport timeout, error, cancellation, or size-limit outcomes cannot become a candidate or clean result.
- Header names are compared case-insensitively. Only allowlisted response metadata is retained; body content, cookies, and credentials are not check evidence.

## Duplicate candidate policy

For the same assessment, endpoint, check ID/version, and endpoint-definition hash, an existing finding other than `Resolved` or `Closed` suppresses a duplicate candidate. The original finding and evidence remain unchanged. The new TestRun is preserved and linked to the existing finding through `SECURITY_CANDIDATE_DUPLICATE_SUPPRESSED` in the canonical audit stream. A new observation after resolution or closure may create a new candidate. A changed endpoint definition is a distinct observation.

## Reporting and limitations

Versioned JSON and HTML reports include transport and security outcomes separately, check purpose/limitations, analyst finding state, and retest outcome/provenance. Candidate status is not analyst confirmation. `NO_ISSUE_OBSERVED` is not proof of absence across other responses or routes. No browser exploitability testing is performed. CSV remains a finding-row export and does not represent execution coverage.
