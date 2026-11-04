# Phase 5 Execution Safety

## Request path

An analyst explicitly chooses a currently approved endpoint and an enabled registered check. The API verifies assessment ownership, assessment-type applicability, active authorization, endpoint approval/current inventory, allowed method, and required-parameter support. The check supplies only its registered method and budget; all network access goes through the shared runner.

The runner revalidates target scope at request time, resolves and constrains destination addresses, verifies TLS, applies timeout/response/request/concurrency limits, and revalidates every redirect before following it. Local HTTP is restricted to explicitly configured lab use. Importing an endpoint does not execute it.

Imported server origins are now used only for endpoints classified `IN_SCOPE`; the approval path and runner validate the derived target again. Invalid origins fail closed. Legacy endpoints without an origin use the assessment's approved host configuration.

## Result handling

Transport status and check outcome are independent. Evaluator errors map to `ERROR`, never PASS or a candidate finding. Evaluator exception details are discarded. Evidence must be JSON-safe and at most 64 KiB; output is passed through evidence sanitization before database persistence. Check result text is bounded. Existing runner behavior avoids storing response bodies and raw cookie values.

`FAIL` is an assertion result, not a confirmed vulnerability. Current candidates enter the existing analyst review lifecycle with informational severity. `INCONCLUSIVE`, `ERROR`, `BLOCKED`, and `NOT_APPLICABLE` do not count as passing coverage.

Registered checks selected in the Security Testing UI are persisted as `TestRun` jobs in the existing queue. Workers revalidate authorization and endpoint state, use check-specific limits, isolate evaluator errors, persist sanitized results, and link candidate findings. The existing cancellation endpoint works for these queued/running check jobs. No second queue or result table was introduced.

## Operational limitations

- The synchronous `/testing/runs` compatibility endpoint still has no in-flight cancellation. The dashboard uses the queued route.
- The queue executes one explicitly selected check per endpoint. Assessment-level profiles and batch-wide budgets/recovery are not implemented.
- Do not expand to multi-endpoint profiles until check-run state, cancellation, total-assessment budgets, and partial result persistence are implemented.
- Do not add identity or injection checks until authorized test identities, owned fixtures, and expected outcome oracles are configured.
- Never use public targets in automated tests. Current verification uses a local mock server and unit fixtures.
