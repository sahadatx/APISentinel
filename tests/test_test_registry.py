from apisentinel.runner import RequestOutcome, RunnerResult
from apisentinel.test_registry import (
    REGISTRY,
    ExecutionClassification,
    SecurityOutcome,
    classify_execution,
    enabled_test_ids,
    public_registry,
    resolve_test,
)

TEST_ID = "response.header.content_type_options"
HSTS_ID = "response.header.strict_transport_security"
ERROR_DISCLOSURE_ID = "server.error.verbose_exception"


def test_registry_is_typed_and_disabled_or_unknown_checks_fail_closed():
    assert TEST_ID in REGISTRY
    definition = resolve_test(TEST_ID, configured=TEST_ID)
    assert definition.version == "1.0.0"
    assert definition.passive is False
    assert definition.supported_methods == ("GET",)
    hsts = resolve_test(HSTS_ID, configured=HSTS_ID)
    assert hsts.required_scheme == "https"
    disclosure = REGISTRY[ERROR_DISCLOSURE_ID]
    assert disclosure.max_requests == 1
    assert disclosure.max_response_bytes == 65_536
    assert disclosure.owasp_categories == ("API8:2023",)
    assert disclosure.platforms == ("WEB_API", "ANDROID_API", "BOTH")
    assert next(item for item in public_registry(HSTS_ID)
                if item["identifier"] == HSTS_ID)["enabled"] is True
    assert enabled_test_ids("") == set()
    assert public_registry("")[0]["enabled"] is False
    try:
        resolve_test(TEST_ID, configured="")
    except PermissionError:
        pass
    else:
        raise AssertionError("Disabled test unexpectedly resolved")
    try:
        resolve_test("user-supplied-code", configured=TEST_ID)
    except KeyError:
        pass
    else:
        raise AssertionError("Unknown test unexpectedly resolved")


def test_check_result_rejects_unbounded_or_non_json_evidence():
    import pytest

    from apisentinel.test_registry import CheckResult

    with pytest.raises(ValueError, match="JSON-safe"):
        CheckResult(SecurityOutcome.INCONCLUSIVE, {"bad": object()}, "x", "y")
    with pytest.raises(ValueError, match="64 KiB"):
        CheckResult(SecurityOutcome.INCONCLUSIVE, {"data": "x" * 70_000}, "x", "y")
    with pytest.raises(TypeError, match="outcome"):
        CheckResult("SUCCESS", {}, "x", "y")


def test_header_check_has_truthful_positive_negative_inconclusive_and_error_outcomes():
    check = REGISTRY[TEST_ID].evaluate

    candidate = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                   headers={"content-type": "text/html; charset=utf-8"}))
    assert candidate.outcome is SecurityOutcome.CANDIDATE_FOUND
    assert "does not prove" in candidate.limitation
    assert candidate.evidence["response_headers"]["x-content-type-options"] is None

    no_issue = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                  headers={"content-type": "text/html", "x-content-type-options": "nosniff"}))
    assert no_issue.outcome is SecurityOutcome.NO_ISSUE_OBSERVED

    case_insensitive = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                          headers={"Content-Type": "text/html", "X-Content-Type-Options": "NoSnIfF"}))
    assert case_insensitive.outcome is SecurityOutcome.NO_ISSUE_OBSERVED

    incorrect = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                   headers={"content-type": "text/html", "x-content-type-options": "nosniff; invalid"}))
    assert incorrect.outcome is SecurityOutcome.INCONCLUSIVE

    duplicate = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                   headers={"Content-Type": "text/html", "content-type": "application/json",
                                            "x-content-type-options": "nosniff"}))
    assert duplicate.outcome is SecurityOutcome.INCONCLUSIVE

    combined_duplicate = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                            headers={"content-type": "text/html",
                                                     "x-content-type-options": "nosniff, nosniff"}))
    assert combined_duplicate.outcome is SecurityOutcome.INCONCLUSIVE

    non_success = check(RunnerResult(RequestOutcome.COMPLETED, status_code=404,
                                     headers={"content-type": "text/plain"}))
    assert non_success.outcome is SecurityOutcome.INCONCLUSIVE
    missing_status = check(RunnerResult(RequestOutcome.COMPLETED,
                                        headers={"content-type": "text/plain"}))
    assert missing_status.outcome is SecurityOutcome.INCONCLUSIVE

    inconclusive = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                      headers={"content-type": "application/octet-stream"}))
    assert inconclusive.outcome is SecurityOutcome.INCONCLUSIVE

    error = check(RunnerResult(RequestOutcome.TIMEOUT, detail="timed out"))
    assert error.outcome is SecurityOutcome.ERROR
    oversized = check(RunnerResult(RequestOutcome.OVERSIZED_RESPONSE, status_code=200))
    assert oversized.outcome is SecurityOutcome.ERROR
    redirect_blocked = check(RunnerResult(RequestOutcome.BLOCKED_SCOPE, redirect_count=1))
    assert redirect_blocked.outcome is SecurityOutcome.NOT_RUN

    not_run = check(RunnerResult(RequestOutcome.BLOCKED_SCOPE))
    assert not_run.outcome is SecurityOutcome.NOT_RUN


def test_evidence_contains_only_allowlisted_response_headers():
    result = REGISTRY[TEST_ID].evaluate(RunnerResult(
        RequestOutcome.COMPLETED, status_code=200,
        headers={"content-type": "text/html", "x-content-type-options": "nosniff",
                 "set-cookie": "session=do-not-retain", "authorization": "Bearer do-not-retain"},
    ))
    assert result.outcome is SecurityOutcome.NO_ISSUE_OBSERVED
    assert "set-cookie" not in result.evidence["response_headers"]
    assert "authorization" not in result.evidence["response_headers"]


def test_runner_cookie_metadata_never_includes_cookie_values():
    from httpx import Headers

    from apisentinel.runner import _safe_response_headers

    safe = _safe_response_headers(Headers([
        ("set-cookie", "session_id=super-secret; Secure; HttpOnly; SameSite=Lax"),
        ("access-control-allow-origin", "*"),
        ("access-control-allow-credentials", "true"),
    ]))
    assert safe["cookie-metadata"] == "session_id;httponly;samesite;secure"
    assert "super-secret" not in str(safe)
    assert safe["access-control-allow-origin"] == "*"


def test_cors_check_flags_only_wildcard_with_credentials():
    from apisentinel.runner import RequestOutcome, RunnerResult
    from apisentinel.test_registry import REGISTRY

    evaluate = REGISTRY["response.header.cors_policy"].evaluate
    candidate = evaluate(RunnerResult(RequestOutcome.COMPLETED, status_code=200, headers={
        "access-control-allow-origin": "*", "access-control-allow-credentials": "true"}))
    inconclusive = evaluate(RunnerResult(RequestOutcome.COMPLETED, status_code=200, headers={
        "access-control-allow-origin": "*"}))
    assert candidate.outcome.value == "CANDIDATE_FOUND"
    assert inconclusive.outcome.value == "INCONCLUSIVE"


def test_session_cookie_flags_use_metadata_only():
    from apisentinel.runner import RequestOutcome, RunnerResult
    from apisentinel.test_registry import REGISTRY

    evaluate = REGISTRY["response.cookie.session_flags"].evaluate
    result = evaluate(RunnerResult(RequestOutcome.COMPLETED, status_code=200, headers={
        "cookie-metadata": "session_id;secure;httponly;samesite"}))
    assert result.outcome.value == "NO_ISSUE_OBSERVED"
    assert "value" not in str(result.evidence).lower()
    assert "do-not-retain" not in str(result.evidence)


def test_verbose_server_error_check_keeps_only_bounded_redacted_indicators():
    check = REGISTRY[ERROR_DISCLOSURE_ID].evaluate
    trace = (b"Traceback (most recent call last):\n  File '/app/src/handler.py', line 23\n"
             b"  RuntimeError: fixture-secret-value\n")
    candidate = check(RunnerResult(RequestOutcome.COMPLETED, status_code=500, body=trace))
    assert candidate.outcome is SecurityOutcome.CANDIDATE_FOUND
    assert candidate.evidence["indicators"] == ["python_traceback", "application_path"]
    assert candidate.evidence["response_bytes_examined"] == len(trace)
    assert "fixture-secret-value" not in str(candidate.evidence)
    assert "Traceback" not in str(candidate.evidence)

    ordinary = check(RunnerResult(RequestOutcome.COMPLETED, status_code=500,
                                  body=b"Internal Server Error"))
    assert ordinary.outcome is SecurityOutcome.NO_ISSUE_OBSERVED
    assert ordinary.evidence["indicators"] == []
    assert "not proof" in ordinary.limitation

    non_error = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, body=trace))
    assert non_error.outcome is SecurityOutcome.INCONCLUSIVE
    unavailable = check(RunnerResult(RequestOutcome.BLOCKED_SCOPE))
    assert unavailable.outcome is SecurityOutcome.NOT_RUN


def test_execution_classification_is_distinct_from_transport_and_vulnerability_severity():
    check = REGISTRY[TEST_ID].evaluate
    candidate = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                   headers={"content-type": "text/plain"}))
    pass_result = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200,
                                     headers={"content-type": "text/plain",
                                              "x-content-type-options": "nosniff"}))
    inconclusive = check(RunnerResult(RequestOutcome.COMPLETED, status_code=404))
    error = check(RunnerResult(RequestOutcome.TIMEOUT))
    blocked = check(RunnerResult(RequestOutcome.BLOCKED_SCOPE))
    assert classify_execution(pass_result, RequestOutcome.COMPLETED) is ExecutionClassification.PASS
    assert classify_execution(candidate, RequestOutcome.COMPLETED) is ExecutionClassification.FAIL
    assert classify_execution(inconclusive, RequestOutcome.COMPLETED) is ExecutionClassification.INCONCLUSIVE
    assert classify_execution(error, RequestOutcome.TIMEOUT) is ExecutionClassification.ERROR
    assert classify_execution(blocked, RequestOutcome.BLOCKED_SCOPE) is ExecutionClassification.BLOCKED
    assert classify_execution(None, RequestOutcome.COMPLETED) is ExecutionClassification.NOT_APPLICABLE


def test_hsts_registry_contract_and_policy_parsing():
    check = REGISTRY[HSTS_ID].evaluate
    assert REGISTRY[HSTS_ID].version == "1.0.0"
    assert REGISTRY[HSTS_ID].required_scheme == "https"

    missing = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="https"))
    assert missing.outcome is SecurityOutcome.CANDIDATE_FOUND
    assert "does not prove" in missing.limitation

    positive = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="https",
                                  headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}))
    assert positive.outcome is SecurityOutcome.NO_ISSUE_OBSERVED
    assert positive.evidence["max_age_seconds"] == 31536000
    assert positive.evidence["include_subdomains"] is True
    assert positive.evidence["preload"] is True

    # These directives are policy choices; a positive max-age is not rejected
    # merely because either optional directive is absent.
    optional_omitted = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="https",
                                          headers={"strict-transport-security": "max-age=86400; future=value"}))
    assert optional_omitted.outcome is SecurityOutcome.NO_ISSUE_OBSERVED
    zero = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="https",
                              headers={"strict-transport-security": "MAX-AGE=0"}))
    assert zero.outcome is SecurityOutcome.CANDIDATE_FOUND

    http = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="http"))
    assert http.outcome is SecurityOutcome.INCONCLUSIVE
    assert "HTTP" in http.explanation

    for value in ("max-age=abc", "includeSubDomains", "max-age=1;;preload",
                  "max-age=1; includeSubDomains=yes", "max-age=1; max-age=2"):
        result = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="https",
                                    headers={"strict-transport-security": value}))
        assert result.outcome is SecurityOutcome.INCONCLUSIVE, value

    case_insensitive = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="https",
                                          headers={"StRiCt-TrAnSpOrT-SeCuRiTy": "max-age=20"}))
    assert case_insensitive.outcome is SecurityOutcome.NO_ISSUE_OBSERVED
    duplicate = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="https",
                                   headers={"Strict-Transport-Security": "max-age=20",
                                            "strict-transport-security": "max-age=30"}))
    assert duplicate.outcome is SecurityOutcome.INCONCLUSIVE
    combined = check(RunnerResult(RequestOutcome.COMPLETED, status_code=200, final_scheme="https",
                                  headers={"strict-transport-security": "max-age=20, max-age=30"}))
    assert combined.outcome is SecurityOutcome.INCONCLUSIVE
    non_success = check(RunnerResult(RequestOutcome.COMPLETED, status_code=503, final_scheme="https",
                                     headers={"strict-transport-security": "max-age=20"}))
    assert non_success.outcome is SecurityOutcome.INCONCLUSIVE
    for outcome in (RequestOutcome.TIMEOUT, RequestOutcome.TRANSPORT_ERROR,
                    RequestOutcome.OVERSIZED_RESPONSE, RequestOutcome.CANCELLED,
                    RequestOutcome.BLOCKED_SCOPE):
        result = check(RunnerResult(outcome, final_scheme="https"))
        assert result.outcome in {SecurityOutcome.ERROR, SecurityOutcome.NOT_RUN}
