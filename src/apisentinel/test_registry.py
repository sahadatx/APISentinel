"""Typed registry for reviewed, server-implemented security checks."""
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import StrEnum

from .runner import RequestOutcome, RunnerResult


class SecurityOutcome(StrEnum):
    NOT_RUN = "NOT_RUN"
    INCONCLUSIVE = "INCONCLUSIVE"
    NO_ISSUE_OBSERVED = "NO_ISSUE_OBSERVED"
    CANDIDATE_FOUND = "CANDIDATE_FOUND"
    ERROR = "ERROR"


class ExecutionClassification(StrEnum):
    """Concise execution state, separate from transport and finding severity."""
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class CheckResult:
    outcome: SecurityOutcome
    evidence: dict
    explanation: str
    limitation: str
    remediation: str = ""

    def __post_init__(self):
        if not isinstance(self.outcome, SecurityOutcome):
            raise TypeError("Check results must use a registered security outcome")
        if not isinstance(self.evidence, dict):
            raise TypeError("Check evidence must be an object")
        try:
            encoded = json.dumps(self.evidence, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError):
            raise ValueError("Check evidence must contain JSON-safe values") from None
        if len(encoded.encode("utf-8")) > 65_536:
            raise ValueError("Check evidence exceeds the 64 KiB limit")
        for field_name in ("explanation", "limitation", "remediation"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or len(value) > 4_000:
                raise ValueError("Check result text must be bounded strings")


CheckCallable = Callable[[RunnerResult], CheckResult]


@dataclass(frozen=True)
class TestDefinition:
    __test__ = False

    identifier: str
    version: str
    name: str
    category: str
    purpose: str
    limitations: str
    supported_methods: tuple[str, ...]
    endpoint_characteristics: tuple[str, ...]
    required_authentication: tuple[str, ...]
    passive: bool
    safety_prerequisites: tuple[str, ...]
    execution_gates: tuple[str, ...]
    expected_evidence: tuple[str, ...]
    outcome_interpretation: dict[str, str]
    permissions: tuple[str, ...]
    evaluate: CheckCallable
    required_scheme: str | None = None
    owasp_categories: tuple[str, ...] = ("API8:2023",)
    platforms: tuple[str, ...] = ("WEB_API", "ANDROID_API", "BOTH")
    required_inputs: tuple[str, ...] = ("Approved endpoint", "Active authorization",)
    # Explicitly unauthenticated test against an endpoint whose contract requires auth.
    allows_unauthenticated_probe: bool = False
    requires_auth_protected_endpoint: bool = False
    supports_authenticated_execution: bool = False
    required_test_identity_count: int = 0
    workflow: str | None = None
    redirect_limit: int | None = None
    supported_content_types: tuple[str, ...] = ()
    max_requests: int = 1
    max_duration_seconds: int = 90
    max_response_bytes: int = 1_000_000
    safety_classification: str = "ACTIVE_READ_ONLY"
    taxonomy_version: str = "OWASP API Security Top 10 2023"

    def __post_init__(self):
        if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", self.identifier):
            raise ValueError("Check identifiers must be stable lowercase tokens")
        if not re.fullmatch(r"\d+\.\d+\.\d+", self.version):
            raise ValueError("Check versions must use semantic version syntax")
        if not self.name.strip() or not self.purpose.strip() or not self.limitations.strip():
            raise ValueError("Checks require a name, purpose, and limitations")
        if not callable(self.evaluate):
            raise TypeError("Checks require a server-implemented evaluator")
        if not self.supported_methods or any(method not in {"GET", "HEAD", "OPTIONS"} for method in self.supported_methods):
            raise ValueError("Checks may only declare supported safe HTTP methods")
        if not isinstance(self.passive, bool) or not self.category.strip():
            raise ValueError("Checks require a valid category and passive flag")
        if (not 1 <= self.max_requests <= 16 or not 1 <= self.max_duration_seconds <= 300
                or not 1024 <= self.max_response_bytes <= 5_000_000):
            raise ValueError("Check resource budgets must be positive and bounded")
        if not self.owasp_categories or not self.platforms or not self.required_inputs:
            raise ValueError("Checks must declare taxonomy, applicability, and prerequisites")
        if not 0 <= self.required_test_identity_count <= 2:
            raise ValueError("Checks may require at most two explicit test identities")
        if self.workflow not in {None, "BOLA", "BFLA"}:
            raise ValueError("Unsupported bounded test workflow")
        if self.workflow and (self.required_test_identity_count != 2 or not self.supports_authenticated_execution):
            raise ValueError("Identity comparison workflows require two identities and authenticated execution")
        if self.redirect_limit is not None and not 0 <= self.redirect_limit <= 3:
            raise ValueError("Redirect budget must be between zero and three")

    def public(self, *, enabled: bool) -> dict:
        values = asdict(self)
        values.pop("evaluate", None)
        values.update(enabled=enabled, passive=self.passive,
                      max_redirects=(self.redirect_limit if self.redirect_limit is not None
                                     else max(0, self.max_requests - 1)))
        return values


def evaluate_safely(definition: TestDefinition, result: RunnerResult) -> tuple[CheckResult, bool]:
    """Evaluate a trusted registry entry and return bounded, redacted output."""
    try:
        from .safety import sanitize_evidence

        evaluated = definition.evaluate(result)
        if not isinstance(evaluated, CheckResult):
            raise TypeError("invalid evaluator result")
        evidence = sanitize_evidence(evaluated.evidence)
        encoded = json.dumps(evidence, allow_nan=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 65_536:
            raise ValueError("oversized evaluator evidence")
        return CheckResult(
            outcome=evaluated.outcome, evidence=evidence,
            explanation=sanitize_evidence(evaluated.explanation)[:4_000],
            limitation=sanitize_evidence(evaluated.limitation)[:4_000],
            remediation=sanitize_evidence(evaluated.remediation)[:4_000],
        ), False
    except Exception:  # noqa: BLE001 - isolate registry evaluator failures from transport
        return CheckResult(
            SecurityOutcome.ERROR, {},
            "The registered security check failed safely during evaluation.",
            "Transport completed independently; the check result is unavailable and no security conclusion was recorded.",
        ), True


def _content_type_options(result: RunnerResult) -> CheckResult:
    """Observe a header configuration; this is a candidate, never a confirmed exploit."""
    if result.outcome is not RequestOutcome.COMPLETED:
        if result.outcome in {RequestOutcome.SKIPPED, RequestOutcome.BLOCKED_SCOPE,
                              RequestOutcome.BLOCKED_DESTINATION, RequestOutcome.CANCELLED,
                              RequestOutcome.AUTH_UNAVAILABLE}:
            return CheckResult(SecurityOutcome.NOT_RUN, {}, "No HTTP response was available for this check.",
                               "A blocked or skipped transport provides no security-test result.")
        return CheckResult(SecurityOutcome.ERROR, {}, "The HTTP transport did not complete; the check could not evaluate a response.",
                           "Transport failures are not interpreted as security findings or clean results.")

    header_values: dict[str, list[str]] = {}
    for key, value in (result.headers or {}).items():
        header_values.setdefault(str(key).strip().lower(), []).append(str(value).strip())
    content_types = header_values.get("content-type", [])
    nosniff_values = header_values.get("x-content-type-options", [])
    content_type_value = content_types[0] if len(content_types) == 1 else ""
    nosniff_value = nosniff_values[0] if len(nosniff_values) == 1 else ""
    # HTTPX combines duplicate field lines with commas. Neither field supports
    # a comma-list in this check's interpretation, so treat it as ambiguous.
    duplicate_or_ambiguous = (len(content_types) > 1 or len(nosniff_values) > 1
                              or "," in content_type_value or "," in nosniff_value)
    content_type = content_type_value.split(";", 1)[0].strip().lower()
    nosniff = nosniff_value.strip().lower()
    evidence = {
        "status_code": result.status_code,
        "response_headers": {
            "content-type": content_type_value or None,
            "x-content-type-options": nosniff_value or None,
        },
    }
    if result.status_code is None:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The completed transport did not provide an HTTP status code.",
                           "A complete response status is required before interpreting response headers.")
    if not 200 <= result.status_code < 300:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The response was not a successful 2xx response, so this check did not classify its header policy.",
                           "Error and redirect responses may have different header behavior; this check evaluates successful endpoint responses only.")
    if duplicate_or_ambiguous:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The response contains duplicate or ambiguous Content-Type or X-Content-Type-Options values.",
                           "This check does not choose between repeated or comma-combined header values.")
    if not content_type:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The response did not declare a Content-Type, so the header policy could not be evaluated.",
                           "This check evaluates response metadata only and does not inspect browser usage or content.")
    if content_type not in {"text/html", "application/xhtml+xml", "application/json", "text/plain"}:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The response media type is outside this check's supported set.",
                           "The check does not evaluate media types outside its documented subset.")
    if nosniff == "nosniff":
        return CheckResult(SecurityOutcome.NO_ISSUE_OBSERVED, evidence,
                           "The response declares X-Content-Type-Options: nosniff.",
                           "This observes one response only; it does not validate every route or browser behavior.")
    if nosniff and nosniff != "nosniff":
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The response contains an unrecognized X-Content-Type-Options value.",
                           "This check does not interpret non-standard header values.")
    return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                       "The response uses a supported media type but does not declare X-Content-Type-Options: nosniff.",
                       "Header absence alone does not prove exploitable MIME sniffing; browser use, content, and route context require analyst validation.",
                       "Where compatible with the application, configure X-Content-Type-Options: nosniff and verify content types.")


_HTTP_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def _strict_transport_security(result: RunnerResult) -> CheckResult:
    """Observe one final HTTPS response's HSTS policy header, without browser claims."""
    if result.outcome is not RequestOutcome.COMPLETED:
        if result.outcome in {RequestOutcome.SKIPPED, RequestOutcome.BLOCKED_SCOPE,
                              RequestOutcome.BLOCKED_DESTINATION, RequestOutcome.CANCELLED,
                              RequestOutcome.AUTH_UNAVAILABLE}:
            return CheckResult(SecurityOutcome.NOT_RUN, {}, "No HTTP response was available for this check.",
                               "A blocked or skipped transport provides no security-test result.")
        return CheckResult(SecurityOutcome.ERROR, {}, "The HTTP transport did not complete; the check could not evaluate a response.",
                           "Transport failures are not interpreted as security findings or clean results.")

    values: list[str] = []
    for name, value in (result.headers or {}).items():
        if str(name).strip().lower() == "strict-transport-security":
            values.append(str(value).strip())
    evidence = {
        "final_scheme": result.final_scheme,
        "status_code": result.status_code,
        "strict_transport_security": values[0] if len(values) == 1 else (", ".join(values) if values else None),
    }
    if result.final_scheme != "https":
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The final response was not verified as HTTPS; HSTS policy cannot be evaluated from HTTP.",
                           "Browsers ignore Strict-Transport-Security received over insecure HTTP. Redirects are evaluated only at the runner's final response.")
    if result.status_code is None or not 200 <= result.status_code < 300:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "A successful 2xx HTTPS response was not available for HSTS evaluation.",
                           "Non-success responses and responses without a status are not classified by this check.")
    if not values:
        evidence.update(max_age_seconds=None, include_subdomains=False, preload=False)
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "The successful HTTPS response did not include Strict-Transport-Security.",
                           "This is a low-confidence, single-response configuration observation. It does not prove a downgrade or other exploitable weakness; route and deployment policy require analyst review.",
                           "Review the deployment's HTTPS policy and configure an appropriate positive max-age where HSTS is required.")
    if len(values) != 1 or "," in values[0]:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The response contains duplicate or comma-ambiguous Strict-Transport-Security values.",
                           "This check does not choose between repeated header values.")

    directives: dict[str, str | None] = {}
    for raw_directive in values[0].split(";"):
        part = raw_directive.strip()
        if not part:
            return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                               "The Strict-Transport-Security header contains an empty or malformed directive.",
                               "Malformed directive lists are not interpreted.")
        if "=" in part:
            name, raw_value = part.split("=", 1)
            name, value = name.strip().lower(), raw_value.strip()
            if not value or not _HTTP_TOKEN.fullmatch(name) or not _HTTP_TOKEN.fullmatch(value):
                return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                                   "The Strict-Transport-Security header contains a malformed directive.",
                                   "Directive names and values must be valid tokens for this parser.")
        else:
            name, value = part.lower(), None
            if not _HTTP_TOKEN.fullmatch(name):
                return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                                   "The Strict-Transport-Security header contains a malformed directive name.",
                                   "Directive names must be valid tokens for this parser.")
        if name in directives:
            return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                               "The Strict-Transport-Security header repeats a directive.",
                               "Conflicting or repeated directives are treated as ambiguous.")
        directives[name] = value

    max_age = directives.get("max-age")
    if max_age is None or not max_age.isascii() or not max_age.isdigit():
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The Strict-Transport-Security header lacks a valid decimal max-age directive.",
                           "A present but malformed policy is not treated as either secure or absent.")
    for boolean_directive in ("includesubdomains", "preload"):
        if boolean_directive in directives and directives[boolean_directive] is not None:
            return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                               f"The {boolean_directive} directive has an unexpected value.",
                               "Boolean directives must not have values.")
    if len(max_age) > 20:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The Strict-Transport-Security max-age exceeds the parser's supported numeric range.",
                           "Very large numeric directives are not retained or interpreted by this check.")
    try:
        max_age_seconds = int(max_age)
    except ValueError:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The Strict-Transport-Security max-age value is outside the supported numeric range.",
                           "The parser does not infer policy from an unrepresentable max-age value.")
    include_subdomains = "includesubdomains" in directives
    preload = "preload" in directives
    evidence.update(max_age_seconds=max_age_seconds, include_subdomains=include_subdomains, preload=preload)
    if max_age_seconds == 0:
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "The HTTPS response declares max-age=0, which disables stored HSTS policy for the host.",
                           "This is a low-confidence policy observation, not proof of an exploitable downgrade. Whether HSTS is required and the appropriate duration depend on deployment context.",
                           "If HSTS is required, review the intended deployment policy and use an appropriate positive max-age.")
    return CheckResult(SecurityOutcome.NO_ISSUE_OBSERVED, evidence,
                       "The HTTPS response declares a syntactically valid positive HSTS max-age.",
                       "This observes one response only. It does not verify browser behavior, certificate deployment, subdomain readiness, preload eligibility, or whether this policy meets organizational requirements.")


_PYTHON_TRACEBACK = re.compile(rb"Traceback \(most recent call last\):")
_JAVA_TRACE = re.compile(rb"\bat\s+[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\([^\r\n)]{1,160}:\d+\)")
_NODE_TRACE = re.compile(rb"\bat\s+[^\r\n()]{1,100}\([^\r\n()]{1,180}:[1-9]\d*:[1-9]\d*\)")
_SERVER_PATH = re.compile(rb"(?:/var/www/|/usr/src/app/|/app/src/|/home/[^/\s]+/)[^\r\n\s:]{1,160}")


def _verbose_server_error(result: RunnerResult) -> CheckResult:
    """Flag recognizable stack traces in a bounded 5xx response without retaining text."""
    if result.outcome is not RequestOutcome.COMPLETED:
        if result.outcome in {RequestOutcome.SKIPPED, RequestOutcome.BLOCKED_SCOPE,
                              RequestOutcome.BLOCKED_DESTINATION, RequestOutcome.CANCELLED,
                              RequestOutcome.AUTH_UNAVAILABLE}:
            return CheckResult(SecurityOutcome.NOT_RUN, {}, "No HTTP response was available for this check.",
                               "A blocked or skipped transport provides no security-test result.")
        return CheckResult(SecurityOutcome.ERROR, {}, "The HTTP transport did not complete; the check could not evaluate a response.",
                           "Transport failures are not interpreted as a clean result or a vulnerability.")
    if result.status_code is None or not 500 <= result.status_code <= 599:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, {"status_code": result.status_code},
                           "The response was not an HTTP 5xx response.",
                           "This check only examines server-error responses and does not infer error behavior from other status codes.")
    body = (result.body or b"")[:65_536]
    indicators = []
    for name, pattern in (("python_traceback", _PYTHON_TRACEBACK), ("java_stack_frame", _JAVA_TRACE),
                          ("node_stack_frame", _NODE_TRACE), ("application_path", _SERVER_PATH)):
        if pattern.search(body):
            indicators.append(name)
    evidence = {"status_code": result.status_code, "response_bytes_examined": len(body),
                "response_sha256": hashlib.sha256(result.body or b"").hexdigest(),
                "indicators": indicators, "analysis_cap_bytes": 65_536}
    if indicators:
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "A bounded 5xx response contains a recognizable stack-trace or application-path indicator.",
                           "This heuristic retains no response text and does not prove the data is sensitive or exposed to an unauthorized caller. Validate using a controlled error fixture and review the endpoint's intended disclosure policy.",
                           "Return generic client errors and keep stack traces, source paths, and diagnostic details in access-controlled server logs.")
    return CheckResult(SecurityOutcome.NO_ISSUE_OBSERVED, evidence,
                       "No supported stack-trace or application-path signature was found in the inspected 5xx response prefix.",
                       "This is not proof that the response contains no sensitive information. Only the first 64 KiB is inspected; generic and novel error formats are not detected.")


def _cors_policy(result: RunnerResult) -> CheckResult:
    """Observe a wildcard plus credential CORS misconfiguration without probing Origin."""
    if result.outcome is not RequestOutcome.COMPLETED:
        return CheckResult(SecurityOutcome.NOT_RUN, {}, "No HTTP response was available for CORS observation.",
                           "A blocked or failed transport does not establish CORS behavior.")
    headers = {str(k).lower(): str(v).strip() for k, v in (result.headers or {}).items()}
    origin = headers.get("access-control-allow-origin")
    credentials = headers.get("access-control-allow-credentials", "").lower()
    evidence = {"status_code": result.status_code, "allow_origin": origin,
                "allow_credentials": credentials == "true",
                "vary_origin": "origin" in [v.strip().lower() for v in headers.get("vary", "").split(",")]}
    if origin == "*" and credentials == "true":
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "The response combines wildcard origin access with credential permission.",
                           "Browsers reject wildcard origins for credentialed CORS; this observation alone does not show sensitive data exposure.",
                           "Use an explicit trusted-origin allowlist and validate browser behavior.")
    return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                       "The single response did not establish an unsafe credentialed wildcard CORS policy.",
                       "This check does not send Origin or preflight requests and does not test origin reflection or browser enforcement.")


def _session_cookie_flags(result: RunnerResult) -> CheckResult:
    """Inspect cookie names and attribute names only; values are removed by runner."""
    if result.outcome is not RequestOutcome.COMPLETED:
        return CheckResult(SecurityOutcome.NOT_RUN, {}, "No HTTP response was available for cookie policy observation.",
                           "A blocked or failed transport does not establish cookie policy.")
    rows = []
    for row in (result.headers or {}).get("cookie-metadata", "").splitlines()[:20]:
        parts = [part.strip().lower() for part in row.split(";")]
        name = parts[0] if parts else ""
        if any(token in name for token in ("session", "auth", "token")):
            rows.append({"name": name[:128], "attributes": sorted(set(parts[1:]))})
    evidence = {"session_cookie_count": len(rows), "cookies": rows}
    if not rows:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "No cookie with a recognizable session, authentication, or token name was observed.",
                           "Cookie-name recognition is heuristic; application-specific session cookies may not be recognized.")
    missing = [{"name": row["name"], "missing": [flag for flag in ("secure", "httponly", "samesite")
                if flag not in row["attributes"]]} for row in rows]
    evidence["missing_attributes"] = missing
    if any(item["missing"] for item in missing):
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "A likely session cookie is missing one or more Secure, HttpOnly, or SameSite attributes.",
                           "This is a name-based single-response heuristic; required attributes depend on deployment context and no cookie values are retained.",
                           "Review session-cookie policy and set Secure, HttpOnly, and an appropriate SameSite attribute where applicable.")
    return CheckResult(SecurityOutcome.NO_ISSUE_OBSERVED, evidence,
                       "Recognized session cookies include Secure, HttpOnly, and SameSite attributes.",
                       "This observes one response only and does not validate scope, lifetime, rotation, or browser behavior.")


def _unauthenticated_access(result: RunnerResult) -> CheckResult:
    """Check only whether a contract-protected read endpoint answers unauthenticated."""
    if result.outcome is not RequestOutcome.COMPLETED:
        if result.outcome in {RequestOutcome.SKIPPED, RequestOutcome.BLOCKED_SCOPE,
                              RequestOutcome.BLOCKED_DESTINATION, RequestOutcome.CANCELLED}:
            return CheckResult(SecurityOutcome.NOT_RUN, {}, "No HTTP response was available for this check.",
                               "A blocked or skipped transport provides no security-test result.")
        return CheckResult(SecurityOutcome.ERROR, {}, "The HTTP transport did not complete.",
                           "Transport failures are not interpreted as authorization results.")
    evidence = {"status_code": result.status_code}
    if result.status_code is None:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The response did not contain an HTTP status code.",
                           "A complete response is required to interpret unauthenticated access.")
    if 200 <= result.status_code < 300:
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "An endpoint marked as requiring authentication returned a successful response without credentials.",
                           "The contract may be stale or the response may be intentionally public; validate the endpoint policy and response sensitivity.",
                           "Confirm the endpoint's intended access policy and enforce authentication where required.")
    if result.status_code in {401, 403}:
        return CheckResult(SecurityOutcome.NO_ISSUE_OBSERVED, evidence,
                           "The unauthenticated request was rejected with an authentication or authorization status.",
                           "One request does not validate every role, object, or alternate route.")
    return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                       "The response did not establish whether the endpoint requires authentication.",
                       "Not-found, redirect, rate-limit, and server-error responses need endpoint-specific review.")


_SENSITIVE_PROPERTY = re.compile(
    r"(?:^|[_-])(password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"ssn|social[_-]?security|credit[_-]?card|card[_-]?number|cvv|email|"
    r"phone|mobile|birth[_-]?date|date[_-]?of[_-]?birth|address|is[_-]?admin|role)(?:$|[_-])",
    re.IGNORECASE,
)


def _sensitive_property_observation(result: RunnerResult) -> CheckResult:
    """Identify sensitive-looking JSON property names without retaining values."""
    if result.outcome is not RequestOutcome.COMPLETED:
        if result.outcome in {RequestOutcome.SKIPPED, RequestOutcome.BLOCKED_SCOPE,
                              RequestOutcome.BLOCKED_DESTINATION, RequestOutcome.CANCELLED}:
            return CheckResult(SecurityOutcome.NOT_RUN, {}, "No HTTP response was available for this check.",
                               "A blocked or skipped transport provides no security-test result.")
        return CheckResult(SecurityOutcome.ERROR, {}, "The HTTP transport did not complete.",
                           "Transport failures are not interpreted as property exposure results.")
    if result.status_code is None or not 200 <= result.status_code < 300:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, {"status_code": result.status_code},
                           "A successful response was not available for JSON property inspection.",
                           "Error responses are outside this check's documented scope.")
    media_types = [str(value).split(";", 1)[0].strip().lower()
                   for key, value in (result.headers or {}).items()
                   if str(key).lower() == "content-type"]
    if len(media_types) != 1 or not (media_types[0] == "application/json" or media_types[0].endswith("+json")):
        return CheckResult(SecurityOutcome.INCONCLUSIVE, {"status_code": result.status_code},
                           "The response did not have one unambiguous JSON Content-Type.",
                           "Only JSON responses are inspected; response values are never stored as evidence.")
    try:
        document = json.loads(result.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return CheckResult(SecurityOutcome.INCONCLUSIVE, {"status_code": result.status_code},
                           "The bounded response body was not valid JSON.",
                           "Malformed or truncated response bodies are not interpreted.")
    matched: set[str] = set()
    visited = 0
    stack = [(document, 0)]
    while stack and visited < 5000:
        value, depth = stack.pop()
        visited += 1
        if depth > 20:
            continue
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)[:100].lower()
                if _SENSITIVE_PROPERTY.search(key_text):
                    # Persist only a fixed category label, never a server-supplied key.
                    matched.add(next((label for needle, label in (
                        ("password", "password"), ("passwd", "password"), ("secret", "secret"),
                        ("token", "token"), ("api_key", "api_key"), ("api-key", "api_key"),
                        ("private_key", "private_key"), ("private-key", "private_key"),
                        ("ssn", "government_identifier"), ("social_security", "government_identifier"),
                        ("credit_card", "payment_card"), ("card_number", "payment_card"),
                        ("cvv", "payment_card"), ("email", "email"), ("phone", "phone"),
                        ("mobile", "phone"), ("birth_date", "birth_date"), ("date_of_birth", "birth_date"),
                        ("address", "address"), ("is_admin", "privileged_role"), ("role", "privileged_role"),
                    ) if needle in key_text), "sensitive_property"))
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value[:500]
                         if isinstance(child, (dict, list)))
    evidence = {"status_code": result.status_code, "response_bytes": len(result.body),
                "matched_property_names": sorted(matched)[:50],
                "inspection_limit_reached": bool(stack or visited >= 5000)}
    if matched:
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "The JSON response contains property names commonly associated with sensitive or privileged data.",
                           "Property names alone do not prove unauthorized disclosure; verify the expected schema and access policy. Values and response paths are deliberately not retained.",
                           "Review the response schema and ensure each property is necessary and authorized for this caller.")
    return CheckResult(SecurityOutcome.NO_ISSUE_OBSERVED, evidence,
                       "No configured sensitive-property names were observed in the inspected JSON response.",
                       "This bounded name-based heuristic cannot identify every sensitive field or prove property-level authorization.")


def _rate_limit_observation(result: RunnerResult) -> CheckResult:
    """Record quota-related response metadata without sending repeated requests."""
    if result.outcome is not RequestOutcome.COMPLETED:
        if result.outcome in {RequestOutcome.SKIPPED, RequestOutcome.BLOCKED_SCOPE,
                              RequestOutcome.BLOCKED_DESTINATION, RequestOutcome.CANCELLED}:
            return CheckResult(SecurityOutcome.NOT_RUN, {}, "No HTTP response was available for this check.",
                               "A blocked or skipped transport provides no policy observation.")
        return CheckResult(SecurityOutcome.ERROR, {}, "The HTTP transport did not complete.",
                           "Transport failures do not establish resource-consumption policy.")
    names = {"ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "retry-after",
             "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"}
    observed = sorted({str(key).strip().lower() for key in (result.headers or {})
                       if str(key).strip().lower() in names})
    evidence = {"status_code": result.status_code, "quota_header_names": observed,
                "rate_limited_response": result.status_code == 429}
    return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                       "One response was inspected for quota headers; no repeated or load-generating requests were sent.",
                       "A single response cannot verify quota enforcement, burst behavior, or resource limits. Compare this observation with the client's documented policy.")


def _bola_synthetic_pair(result: RunnerResult) -> CheckResult:
    """Compare two identities against only their client-provided synthetic objects."""
    if result.outcome is not RequestOutcome.COMPLETED:
        if result.outcome in {RequestOutcome.SKIPPED, RequestOutcome.BLOCKED_SCOPE,
                              RequestOutcome.BLOCKED_DESTINATION, RequestOutcome.CANCELLED,
                              RequestOutcome.AUTH_UNAVAILABLE}:
            return CheckResult(SecurityOutcome.NOT_RUN, {}, "The identity comparison did not complete.",
                               "A blocked or incomplete request provides no ownership result.")
        return CheckResult(SecurityOutcome.ERROR, {}, "The identity comparison failed during transport.",
                           "Transport failures are not interpreted as object authorization outcomes.")
    observations = ((result.check_context or {}).get("observations")
                    if isinstance(result.check_context, dict) else None)
    if not isinstance(observations, list):
        return CheckResult(SecurityOutcome.INCONCLUSIVE, {},
                           "Four authorized identity/object comparisons were not completed.",
                           "Both synthetic objects must be readable by their owner identities before cross-identity denial can be interpreted.")
    evidence = {"identity_observations": [
        {"identity_label": str(row.get("identity_label", ""))[:100],
         "role": str(row.get("role", ""))[:80], "relation": row.get("relation"),
         "status_code": row.get("status_code")} for row in observations if isinstance(row, dict)
    ]}
    if len(observations) != 4:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "An owner-access control did not succeed, so cross-identity requests were skipped.",
                           "Both synthetic objects must be readable by their owner identities before cross-identity denial can be interpreted.")
    own = [row for row in observations if isinstance(row, dict) and row.get("relation") == "own"]
    cross = [row for row in observations if isinstance(row, dict) and row.get("relation") == "cross"]
    if len(own) != 2 or len(cross) != 2 or any(
        not isinstance(row.get("status_code"), int) or not 200 <= row["status_code"] < 300 for row in own
    ):
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "At least one owner identity could not read its synthetic object.",
                           "Owner access is the control case; missing or inaccessible synthetic records prevent a cross-identity conclusion.")
    unauthorized_successes = [row for row in cross if isinstance(row.get("status_code"), int)
                              and 200 <= row["status_code"] < 300]
    if unauthorized_successes:
        evidence["cross_identity_success_labels"] = sorted({str(row.get("object_owner_label", ""))[:100]
                                                               for row in unauthorized_successes})
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "An identity received a successful response for the other identity's client-designated synthetic object.",
                           "This is a status-only candidate; verify object ownership policy and the synthetic-object oracle. No response body or object identifier is retained.",
                           "Enforce object-level authorization for every object access using the authenticated principal's ownership or access policy.")
    if all(row.get("status_code") in {401, 403, 404} for row in cross):
        return CheckResult(SecurityOutcome.NO_ISSUE_OBSERVED, evidence,
                           "Both cross-identity synthetic-object requests received a denial or not-found status after owner access succeeded.",
                           "This checks two synthetic objects on one endpoint only; it does not establish route-wide or role-wide authorization.")
    return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                       "A cross-identity response did not clearly allow or deny access.",
                       "Redirects, throttling, and server errors require client-specific interpretation.")


def _function_role_pair(result: RunnerResult) -> CheckResult:
    """Compare one explicitly allowed and one explicitly denied test role on a read endpoint."""
    if result.outcome is not RequestOutcome.COMPLETED:
        if result.outcome in {RequestOutcome.SKIPPED, RequestOutcome.BLOCKED_SCOPE,
                              RequestOutcome.BLOCKED_DESTINATION, RequestOutcome.CANCELLED,
                              RequestOutcome.AUTH_UNAVAILABLE}:
            return CheckResult(SecurityOutcome.NOT_RUN, {}, "The role comparison did not complete.",
                               "A blocked or incomplete request provides no role authorization result.")
        return CheckResult(SecurityOutcome.ERROR, {}, "The role comparison failed during transport.",
                           "Transport failures are not interpreted as function-level authorization outcomes.")
    observations = ((result.check_context or {}).get("observations")
                    if isinstance(result.check_context, dict) else None)
    if not isinstance(observations, list):
        return CheckResult(SecurityOutcome.INCONCLUSIVE, {},
                           "Both role requests were not completed.",
                           "The client-approved allow and deny roles are required as the comparison oracle.")
    evidence = {"role_observations": [
        {"identity_label": str(row.get("identity_label", ""))[:100],
         "role": str(row.get("role", ""))[:80], "expected_access": "ALLOW" if row.get("expected_allowed") else "DENY",
         "status_code": row.get("status_code")} for row in observations if isinstance(row, dict)
    ]}
    if len(observations) != 2:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The client-designated allowed identity did not succeed; the denied identity was not requested.",
                           "A successful allowed-role control is required before interpreting the deny-role response.")
    allowed = [row for row in observations if isinstance(row, dict) and row.get("expected_allowed") is True]
    denied = [row for row in observations if isinstance(row, dict) and row.get("expected_allowed") is False]
    if len(allowed) != 1 or len(denied) != 1:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The expected role matrix did not identify exactly one allowed and one denied identity.",
                           "The test requires a client-confirmed endpoint-to-role expectation.")
    allow_status, deny_status = allowed[0].get("status_code"), denied[0].get("status_code")
    if not isinstance(allow_status, int) or not 200 <= allow_status < 300:
        return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                           "The client-designated allowed identity did not receive a successful response.",
                           "A valid allow-role control is required before interpreting the deny-role response.")
    if isinstance(deny_status, int) and 200 <= deny_status < 300:
        return CheckResult(SecurityOutcome.CANDIDATE_FOUND, evidence,
                           "The client-designated denied identity received a successful response from this read endpoint.",
                           "This is a status-only candidate; confirm the approved role matrix and whether the operation intentionally permits both roles.",
                           "Enforce endpoint-level function permissions against the authenticated role or policy.")
    if deny_status in {401, 403, 404}:
        return CheckResult(SecurityOutcome.NO_ISSUE_OBSERVED, evidence,
                           "The client-designated denied identity received a denial or not-found status while the allowed identity succeeded.",
                           "This checks one endpoint and two client-provided test identities only.")
    return CheckResult(SecurityOutcome.INCONCLUSIVE, evidence,
                       "The denied-role response did not clearly allow or deny access.",
                       "Redirects, throttling, and server errors require client-specific interpretation.")


def classify_execution(check_result: CheckResult | None, transport_outcome: RequestOutcome) -> ExecutionClassification:
    """Map the legacy detailed result contract to the stable six-state UI contract."""
    if check_result is None:
        return ExecutionClassification.NOT_APPLICABLE
    if check_result.outcome is SecurityOutcome.NO_ISSUE_OBSERVED:
        return ExecutionClassification.PASS
    if check_result.outcome is SecurityOutcome.CANDIDATE_FOUND:
        # FAIL means the configured observation failed; the linked finding remains
        # an unconfirmed Candidate until an analyst validates it.
        return ExecutionClassification.FAIL
    if check_result.outcome is SecurityOutcome.INCONCLUSIVE:
        return ExecutionClassification.INCONCLUSIVE
    if check_result.outcome is SecurityOutcome.ERROR:
        return ExecutionClassification.ERROR
    if transport_outcome in {RequestOutcome.BLOCKED_SCOPE, RequestOutcome.BLOCKED_DESTINATION,
                             RequestOutcome.CANCELLED, RequestOutcome.AUTH_UNAVAILABLE,
                             RequestOutcome.SKIPPED}:
        return ExecutionClassification.BLOCKED
    return ExecutionClassification.NOT_APPLICABLE


REGISTRY: dict[str, TestDefinition] = {
    "response.header.cors_policy": TestDefinition(
        identifier="response.header.cors_policy", version="1.0.0", name="CORS credential policy observation",
        category="Misconfiguration", purpose="Observe wildcard origin combined with credential permission.",
        limitations="Single-response observation only; does not send Origin/preflight requests or establish browser data exposure.",
        supported_methods=("GET", "HEAD"), endpoint_characteristics=("Current approved endpoint",),
        required_authentication=("No authentication",), passive=False,
        safety_prerequisites=("Owned assessment", "Current approved endpoint", "Recorded authorization", "In-scope read-only method"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",), expected_evidence=("status code", "CORS allow-origin", "CORS allow-credentials", "Vary"),
        outcome_interpretation={"CANDIDATE_FOUND": "Wildcard origin and credentials were observed; analyst review is required.", "INCONCLUSIVE": "One response did not characterize the CORS policy."},
        permissions=("Authenticated analyst", "Assessment owner"), evaluate=_cors_policy,
        owasp_categories=("API8:2023",), max_response_bytes=1024,
    ),
    "response.cookie.session_flags": TestDefinition(
        identifier="response.cookie.session_flags", version="1.0.0", name="Session cookie security attributes",
        category="Misconfiguration", purpose="Inspect likely session cookie flags without retaining cookie values.",
        limitations="Name-based, single-response observation; application context determines required attributes.",
        supported_methods=("GET",), endpoint_characteristics=("Current approved endpoint",),
        required_authentication=("No authentication",), passive=False,
        safety_prerequisites=("Owned assessment", "Current approved endpoint", "Recorded authorization", "In-scope GET"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",), expected_evidence=("recognized cookie names", "attribute names only"),
        outcome_interpretation={"CANDIDATE_FOUND": "A likely session cookie missed recommended flags; analyst review is required.", "INCONCLUSIVE": "No recognized session cookie was observed."},
        permissions=("Authenticated analyst", "Assessment owner"), evaluate=_session_cookie_flags,
        owasp_categories=("API8:2023",), max_response_bytes=1024,
    ),
    "response.header.content_type_options": TestDefinition(
        identifier="response.header.content_type_options",
        version="1.0.0",
        name="Content-Type sniffing policy header",
        category="Misconfiguration",
        purpose="Observe whether one successful authorized response declares X-Content-Type-Options: nosniff.",
        limitations="Single-response metadata observation for 2xx responses and a supported media type. Missing header creates only a low-confidence candidate and does not establish exploitability.",
        supported_methods=("GET",),
        endpoint_characteristics=("Current approved endpoint", "Supported Content-Type: HTML, XHTML, JSON, or plain text"),
        required_authentication=("No authentication",),
        # It sends a network request, so it is classified active despite using a
        # no-payload GET and only observing response headers.
        passive=False,
        safety_prerequisites=("Owned assessment", "Current approved endpoint", "Recorded authorization", "In-scope GET"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",),
        expected_evidence=("status code", "Content-Type", "X-Content-Type-Options"),
        outcome_interpretation={
            "NOT_RUN": "No response was available because execution was blocked, skipped, cancelled, or authentication was unavailable.",
            "INCONCLUSIVE": "The response metadata did not support a safe conclusion.",
            "NO_ISSUE_OBSERVED": "A supported Content-Type response declared nosniff.",
            "CANDIDATE_FOUND": "A supported Content-Type response omitted nosniff; analyst validation is required.",
            "ERROR": "Transport failed before this check could evaluate a response.",
        },
        permissions=("Authenticated analyst", "Assessment owner"),
        evaluate=_content_type_options,
    ),
    "response.header.strict_transport_security": TestDefinition(
        identifier="response.header.strict_transport_security",
        version="1.0.0",
        name="Strict-Transport-Security policy header",
        category="Misconfiguration",
        purpose="Observe the Strict-Transport-Security policy on one successful final HTTPS response.",
        limitations="Bounded single-response metadata observation only. It does not test browser behavior, certificate configuration, redirects across routes, subdomain readiness, preload eligibility, or policy requirements for this deployment.",
        supported_methods=("GET",),
        endpoint_characteristics=("Current approved endpoint", "Final response must use HTTPS and return 2xx"),
        required_authentication=("No authentication",),
        passive=False,
        safety_prerequisites=("Owned assessment", "Current approved endpoint", "Recorded authorization", "In-scope GET over HTTPS"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",),
        expected_evidence=("final scheme", "status code", "Strict-Transport-Security", "max-age", "includeSubDomains", "preload"),
        outcome_interpretation={
            "NOT_RUN": "Request was blocked, skipped, cancelled, or authentication was unavailable.",
            "INCONCLUSIVE": "HTTP, non-2xx, malformed, duplicated, or incomplete metadata could not support a safe conclusion.",
            "NO_ISSUE_OBSERVED": "One final 2xx HTTPS response declares a valid positive max-age.",
            "CANDIDATE_FOUND": "The HSTS header is absent or max-age is zero; analyst review is required.",
            "ERROR": "Transport failed or the response was incomplete before evaluation.",
        },
        permissions=("Authenticated analyst", "Assessment owner"),
        evaluate=_strict_transport_security,
        required_scheme="https",
        owasp_categories=("API8:2023",),
        supported_content_types=("any HTTP media type; response metadata only",),
        max_response_bytes=1024,
    ),
    "server.error.verbose_exception": TestDefinition(
        identifier="server.error.verbose_exception",
        version="1.0.0",
        name="Verbose server error disclosure",
        category="Misconfiguration",
        purpose="Look for a small set of recognizable stack-trace and application-path signatures in an authorized GET's 5xx response.",
        limitations="Heuristic indicator only; no raw response text is retained. It does not prove data sensitivity or unauthorized exposure and does not detect every framework or error format.",
        supported_methods=("GET",),
        endpoint_characteristics=("Current approved endpoint", "5xx response required for interpretation"),
        required_authentication=("No authentication",),
        passive=False,
        safety_prerequisites=("Owned assessment", "Current approved endpoint", "Recorded authorization", "In-scope GET", "Controlled error behavior is preferred"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",),
        expected_evidence=("HTTP status", "bounded response byte count", "response SHA-256", "matched indicator names only"),
        outcome_interpretation={
            "NOT_RUN": "No response was available because policy, authorization, authentication, or cancellation blocked execution.",
            "INCONCLUSIVE": "The response was not a 5xx error response.",
            "NO_ISSUE_OBSERVED": "No known stack-trace/path signature was found in the inspected prefix; this is not a clean bill of health.",
            "CANDIDATE_FOUND": "A known stack-trace/path signature was observed; analyst validation is required.",
            "ERROR": "Transport failed before evaluation.",
        },
        permissions=("Authenticated analyst", "Assessment owner"),
        evaluate=_verbose_server_error,
        owasp_categories=("API8:2023",),
        required_inputs=("Approved endpoint", "Active authorization", "A controlled 5xx response is needed to evaluate the signature"),
        supported_content_types=("any HTTP media type; first 65,536 response bytes only",),
        max_response_bytes=65_536,
    ),
    "authentication.unauthenticated_access": TestDefinition(
        identifier="authentication.unauthenticated_access", version="1.0.0",
        name="Unauthenticated access on protected read endpoint", category="Authentication",
        purpose="Check whether an endpoint marked as protected returns success to a request with no credentials.",
        limitations="One unauthenticated read-only request only. A contract may be stale, and this does not test roles, object ownership, token lifecycle, or alternate routes.",
        supported_methods=("GET", "HEAD"), endpoint_characteristics=("Contract marks authentication as required",),
        required_authentication=("Deliberately unauthenticated request",), passive=False,
        safety_prerequisites=("Owned assessment", "Current approved endpoint", "Recorded authorization", "In-scope read-only method"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",),
        expected_evidence=("HTTP status code only",),
        outcome_interpretation={"CANDIDATE_FOUND": "A contract-protected endpoint returned success without credentials; validate the expected policy.",
                                "NO_ISSUE_OBSERVED": "The unauthenticated request received 401 or 403.",
                                "INCONCLUSIVE": "The response did not establish the authentication requirement."},
        permissions=("Authenticated analyst", "Assessment owner"), evaluate=_unauthenticated_access,
        owasp_categories=("API2:2023",), required_inputs=("Approved endpoint marked auth required",),
        allows_unauthenticated_probe=True, requires_auth_protected_endpoint=True, max_response_bytes=1024,
    ),
    "authorization.sensitive_property_observation": TestDefinition(
        identifier="authorization.sensitive_property_observation", version="1.0.0",
        name="Sensitive-looking JSON property observation", category="Authorization",
        purpose="Inspect one successful JSON response for common sensitive or privileged property names while discarding all values.",
        limitations="Name-based heuristic only; it does not prove unauthorized disclosure or validate the approved property schema or caller role.",
        supported_methods=("GET",), endpoint_characteristics=("Successful JSON response", "Unauthenticated endpoint"),
        required_authentication=("No authentication",), passive=False,
        safety_prerequisites=("Owned assessment", "Current approved endpoint", "Recorded authorization", "In-scope GET"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",),
        expected_evidence=("HTTP status", "response byte count", "fixed sensitive-property category labels only"),
        outcome_interpretation={"CANDIDATE_FOUND": "Sensitive-looking property categories were observed; verify the schema and access policy.",
                                "NO_ISSUE_OBSERVED": "No configured property names were observed in the bounded JSON response.",
                                "INCONCLUSIVE": "Response was not a supported JSON success."},
        permissions=("Authenticated analyst", "Assessment owner"), evaluate=_sensitive_property_observation,
        owasp_categories=("API3:2023",), max_response_bytes=512_000,
    ),
    "resource.rate_limit_observation": TestDefinition(
        identifier="resource.rate_limit_observation", version="1.0.0",
        name="Rate-limit metadata observation", category="Input Validation",
        purpose="Record quota-related headers from one authorized response without sending repeated requests.",
        limitations="A single request cannot test enforcement, burst behavior, or resource limits. The result is always inconclusive and should be compared with client-provided policy.",
        supported_methods=("GET", "HEAD"), endpoint_characteristics=("One normal response only",),
        required_authentication=("No authentication",), passive=False,
        safety_prerequisites=("Owned assessment", "Current approved endpoint", "Recorded authorization", "In-scope read-only method"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",),
        expected_evidence=("HTTP status", "quota header names only", "whether response status was 429"),
        outcome_interpretation={"INCONCLUSIVE": "One response cannot establish resource-consumption limits."},
        permissions=("Authenticated analyst", "Assessment owner"), evaluate=_rate_limit_observation,
        owasp_categories=("API4:2023",), max_response_bytes=1024,
    ),
    "authorization.bola.synthetic_pair": TestDefinition(
        identifier="authorization.bola.synthetic_pair", version="1.0.0",
        name="BOLA check with two synthetic objects", category="Authorization",
        purpose="Compare two client-provisioned test identities against only their own synthetic object IDs on one approved read endpoint.",
        limitations="Status-only, one endpoint and two synthetic objects. A valid owner-access control is required; this does not establish route-wide or tenant-wide authorization.",
        supported_methods=("GET",), endpoint_characteristics=("Authentication required", "Declared path parameter for synthetic object ID"),
        required_authentication=("Two active client-provisioned bearer test identities",), passive=False,
        safety_prerequisites=("Owned assessment", "Current approved GET endpoint", "Recorded authorization",
                              "Two disposable test identities", "Two existing synthetic objects with known owners"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",),
        expected_evidence=("identity labels and roles", "own/cross relation", "HTTP status codes only"),
        outcome_interpretation={"CANDIDATE_FOUND": "A cross-identity request returned success; confirm the synthetic ownership oracle.",
                                "NO_ISSUE_OBSERVED": "Both owner controls succeeded and cross-identity requests were denied.",
                                "INCONCLUSIVE": "Owner access or clear cross-identity outcomes were unavailable."},
        permissions=("Authenticated analyst", "Assessment owner"), evaluate=_bola_synthetic_pair,
        owasp_categories=("API1:2023",),
        required_inputs=("Select two active test identities", "Select one declared path parameter", "Provide two different existing synthetic object IDs"),
        requires_auth_protected_endpoint=True, supports_authenticated_execution=True,
        required_test_identity_count=2, workflow="BOLA", max_requests=4, max_duration_seconds=90,
        max_response_bytes=262_144, redirect_limit=0,
    ),
    "authorization.function_role_pair": TestDefinition(
        identifier="authorization.function_role_pair", version="1.0.0",
        name="Function-level access check with approved role pair", category="Authorization",
        purpose="Compare one client-designated allowed role and one denied role on the same approved read-only endpoint.",
        limitations="Status-only, one endpoint and two client-provisioned identities. It does not infer role policy or test mutation, admin workflows, or alternate routes.",
        supported_methods=("GET",), endpoint_characteristics=("Authentication required", "Client-provided allow/deny role matrix"),
        required_authentication=("Two active client-provisioned bearer test identities",), passive=False,
        safety_prerequisites=("Owned assessment", "Current approved GET endpoint", "Recorded authorization",
                              "Two disposable test identities", "Client-confirmed expected endpoint-to-role matrix"),
        execution_gates=("APISENTINEL_ALLOW_ACTIVE_TESTS",),
        expected_evidence=("identity labels and roles", "expected allow/deny", "HTTP status codes only"),
        outcome_interpretation={"CANDIDATE_FOUND": "The client-designated denied identity received success; review the role matrix.",
                                "NO_ISSUE_OBSERVED": "The allowed identity succeeded and denied identity was rejected.",
                                "INCONCLUSIVE": "The role oracle or a clear response was unavailable."},
        permissions=("Authenticated analyst", "Assessment owner"), evaluate=_function_role_pair,
        owasp_categories=("API5:2023",),
        required_inputs=("Select two active test identities", "Choose which identity is explicitly allowed for this endpoint"),
        requires_auth_protected_endpoint=True, supports_authenticated_execution=True,
        required_test_identity_count=2, workflow="BFLA", max_requests=2, max_duration_seconds=90,
        max_response_bytes=262_144, redirect_limit=0,
    ),
}


def enabled_test_ids(configured: str | tuple[str, ...] | list[str] | None = None) -> set[str]:
    if configured is None:
        from .config import settings
        configured = settings.enabled_security_tests
    values = configured.split(",") if isinstance(configured, str) else configured
    return {str(value).strip() for value in values if str(value).strip()}


def public_registry(configured=None) -> list[dict]:
    enabled = enabled_test_ids(configured)
    return [definition.public(enabled=identifier in enabled)
            for identifier, definition in sorted(REGISTRY.items())]


def resolve_test(identifier: str, configured=None) -> TestDefinition:
    definition = REGISTRY.get(identifier)
    if definition is None:
        raise KeyError("Unknown security test identifier")
    if identifier not in enabled_test_ids(configured):
        raise PermissionError("Security test is disabled by server configuration")
    return definition
