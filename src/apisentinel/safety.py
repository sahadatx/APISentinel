import re
from fnmatch import fnmatch
from urllib.parse import unquote, urlparse

from fastapi import HTTPException

from .models import Assessment

_SENSITIVE_EVIDENCE_KEYS = {
    "authorization", "token", "access_token", "refresh_token", "password", "secret",
    "api_key", "cookie", "set-cookie", "set_cookie", "body", "request_body", "response_body",
    "raw_request", "raw_response", "response_excerpt",
}
_SECRET_TEXT = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+|"
    r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|token)\s*[:=]\s*[^\s,;&]+"
)


def validate_target(assessment: Assessment, target: str, *, allow_http: bool = False, method: str = "GET") -> str:
    """Validate URL against explicit assessment scope. DNS/IP resolution is intentionally absent."""
    parsed = urlparse(target)
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme.lower() not in allowed_schemes or not parsed.hostname:
        raise HTTPException(403, "Target scheme is not permitted")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(403, "URL user information is not permitted")
    host = parsed.hostname.lower().rstrip(".")
    allowed = [h.lower().rstrip(".") for h in (assessment.allowed_hosts or [])]
    from .authorization import authorization_allows

    if not authorization_allows(assessment, method):
        raise HTTPException(403, "A current reviewed authorization for this method and scope is required")
    if not any(host == h or host.endswith("." + h) for h in allowed):
        raise HTTPException(403, "Target host is outside the assessment scope")
    raw_path = parsed.path or "/"
    if re.search(r"%(?![0-9a-fA-F]{2})", raw_path) or "\\" in raw_path or any(ord(char) < 32 for char in raw_path):
        raise HTTPException(403, "Malformed target path")
    path = raw_path
    try:
        for _ in range(8):
            decoded = unquote(path, errors="strict")
            if any(segment in {".", ".."} for segment in decoded.split("/")):
                raise HTTPException(403, "Path traversal is not permitted")
            if decoded == path:
                break
            path = decoded
        else:
            raise HTTPException(403, "Excessively encoded target path")
    except UnicodeDecodeError:
        raise HTTPException(403, "Malformed target path") from None
    paths = assessment.allowed_paths or ["/**"]
    if not any(fnmatch(path, p) or (p.endswith("/**") and path.startswith(p[:-3])) for p in paths):
        raise HTTPException(403, "Target path is outside the assessment scope")
    if any(fnmatch(path, p) for p in (assessment.excluded_paths or [])):
        raise HTTPException(403, "Target path is explicitly excluded")
    return target


def sanitize_evidence(value):
    """Mask credential material and body-like fields recursively before persistence/export."""
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower().replace("-", "_") in _SENSITIVE_EVIDENCE_KEYS else sanitize_evidence(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_evidence(v) for v in value]
    if isinstance(value, str):
        return _SECRET_TEXT.sub("[REDACTED]", value)
    return value
