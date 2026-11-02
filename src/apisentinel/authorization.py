"""Assessment authorization attestation and execution-gate helpers.

This records an analyst's review of supplied authorization metadata. It does
not authenticate the legal authority or authenticity of the referenced proof.
"""
import hashlib
import json
from datetime import UTC, datetime

SUPPORTED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def authorization_scope_snapshot(assessment, methods: list[str] | tuple[str, ...]) -> dict:
    return {
        "environment": str(assessment.environment or "").strip().lower(),
        "hosts": sorted({str(value).strip().lower().rstrip(".") for value in (assessment.allowed_hosts or [])}),
        "paths": sorted({str(value).strip() for value in (assessment.allowed_paths or [])}),
        "exclusions": sorted({str(value).strip() for value in (assessment.excluded_paths or [])}),
        "methods": sorted({str(value).strip().upper() for value in methods}),
        "max_requests_per_minute": int(assessment.max_requests_per_minute or 30),
        "testing_window_start": str(assessment.testing_window_start or ""),
        "testing_window_end": str(assessment.testing_window_end or ""),
    }


def scope_fingerprint(snapshot: dict) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def parse_testing_window(start: str | None, end: str | None) -> tuple[datetime | None, datetime | None]:
    """Return an optional timezone-aware, half-open testing window in UTC."""
    start_text, end_text = str(start or "").strip(), str(end or "").strip()
    if not start_text and not end_text:
        return None, None
    if not start_text or not end_text:
        raise ValueError("Testing window start and end must both be provided")

    def parse(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            raise ValueError("Testing window values must be ISO 8601 timestamps") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("Testing window timestamps must include a timezone")
        return parsed.astimezone(UTC)

    start_at, end_at = parse(start_text), parse(end_text)
    if start_at >= end_at:
        raise ValueError("Testing window end must be later than its start")
    return start_at, end_at


def authorization_state(assessment, *, now: datetime | None = None) -> str:
    status = str(assessment.authorization_status or "REVIEW_REQUIRED")
    if status == "REVOKED":
        return "REVOKED"
    methods = list(assessment.authorization_methods or [])
    valid_from, expires_at = _utc(assessment.authorization_valid_from), _utc(assessment.authorization_expires_at)
    recorded = bool(
        assessment.authorization_reference.strip()
        and assessment.authorization_party.strip()
        and assessment.authorization_recorded_by_id
        and assessment.authorization_recorded_at
        and assessment.authorization_scope_hash
        and methods and set(methods).issubset(SUPPORTED_METHODS)
        and valid_from and expires_at and valid_from < expires_at
    )
    if not recorded:
        return "REVIEW_REQUIRED"
    current_snapshot = authorization_scope_snapshot(assessment, methods)
    if scope_fingerprint(current_snapshot) != assessment.authorization_scope_hash:
        return "REVIEW_REQUIRED"
    try:
        window_start, window_end = parse_testing_window(
            assessment.testing_window_start, assessment.testing_window_end,
        )
    except ValueError:
        return "REVIEW_REQUIRED"
    instant = _utc(now or datetime.now(UTC))
    if expires_at <= instant:
        return "EXPIRED"
    if valid_from > instant:
        return "SCHEDULED"
    if status == "RECORDED":
        return "RECORDED"
    if status != "ACTIVE" or not assessment.authorization_reviewed_by_id or not assessment.authorization_reviewed_at:
        return "REVIEW_REQUIRED"
    if window_start and instant < window_start:
        return "SCHEDULED"
    if window_end and instant >= window_end:
        return "WINDOW_CLOSED"
    return "ACTIVE"


def authorization_allows(assessment, method: str, *, now: datetime | None = None) -> bool:
    return (str(getattr(assessment, "status", "")) != "Archived"
            and authorization_state(assessment, now=now) == "ACTIVE"
            and method.upper() in set(assessment.authorization_methods or []))


def legacy_authorization_only(assessment) -> bool:
    return bool(assessment.authorization_confirmed or (assessment.authorization_reference or "").strip()) and authorization_state(assessment) == "REVIEW_REQUIRED"
