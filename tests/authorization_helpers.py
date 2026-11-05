from datetime import UTC, datetime, timedelta

from apisentinel.authorization import authorization_scope_snapshot, scope_fingerprint


def activate_local_authorization(assessment, analyst_id: int, *, methods=None, now=None):
    instant = now or datetime.now(UTC)
    permitted = list(methods or ["GET", "HEAD", "OPTIONS"])
    snapshot = authorization_scope_snapshot(assessment, permitted)
    assessment.authorization_reference = "test-only local fixture"
    assessment.authorization_confirmed = True
    assessment.authorization_status = "ACTIVE"
    assessment.authorization_scope_snapshot = snapshot
    assessment.authorization_scope_hash = scope_fingerprint(snapshot)
    assessment.authorization_methods = permitted
    assessment.authorization_valid_from = instant - timedelta(minutes=5)
    assessment.authorization_expires_at = instant + timedelta(hours=1)
    assessment.authorization_party = "Local test API owner"
    assessment.authorization_recorded_by_id = analyst_id
    assessment.authorization_recorded_at = instant - timedelta(minutes=1)
    assessment.authorization_reviewed_by_id = analyst_id
    assessment.authorization_reviewed_at = instant
    assessment.authorization_reason = "Isolated local test fixture authorization"
    return assessment
