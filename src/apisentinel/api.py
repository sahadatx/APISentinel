import base64
import csv
import hashlib
import io
import json
import re
import warnings
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatch
from html import escape
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from pydantic import ValidationError
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from . import models, schemas
from .access import ALL_CLIENT_ROLES, client_access_filter
from .auth import analyst_from_request, require_analyst
from .authorization import (
    authorization_allows,
    authorization_scope_snapshot,
    authorization_state,
    parse_testing_window,
    scope_fingerprint,
)
from .burp_findings_import import (
    ADAPTER_ID as BURP_ADAPTER_ID,
)
from .burp_findings_import import (
    ADAPTER_VERSION as BURP_ADAPTER_VERSION,
)
from .burp_findings_import import (
    BurpImportError,
    parse_burp_scanner_xml,
)
from .collection_import import (
    android_capture_to_openapi,
    burp_to_openapi,
    har_to_openapi,
    postman_to_openapi,
)
from .config import settings
from .credential_vault import DatabaseCredentialResolver, encrypt_bearer
from .cvss import calculate_cvss_v31
from .db import get_db
from .discovery import import_openapi, parse_import_envelope
from .finding_analysis import finding_analysis_fields
from .graphql_import import parse_graphql_introspection
from .job_queue import idempotency_digest
from .manual_review_catalog import FRAMEWORKS as MANUAL_REVIEW_FRAMEWORKS
from .manual_review_catalog import control_for as manual_review_control_for
from .manual_review_catalog import public_catalog as manual_review_public_catalog
from .request_builder import RequestBuildError, build_request
from .runner import BearerTokenReference, RequestOutcome, RequestPolicy, RunnerResult, run_request
from .safety import sanitize_evidence, validate_target
from .secrets import encrypt_secret, encryption_configured
from .test_registry import (
    REGISTRY,
    SecurityOutcome,
    classify_execution,
    evaluate_safely,
    public_registry,
    resolve_test,
)

router = APIRouter(dependencies=[Depends(require_analyst)])

MAX_APK_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_IPA_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_AUTHORIZATION_EVIDENCE_BYTES = 10 * 1024 * 1024
MAX_FINDING_IMAGE_BYTES = 8 * 1024 * 1024
MAX_FINDING_IMAGE_STORED_BYTES = 2 * 1024 * 1024
MAX_FINDING_ATTACHMENTS = 5


async def _parse_apk_isolated(blob: bytes) -> dict:

    if not settings.apk_parser_url:
        raise HTTPException(503, "Isolated APK parser is not configured")
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                     timeout=httpx.Timeout(12, connect=2)) as client:
            response = await client.post(settings.apk_parser_url + "/parse",
                                         content=blob,
                                         headers={"Content-Type": "application/vnd.android.package-archive"})
    except httpx.HTTPError:
        raise HTTPException(503, "Isolated APK parser is unavailable") from None
    if response.status_code == 422:
        raise HTTPException(422, "APK could not be parsed safely")
    if response.status_code != 200:
        raise HTTPException(503, "Isolated APK parser returned an invalid response")
    try:
        result = response.json()
        package = result["package_name"]
        version_name = result.get("version_name", "")
        version_code = result.get("version_code", 0)
        api_level = result.get("api_level")
        metadata = result.get("metadata", {})
        if (not isinstance(package, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", package)
                or not isinstance(version_name, str) or len(version_name) > 200
                or not isinstance(version_code, int) or not 0 <= version_code <= 2**31 - 1
                or (api_level is not None and (not isinstance(api_level, int) or not 1 <= api_level <= 1000))
                or not isinstance(metadata, dict)):
            raise ValueError
        return {"package_name": package, "version_name": version_name,
                "version_code": version_code, "api_level": api_level,
                "metadata": sanitize_evidence(metadata)}
    except (ValueError, KeyError, TypeError):
        raise HTTPException(503, "Isolated APK parser returned invalid metadata") from None


async def _parse_ipa_isolated(blob: bytes) -> dict:
    if not settings.apk_parser_url:
        raise HTTPException(503, "Isolated mobile artifact parser is not configured")
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                     timeout=httpx.Timeout(20, connect=2)) as client:
            response = await client.post(settings.apk_parser_url + "/parse-ipa", content=blob,
                                         headers={"Content-Type": "application/octet-stream"})
    except httpx.HTTPError:
        raise HTTPException(503, "Isolated iOS metadata parser is unavailable") from None
    if response.status_code == 422:
        raise HTTPException(422, "IPA could not be parsed safely")
    if response.status_code != 200:
        raise HTTPException(503, "Isolated iOS metadata parser returned an invalid response")
    try:
        result = response.json()
        bundle_id = result["bundle_id"]
        metadata = result.get("metadata", {})
        if (not isinstance(bundle_id, str) or
                not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", bundle_id) or
                not isinstance(metadata, dict)):
            raise ValueError
        return {
            "bundle_id": bundle_id,
            "display_name": str(result.get("display_name", ""))[:200],
            "version_name": str(result.get("version_name", ""))[:100],
            "build_number": str(result.get("build_number", ""))[:40],
            "minimum_os_version": str(result.get("minimum_os_version", ""))[:40],
            "metadata": sanitize_evidence(metadata),
        }
    except (ValueError, KeyError, TypeError):
        raise HTTPException(503, "Isolated iOS parser returned invalid metadata") from None

FINDING_TRANSITIONS = {
    "Candidate": {"Needs Review"},
    "Needs Review": {"Confirmed", "False Positive", "Accepted Risk", "Remediation In Progress", "Closed"},
    "Confirmed": {"Accepted Risk", "Remediation In Progress", "Retest Required", "Closed"},
    "False Positive": {"Needs Review"},
    "Accepted Risk": {"Needs Review", "Remediation In Progress", "Retest Required", "Closed"},
    "Remediation In Progress": {"Accepted Risk", "Retest Required", "Closed"},
    "Retest Required": {"Accepted Risk", "Remediation In Progress", "Closed"},
    "Resolved": {"Retest Required"},
    "Closed": {"Needs Review"},
    # Legacy states remain readable and can be explicitly moved into the new lifecycle.
    "Fixed": {"Retest Required", "Closed"},
    "Retested": {"Needs Review", "Retest Required"},
}
VALIDATION_TRANSITIONS = {
    "PENDING_VALIDATION": {"NEEDS_REVIEW", "VALIDATED", "REJECTED", "INCONCLUSIVE"},
    "NEEDS_REVIEW": {"VALIDATED", "REJECTED", "INCONCLUSIVE"},
    "VALIDATED": {"NEEDS_REVIEW", "REJECTED", "INCONCLUSIVE"},
    "REJECTED": {"NEEDS_REVIEW"},
    "INCONCLUSIVE": {"NEEDS_REVIEW", "VALIDATED", "REJECTED"},
}


def _client_role(db: Session, client: models.Client, analyst_id: int) -> str | None:
    if client.owner_user_id == analyst_id:
        return "owner"
    membership = db.query(models.ClientMembership).filter_by(client_id=client.id, analyst_id=analyst_id).first()
    return membership.role if membership else None


def _validate_assessment_team(db: Session, client: models.Client, details: dict, *, default_assignee_id: int) -> dict:
    memberships = (db.query(models.ClientMembership.analyst_id, models.ClientMembership.role)
                   .join(models.Analyst, models.Analyst.id == models.ClientMembership.analyst_id)
                   .filter(models.ClientMembership.client_id == client.id, models.Analyst.is_active.is_(True)).all())
    owner = db.get(models.Analyst, client.owner_user_id)
    roles = ({client.owner_user_id: "owner"} if owner and owner.is_active else {})
    roles.update({analyst_id: role for analyst_id, role in memberships})
    result = dict(details or {})
    assignee_id = result.get("assigned_analyst_id") or default_assignee_id
    if roles.get(assignee_id) not in {"owner", "analyst"}:
        raise HTTPException(422, "Assigned analyst must have owner or analyst access to this client")
    reviewer_id = result.get("reviewer_id")
    if reviewer_id is not None and roles.get(reviewer_id) not in {"owner", "reviewer"}:
        raise HTTPException(422, "Reviewer must be the client owner or have reviewer access")
    result["assigned_analyst_id"] = assignee_id
    return result


def _require_client_role(db: Session, client: models.Client, analyst_id: int, roles: tuple[str, ...]):
    role = _client_role(db, client, analyst_id)
    if role is None:
        raise HTTPException(404, "Client not found")
    if role != "owner" and role not in roles:
        raise HTTPException(403, "Client membership does not allow this action")
    return client


def owned_client_or_404(db: Session, client_id: int, analyst_id: int, *, required_roles: tuple[str, ...] = ("analyst",)):
    obj = db.query(models.Client).filter(models.Client.id == client_id,
                                         client_access_filter(analyst_id)).first()
    if obj is None:
        raise HTTPException(404, "Client not found")
    return _require_client_role(db, obj, analyst_id, required_roles)


def owned_assessment_or_404(db: Session, assessment_id: int, analyst_id: int,
                            *, required_roles: tuple[str, ...] = ("analyst",)):
    obj = (
        db.query(models.Assessment)
        .join(models.Client, models.Assessment.client_id == models.Client.id)
        .filter(models.Assessment.id == assessment_id, client_access_filter(analyst_id))
        .first()
    )
    if obj is None:
        raise HTTPException(404, "Assessment not found")
    _require_client_role(db, obj.client, analyst_id, required_roles)
    return obj


def owned_finding_or_404(db: Session, finding_id: int, analyst_id: int,
                         *, required_roles: tuple[str, ...] = ("analyst",)):
    obj = (
        db.query(models.Finding)
        .join(models.Assessment, models.Finding.assessment_id == models.Assessment.id)
        .join(models.Client, models.Assessment.client_id == models.Client.id)
        .filter(models.Finding.id == finding_id, client_access_filter(analyst_id))
        .first()
    )
    if obj is None:
        raise HTTPException(404, "Finding not found")
    _require_client_role(db, obj.assessment.client, analyst_id, required_roles)
    return obj


def _finding_read_payload(obj: models.Finding) -> dict:
    payload = schemas.FindingRead.model_validate(obj).model_dump()
    if not payload.get("risk_analysis"):
        normalized = finding_analysis_fields(
            assessment_id=obj.assessment_id, endpoint_id=obj.endpoint_id,
            test_id=(obj.evidence or {}).get("test_id"),
            test_version=(obj.evidence or {}).get("test_version"),
            category=obj.vulnerability_category, severity=obj.severity,
            confidence=obj.confidence, confidence_rationale=obj.confidence_rationale,
            remediation_guidance_type=obj.remediation_guidance_type,
        )
        payload.update(normalized)
    payload["evidence_attachments"] = [finding_attachment_metadata(item)
                                       for item in sorted(obj.evidence_attachments, key=lambda item: item.id)]
    return payload


def finding_attachment_metadata(item: models.FindingEvidenceAttachment) -> dict:
    return {"id": item.id, "finding_id": item.finding_id, "filename": item.filename,
            "mime_type": item.mime_type, "caption": item.caption, "sha256": item.sha256,
            "width": item.width, "height": item.height,
            "created_at": item.created_at.isoformat() if item.created_at else None}


def assessment_read_payload(assessment):
    status = authorization_state(assessment)
    payload = schemas.AssessmentRead.model_validate(assessment).model_dump()
    payload["authorization_status"] = status
    # Keep the legacy response key, but never let its old database value imply
    # that an unreviewed authorization is current.
    payload["authorization_confirmed"] = status == "ACTIVE"
    payload["target_configs"] = sanitize_evidence(payload.get("target_configs") or {})
    payload["engagement_details"] = sanitize_evidence(payload.get("engagement_details") or {})
    return payload


def _utc_range(start_at: datetime | None, end_at: datetime | None):
    if start_at is not None and start_at.tzinfo is None:
        raise HTTPException(422, "start_at must include a timezone")
    if end_at is not None and end_at.tzinfo is None:
        raise HTTPException(422, "end_at must include a timezone")
    start = start_at.astimezone(UTC) if start_at else None
    end = end_at.astimezone(UTC) if end_at else None
    if start and end and start >= end:
        raise HTTPException(422, "start_at must be earlier than end_at")
    return start, end


def _created_in_range(query, column, start, end):
    if start is not None:
        query = query.filter(column >= start)
    if end is not None:
        query = query.filter(column < end)
    return query


def _grouped_counts(db: Session, query, column) -> dict[str, int]:
    rows = query.with_entities(column, func.count()).group_by(column).all()
    return {str(key if key is not None else "UNKNOWN"): int(count) for key, count in rows}


@router.get("/dashboard", response_model=schemas.DashboardRead)
def dashboard(request: Request, db: Session = Depends(get_db),
              start_at: datetime | None = None, end_at: datetime | None = None):
    analyst_id = analyst_from_request(request).id
    start, end = _utc_range(start_at, end_at)
    clients_q = _created_in_range(db.query(models.Client).filter(client_access_filter(analyst_id)),
                                  models.Client.created_at, start, end)
    assessments_q = _created_in_range(db.query(models.Assessment).join(models.Client)
                                      .filter(client_access_filter(analyst_id)), models.Assessment.created_at, start, end)
    # Endpoint has no persisted creation timestamp, so current inventory remains
    # an all-time snapshot even when the other metrics use a date range.
    endpoints_q = db.query(models.Endpoint).join(models.Assessment).join(models.Client).filter(
        client_access_filter(analyst_id), models.Endpoint.inventory_current.is_(True))
    findings_q = _created_in_range(db.query(models.Finding).join(models.Assessment).join(models.Client)
                                   .filter(client_access_filter(analyst_id)), models.Finding.created_at, start, end)
    reports_q = _created_in_range(db.query(models.Report).join(models.Assessment).join(models.Client)
                                  .filter(client_access_filter(analyst_id)), models.Report.created_at, start, end)
    retests_q = _created_in_range(db.query(models.Retest).join(models.Finding).join(models.Assessment)
                                  .join(models.Client).filter(client_access_filter(analyst_id)), models.Retest.created_at, start, end)
    audit_q = _created_in_range(db.query(models.ExecutionAuditEvent).join(models.Client)
                                .filter(client_access_filter(analyst_id)), models.ExecutionAuditEvent.created_at, start, end)
    runs_q = _created_in_range(db.query(models.TestRun).join(models.Assessment).join(models.Client)
                               .filter(client_access_filter(analyst_id)), models.TestRun.created_at, start, end)
    recent_assessments = assessments_q.order_by(models.Assessment.created_at.desc(), models.Assessment.id.desc()).limit(6).all()
    recent_findings = findings_q.order_by(models.Finding.created_at.desc(), models.Finding.id.desc()).limit(6).all()
    activity_rows = audit_q.order_by(models.ExecutionAuditEvent.created_at.desc(),
                                     models.ExecutionAuditEvent.id.desc()).limit(10).all()
    return {
        "time_range": {"start_at": start.isoformat() if start else None,
                       "end_at_exclusive": end.isoformat() if end else None,
                       "timezone": "UTC", "semantics": "created_at >= start_at and created_at < end_at",
                       "endpoint_inventory": "current all-time inventory; not date-filtered because Endpoint has no creation timestamp"},
        "clients": clients_q.count(), "assessments": assessments_q.count(),
        "assessment_status": _grouped_counts(db, assessments_q, models.Assessment.status),
        "assessment_type": _grouped_counts(db, assessments_q, models.Assessment.assessment_type),
        "endpoints": endpoints_q.count(),
        "approved_endpoint_count": endpoints_q.filter(models.Endpoint.review_state == "APPROVED").count(),
        "execution_approved_endpoint_count": endpoints_q.filter(
            models.Endpoint.review_state == "APPROVED", models.Endpoint.execution_approved.is_(True)).count(),
        "endpoint_review_state": _grouped_counts(db, endpoints_q, models.Endpoint.review_state),
        "findings": findings_q.count(),
        "finding_severity": _grouped_counts(db, findings_q, models.Finding.severity),
        "finding_validation_state": _grouped_counts(db, findings_q, models.Finding.validation_state),
        "finding_triage_status": _grouped_counts(db, findings_q, models.Finding.status),
        "finding_open_count": findings_q.filter(~models.Finding.status.in_(
            {"Closed", "Resolved", "False Positive", "Accepted Risk"})).count(),
        "finding_resolved_count": findings_q.filter(models.Finding.remediation_status == "VERIFIED_FIXED").count(),
        "finding_validated_count": findings_q.filter(models.Finding.validation_state == "VALIDATED").count(),
        "finding_unvalidated_count": findings_q.filter(models.Finding.validation_state.in_(
            {"PENDING_VALIDATION", "NEEDS_REVIEW", "INCONCLUSIVE"})).count(),
        "finding_rejected_count": findings_q.filter(models.Finding.validation_state == "REJECTED").count(),
        "finding_accepted_risk_count": findings_q.filter(models.Finding.status == "Accepted Risk").count(),
        "remediation_status": _grouped_counts(db, findings_q, models.Finding.remediation_status),
        "remediation_overdue_count": findings_q.filter(
            models.Finding.remediation_target_date < datetime.now(UTC).date(),
            ~models.Finding.remediation_status.in_({"VERIFIED_FIXED", "CLOSED", "ACCEPTED_RISK"})).count(),
        "retest_outcome": _grouped_counts(db, retests_q, models.Retest.outcome),
        "execution_status": _grouped_counts(db, runs_q, models.TestRun.status),
        "security_outcome": _grouped_counts(db, runs_q, models.TestRun.security_outcome),
        "reports": reports_q.count(), "report_status": _grouped_counts(db, reports_q, models.Report.status),
        "recent_assessments": [assessment_read_payload(row) for row in recent_assessments],
        "recent_findings": [{"id": row.id, "assessment_id": row.assessment_id,
                              "title": row.title, "severity": row.severity, "status": row.status,
                              "validation_state": row.validation_state,
                              "remediation_status": row.remediation_status,
                              "created_at": row.created_at} for row in recent_findings],
        "recent_activity": [{"id": row.id, "actor_id": row.actor_id, "client_id": row.client_id,
                             "assessment_id": row.assessment_id, "test_run_id": row.test_run_id,
                             "finding_id": row.finding_id, "event_type": row.event_type,
                             "outcome": row.outcome, "metadata": sanitize_evidence(row.metadata_json or {}),
                             "created_at": row.created_at} for row in activity_rows],
    }


@router.get("/clients", response_model=list[schemas.ClientRead])
def clients(request: Request, db: Session = Depends(get_db), search: str = ""):
    q = db.query(models.Client).filter(client_access_filter(analyst_from_request(request).id))
    if search:
        q = q.filter(models.Client.name.ilike(f"%{search}%"))
    rows = q.order_by(models.Client.name).all()
    return [schemas.ClientRead.model_validate(row).model_dump() | {"access_role": _client_role(db, row, analyst_from_request(request).id)}
            for row in rows]


@router.post("/clients", response_model=schemas.ClientRead, status_code=201)
def create_client(data: schemas.ClientCreate, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    obj = models.Client(**data.model_dump(), owner_user_id=analyst_id)
    db.add(obj)
    db.flush()
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=obj.id,
                                      event_type="CLIENT_CREATED", outcome="CREATED",
                                      metadata_json={"status": obj.status}))
    db.commit(); db.refresh(obj)
    return schemas.ClientRead.model_validate(obj).model_dump() | {"access_role": "owner"}


@router.patch("/clients/{client_id}/status", response_model=schemas.ClientRead)
def update_client_status(client_id: int, data: schemas.ClientStatusUpdate,
                         request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    client = owned_client_or_404(db, client_id, analyst_id, required_roles=())
    if client.owner_user_id != analyst_id:
        raise HTTPException(403, "Only the client owner can change client status")
    if client.status != data.expected_status:
        raise HTTPException(409, "Client status changed; refresh and try again")
    previous_status = client.status
    if previous_status == data.status:
        return schemas.ClientRead.model_validate(client).model_dump() | {"access_role": "owner"}
    client.status = data.status
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=client.id, event_type="CLIENT_STATUS_CHANGED", outcome="UPDATED",
        metadata_json={"previous_status": previous_status, "status": client.status},
    ))
    db.commit()
    db.refresh(client)
    return schemas.ClientRead.model_validate(client).model_dump() | {"access_role": "owner"}


@router.get("/clients/{client_id}/members")
def client_members(client_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    client = owned_client_or_404(db, client_id, analyst_id, required_roles=())
    if client.owner_user_id != analyst_id:
        raise HTTPException(403, "Only the client owner can administer memberships")
    rows = (db.query(models.ClientMembership, models.Analyst)
            .join(models.Analyst, models.ClientMembership.analyst_id == models.Analyst.id)
            .filter(models.ClientMembership.client_id == client.id).order_by(models.Analyst.login_normalized).all())
    return [{"login": user.login_normalized, "role": member.role, "created_at": member.created_at}
            for member, user in rows]


@router.get("/clients/{client_id}/team")
def client_team(client_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    client = owned_client_or_404(db, client_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
    owner = db.get(models.Analyst, client.owner_user_id)
    rows = (db.query(models.ClientMembership, models.Analyst)
            .join(models.Analyst, models.ClientMembership.analyst_id == models.Analyst.id)
            .filter(models.ClientMembership.client_id == client.id, models.Analyst.is_active.is_(True))
            .order_by(models.Analyst.login_normalized).all())
    team = [{"id": client.owner_user_id, "login": owner.login_normalized if owner else "Client owner", "role": "owner"}]
    team.extend({"id": member.analyst_id, "login": user.login_normalized, "role": member.role}
                for member, user in rows)
    return team


@router.post("/clients/{client_id}/members", status_code=201)
def add_client_member(client_id: int, data: schemas.ClientMembershipCreate,
                      request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    client = db.query(models.Client).filter_by(id=client_id, owner_user_id=analyst_id).first()
    if client is None:
        raise HTTPException(404, "Client not found")
    login = data.login.strip().casefold()
    member = db.query(models.Analyst).filter_by(login_normalized=login, is_active=True).first()
    if member is None:
        raise HTTPException(404, "Active analyst account not found")
    if member.id == analyst_id:
        raise HTTPException(409, "Client owner already has full workspace access")
    existing = db.get(models.ClientMembership, (client.id, member.id))
    if existing:
        existing.role = data.role
        event_type = "CLIENT_MEMBER_ROLE_CHANGED"
    else:
        db.add(models.ClientMembership(client_id=client.id, analyst_id=member.id,
                                       role=data.role, granted_by_id=analyst_id))
        event_type = "CLIENT_MEMBER_ADDED"
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=client.id,
                                      event_type=event_type, outcome=data.role,
                                      metadata_json={"member_id": member.id, "role": data.role}))
    db.commit()
    return {"client_id": client.id, "login": member.login_normalized, "role": data.role}


@router.delete("/clients/{client_id}/members/{member_login}")
def remove_client_member(client_id: int, member_login: str, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    client = db.query(models.Client).filter_by(id=client_id, owner_user_id=analyst_id).first()
    if client is None:
        raise HTTPException(404, "Client not found")
    login = member_login.strip().casefold()
    member = db.query(models.Analyst).filter_by(login_normalized=login).first()
    membership = db.get(models.ClientMembership, (client.id, member.id)) if member else None
    if membership is None:
        raise HTTPException(404, "Client membership not found")
    db.delete(membership)
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=client.id,
                                      event_type="CLIENT_MEMBER_REMOVED", outcome="REVOKED",
                                      metadata_json={"member_id": member.id}))
    db.commit()
    return {"removed": True}


@router.get("/assessments", response_model=list[schemas.AssessmentRead])
def assessments(request: Request, response: Response, db: Session = Depends(get_db),
                client_id: int | None = None, search: str = "", assessment_type: str | None = None,
                environment: str | None = None, status: str | None = None,
                authorization_status_filter: str | None = None,
                limit: int = 500, offset: int = 0):
    analyst_id = analyst_from_request(request).id
    q = db.query(models.Assessment).join(models.Client).filter(client_access_filter(analyst_id))
    if client_id is not None:
        owned_client_or_404(db, client_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
        q = q.filter(models.Assessment.client_id == client_id)
    if assessment_type:
        if assessment_type not in {"WEB_API", "ANDROID_API", "BOTH"}:
            raise HTTPException(422, "Unsupported assessment type filter")
        q = q.filter(models.Assessment.assessment_type == assessment_type)
    if environment:
        if environment not in {"development", "staging", "production", "lab"}:
            raise HTTPException(422, "Unsupported environment filter")
        q = q.filter(models.Assessment.environment == environment)
    if status:
        if status not in {"Draft", "Scope Review", "Ready", "Running", "Completed", "Failed", "Cancelled", "Archived"}:
            raise HTTPException(422, "Unsupported assessment status filter")
        q = q.filter(models.Assessment.status == status)
    if search.strip():
        q = q.filter(models.Assessment.name.ilike(f"%{search.strip()[:100]}%"))
    if authorization_status_filter:
        # Authorization status is derived from the current versioned scope.
        # Filter the already tenant-scoped, bounded list rather than trusting a stored status.
        rows = q.order_by(models.Assessment.created_at.desc()).limit(5000).all()
        filtered = [row for row in rows if authorization_state(row) == authorization_status_filter]
        response.headers["X-Total-Count"] = str(len(filtered))
        return [assessment_read_payload(row) for row in filtered[max(0, offset):max(0, offset) + min(max(limit, 1), 500)]]
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    bounded_limit = min(max(limit, 1), 500)
    return [assessment_read_payload(row) for row in q.order_by(models.Assessment.created_at.desc(), models.Assessment.id.desc())
            .offset(max(offset, 0)).limit(bounded_limit).all()]


@router.post("/assessments", response_model=schemas.AssessmentRead, status_code=201)
def create_assessment(data: schemas.AssessmentCreate, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    client = owned_client_or_404(db, data.client_id, analyst_id)
    values = data.model_dump()
    # Legacy UI/input fields are not authorization evidence and cannot activate
    # the new gate, including when an assessment is first created.
    values["authorization_confirmed"] = False
    values["authorization_reference"] = ""
    values["created_by_id"] = analyst_id
    values["description"] = sanitize_evidence(values["description"])
    values["target_configs"] = sanitize_evidence(values["target_configs"])
    values["engagement_details"] = data.engagement_details.model_dump(mode="json")
    values["engagement_details"] = _validate_assessment_team(
        db, client, values["engagement_details"], default_assignee_id=analyst_id,
    )
    obj = models.Assessment(**values)
    db.add(obj)
    db.flush()
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=client.id,
                                      assessment_id=obj.id, event_type="ASSESSMENT_CREATED",
                                      outcome="DRAFT", metadata_json={
                                          "assessment_type": obj.assessment_type,
                                          "environment": obj.environment,
                                          "configuration_version": obj.configuration_version,
                                          "target_sources": sorted(obj.target_configs),
                                          "network_execution": False,
                                      }))
    db.commit(); db.refresh(obj)
    return assessment_read_payload(obj)


@router.get("/assessments/{assessment_id}", response_model=schemas.AssessmentRead)
def assessment_detail(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    return assessment_read_payload(owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES))


@router.patch("/assessments/{assessment_id}", response_model=schemas.AssessmentRead)
def update_assessment(assessment_id: int, data: schemas.AssessmentUpdate, request: Request,
                      db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    assessment = (db.query(models.Assessment).filter_by(id=assessment.id)
                  .with_for_update().populate_existing().first())
    if assessment.configuration_version != data.expected_configuration_version:
        raise HTTPException(409, "Assessment configuration changed; reload before saving")
    if db.query(models.TestRun).filter(models.TestRun.assessment_id == assessment.id,
                                       models.TestRun.status.in_(["RUNNING", "QUEUED"])).first():
        raise HTTPException(409, "Assessment configuration cannot change while an execution is running")
    if assessment.status == "Archived":
        raise HTTPException(409, "Archived assessments are read-only")
    updates = data.model_dump(exclude_unset=True, mode="json")
    updates.pop("expected_configuration_version", None)
    if not updates:
        raise HTTPException(422, "No assessment changes were supplied")
    if any(value is None for value in updates.values()):
        raise HTTPException(422, "Assessment configuration values cannot be null")
    try:
        parse_testing_window(
            updates.get("testing_window_start", assessment.testing_window_start),
            updates.get("testing_window_end", assessment.testing_window_end),
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    target_type = updates.get("assessment_type", assessment.assessment_type)
    target_configs = updates.get("target_configs", assessment.target_configs or {})
    if ((target_type == "WEB_API" and "android_api" in target_configs)
            or (target_type == "ANDROID_API" and "web_api" in target_configs)):
        raise HTTPException(422, "Target configuration does not match the selected assessment type")
    target_environment = updates.get("environment", assessment.environment)
    if target_environment == "production" and any(
            config.get("base_url") and urlsplit(config["base_url"]).scheme != "https"
            for platform, config in target_configs.items()
            if platform in {"web_api", "android_api"} and isinstance(config, dict)):
        raise HTTPException(422, "Production target base URLs must use HTTPS")
    for key, value in updates.items():
        if key == "description" or key == "target_configs":
            value = sanitize_evidence(value)
        if key == "target_configs" and (assessment.target_configs or {}).get("demo_workspace") is True:
            # Request schemas accept platform settings only. Persisted fixture
            # provenance is immutable and must survive ordinary form edits.
            current_targets = assessment.target_configs or {}
            value = {**value, "demo_workspace": True}
            if "scenario_dataset_version" in current_targets:
                value["scenario_dataset_version"] = current_targets["scenario_dataset_version"]
        if key == "engagement_details":
            current = assessment.engagement_details or {}
            value = _validate_assessment_team(
                db, assessment.client, value,
                default_assignee_id=current.get("assigned_analyst_id") or analyst_id,
            )
            value = sanitize_evidence(value)
        if key in {"allowed_hosts", "allowed_paths", "excluded_paths"}:
            value = [str(item).strip() for item in value if str(item).strip()]
        setattr(assessment, key, value)
    assessment.configuration_version += 1
    assessment.updated_at = datetime.now(UTC)
    metadata = {"configuration_version": assessment.configuration_version,
                "changed_fields": sorted(updates),
                "scope_changed": bool({"allowed_hosts", "allowed_paths", "excluded_paths", "environment", "testing_window_start", "testing_window_end"} & updates.keys()),
                "authorization_revalidation_required": bool({"allowed_hosts", "allowed_paths", "excluded_paths", "environment", "testing_window_start", "testing_window_end"} & updates.keys())}
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=assessment.client_id,
                                      assessment_id=assessment.id, event_type="ASSESSMENT_UPDATED",
                                      outcome="UPDATED", metadata_json=metadata))
    try:
        db.commit()
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Assessment changed concurrently; reload before saving") from None
    db.refresh(assessment)
    return assessment_read_payload(assessment)


@router.post("/assessments/{assessment_id}/archive")
def archive_assessment(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    if assessment.status == "Archived":
        return {"assessment_id": assessment.id, "status": "Archived"}
    if db.query(models.TestRun).filter(models.TestRun.assessment_id == assessment.id,
                                       models.TestRun.status.in_(["RUNNING", "QUEUED"])).first():
        raise HTTPException(409, "Queued or running assessment jobs must finish or be cancelled before archiving")
    assessment.status = "Archived"
    assessment.configuration_version += 1
    assessment.updated_at = datetime.now(UTC)
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=assessment.client_id,
                                      assessment_id=assessment.id, event_type="ASSESSMENT_ARCHIVED",
                                      outcome="ARCHIVED", metadata_json={
                                          "configuration_version": assessment.configuration_version,
                                          "history_retained": True,
                                      }))
    db.commit()
    return {"assessment_id": assessment.id, "status": assessment.status}


@router.post("/assessments/{assessment_id}/restore")
def restore_assessment(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    assessment = (db.query(models.Assessment).filter_by(id=assessment.id)
                  .with_for_update().populate_existing().first())
    if assessment.status != "Archived":
        raise HTTPException(409, "Assessment is not archived")
    assessment.status = "Draft"
    assessment.authorization_status = "REVIEW_REQUIRED"
    assessment.authorization_confirmed = False
    assessment.configuration_version += 1
    assessment.updated_at = datetime.now(UTC)
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=assessment.client_id,
                                      assessment_id=assessment.id, event_type="ASSESSMENT_RESTORED",
                                      outcome="DRAFT", metadata_json={
                                          "configuration_version": assessment.configuration_version,
                                          "authorization_revalidation_required": True,
                                          "history_retained": True,
                                      }))
    db.commit()
    db.refresh(assessment)
    return assessment_read_payload(assessment)


@router.get("/assessments/{assessment_id}/history")
def assessment_history(assessment_id: int, request: Request, db: Session = Depends(get_db),
                       limit: int = 100, offset: int = 0):
    assessment = owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id,
                                         required_roles=ALL_CLIENT_ROLES)
    events = (db.query(models.ExecutionAuditEvent).filter_by(assessment_id=assessment.id)
              .order_by(models.ExecutionAuditEvent.created_at.desc(), models.ExecutionAuditEvent.id.desc())
              .offset(max(offset, 0)).limit(min(max(limit, 1), 200)).all())
    return [{"id": event.id, "actor_id": event.actor_id, "event_type": event.event_type,
             "outcome": event.outcome, "created_at": event.created_at,
             "metadata": sanitize_evidence(event.metadata_json or {})} for event in events]


@router.get("/audit/events", response_model=schemas.AuditEventPage)
def list_audit_events(request: Request, db: Session = Depends(get_db),
                      start_at: datetime | None = None, end_at: datetime | None = None,
                      client_id: int | None = Query(default=None, gt=0),
                      assessment_id: int | None = Query(default=None, gt=0),
                      actor_id: int | None = Query(default=None, gt=0),
                      event_type: str | None = Query(default=None, min_length=1, max_length=60),
                      outcome: str | None = Query(default=None, min_length=1, max_length=40),
                      target_type: str | None = Query(default=None, pattern="^(client|assessment|test_run|finding)$"),
                      target_id: int | None = Query(default=None, gt=0),
                      limit: int = Query(default=50, ge=1, le=200),
                      offset: int = Query(default=0, ge=0)):
    analyst_id = analyst_from_request(request).id
    start, end = _utc_range(start_at, end_at)
    if (target_type is None) != (target_id is None):
        raise HTTPException(422, "target_type and target_id must be supplied together")
    if client_id is not None:
        owned_client_or_404(db, client_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
    if assessment_id is not None:
        owned_assessment_or_404(db, assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)

    query = db.query(models.ExecutionAuditEvent).join(models.Client).filter(client_access_filter(analyst_id))
    if start:
        query = query.filter(models.ExecutionAuditEvent.created_at >= start)
    if end:
        query = query.filter(models.ExecutionAuditEvent.created_at < end)
    if client_id is not None:
        query = query.filter(models.ExecutionAuditEvent.client_id == client_id)
    if assessment_id is not None:
        query = query.filter(models.ExecutionAuditEvent.assessment_id == assessment_id)
    if actor_id is not None:
        query = query.filter(models.ExecutionAuditEvent.actor_id == actor_id)
    if event_type:
        query = query.filter(models.ExecutionAuditEvent.event_type == event_type)
    if outcome:
        query = query.filter(models.ExecutionAuditEvent.outcome == outcome)
    if target_type and target_id is not None:
        target_column = {"client": models.ExecutionAuditEvent.client_id,
                         "assessment": models.ExecutionAuditEvent.assessment_id,
                         "test_run": models.ExecutionAuditEvent.test_run_id,
                         "finding": models.ExecutionAuditEvent.finding_id}[target_type]
        query = query.filter(target_column == target_id)
    total = query.count()
    rows = query.order_by(models.ExecutionAuditEvent.created_at.desc(),
                          models.ExecutionAuditEvent.id.desc()).offset(offset).limit(limit).all()
    return {"items": [{"id": row.id, "actor_id": row.actor_id, "client_id": row.client_id,
                        "assessment_id": row.assessment_id, "test_run_id": row.test_run_id,
                        "finding_id": row.finding_id, "event_type": row.event_type,
                        "outcome": row.outcome, "metadata": sanitize_evidence(row.metadata_json or {}),
                        "created_at": row.created_at} for row in rows],
            "total": total, "limit": limit, "offset": offset,
            "time_range": {"start_at": start.isoformat() if start else None,
                           "end_at_exclusive": end.isoformat() if end else None, "timezone": "UTC"}}


@router.get("/audit/events/{event_id}", response_model=schemas.AuditEventRead)
def audit_event_details(event_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    row = (db.query(models.ExecutionAuditEvent).join(models.Client)
           .filter(models.ExecutionAuditEvent.id == event_id, client_access_filter(analyst_id)).first())
    if row is None:
        raise HTTPException(404, "Audit event not found")
    return {"id": row.id, "actor_id": row.actor_id, "client_id": row.client_id,
            "assessment_id": row.assessment_id, "test_run_id": row.test_run_id,
            "finding_id": row.finding_id, "event_type": row.event_type,
            "outcome": row.outcome, "metadata": sanitize_evidence(row.metadata_json or {}),
            "created_at": row.created_at}


@router.get("/assessments/{assessment_id}/android-applications")
def android_applications(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    assessment = owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    if assessment.assessment_type not in {"ANDROID_API", "BOTH"}:
        raise HTTPException(409, "Android metadata is available only for ANDROID_API or BOTH assessments")
    rows = db.query(models.AndroidApplication).filter_by(assessment_id=assessment.id).order_by(models.AndroidApplication.id).all()
    return [{"id": row.id, "assessment_id": row.assessment_id, "package_name": row.package_name,
             "version_name": row.version_name, "version_code": row.version_code,
             "artifact_sha256": row.artifact_sha256, "api_level": row.api_level,
             "metadata": sanitize_evidence(row.metadata_json), "created_at": row.created_at} for row in rows]


@router.post("/assessments/{assessment_id}/android-applications", status_code=201)
def add_android_application(assessment_id: int, data: schemas.AndroidApplicationCreate,
                            request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    if assessment.assessment_type not in {"ANDROID_API", "BOTH"}:
        raise HTTPException(409, "Android metadata is available only for ANDROID_API or BOTH assessments")
    metadata = sanitize_evidence(data.metadata)
    if len(json.dumps(metadata, separators=(",", ":"))) > 16_384:
        raise HTTPException(422, "Android metadata exceeds the 16 KiB limit")
    row = models.AndroidApplication(
        assessment_id=assessment.id, package_name=data.package_name,
        version_name=data.version_name, version_code=data.version_code,
        artifact_sha256=data.artifact_sha256.lower(), api_level=data.api_level,
        metadata_json=metadata, created_by=analyst_id,
    )
    db.add(row)
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="ANDROID_METADATA_RECORDED", outcome="RECORDED",
        metadata_json={"package_name": data.package_name, "artifact_sha256": data.artifact_sha256.lower()},
    ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Android application metadata already exists for this package") from None
    db.refresh(row)
    return {"id": row.id, "assessment_id": row.assessment_id, "package_name": row.package_name,
            "version_name": row.version_name, "version_code": row.version_code,
            "artifact_sha256": row.artifact_sha256, "api_level": row.api_level,
            "metadata": sanitize_evidence(row.metadata_json), "created_at": row.created_at}


@router.post("/assessments/{assessment_id}/android-applications/apk", status_code=201)
async def import_android_apk(assessment_id: int, request: Request,
                             apk: UploadFile = File(...), db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    if assessment.assessment_type not in {"ANDROID_API", "BOTH"}:
        raise HTTPException(409, "APK parsing is available only for ANDROID_API or BOTH assessments")
    if apk.content_type not in {"application/vnd.android.package-archive", "application/octet-stream", "application/zip"}:
        raise HTTPException(415, "APK content type is not supported")
    blob = await apk.read(MAX_APK_UPLOAD_BYTES + 1)
    await apk.close()
    if not blob or len(blob) > MAX_APK_UPLOAD_BYTES:
        raise HTTPException(413, "APK exceeds the 20 MiB upload limit")
    parsed = await _parse_apk_isolated(blob)
    artifact_hash = hashlib.sha256(blob).hexdigest()
    row = models.AndroidApplication(
        assessment_id=assessment.id, package_name=parsed["package_name"],
        version_name=parsed["version_name"], version_code=parsed["version_code"],
        artifact_sha256=artifact_hash, api_level=parsed["api_level"],
        metadata_json=parsed["metadata"], created_by=analyst_id,
    )
    db.add(row)
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="ANDROID_APK_PARSED", outcome="METADATA_ONLY",
        metadata_json={"package_name": parsed["package_name"], "artifact_sha256": artifact_hash,
                       "apk_bytes_stored": False, "parser_isolated": True},
    ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Android application metadata already exists for this package") from None
    db.refresh(row)
    return {"id": row.id, "assessment_id": row.assessment_id, "package_name": row.package_name,
            "version_name": row.version_name, "version_code": row.version_code,
            "artifact_sha256": row.artifact_sha256, "api_level": row.api_level,
            "metadata": sanitize_evidence(row.metadata_json), "created_at": row.created_at}


@router.get("/assessments/{assessment_id}/ios-applications")
def ios_applications(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    assessment = owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id,
                                         required_roles=ALL_CLIENT_ROLES)
    if assessment.assessment_type not in {"ANDROID_API", "BOTH"}:
        raise HTTPException(409, "Mobile application metadata is available only for mobile or combined assessments")
    rows = (db.query(models.IOSApplication).filter_by(assessment_id=assessment.id)
            .order_by(models.IOSApplication.id).all())
    return [{"id": row.id, "assessment_id": row.assessment_id, "bundle_id": row.bundle_id,
             "display_name": row.display_name, "version_name": row.version_name,
             "build_number": row.build_number, "minimum_os_version": row.minimum_os_version,
             "artifact_sha256": row.artifact_sha256,
             "metadata": sanitize_evidence(row.metadata_json), "created_at": row.created_at}
            for row in rows]


@router.post("/assessments/{assessment_id}/ios-applications/ipa", status_code=201)
async def import_ios_ipa(assessment_id: int, request: Request,
                         ipa: UploadFile = File(...), db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    if assessment.assessment_type not in {"ANDROID_API", "BOTH"}:
        raise HTTPException(409, "iOS metadata is available only for mobile or combined assessments")
    if ipa.content_type not in {"application/octet-stream", "application/zip", "application/x-itunes-ipa"}:
        raise HTTPException(415, "IPA content type is not supported")
    blob = await ipa.read(MAX_IPA_UPLOAD_BYTES + 1)
    await ipa.close()
    if not blob or len(blob) > MAX_IPA_UPLOAD_BYTES:
        raise HTTPException(413, "IPA exceeds the 50 MiB upload limit")
    parsed = await _parse_ipa_isolated(blob)
    artifact_hash = hashlib.sha256(blob).hexdigest()
    row = models.IOSApplication(
        assessment_id=assessment.id, bundle_id=parsed["bundle_id"],
        display_name=parsed["display_name"], version_name=parsed["version_name"],
        build_number=parsed["build_number"], minimum_os_version=parsed["minimum_os_version"],
        artifact_sha256=artifact_hash, metadata_json=parsed["metadata"], created_by=analyst_id,
    )
    db.add(row)
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="IOS_IPA_METADATA_IMPORTED", outcome="METADATA_ONLY",
        metadata_json={"bundle_id": parsed["bundle_id"], "artifact_sha256": artifact_hash,
                       "ipa_bytes_stored": False, "parser_isolated": True},
    ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "iOS application metadata already exists for this bundle") from None
    db.refresh(row)
    return {"id": row.id, "assessment_id": row.assessment_id, "bundle_id": row.bundle_id,
            "display_name": row.display_name, "version_name": row.version_name,
            "build_number": row.build_number, "minimum_os_version": row.minimum_os_version,
            "artifact_sha256": row.artifact_sha256, "metadata": sanitize_evidence(row.metadata_json),
            "created_at": row.created_at}


@router.get("/assessments/{assessment_id}/credential-profile")
def get_credential_profile(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    assessment = owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    profile = db.query(models.CredentialProfile).filter_by(assessment_id=assessment.id).first()
    return {"assessment_id": assessment.id, "auth_type": "BEARER" if profile else None,
            "configured": bool(profile and profile.active), "updated_at": profile.updated_at if profile else None}


@router.put("/assessments/{assessment_id}/credential-profile")
def set_credential_profile(assessment_id: int, data: schemas.BearerCredentialCreate,
                           request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    if not encryption_configured():
        raise HTTPException(503, "Credential encryption is not configured")
    try:
        encrypted = encrypt_bearer(data.token)
    except Exception:  # noqa: BLE001 - keep crypto/configuration errors sanitized.
        raise HTTPException(503, "Credential encryption is unavailable") from None
    profile = db.query(models.CredentialProfile).filter_by(assessment_id=assessment.id).first()
    event_outcome = "UPDATED" if profile else "CREATED"
    if profile is None:
        profile = models.CredentialProfile(assessment_id=assessment.id, auth_type="BEARER",
                                           encrypted_secret=encrypted, active=True, created_by=analyst_id)
        db.add(profile)
    else:
        profile.encrypted_secret = encrypted
        profile.auth_type = "BEARER"
        profile.active = True
        profile.created_by = analyst_id
        profile.updated_at = models.now()
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="CREDENTIAL_PROFILE_CHANGED", outcome=event_outcome,
        metadata_json={"credential_type": "BEARER", "secret_material": "not_recorded"},
    ))
    db.commit(); db.refresh(profile)
    return {"assessment_id": assessment.id, "auth_type": profile.auth_type,
            "configured": profile.active, "updated_at": profile.updated_at}


@router.delete("/assessments/{assessment_id}/credential-profile")
def revoke_credential_profile(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    profile = db.query(models.CredentialProfile).filter_by(assessment_id=assessment.id).first()
    if profile and profile.active:
        profile.active = False
        profile.updated_at = models.now()
        db.add(models.ExecutionAuditEvent(
            actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
            event_type="CREDENTIAL_PROFILE_REVOKED", outcome="REVOKED",
            metadata_json={"credential_type": profile.auth_type},
        ))
        db.commit()
    return {"assessment_id": assessment.id, "configured": False}


@router.get("/assessments/{assessment_id}/test-identities")
def list_test_identity_profiles(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    assessment = owned_assessment_or_404(
        db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES,
    )
    rows = (db.query(models.TestIdentityProfile).filter_by(assessment_id=assessment.id)
            .order_by(models.TestIdentityProfile.id).all())
    return [{"id": row.id, "assessment_id": row.assessment_id, "label": row.label,
             "role": row.role, "active": row.active, "created_at": row.created_at,
             "updated_at": row.updated_at} for row in rows]


@router.post("/assessments/{assessment_id}/test-identities", status_code=201)
def create_test_identity_profile(assessment_id: int, data: schemas.TestIdentityProfileCreate,
                                 request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    label, role = data.label.strip(), data.role.strip()
    token = data.bearer_token.get_secret_value().strip()
    if (len(label) < 2 or not role or len(token) < 8
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token)):
        raise HTTPException(422, "Provide a short identity label, role, and bearer token")
    if not encryption_configured():
        raise HTTPException(503, "Credential encryption is not configured")
    if db.query(models.TestIdentityProfile).filter_by(assessment_id=assessment.id, label=label).first():
        raise HTTPException(409, "A test identity with this label already exists")
    try:
        encrypted = encrypt_secret(token.encode("utf-8"), purpose="test-identity-profile")
    except Exception:  # noqa: BLE001 - keep crypto/configuration errors sanitized.
        raise HTTPException(503, "Test identity encryption is unavailable") from None
    row = models.TestIdentityProfile(assessment_id=assessment.id, label=label, role=role,
                                     encrypted_secret=encrypted, active=True, created_by=analyst_id)
    db.add(row)
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="TEST_IDENTITY_PROFILE_CREATED", outcome="CREATED",
        metadata_json={"label": label, "role": role, "secret_material": "not_recorded"},
    ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A test identity with this label already exists") from None
    db.refresh(row)
    return {"id": row.id, "assessment_id": row.assessment_id, "label": row.label,
            "role": row.role, "active": row.active, "created_at": row.created_at,
            "updated_at": row.updated_at}


@router.delete("/assessments/{assessment_id}/test-identities/{identity_id}")
def revoke_test_identity_profile(assessment_id: int, identity_id: int,
                                 request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    row = db.query(models.TestIdentityProfile).filter_by(
        id=identity_id, assessment_id=assessment.id,
    ).first()
    if row is None:
        raise HTTPException(404, "Test identity not found")
    if row.active:
        row.active = False
        row.encrypted_secret = ""
        row.updated_at = models.now()
        db.add(models.ExecutionAuditEvent(
            actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
            event_type="TEST_IDENTITY_PROFILE_REVOKED", outcome="REVOKED",
            metadata_json={"label": row.label, "role": row.role, "secret_material": "not_recorded"},
        ))
        db.commit()
    return {"id": row.id, "assessment_id": assessment.id, "label": row.label,
            "role": row.role, "active": False}


@router.get("/assessments/{assessment_id}/authorization")
def get_authorization(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    assessment = owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    payload = assessment_read_payload(assessment)
    return {key: payload[key] for key in (
        "id", "client_id", "authorization_reference", "authorization_status",
        "authorization_scope_snapshot", "authorization_methods", "authorization_party",
        "authorization_valid_from", "authorization_expires_at", "authorization_recorded_by_id",
        "authorization_recorded_at", "authorization_reviewed_by_id", "authorization_reviewed_at",
        "authorization_revoked_at", "authorization_reason", "authorization_version",
        "authorization_evidence_sha256", "authorization_evidence_name", "authorization_evidence_size",
    )} | {"authenticity_verified": False, "review_note": "Evidence fingerprint is recorded; signer identity and legal authenticity still require independent verification."}


@router.post("/assessments/{assessment_id}/authorization/evidence")
async def attach_authorization_evidence(assessment_id: int, request: Request,
                                        document: UploadFile = File(...), db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    if document.content_type != "application/pdf":
        raise HTTPException(415, "Authorization evidence must be a PDF")
    blob = await document.read(MAX_AUTHORIZATION_EVIDENCE_BYTES + 1)
    filename = re.sub(r"[^A-Za-z0-9._ -]", "_", (document.filename or "authorization.pdf").split("/")[-1].split("\\")[-1])[:200]
    await document.close()
    if len(blob) < 8 or len(blob) > MAX_AUTHORIZATION_EVIDENCE_BYTES:
        raise HTTPException(413, "Authorization evidence exceeds the 10 MiB limit")
    if not blob.startswith(b"%PDF-"):
        raise HTTPException(422, "Authorization evidence is not a PDF document")
    previous_status = assessment.authorization_status
    assessment.authorization_evidence_sha256 = hashlib.sha256(blob).hexdigest()
    assessment.authorization_evidence_name = filename or "authorization.pdf"
    assessment.authorization_evidence_size = len(blob)
    assessment.authorization_status = "REVIEW_REQUIRED"
    assessment.authorization_reviewed_by_id = None
    assessment.authorization_reviewed_at = None
    assessment.authorization_revoked_at = None
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="AUTHORIZATION_EVIDENCE_FINGERPRINTED", outcome="RECORDED",
        metadata_json={"sha256": assessment.authorization_evidence_sha256,
                       "filename": assessment.authorization_evidence_name,
                       "bytes": len(blob), "document_persisted": False},
    ))
    try:
        db.commit()
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Authorization changed concurrently; reload before attaching evidence") from None
    return {"assessment_id": assessment.id, "sha256": assessment.authorization_evidence_sha256,
            "filename": assessment.authorization_evidence_name, "bytes": assessment.authorization_evidence_size,
            "authorization_status": assessment.authorization_status,
            "authorization_version": assessment.authorization_version,
            "previous_status": previous_status, "document_persisted": False}


@router.get("/assessments/{assessment_id}/authorization/history")
def authorization_history(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    assessment = owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    events = (db.query(models.ExecutionAuditEvent)
              .filter_by(assessment_id=assessment.id)
              .filter(models.ExecutionAuditEvent.event_type.in_(
                  ["AUTHORIZATION_EVIDENCE_FINGERPRINTED", "AUTHORIZATION_RECORDED",
                   "AUTHORIZATION_REVIEWED", "AUTHORIZATION_SELF_REVIEWED", "AUTHORIZATION_REVOKED"]))
              .order_by(models.ExecutionAuditEvent.created_at, models.ExecutionAuditEvent.id).all())
    return [{"id": event.id, "actor_id": event.actor_id, "event_type": event.event_type,
             "outcome": event.outcome, "created_at": event.created_at,
             "metadata": sanitize_evidence(event.metadata_json or {})} for event in events]


def _authorization_audit(db, assessment, analyst_id: int, event_type: str, reason: str, previous_status: str):
    metadata = {"prior_status": previous_status,
                "new_status": assessment.authorization_status,
                "authorization_version": assessment.authorization_version,
                "scope_hash": assessment.authorization_scope_hash,
                "scope": assessment.authorization_scope_snapshot,
                "methods": assessment.authorization_methods,
                "authorizing_party": assessment.authorization_party,
                "evidence_sha256": assessment.authorization_evidence_sha256,
                "evidence_name": assessment.authorization_evidence_name,
                "reference_sha256": hashlib.sha256(assessment.authorization_reference.encode()).hexdigest() if assessment.authorization_reference else "",
                "valid_from": assessment.authorization_valid_from.isoformat() if assessment.authorization_valid_from else None,
                "expires_at": assessment.authorization_expires_at.isoformat() if assessment.authorization_expires_at else None,
                "reason": sanitize_evidence(reason)}
    if event_type in {"AUTHORIZATION_REVIEWED", "AUTHORIZATION_SELF_REVIEWED"}:
        metadata["self_review"] = assessment.authorization_recorded_by_id == assessment.authorization_reviewed_by_id
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type=event_type, outcome=assessment.authorization_status, metadata_json=metadata,
    ))


@router.post("/assessments/{assessment_id}/authorization/record")
def record_authorization(assessment_id: int, data: schemas.AuthorizationRecordCreate, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    if data.expected_version != assessment.authorization_version:
        raise HTTPException(409, "Authorization record changed; reload before editing")
    if data.valid_from >= data.expires_at:
        raise HTTPException(422, "Authorization expiry must be after its start time")
    if settings.environment.lower() in {"staging", "production"} and not assessment.authorization_evidence_sha256:
        raise HTTPException(409, "Attach the authorization PDF before recording production-scope authorization")
    snapshot = authorization_scope_snapshot(assessment, data.permitted_methods)
    if not snapshot["hosts"] or not snapshot["paths"]:
        raise HTTPException(409, "Assessment host and path scope must be configured before authorization")
    prior_status = assessment.authorization_status
    previous_hash = assessment.authorization_scope_hash
    if previous_hash and previous_hash != scope_fingerprint(snapshot) and len(data.reason.strip()) < 10:
        raise HTTPException(422, "A material scope change requires a detailed reason")
    assessment.authorization_reference = data.reference.strip()
    assessment.authorization_party = data.authorizing_party.strip()
    assessment.authorization_methods = data.permitted_methods
    assessment.authorization_scope_snapshot = snapshot
    assessment.authorization_scope_hash = scope_fingerprint(snapshot)
    assessment.authorization_valid_from = data.valid_from
    assessment.authorization_expires_at = data.expires_at
    assessment.authorization_recorded_by_id = analyst_id
    assessment.authorization_recorded_at = datetime.now(UTC)
    assessment.authorization_reviewed_by_id = None
    assessment.authorization_reviewed_at = None
    assessment.authorization_revoked_at = None
    assessment.authorization_reason = sanitize_evidence(data.reason.strip())
    assessment.authorization_status = "RECORDED"
    assessment.authorization_confirmed = False
    try:
        db.flush()
        _authorization_audit(db, assessment, analyst_id, "AUTHORIZATION_RECORDED", data.reason, prior_status)
        db.commit(); db.refresh(assessment)
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Authorization changed concurrently; reload and retry") from None
    return get_authorization(assessment_id, request, db)


@router.post("/assessments/{assessment_id}/authorization/review")
def review_authorization(assessment_id: int, data: schemas.AuthorizationReview, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    is_self_review = False
    assessment = db.query(models.Assessment).join(
        models.Client, models.Assessment.client_id == models.Client.id
    ).filter(models.Assessment.id == assessment_id,
             client_access_filter(analyst_id, ("analyst", "reviewer"))).first()
    if assessment is None:
        raise HTTPException(404, "Assessment not found")
    is_self_review = assessment.authorization_recorded_by_id == analyst_id
    if is_self_review:
        if not data.solo_operator_self_review:
            raise HTTPException(409, "Confirm the solo-operator self-review acknowledgement to continue")
        client = db.get(models.Client, assessment.client_id)
        another_active_owner = bool(
            client and client.owner_user_id != analyst_id
            and db.query(models.Analyst.id).filter_by(id=client.owner_user_id, is_active=True).first()
        )
        another_active_member = (db.query(models.ClientMembership.analyst_id)
                                 .join(models.Analyst, models.Analyst.id == models.ClientMembership.analyst_id)
                                 .filter(models.ClientMembership.client_id == assessment.client_id,
                                         models.ClientMembership.analyst_id != analyst_id,
                                         models.Analyst.is_active.is_(True)).first())
        if another_active_owner or another_active_member:
            raise HTTPException(409, "Self-review is only available when you are the sole active client member")
    else:
        if data.solo_operator_self_review:
            raise HTTPException(422, "Solo-operator acknowledgement applies only when reviewing your own record")
        assessment = owned_assessment_or_404(db, assessment_id, analyst_id, required_roles=("reviewer",))
    if data.expected_version != assessment.authorization_version:
        raise HTTPException(409, "Authorization record changed; reload before review")
    if authorization_state(assessment) != "RECORDED":
        raise HTTPException(409, "A complete, current authorization record is required for review")
    if settings.environment.lower() in {"staging", "production"} and not assessment.authorization_evidence_sha256:
        raise HTTPException(409, "Authorization evidence fingerprint is required before activation")
    expires_at = assessment.authorization_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(UTC):
        raise HTTPException(409, "Expired authorization cannot be activated")
    prior_status = assessment.authorization_status
    assessment.authorization_status = "ACTIVE"
    assessment.authorization_confirmed = True
    assessment.authorization_reviewed_by_id = analyst_id
    assessment.authorization_reviewed_at = datetime.now(UTC)
    assessment.authorization_reason = sanitize_evidence(data.reason.strip())
    try:
        db.flush()
        _authorization_audit(db, assessment, analyst_id,
                             "AUTHORIZATION_SELF_REVIEWED" if is_self_review else "AUTHORIZATION_REVIEWED",
                             data.reason, prior_status)
        db.commit(); db.refresh(assessment)
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Authorization changed concurrently; reload and retry") from None
    return get_authorization(assessment_id, request, db)


@router.post("/assessments/{assessment_id}/authorization/revoke")
def revoke_authorization(assessment_id: int, data: schemas.AuthorizationRevoke, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    if data.expected_version != assessment.authorization_version:
        raise HTTPException(409, "Authorization record changed; reload before revocation")
    if assessment.authorization_status == "REVOKED":
        raise HTTPException(409, "Authorization is already revoked")
    prior_status = assessment.authorization_status
    assessment.authorization_status = "REVOKED"
    assessment.authorization_confirmed = False
    assessment.authorization_revoked_at = datetime.now(UTC)
    assessment.authorization_reason = sanitize_evidence(data.reason.strip())
    try:
        db.flush()
        _authorization_audit(db, assessment, analyst_id, "AUTHORIZATION_REVOKED", data.reason, prior_status)
        db.commit(); db.refresh(assessment)
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Authorization changed concurrently; reload and retry") from None
    return get_authorization(assessment_id, request, db)


@router.post("/assessments/{assessment_id}/scope-check")
def check_scope(assessment_id: int, target: str, request: Request, db: Session = Depends(get_db)):
    assessment = owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    validate_target(assessment, target)
    return {"in_scope": True, "target": target, "assessment_id": assessment_id}


@router.post("/discovery/openapi", status_code=201)
async def discovery_import(request: Request, db: Session = Depends(get_db)):

    length = request.headers.get("content-length")
    if length:
        try:
            if int(length) > settings.openapi_max_document_bytes:
                raise HTTPException(413, "OpenAPI document exceeds the configured size limit")
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length header") from None
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > settings.openapi_max_document_bytes:
            raise HTTPException(413, "OpenAPI document exceeds the configured size limit")
        chunks.append(chunk)
    envelope = parse_import_envelope(b"".join(chunks), settings.openapi_max_document_bytes)
    try:
        data = schemas.OpenAPIImport.model_validate(envelope)
    except ValidationError:
        raise HTTPException(422, "Import request requires assessment_id and a JSON OpenAPI document") from None
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, data.assessment_id, analyst_id)
    document = data.document
    if data.source == "postman_v2.1":
        document = postman_to_openapi(document)
    elif data.source == "burp_http_history":
        document = burp_to_openapi(document)
    elif data.source == "browser_har_1.2":
        document = har_to_openapi(document)
    elif data.source == "android_http_capture_v1":
        document = android_capture_to_openapi(document)
    result = import_openapi(db, assessment, document, analyst_id=analyst_id, source=data.source)
    result["endpoints"] = [schemas.EndpointRead.model_validate(endpoint).model_dump(mode="json") for endpoint in result["endpoints"]]
    return result


@router.post("/discovery/graphql-schemas", status_code=201)
async def import_graphql_schema(request: Request, db: Session = Depends(get_db)):
    """Store a sanitized inventory from a client-provided GraphQL introspection export."""
    length = request.headers.get("content-length")
    if length:
        try:
            if int(length) > settings.openapi_max_document_bytes:
                raise HTTPException(413, "GraphQL introspection document exceeds the configured size limit")
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length header") from None
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > settings.openapi_max_document_bytes:
            raise HTTPException(413, "GraphQL introspection document exceeds the configured size limit")
        chunks.append(chunk)
    envelope = parse_import_envelope(b"".join(chunks), settings.openapi_max_document_bytes)
    try:
        data = schemas.GraphQLSchemaImport.model_validate(envelope)
        raw_document = json.dumps(data.document, separators=(",", ":"), ensure_ascii=False,
                                  allow_nan=False).encode("utf-8")
    except (ValidationError, TypeError, ValueError):
        raise HTTPException(422, "Import request requires assessment_id and a GraphQL introspection JSON document") from None
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, data.assessment_id, analyst_id)
    summary, content_hash = parse_graphql_introspection(raw_document, settings.openapi_max_document_bytes)
    row = models.GraphQLSchemaDocument(assessment_id=assessment.id, imported_by=analyst_id,
                                       content_hash=content_hash, schema_summary=summary)
    db.add(row)
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="GRAPHQL_SCHEMA_METADATA_IMPORTED", outcome="METADATA_ONLY",
        metadata_json={"content_hash": content_hash, "type_count": summary["type_count"],
                       "field_count": summary["field_count"], "raw_schema_stored": False,
                       "target_requests_sent": False},
    ))
    db.commit()
    db.refresh(row)
    return {"id": row.id, "assessment_id": row.assessment_id, "content_hash": row.content_hash,
            "schema_summary": row.schema_summary, "created_at": row.created_at}


@router.get("/discovery/graphql-schemas")
def graphql_schema_imports(assessment_id: int, request: Request, response: Response,
                           db: Session = Depends(get_db), limit: int = 10, offset: int = 0):
    owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id,
                            required_roles=ALL_CLIENT_ROLES)
    if limit < 1 or limit > 10 or offset < 0:
        raise HTTPException(422, "limit must be 1-10 and offset must be non-negative")
    query = db.query(models.GraphQLSchemaDocument).filter_by(assessment_id=assessment_id)
    total = query.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Next-Offset"] = str(offset + limit if offset + limit < total else "")
    rows = query.order_by(models.GraphQLSchemaDocument.id.desc()).offset(offset).limit(limit).all()
    return [{"id": row.id, "assessment_id": row.assessment_id, "content_hash": row.content_hash,
             "schema_summary": row.schema_summary, "created_at": row.created_at} for row in rows]


@router.get("/discovery/endpoints", response_model=list[schemas.EndpointRead])
def endpoints(assessment_id: int, request: Request, response: Response, db: Session = Depends(get_db), search: str = "", method: str = "", source: str = "", review_state: str = "", scope_status: str = "", inventory_current: bool | None = None, limit: int = 100, offset: int = 0):
    owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    if limit < 1 or limit > 500 or offset < 0:
        raise HTTPException(422, "limit must be 1-500 and offset must be non-negative")
    q = db.query(models.Endpoint).filter_by(assessment_id=assessment_id)
    if search: q = q.filter(models.Endpoint.path.ilike(f"%{search[:200]}%"))
    if method: q = q.filter_by(method=method.upper())
    if source: q = q.filter_by(source=source[:80])
    if review_state: q = q.filter_by(review_state=review_state.upper())
    if inventory_current is not None: q = q.filter_by(inventory_current=inventory_current)
    if scope_status:
        normalized_scope = scope_status.upper()
        if normalized_scope not in {"IN_SCOPE", "OUT_OF_SCOPE", "UNRESOLVED", "EXCLUDED"}:
            raise HTTPException(422, "scope_status must be IN_SCOPE, OUT_OF_SCOPE, UNRESOLVED, or EXCLUDED")
        q = q.filter_by(scope_status=normalized_scope)
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Next-Offset"] = str(offset + limit if offset + limit < total else "")
    rows = q.order_by(models.Endpoint.inventory_current.desc(), models.Endpoint.path, models.Endpoint.method).offset(offset).limit(limit).all()
    if rows:
        endpoint_ids = [row.id for row in rows]
        review_events = (db.query(models.ExecutionAuditEvent)
                         .filter(models.ExecutionAuditEvent.assessment_id == assessment_id,
                                 models.ExecutionAuditEvent.event_type.in_(("ENDPOINT_REVIEW_DECISION",
                                                                           "ENDPOINT_SCOPE_REVIEWED",
                                                                           "ENDPOINT_SCOPE_REVALIDATED")),
                                 models.ExecutionAuditEvent.metadata_json["endpoint_id"].as_integer().in_(endpoint_ids))
                         .order_by(models.ExecutionAuditEvent.id.desc()).all())
        last_reviewed = {}
        for event in review_events:
            endpoint_id = (event.metadata_json or {}).get("endpoint_id")
            if endpoint_id not in last_reviewed:
                last_reviewed[endpoint_id] = event.created_at
        return [schemas.EndpointRead.model_validate(row).model_dump(mode="json") | {
            "last_reviewed_at": last_reviewed.get(row.id)
        } for row in rows]
    return rows


@router.get("/discovery/coverage")
def discovery_coverage(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    """Coverage describes only artifacts imported into this assessment, never total API coverage."""
    owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    all_endpoints = db.query(models.Endpoint).filter_by(assessment_id=assessment_id).all()
    current = [endpoint for endpoint in all_endpoints if endpoint.inventory_current]
    imports = db.query(models.OpenAPIDocument).filter_by(assessment_id=assessment_id).all()
    source_counts: dict[str, int] = {}
    for endpoint in current:
        endpoint_sources = {item.get("source") for item in (endpoint.source_provenance or []) if isinstance(item, dict)}
        endpoint_sources.discard(None)
        for source_name in endpoint_sources or {endpoint.source}:
            source_counts[source_name] = source_counts.get(source_name, 0) + 1
    review_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    for endpoint in current:
        review_counts[endpoint.review_state] = review_counts.get(endpoint.review_state, 0) + 1
        scope_counts[endpoint.scope_status] = scope_counts.get(endpoint.scope_status, 0) + 1
    current_hashes = {endpoint.id: endpoint.definition_hash for endpoint in current}
    decisions = db.query(models.ExecutionAuditEvent).filter_by(
        assessment_id=assessment_id, event_type="ENDPOINT_REVIEW_DECISION"
    ).all()
    reviewed_ids = {
        event.metadata_json.get("endpoint_id") for event in decisions
        if event.metadata_json.get("endpoint_id") in current_hashes
        and event.metadata_json.get("definition_hash") == current_hashes[event.metadata_json.get("endpoint_id")]
    }
    return {
        "assessment_id": assessment_id,
        "coverage_basis": "supplied_import_sources_only; this is not proof of complete application API coverage",
        "raw_candidates": sum(len(row.endpoint_ids or []) for row in imports),
        "unique_current_endpoints": len(current),
        "historical_endpoint_records": len(all_endpoints) - len(current),
        "by_source": dict(sorted(source_counts.items())),
        "by_review_status": dict(sorted(review_counts.items())),
        "by_scope_status": dict(sorted(scope_counts.items())),
        "reviewed": len(reviewed_ids),
        "approved": review_counts.get("APPROVED", 0),
        "excluded": sum(endpoint.scope_status == "EXCLUDED" or endpoint.review_state == "REJECTED"
                        for endpoint in current),
        "out_of_scope": scope_counts.get("OUT_OF_SCOPE", 0),
        "unresolved": scope_counts.get("UNRESOLVED", 0),
        # Malformed imports return a structured 4xx and are not persisted as successful batches.
        "parser_errors": 0,
        "import_warnings": sum(len(row.issues or []) for row in imports),
        "imports_with_warnings": sum(bool(row.issues) for row in imports),
        "missing_metadata": sum(not endpoint.operation_id or not endpoint.summary for endpoint in current),
    }


@router.get("/discovery/imports")
def discovery_imports(assessment_id: int, request: Request, response: Response, db: Session = Depends(get_db),
                      limit: int = 100, offset: int = 0):
    owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    if limit < 1 or limit > 500 or offset < 0:
        raise HTTPException(422, "limit must be 1-500 and offset must be non-negative")
    query = db.query(models.OpenAPIDocument).filter_by(assessment_id=assessment_id)
    total = query.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Next-Offset"] = str(offset + limit if offset + limit < total else "")
    rows = query.order_by(models.OpenAPIDocument.id.desc()).offset(offset).limit(limit).all()
    return [{"id": row.id, "assessment_id": row.assessment_id, "imported_by": row.imported_by,
             "source": row.source, "openapi_version": row.openapi_version, "content_hash": row.content_hash,
             "version_id": row.content_hash, "server_declarations": row.server_declarations,
             "artifact_metadata": row.artifact_metadata,
             "issues": row.issues, "endpoint_ids": row.endpoint_ids,
             "change_summary": row.change_summary, "created_at": row.created_at}
            for row in rows]


@router.get("/discovery/endpoints/{endpoint_id}/history")
def endpoint_review_history(endpoint_id: int, request: Request, response: Response, db: Session = Depends(get_db),
                            limit: int = 100, offset: int = 0):
    endpoint = (db.query(models.Endpoint)
                .join(models.Assessment, models.Endpoint.assessment_id == models.Assessment.id)
                .join(models.Client, models.Assessment.client_id == models.Client.id)
                .filter(models.Endpoint.id == endpoint_id,
                        client_access_filter(analyst_from_request(request).id, ALL_CLIENT_ROLES)).first())
    if endpoint is None:
        raise HTTPException(404, "Endpoint not found")
    if limit < 1 or limit > 500 or offset < 0:
        raise HTTPException(422, "limit must be 1-500 and offset must be non-negative")
    events = (db.query(models.ExecutionAuditEvent)
              .filter(models.ExecutionAuditEvent.assessment_id == endpoint.assessment_id,
                      models.ExecutionAuditEvent.event_type.in_(("ENDPOINT_REVIEW_DECISION",
                                                                  "ENDPOINT_REVIEW_INVALIDATED",
                                                                  "ENDPOINT_SCOPE_REVALIDATED",
                                                                  "ENDPOINT_SCOPE_REVIEWED")))
              .order_by(models.ExecutionAuditEvent.id.desc()).all())
    matching = [event for event in events if (event.metadata_json or {}).get("endpoint_id") == endpoint.id]
    response.headers["X-Total-Count"] = str(len(matching))
    response.headers["X-Next-Offset"] = str(offset + limit if offset + limit < len(matching) else "")
    allowed = {"endpoint_id", "method", "import_id", "definition_hash", "reason", "scope_status",
               "prior_scope_status", "old_definition_hash", "new_definition_hash", "server_review_issues",
               "prior_review_state", "review_state"}
    return [{"id": event.id, "actor_id": event.actor_id, "event_type": event.event_type,
             "outcome": event.outcome, "created_at": event.created_at,
             "details": {key: value for key, value in (event.metadata_json or {}).items() if key in allowed}}
            for event in matching[offset:offset + limit]]


@router.post("/discovery/endpoints/{endpoint_id}/execution-approval", response_model=schemas.EndpointRead)
def approve_endpoint_execution(endpoint_id: int, data: schemas.EndpointExecutionApproval, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    endpoint = (
        db.query(models.Endpoint)
        .join(models.Assessment, models.Endpoint.assessment_id == models.Assessment.id)
        .join(models.Client, models.Assessment.client_id == models.Client.id)
        .filter(models.Endpoint.id == endpoint_id, client_access_filter(analyst_id, ("analyst", "reviewer")))
        .first()
    )
    if endpoint is None:
        raise HTTPException(404, "Endpoint not found")
    assessment = owned_assessment_or_404(db, endpoint.assessment_id, analyst_id, required_roles=("analyst", "reviewer"))
    if data.approved:
        if not endpoint.inventory_current:
            raise HTTPException(409, "This endpoint definition is stale and cannot be approved")
        if endpoint.scope_status in {"OUT_OF_SCOPE", "EXCLUDED"}:
            raise HTTPException(409, f"Endpoint scope is {endpoint.scope_status.lower()}: {endpoint.scope_reason}")
        if endpoint.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise HTTPException(409, "This HTTP method is inventory-only and cannot be approved for execution")
        if any(item.get("in") in {"path", "query"} and item.get("required", True) for item in (endpoint.parameters or [])):
            raise HTTPException(409, "Required path or query parameters cannot be supplied by the current request mode")
        if not authorization_allows(assessment, endpoint.method):
            raise HTTPException(409, "A current reviewed authorization for this method and scope is required")
        target = _endpoint_request_url(assessment, endpoint)
        if not target:
            raise HTTPException(409, "Endpoint target cannot be derived safely from the approved assessment scope")
        try:
                    validate_target(assessment, target, allow_http=settings.allow_local_lab and settings.runner_lab_allow_http, method=endpoint.method)
        except HTTPException:
            raise HTTPException(409, "Endpoint path is outside the approved assessment scope") from None
    endpoint.execution_approved = data.approved
    endpoint.execution_approved_by = analyst_id if data.approved else None
    endpoint.execution_approved_at = datetime.now(UTC) if data.approved else None
    endpoint.review_state = "APPROVED" if data.approved else "REJECTED"
    endpoint.review_reason = data.reason.strip()
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="ENDPOINT_REVIEW_DECISION",
        outcome="APPROVED" if data.approved else "REJECTED",
        metadata_json={"endpoint_id": endpoint.id, "method": endpoint.method.upper(),
                       "import_id": endpoint.import_id, "definition_hash": endpoint.definition_hash,
                       "reason": data.reason.strip(), "server_review_issues": endpoint.server_review_issues},
    ))
    db.commit(); db.refresh(endpoint)
    return endpoint


@router.post("/discovery/endpoints/{endpoint_id}/scope-review", response_model=schemas.EndpointRead)
def update_endpoint_scope_review(endpoint_id: int, data: schemas.EndpointScopeReview, request: Request,
                                 db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    endpoint = (db.query(models.Endpoint)
                .join(models.Assessment, models.Endpoint.assessment_id == models.Assessment.id)
                .join(models.Client, models.Assessment.client_id == models.Client.id)
                .filter(models.Endpoint.id == endpoint_id,
                        client_access_filter(analyst_id, ("analyst", "reviewer")))
                .first())
    if endpoint is None:
        raise HTTPException(404, "Endpoint not found")
    assessment = owned_assessment_or_404(db, endpoint.assessment_id, analyst_id,
                                         required_roles=("analyst", "reviewer"))
    if not endpoint.inventory_current:
        raise HTTPException(409, "A stale endpoint definition cannot be reviewed")

    host_in_scope = False
    path_in_scope = False
    explicit_exclusion = False
    try:
        parsed = urlsplit(endpoint.server_origin or "")
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".") if parsed.hostname else ""
        allowed_hosts = [str(value).encode("idna").decode("ascii").lower().rstrip(".")
                         for value in (assessment.allowed_hosts or [])]
        host_in_scope = bool(host) and any(host == allowed or host.endswith("." + allowed)
                                           for allowed in allowed_hosts)
        path = (endpoint.server_base_path.rstrip("/") + endpoint.path) if endpoint.server_base_path else endpoint.path
        allowed_paths = assessment.allowed_paths or ["/**"]
        path_in_scope = any(fnmatch(path, pattern) or
                            (pattern.endswith("/**") and path.startswith(pattern[:-3]))
                            for pattern in allowed_paths)
        explicit_exclusion = any(fnmatch(path, pattern) for pattern in (assessment.excluded_paths or []))
    except (AttributeError, UnicodeError, ValueError):
        host_in_scope = path_in_scope = explicit_exclusion = False

    if data.scope_status == "IN_SCOPE" and not (host_in_scope and path_in_scope and not explicit_exclusion):
        raise HTTPException(409, "This endpoint does not match the assessment's currently recorded host and path scope")
    if data.scope_status == "OUT_OF_SCOPE" and host_in_scope and path_in_scope and not explicit_exclusion:
        raise HTTPException(409, "This endpoint matches the assessment's currently recorded scope")
    if data.scope_status == "EXCLUDED" and not (explicit_exclusion or data.reason.strip()):
        raise HTTPException(422, "An exclusion reason is required")

    prior_scope = endpoint.scope_status
    prior_review = endpoint.review_state
    endpoint.scope_status = data.scope_status
    endpoint.scope_reason = sanitize_evidence(data.reason.strip())
    endpoint.review_state = "NEEDS_REVIEW"
    endpoint.review_reason = sanitize_evidence(data.reason.strip())
    endpoint.execution_approved = False
    endpoint.execution_approved_by = None
    endpoint.execution_approved_at = None
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type="ENDPOINT_SCOPE_REVIEWED", outcome=data.scope_status,
        metadata_json={"endpoint_id": endpoint.id, "method": endpoint.method.upper(),
                       "prior_scope_status": prior_scope, "scope_status": data.scope_status,
                       "prior_review_state": prior_review, "review_state": "NEEDS_REVIEW",
                       "reason": sanitize_evidence(data.reason.strip()),
                       "definition_hash": endpoint.definition_hash},
    ))
    db.commit()
    db.refresh(endpoint)
    return endpoint


def _endpoint_request_url(assessment: models.Assessment, endpoint: models.Endpoint) -> str:
    """Build target from stored assessment scope; callers cannot supply a URL."""

    origin = str(endpoint.server_origin or "").strip()
    if origin:
        if endpoint.scope_status != "IN_SCOPE":
            return ""
        try:
            parsed_origin = urlsplit(origin)
            if (parsed_origin.scheme.lower() not in {"http", "https"} or not parsed_origin.hostname
                    or parsed_origin.username is not None or parsed_origin.password is not None
                    or parsed_origin.path not in {"", "/"} or parsed_origin.query or parsed_origin.fragment):
                return ""
            # Host and port authorization is rechecked by validate_target and
            # the runner. Do not silently substitute a different allowed host.
            netloc = parsed_origin.netloc
            scheme = parsed_origin.scheme.lower()
        except ValueError:
            return ""
        path = endpoint.path
        if endpoint.server_base_path:
            path = endpoint.server_base_path.rstrip("/") + path
        if not path.startswith("/") or path.startswith("//") or "\\" in path:
            return ""
        return urlunsplit((scheme, netloc, path, "", ""))

    hosts = assessment.allowed_hosts or []
    if not hosts:
        return ""
    host = str(hosts[0]).strip()
    # Scope records contain host names only. Reject URL syntax and credentials here.
    try:
        parsed_host = urlsplit("//" + host)
        explicit_port = parsed_host.port
    except ValueError:
        return ""
    if explicit_port is not None:
        return ""
    if not parsed_host.hostname or parsed_host.path or parsed_host.query or parsed_host.fragment or parsed_host.username is not None:
        return ""
    host_name = parsed_host.hostname
    is_lab_loopback = host_name.lower().rstrip(".") in {"localhost", "127.0.0.1", "::1"}
    use_lab_http = bool(
        is_lab_loopback and settings.allow_local_lab and settings.runner_lab_allow_http
        and assessment.environment.lower() in {"development", "lab"} and settings.lab_allowed_ports
    )
    scheme = "http" if use_lab_http else "https"
    port = min(settings.lab_allowed_ports) if use_lab_http else (parsed_host.port or (80 if scheme == "http" else 443))
    netloc = f"[{host_name}]" if ":" in host_name else host_name
    if port != (80 if scheme == "http" else 443):
        netloc += f":{port}"
    path = endpoint.path
    if endpoint.server_base_path:
        path = endpoint.server_base_path.rstrip("/") + path
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        return ""
    return urlunsplit((scheme, netloc, path, "", ""))


def _endpoint_source_metadata(endpoint: models.Endpoint, assessment: models.Assessment) -> dict:
    """Keep latest sanitized import attribution with a shared-engine execution."""
    latest = (endpoint.source_provenance or [])[-1:] if endpoint.source_provenance else []
    provenance = []
    for item in latest:
        if not isinstance(item, dict):
            continue
        provenance.append({key: item.get(key) for key in
                           ("source", "import_id", "artifact_sha256", "artifact_metadata") if key in item})
    return sanitize_evidence({
        "assessment_type": assessment.assessment_type,
        "endpoint_source": endpoint.source,
        "source_provenance": provenance,
    })


def _audit_execution(db: Session, *, analyst_id: int, assessment: models.Assessment, run: models.TestRun, event_type: str, outcome: str, metadata: dict, finding_id: int | None = None):
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        test_run_id=run.id, finding_id=finding_id, event_type=event_type, outcome=outcome,
        metadata_json=metadata,
    ))


@router.post("/testing/runs", status_code=201)
def start_test(data: schemas.TestRunCreate, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, data.assessment_id, analyst_id)
    endpoint = db.query(models.Endpoint).filter_by(id=data.endpoint_id, assessment_id=assessment.id).first()
    if endpoint is None:
        raise HTTPException(404, "Endpoint not found in this assessment")
    definition = None
    if data.test_id:
        try:
            definition = resolve_test(data.test_id)
        except KeyError:
            raise HTTPException(422, "Unknown security test identifier") from None
        except PermissionError:
            raise HTTPException(409, "Security test is disabled by server configuration") from None
        if endpoint.method.upper() not in definition.supported_methods:
            raise HTTPException(409, "Security test does not support this endpoint method")
        if assessment.assessment_type not in definition.platforms:
            raise HTTPException(409, "Security test does not support this assessment type")
        if data.category != definition.category:
            raise HTTPException(422, "Category must match the registered security test")
        if bool(endpoint.auth_required) != bool(definition.requires_auth_protected_endpoint):
            raise HTTPException(409, "This security check requires an endpoint with a matching authentication declaration")
    workflow = definition.workflow if definition else None
    if workflow:
        raise HTTPException(409, "This identity comparison must be queued with its declared test identities")
    started = datetime.now(UTC)
    url = _endpoint_request_url(assessment, endpoint)
    check_budget = ({
        "max_requests": definition.max_requests,
        "max_duration_seconds": min(definition.max_duration_seconds, settings.runner_total_timeout_seconds),
        "max_response_bytes": min(definition.max_response_bytes, settings.runner_max_response_bytes),
        "max_redirects": min(settings.runner_max_redirects, definition.redirect_limit if definition.redirect_limit is not None
                              else max(0, definition.max_requests - 1)),
    } if definition else {
        "max_requests": 1 + settings.runner_max_redirects,
        "max_duration_seconds": settings.runner_total_timeout_seconds,
        "max_response_bytes": settings.runner_max_response_bytes,
        "max_redirects": settings.runner_max_redirects,
    })
    effective_policy = RequestPolicy.from_assessment(
        assessment, analyst_id, allow_local_lab=settings.allow_local_lab,
        max_duration_seconds=check_budget["max_duration_seconds"],
        max_response_bytes=check_budget["max_response_bytes"],
        max_redirects=check_budget["max_redirects"],
    )
    policy_snapshot = {
        "assessment_id": assessment.id,
        "configuration_version": assessment.configuration_version,
        "allowed_methods": sorted(effective_policy.allowed_methods),
        "allowed_schemes": sorted(effective_policy.allowed_schemes),
        "allowed_hosts": sorted(effective_policy.allowed_hosts),
        "allowed_ports": sorted(effective_policy.allowed_ports),
        "allowed_paths": list(effective_policy.allowed_paths),
        "excluded_paths": list(effective_policy.excluded_paths),
        "max_response_bytes": effective_policy.max_response_bytes,
        "total_timeout_seconds": effective_policy.total_timeout,
        "requests_per_minute": effective_policy.requests_per_minute,
        "max_concurrency": effective_policy.max_concurrency,
        "max_redirects": effective_policy.max_redirects,
        "max_requests": check_budget["max_requests"],
        "verify_tls": effective_policy.verify_tls,
    }
    policy_reference = hashlib.sha256(json.dumps(policy_snapshot, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    stale_after = timedelta(seconds=(effective_policy.total_timeout + effective_policy.connect_timeout
                                     + effective_policy.read_timeout + 60))
    stale_cutoff = started - stale_after
    prior_runs = db.query(models.TestRun).filter_by(
        assessment_id=assessment.id, endpoint_id=endpoint.id, status="RUNNING",
    ).all()
    recovered = False
    for prior in prior_runs:
        prior_started = prior.started_at
        if prior_started is None:
            continue  # Missing provenance stays blocked for explicit operator review.
        if prior_started.tzinfo is None:
            prior_started = prior_started.replace(tzinfo=UTC)
        if prior_started < stale_cutoff:
            prior.status = RequestOutcome.TRANSPORT_ERROR.value
            prior.completed_at = started
            prior.summary = "Interrupted request exceeded the configured execution deadline; no security result was recorded"
            prior.execution_metadata = {**(prior.execution_metadata or {}),
                                        "policy_outcome": RequestOutcome.TRANSPORT_ERROR.value,
                                        "recovery": "STALE_RUNNING_REQUEST"}
            _audit_execution(db, analyst_id=analyst_id, assessment=assessment, run=prior,
                             event_type="HTTP_REQUEST_RECOVERED", outcome="STALE_RUNNING_REQUEST",
                             metadata={"endpoint_id": endpoint.id, "run_id": prior.id,
                                       "recovery_after_seconds": int(stale_after.total_seconds())})
            recovered = True
    if recovered:
        db.commit()
    run = models.TestRun(
        assessment_id=assessment.id, endpoint_id=endpoint.id,
        category=definition.category if definition else "HTTP_REQUEST",
        execution_mode=data.execution_mode, analyst_id=analyst_id, method=endpoint.method.upper(),
        test_id=definition.identifier if definition else "",
        test_version=definition.version if definition else "",
        security_outcome=SecurityOutcome.NOT_RUN.value,
        status="RUNNING", summary="Bounded HTTP transport request in progress",
        started_at=started, execution_metadata={"endpoint_id": endpoint.id, "endpoint_definition_hash": endpoint.definition_hash,
                                               "import_id": endpoint.import_id, "mode": data.execution_mode,
                                               "source_context": _endpoint_source_metadata(endpoint, assessment),
                                               "test_id": definition.identifier if definition else None,
                                               "test_version": definition.version if definition else None,
                                               "policy_reference": policy_reference, "policy": policy_snapshot},
    )
    try:
        db.add(run); db.flush()
        _audit_execution(db, analyst_id=analyst_id, assessment=assessment, run=run,
                         event_type="HTTP_REQUEST_STARTED", outcome="RUNNING",
                         metadata={"endpoint_id": endpoint.id, "method": endpoint.method.upper(), "mode": data.execution_mode, "policy_reference": policy_reference})
        db.commit(); db.refresh(run)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "An HTTP request for this endpoint is already running") from None

    if not authorization_allows(assessment, endpoint.method):
        result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Current reviewed authorization is missing, expired, revoked, or out of scope")
    elif (not endpoint.execution_approved or endpoint.review_state != "APPROVED" or not endpoint.inventory_current
          or endpoint.execution_approved_by is None or endpoint.execution_approved_at is None):
        result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Endpoint execution approval is required")
    elif not settings.allow_active_tests:
        result = RunnerResult(RequestOutcome.SKIPPED, detail="HTTP execution is disabled by server policy")
    elif endpoint.auth_required and definition is not None and not definition.allows_unauthenticated_probe:
        result = RunnerResult(RequestOutcome.AUTH_UNAVAILABLE, detail="This registered check does not support authenticated execution")
    elif endpoint.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Only GET, HEAD, and OPTIONS are enabled")
    elif any(item.get("in") in {"path", "query"} and item.get("required", True) for item in (endpoint.parameters or [])):
        result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Required path or query parameters cannot be supplied by the current request mode")
    elif not url:
        result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Endpoint target could not be derived from assessment scope")
    else:
        auth_adapter = (BearerTokenReference(str(assessment.id), DatabaseCredentialResolver(db))
                        if endpoint.auth_required and definition is None else None)
        result = run_request(
            db, assessment.id, analyst_id, endpoint.method, url, auth=auth_adapter,
            max_duration_seconds=check_budget["max_duration_seconds"],
            max_response_bytes=check_budget["max_response_bytes"],
            max_redirects=check_budget["max_redirects"],
        )

    check_result = None
    check_evaluation_error = False
    if definition:
        check_result, check_evaluation_error = evaluate_safely(definition, result)

    finished = datetime.now(UTC)
    # Only safe response metadata is retained; response body and Set-Cookie are never persisted.
    metadata = {
        "endpoint_id": endpoint.id, "mode": data.execution_mode, "policy_reference": policy_reference,
        "endpoint_definition_hash": endpoint.definition_hash, "import_id": endpoint.import_id,
        "source_context": _endpoint_source_metadata(endpoint, assessment),
        "policy": policy_snapshot,
        "status_code": result.status_code, "retained_bytes": len(result.body),
        "redirect_count": result.redirect_count, "response_headers": result.headers or {},
        "final_scheme": result.final_scheme,
        "policy_outcome": result.outcome.value,
        "test_id": definition.identifier if definition else None,
        "test_version": definition.version if definition else None,
        "security_outcome": check_result.outcome.value if check_result else SecurityOutcome.NOT_RUN.value,
        "execution_classification": classify_execution(check_result, result.outcome).value,
        "duration_ms": max(0, int((finished - started).total_seconds() * 1000)),
    }
    if check_result:
        metadata["security_evidence"] = sanitize_evidence(check_result.evidence)
        metadata["security_explanation"] = check_result.explanation
        metadata["security_limitation"] = check_result.limitation
        metadata["execution_classification"] = classify_execution(check_result, result.outcome).value
    if check_evaluation_error:
        metadata["check_evaluation_error"] = True
    run.status = result.outcome.value
    run.security_outcome = check_result.outcome.value if check_result else SecurityOutcome.NOT_RUN.value
    run.summary = ("HTTP transport completed; registered security check failed safely during evaluation"
                   if check_evaluation_error else result.detail or
                   ("HTTP transport completed; no security conclusion was evaluated" if result.outcome is RequestOutcome.COMPLETED else "HTTP transport did not complete successfully"))
    run.completed_at = finished
    run.execution_metadata = metadata
    _audit_execution(db, analyst_id=analyst_id, assessment=assessment, run=run,
                     event_type="HTTP_REQUEST_FINISHED", outcome=run.status, metadata=metadata)
    finding_id = None
    if check_result and check_result.outcome is SecurityOutcome.CANDIDATE_FOUND:
        same_observation = None
        for prior in db.query(models.Finding).filter_by(assessment_id=assessment.id, endpoint_id=endpoint.id).all():
            provenance = prior.evidence or {}
            if (prior.status not in {"Resolved", "Closed"}
                    and provenance.get("test_id") == definition.identifier
                    and provenance.get("test_version") == definition.version
                    and provenance.get("endpoint_definition_hash") == endpoint.definition_hash):
                same_observation = prior
                break
        if same_observation is not None:
            # Keep the original finding and evidence immutable. Link this new
            # observation to it through the canonical audit record instead.
            finding_id = same_observation.id
            same_observation.last_observed_at = finished
            _audit_execution(db, analyst_id=analyst_id, assessment=assessment, run=run,
                             event_type="SECURITY_CANDIDATE_DUPLICATE_SUPPRESSED", outcome="CANDIDATE_FOUND",
                             metadata={"finding_id": same_observation.id, "endpoint_id": endpoint.id,
                                       "test_id": definition.identifier, "test_version": definition.version,
                                       "endpoint_definition_hash": endpoint.definition_hash},
                             finding_id=same_observation.id)
        else:
            finding = models.Finding(
                assessment_id=assessment.id, endpoint_id=endpoint.id, test_run_id=run.id,
                title=definition.name, severity="Informational", status="Candidate",
                endpoint=f"{endpoint.method.upper()} {endpoint.path}",
                validation_state="PENDING_VALIDATION",
                description=check_result.explanation,
                impact=check_result.limitation,
                evidence=sanitize_evidence({
                    "test_id": definition.identifier, "test_version": definition.version,
                    "assessment_id": assessment.id, "endpoint_id": endpoint.id,
                    "endpoint_definition_hash": endpoint.definition_hash, "import_id": endpoint.import_id,
                    "test_run_id": run.id, "confidence": "Low; analyst review required",
                    **check_result.evidence,
                }),
                remediation=check_result.remediation,
                **finding_analysis_fields(
                    assessment_id=assessment.id, endpoint_id=endpoint.id,
                    test_id=definition.identifier, test_version=definition.version,
                    category=definition.category, severity="Informational", confidence="LOW",
                    remediation_guidance_type="CHECK_SPECIFIC" if check_result.remediation else "GENERIC",
                ),
                history=[{"status": "Candidate", "actor": str(analyst_id), "note": "Created by registered check; analyst validation required"}],
            )
            db.add(finding); db.flush(); finding_id = finding.id
            _audit_execution(db, analyst_id=analyst_id, assessment=assessment, run=run,
                             event_type="SECURITY_CANDIDATE_CREATED", outcome="CANDIDATE_FOUND",
                             metadata={"finding_id": finding.id, "endpoint_id": endpoint.id,
                                       "test_id": definition.identifier, "test_version": definition.version},
                             finding_id=finding.id)
    db.commit(); db.refresh(run)
    return {"id": run.id, "assessment_id": run.assessment_id, "endpoint_id": run.endpoint_id,
            "category": run.category, "execution_mode": run.execution_mode, "method": run.method,
            "test_id": run.test_id or None, "test_version": run.test_version or None,
            "security_outcome": run.security_outcome,
            "execution_classification": (run.execution_metadata or {}).get("execution_classification", "NOT_APPLICABLE"),
            "finding_id": finding_id,
            "status": run.status, "summary": run.summary, "started_at": run.started_at,
            "completed_at": run.completed_at, "execution_metadata": run.execution_metadata,
            "created_at": run.created_at}


def _job_payload(run: models.TestRun) -> dict:
    return {"id": run.id, "assessment_id": run.assessment_id, "endpoint_id": run.endpoint_id,
            "status": run.status, "method": run.method, "category": run.category,
            "test_id": run.test_id or None, "test_version": run.test_version or None,
            "security_outcome": run.security_outcome,
            "execution_classification": (run.execution_metadata or {}).get("execution_classification", "NOT_APPLICABLE"),
            "summary": run.summary,
            "attempt_count": run.attempt_count, "started_at": run.started_at,
            "completed_at": run.completed_at, "execution_metadata": run.execution_metadata,
            "created_at": run.created_at}


@router.post("/testing/jobs", status_code=202)
def enqueue_http_job(data: schemas.TestJobCreate, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    key = request.headers.get("idempotency-key", "").strip()
    if not 8 <= len(key) <= 200:
        raise HTTPException(422, "An Idempotency-Key header between 8 and 200 characters is required")
    digest = idempotency_digest(key)
    assessment = owned_assessment_or_404(db, data.assessment_id, analyst_id)
    endpoint = db.query(models.Endpoint).filter_by(id=data.endpoint_id, assessment_id=assessment.id).first()
    if endpoint is None:
        raise HTTPException(404, "Endpoint not found in this assessment")
    definition = None
    if data.test_id:
        try:
            definition = resolve_test(data.test_id)
        except KeyError:
            raise HTTPException(422, "Unknown security test identifier") from None
        except PermissionError:
            raise HTTPException(409, "Security test is disabled by server configuration") from None
        if endpoint.method.upper() not in definition.supported_methods:
            raise HTTPException(409, "Security test does not support this endpoint method")
        if assessment.assessment_type not in definition.platforms:
            raise HTTPException(409, "Security test does not support this assessment type")
        if bool(endpoint.auth_required) != bool(definition.requires_auth_protected_endpoint):
            raise HTTPException(409, "This security check requires an endpoint with a matching authentication declaration")
    workflow = definition.workflow if definition else None
    has_workflow_inputs = bool(data.test_identity_ids or data.synthetic_object_ids
                               or data.object_parameter or data.expected_allowed_identity_id is not None)
    identity_profiles: list[models.TestIdentityProfile] = []
    if workflow is None and has_workflow_inputs:
        raise HTTPException(422, "Identity and synthetic-object inputs are only accepted by checks that declare them")
    if definition and definition.required_test_identity_count:
        if len(data.test_identity_ids) != definition.required_test_identity_count or len(set(data.test_identity_ids)) != definition.required_test_identity_count:
            raise HTTPException(422, "Select two different active test identities")
        identities = (db.query(models.TestIdentityProfile)
                      .filter(models.TestIdentityProfile.assessment_id == assessment.id,
                              models.TestIdentityProfile.id.in_(data.test_identity_ids),
                              models.TestIdentityProfile.active.is_(True)).all())
        identities_by_id = {row.id: row for row in identities}
        if len(identities_by_id) != definition.required_test_identity_count:
            raise HTTPException(422, "Each selected test identity must be active and belong to this assessment")
        identity_profiles = [identities_by_id[identity_id] for identity_id in data.test_identity_ids]
        if not encryption_configured():
            raise HTTPException(503, "Encrypted test identity storage is not configured")
        if workflow == "BOLA":
            if (endpoint.method.upper() != "GET" or len(data.synthetic_object_ids) != 2
                    or any(not item.strip() or len(item) > 200 for item in data.synthetic_object_ids)
                    or data.synthetic_object_ids[0] == data.synthetic_object_ids[1]):
                raise HTTPException(422, "Provide two different existing synthetic object IDs for a GET endpoint")
            parameter = next((item for item in (endpoint.parameters or [])
                              if item.get("name") == data.object_parameter and item.get("in") == "path"), None)
            if parameter is None or not parameter.get("required", True):
                raise HTTPException(422, "Choose a required path parameter declared by this endpoint for the synthetic object ID")
            if data.object_parameter in data.path_parameters:
                raise HTTPException(422, "Enter the object IDs in the dedicated synthetic-object fields")
            if data.expected_allowed_identity_id is not None:
                raise HTTPException(422, "BOLA checks do not accept a role-matrix input")
        elif workflow == "BFLA":
            if (endpoint.method.upper() != "GET" or len(data.synthetic_object_ids)
                    or data.object_parameter):
                raise HTTPException(422, "Function-level comparisons require GET and do not accept object IDs")
            if data.expected_allowed_identity_id not in data.test_identity_ids:
                raise HTTPException(422, "Choose which selected identity is explicitly allowed for this endpoint")
        else:
            raise HTTPException(409, "This identity comparison workflow is not supported")
    if (not endpoint.inventory_current or endpoint.review_state != "APPROVED"
            or not endpoint.execution_approved or endpoint.execution_approved_by is None
            or endpoint.execution_approved_at is None):
        raise HTTPException(409, "Current endpoint execution approval is required before queueing")
    if endpoint.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        raise HTTPException(409, "Only GET, HEAD, and OPTIONS may be queued")
    if not authorization_allows(assessment, endpoint.method):
        raise HTTPException(409, "A current reviewed authorization for this method and scope is required")
    target = _endpoint_request_url(assessment, endpoint)
    if not target:
        raise HTTPException(409, "Endpoint target cannot be derived safely from assessment scope")
    try:
        validate_target(assessment, target, allow_http=settings.allow_local_lab and settings.runner_lab_allow_http,
                        method=endpoint.method)
    except HTTPException:
        raise HTTPException(409, "Endpoint target is outside approved assessment scope") from None
    try:
        path_parameter_sets = [data.path_parameters]
        if workflow == "BOLA":
            path_parameter_sets = [{**data.path_parameters, data.object_parameter: object_id}
                                   for object_id in data.synthetic_object_ids]
        for path_parameters in path_parameter_sets:
            built_url, _built_headers = build_request(
                endpoint, target, path_parameters=path_parameters,
                query_parameters=data.query_parameters, header_parameters=data.header_parameters,
            )
            validate_target(assessment, built_url,
                            allow_http=settings.allow_local_lab and settings.runner_lab_allow_http,
                            method=endpoint.method)
    except (RequestBuildError, HTTPException) as exc:
        if isinstance(exc, HTTPException):
            raise HTTPException(422, "Built endpoint target is outside approved assessment scope") from None
        raise HTTPException(422, str(exc)) from None
    request_parameters = {"path_parameters": data.path_parameters,
                          "query_parameters": data.query_parameters,
                          "header_parameters": data.header_parameters}
    if workflow:
        request_parameters.update({
            "test_identity_ids": data.test_identity_ids,
            "synthetic_object_ids": data.synthetic_object_ids,
            "object_parameter": data.object_parameter,
            "expected_allowed_identity_id": data.expected_allowed_identity_id,
        })
    has_parameters = any(request_parameters.values())
    if has_parameters and not encryption_configured():
        raise HTTPException(503, "Encrypted request parameter storage is not configured")
    existing = db.query(models.TestRun).filter_by(assessment_id=assessment.id, analyst_id=analyst_id,
                                                 idempotency_key=digest).first()
    if existing:
        return _job_payload(existing)
    check_budget = ({"max_requests": definition.max_requests,
                     "max_duration_seconds": min(definition.max_duration_seconds, settings.runner_total_timeout_seconds),
                     "max_response_bytes": min(definition.max_response_bytes, settings.runner_max_response_bytes),
                     "max_redirects": min(settings.runner_max_redirects,
                                          definition.redirect_limit if definition.redirect_limit is not None
                                          else max(0, definition.max_requests - 1))}
                    if definition else None)
    run = models.TestRun(
        assessment_id=assessment.id, endpoint_id=endpoint.id, analyst_id=analyst_id,
        category=definition.category if definition else "HTTP_REQUEST", execution_mode="HTTP_REQUEST",
        method=endpoint.method.upper(), test_id=definition.identifier if definition else "",
        test_version=definition.version if definition else "",
        status="QUEUED", summary="Approved safe HTTP request is queued",
        idempotency_key=digest,
        encrypted_request_parameters=(encrypt_secret(json.dumps(request_parameters, separators=(",", ":")).encode(),
                                                     purpose="http-job-parameters") if has_parameters else None),
        execution_metadata={"endpoint_id": endpoint.id, "endpoint_definition_hash": endpoint.definition_hash,
                            "import_id": endpoint.import_id, "policy_outcome": "QUEUED",
                            "test_id": definition.identifier if definition else None,
                            "test_version": definition.version if definition else None,
                            "test_workflow": workflow,
                            "test_identity_profiles": [{"label": row.label, "role": row.role}
                                                       for row in identity_profiles],
                            "check_budget": check_budget},
    )
    db.add(run)
    try:
        db.flush()
        _audit_execution(db, analyst_id=analyst_id, assessment=assessment, run=run,
                         event_type="HTTP_JOB_QUEUED", outcome="QUEUED",
                         metadata={"endpoint_id": endpoint.id, "method": endpoint.method.upper()})
        db.commit(); db.refresh(run)
    except IntegrityError:
        db.rollback()
        existing = db.query(models.TestRun).filter_by(assessment_id=assessment.id, analyst_id=analyst_id,
                                                     idempotency_key=digest).first()
        if existing:
            return _job_payload(existing)
        raise HTTPException(409, "An execution job conflicts with a currently running endpoint request") from None
    return _job_payload(run)


@router.get("/testing/jobs")
def list_http_jobs(request: Request, response: Response, db: Session = Depends(get_db), assessment_id: int | None = None,
                   limit: int = 100, offset: int = 0):
    analyst_id = analyst_from_request(request).id
    if limit < 1 or limit > 500 or offset < 0:
        raise HTTPException(422, "limit must be 1-500 and offset must be non-negative")
    query = (db.query(models.TestRun).join(models.Assessment).join(models.Client)
             .filter(client_access_filter(analyst_id), models.TestRun.idempotency_key.is_not(None)))
    if assessment_id is not None:
        owned_assessment_or_404(db, assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
        query = query.filter(models.TestRun.assessment_id == assessment_id)
    total = query.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Next-Offset"] = str(offset + limit if offset + limit < total else "")
    return [_job_payload(row) for row in query.order_by(models.TestRun.created_at.desc()).offset(offset).limit(limit)]


@router.get("/testing/jobs/{job_id}")
def get_http_job(job_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    run = (db.query(models.TestRun).join(models.Assessment).join(models.Client)
           .filter(models.TestRun.id == job_id, models.TestRun.idempotency_key.is_not(None),
                   client_access_filter(analyst_id)).first())
    if run is None:
        raise HTTPException(404, "Execution job not found")
    owned_assessment_or_404(db, run.assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
    return _job_payload(run)


@router.post("/testing/jobs/{job_id}/cancel")
def cancel_http_job(job_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    run = (db.query(models.TestRun).join(models.Assessment).join(models.Client)
           .filter(models.TestRun.id == job_id, models.TestRun.idempotency_key.is_not(None),
                   client_access_filter(analyst_id)).first())
    if run is None:
        raise HTTPException(404, "Execution job not found")
    assessment = owned_assessment_or_404(db, run.assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
    if run.status == "QUEUED":
        run.status = RequestOutcome.CANCELLED.value
        run.completed_at = datetime.now(UTC)
        run.summary = "Queued request cancelled before worker execution"
        run.execution_metadata = {**(run.execution_metadata or {}), "policy_outcome": "CANCELLED"}
        if run.test_id in REGISTRY and REGISTRY[run.test_id].workflow:
            run.encrypted_request_parameters = None
        _audit_execution(db, analyst_id=analyst_id, assessment=assessment, run=run,
                         event_type="HTTP_JOB_CANCELLED", outcome="CANCELLED", metadata={"phase": "QUEUED"})
    elif run.status == "RUNNING":
        run.execution_metadata = {**(run.execution_metadata or {}), "cancel_requested": True}
        _audit_execution(db, analyst_id=analyst_id, assessment=assessment, run=run,
                         event_type="HTTP_JOB_CANCELLATION_REQUESTED", outcome="RUNNING", metadata={})
    else:
        raise HTTPException(409, "Only queued or running jobs can be cancelled")
    pending_retest = db.query(models.Retest).filter_by(test_run_id=run.id, outcome="REQUESTED").first()
    if pending_retest is not None and run.completed_at is not None:
        finalize_requested_retest(db, pending_retest, run)
    db.commit(); db.refresh(run)
    return _job_payload(run)


@router.get("/testing/runs")
def test_runs(request: Request, response: Response, db: Session = Depends(get_db), assessment_id: int | None = None,
              limit: int = 100, offset: int = 0):
    if limit < 1 or limit > 500 or offset < 0:
        raise HTTPException(422, "limit must be 1-500 and offset must be non-negative")
    analyst_id = analyst_from_request(request).id
    q = db.query(models.TestRun).join(models.Assessment).join(models.Client).filter(client_access_filter(analyst_id))
    if assessment_id is not None:
        owned_assessment_or_404(db, assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
        q = q.filter(models.TestRun.assessment_id == assessment_id)
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Next-Offset"] = str(offset + limit if offset + limit < total else "")
    page = q.add_columns(models.Assessment.name).order_by(models.TestRun.created_at.desc()).offset(offset).limit(limit).all()
    endpoint_ids = {run.endpoint_id for run, _name in page if run.endpoint_id is not None}
    endpoint_paths = {(endpoint_id, owner_id): path for endpoint_id, owner_id, path in
                      db.query(models.Endpoint.id, models.Endpoint.assessment_id, models.Endpoint.path)
                      .filter(models.Endpoint.id.in_(endpoint_ids)).all()} if endpoint_ids else {}
    return [{"id": r.id, "assessment_id": r.assessment_id, "assessment_name": assessment_name,
             "endpoint_id": r.endpoint_id, "endpoint_path": endpoint_paths.get((r.endpoint_id, r.assessment_id), ""),
             "category": r.category, "execution_mode": r.execution_mode, "queued_job": r.idempotency_key is not None, "test_id": r.test_id or None, "test_version": r.test_version or None, "method": r.method, "status": r.status, "security_outcome": r.security_outcome, "execution_classification": (r.execution_metadata or {}).get("execution_classification", "NOT_APPLICABLE"), "summary": r.summary, "started_at": r.started_at, "completed_at": r.completed_at, "execution_metadata": r.execution_metadata, "created_at": r.created_at} for r, assessment_name in page]


@router.get("/testing/runs/{run_id}")
def get_test_run(run_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    run = (db.query(models.TestRun).join(models.Assessment).join(models.Client)
           .filter(models.TestRun.id == run_id, client_access_filter(analyst_id)).first())
    if run is None:
        raise HTTPException(404, "Execution result not found")
    owned_assessment_or_404(db, run.assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
    finding = db.query(models.Finding).filter_by(test_run_id=run.id).first()
    return {
        "id": run.id,
        "assessment_id": run.assessment_id,
        "endpoint_id": run.endpoint_id,
        "category": run.category,
        "execution_mode": run.execution_mode,
        "queued_job": run.idempotency_key is not None,
        "test_id": run.test_id or None,
        "test_version": run.test_version or None,
        "method": run.method,
        "status": run.status,
        "security_outcome": run.security_outcome,
        "execution_classification": (run.execution_metadata or {}).get("execution_classification", "NOT_APPLICABLE"),
        "finding_id": finding.id if finding else None,
        "summary": run.summary,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "execution_metadata": run.execution_metadata,
        "created_at": run.created_at,
    }


@router.get("/testing/registry")
def test_registry():
    return public_registry()


def build_coverage(assessment_id: int, db: Session):
    assessment = db.get(models.Assessment, assessment_id)
    endpoints = db.query(models.Endpoint).filter_by(assessment_id=assessment_id, inventory_current=True).all()
    workflow_runs = db.query(models.TestRun).filter_by(assessment_id=assessment_id).all()
    all_runs = [run for run in workflow_runs if run.execution_mode != "DEMO"]
    runs = (db.query(models.TestRun).join(models.Endpoint, models.TestRun.endpoint_id == models.Endpoint.id)
            .filter(models.TestRun.assessment_id == assessment_id, models.Endpoint.assessment_id == assessment_id,
                    models.TestRun.execution_mode != "DEMO")
            .order_by(models.TestRun.id.desc()).all())
    transport_latest = {}
    approved_endpoint_ids = {endpoint.id for endpoint in endpoints
                             if endpoint.execution_approved and endpoint.review_state == "APPROVED"}
    for run in runs:
        if run.execution_mode == "HTTP_REQUEST" and run.endpoint_id in approved_endpoint_ids:
            transport_latest.setdefault(run.endpoint_id, run.status)
    transport_completed = sum(status == "COMPLETED" for status in transport_latest.values())
    from .test_registry import REGISTRY, SecurityOutcome, enabled_test_ids
    enabled = enabled_test_ids()
    applicable_tests = [test for test_id, test in REGISTRY.items() if test_id in enabled]
    approved_endpoints = [endpoint for endpoint in endpoints
                          if endpoint.execution_approved and endpoint.review_state == "APPROVED"]
    def check_applicable(endpoint, test):
        if endpoint.method.upper() not in test.supported_methods:
            return False
        if bool(endpoint.auth_required) != bool(test.requires_auth_protected_endpoint):
            return False
        if test.required_scheme is None:
            return True
        target = _endpoint_request_url(assessment, endpoint) if assessment is not None else ""
        return bool(target and urlsplit(target).scheme.lower() == test.required_scheme)

    workflow_findings = db.query(models.Finding).filter_by(assessment_id=assessment_id).all()
    demo_run_ids = {run.id for run in workflow_runs if run.execution_mode == "DEMO"}
    candidates = [finding for finding in workflow_findings
                  if finding.test_run_id is not None and finding.test_run_id not in demo_run_ids]
    latest_security = {}
    latest_security_attempt = {}
    for run in runs:
        if run.test_id in enabled and run.test_id in REGISTRY and run.endpoint_id in approved_endpoint_ids:
            key = (run.endpoint_id, run.test_id)
            latest_security_attempt.setdefault(key, run)
            # A later cancelled/blocked queue attempt has no check outcome and
            # must not erase the last actual observation from the coverage view.
            if run.security_outcome != SecurityOutcome.NOT_RUN.value:
                latest_security.setdefault(key, run)
    security_completed_outcomes = {SecurityOutcome.NO_ISSUE_OBSERVED.value, SecurityOutcome.CANDIDATE_FOUND.value}
    security_planned = sum(1 for endpoint in approved_endpoints for test in applicable_tests
                           if check_applicable(endpoint, test))
    security_completed = sum(1 for endpoint in approved_endpoints for test in applicable_tests
                             if check_applicable(endpoint, test)
                             and (latest_security.get((endpoint.id, test.identifier)) is not None)
                             and latest_security[(endpoint.id, test.identifier)].security_outcome in security_completed_outcomes)
    findings_by_run = {}
    for finding in candidates:
        if finding.test_run_id is not None:
            findings_by_run.setdefault(finding.test_run_id, []).append(finding.id)
    security_matrix = [{
        "endpoint_id": endpoint.id,
        "method": endpoint.method,
        "path": endpoint.path,
        "tests": {test.identifier: (latest_security[(endpoint.id, test.identifier)].security_outcome
                                      if (endpoint.id, test.identifier) in latest_security
                                      else SecurityOutcome.NOT_RUN.value)
                  for test in applicable_tests if check_applicable(endpoint, test)},
        "test_details": {test.identifier: {
            "outcome_run_id": (latest_security[(endpoint.id, test.identifier)].id
                               if (endpoint.id, test.identifier) in latest_security else None),
            "outcome": (latest_security[(endpoint.id, test.identifier)].security_outcome
                        if (endpoint.id, test.identifier) in latest_security else SecurityOutcome.NOT_RUN.value),
            "transport_status": (latest_security_attempt[(endpoint.id, test.identifier)].status
                                 if (endpoint.id, test.identifier) in latest_security_attempt else None),
            "latest_attempt_run_id": (latest_security_attempt[(endpoint.id, test.identifier)].id
                                      if (endpoint.id, test.identifier) in latest_security_attempt else None),
            "finding_ids": (findings_by_run.get(latest_security[(endpoint.id, test.identifier)].id, [])
                            if (endpoint.id, test.identifier) in latest_security else []),
        } for test in applicable_tests if check_applicable(endpoint, test)},
    } for endpoint in approved_endpoints]
    taxonomy = {
        "API1:2023": "Broken Object Level Authorization",
        "API2:2023": "Broken Authentication",
        "API3:2023": "Broken Object Property Level Authorization",
        "API4:2023": "Unrestricted Resource Consumption",
        "API5:2023": "Broken Function Level Authorization",
        "API6:2023": "Unrestricted Access to Sensitive Business Flows",
        "API7:2023": "Server Side Request Forgery",
        "API8:2023": "Security Misconfiguration",
        "API9:2023": "Improper Inventory Management",
        "API10:2023": "Unsafe Consumption of APIs",
    }
    from .owasp_check_catalog import OWASP_CHECK_CATALOG
    latest_inventory_review = (db.query(models.InventoryReview)
                               .filter_by(assessment_id=assessment_id)
                               .order_by(models.InventoryReview.created_at.desc(), models.InventoryReview.id.desc())
                               .first())

    owasp_coverage = {}
    for category_id, category_name in taxonomy.items():
        implemented = [test for test in REGISTRY.values() if category_id in test.owasp_categories]
        enabled_category = [test for test in implemented if test.identifier in enabled]
        combinations = [(endpoint, test) for endpoint in approved_endpoints
                        for test in enabled_category if check_applicable(endpoint, test)]
        observed = [latest_security[(endpoint.id, test.identifier)].security_outcome
                    if (endpoint.id, test.identifier) in latest_security else SecurityOutcome.NOT_RUN.value
                    for endpoint, test in combinations]
        outcome_counts = {outcome.value: observed.count(outcome.value) for outcome in SecurityOutcome}
        blocked_statuses = {"BLOCKED_SCOPE", "BLOCKED_DESTINATION", "AUTH_UNAVAILABLE", "SKIPPED"}
        blocked = sum(
            (latest_security_attempt.get((endpoint.id, test.identifier)) is not None
             and latest_security_attempt[(endpoint.id, test.identifier)].status in blocked_statuses)
            for endpoint, test in combinations
        )
        candidate_findings = []
        confirmed_findings = []
        mapped_ids = {test.identifier for test in implemented}
        for finding in candidates:
            test_id = (finding.evidence or {}).get("test_id")
            if test_id in mapped_ids:
                if finding.status == "Confirmed":
                    confirmed_findings.append(finding.id)
                elif finding.status in {"Candidate", "Needs Review"}:
                    candidate_findings.append(finding.id)
        uncovered_endpoints = sum(not any(check_applicable(endpoint, test) for test in enabled_category)
                                  for endpoint in approved_endpoints)
        missing_prerequisites = sum(
            bool((endpoint.auth_required and "No authentication" in test.required_authentication)
                 or any(item.get("in") in {"path", "query"} and item.get("required", True)
                        for item in (endpoint.parameters or [])))
            for endpoint, test in combinations
        )
        executed = sum(outcome != SecurityOutcome.NOT_RUN.value for outcome in observed)
        owasp_coverage[category_id] = {
            "name": category_name,
            "review_check": OWASP_CHECK_CATALOG[category_id],
            "registered_check_details": [{
                "identifier": test.identifier,
                "name": test.name,
                "version": test.version,
                "enabled": test.identifier in enabled,
                "purpose": test.purpose,
                "limitations": test.limitations,
                "supported_methods": list(test.supported_methods),
                "required_scheme": test.required_scheme,
                "prerequisites": list(test.safety_prerequisites) + list(test.required_inputs),
                "expected_evidence": list(test.expected_evidence),
                "outcome_interpretation": test.outcome_interpretation,
            } for test in implemented],
            "implemented_checks": [test.identifier for test in implemented],
            "enabled_checks": [test.identifier for test in enabled_category],
            "planned": len(combinations),
            "executed": executed,
            "passed": outcome_counts[SecurityOutcome.NO_ISSUE_OBSERVED.value],
            "candidate_results": outcome_counts[SecurityOutcome.CANDIDATE_FOUND.value],
            "confirmed_findings": len(confirmed_findings),
            "candidate_findings": len(candidate_findings),
            "inconclusive": outcome_counts[SecurityOutcome.INCONCLUSIVE.value],
            "errors": outcome_counts[SecurityOutcome.ERROR.value],
            "blocked": blocked,
            "not_run": outcome_counts[SecurityOutcome.NOT_RUN.value],
            "not_applicable": max(0, len(approved_endpoints) * len(enabled_category) - len(combinations)),
            "uncovered_endpoints": uncovered_endpoints,
            "missing_prerequisites": missing_prerequisites,
            "inventory_review": (latest_inventory_review.result if category_id == "API9:2023" and latest_inventory_review else None),
            "meaning": "Check outcome counts describe observations only. Candidate findings remain unconfirmed; zero checks means uncovered, not passed.",
        }
    reviewed_findings = sum(finding.status != "Candidate" for finding in candidates)
    import_rows = db.query(models.OpenAPIDocument).filter_by(assessment_id=assessment_id).all()
    source_counts = {}
    for endpoint in endpoints:
        for item in endpoint.source_provenance or []:
            source_counts[item.get("source", "unknown")] = source_counts.get(item.get("source", "unknown"), 0) + 1
    result = {
        "assessment_id": assessment_id,
        "endpoint_count": len(endpoints),
        "categories": [test.identifier for test in applicable_tests],
        "planned": security_planned,
        "completed": security_completed,
        "percentage": int(security_completed * 100 / security_planned + 0.5) if security_planned else 0,
        "unassigned_runs": sum(1 for run in all_runs if run.endpoint_id is None),
        "endpoint_inventory": {
            "current": len(endpoints),
            "reviewed": sum(endpoint.review_state in {"APPROVED", "REJECTED"} for endpoint in endpoints),
            "approved": sum(endpoint.review_state == "APPROVED" and endpoint.execution_approved for endpoint in endpoints),
        },
        "discovery": {
            "imports": len(import_rows),
            "current_endpoints": len(endpoints),
            "reviewed_endpoints": sum(endpoint.review_state in {"APPROVED", "REJECTED"} for endpoint in endpoints),
            "approved_endpoints": sum(endpoint.review_state == "APPROVED" and endpoint.execution_approved for endpoint in endpoints),
            "provenance_endpoint_records_by_source": source_counts,
            "meaning": "Discovery coverage describes imported and reviewed inventory; it is not vulnerability coverage.",
        },
        "transport_execution": {
            "planned": len(approved_endpoints),
            "completed": transport_completed,
            "percentage": int(transport_completed * 100 / len(approved_endpoints) + 0.5) if approved_endpoints else 0,
            "outcomes": {status: sum(value == status for value in transport_latest.values())
                         for status in ["COMPLETED", "SKIPPED", "BLOCKED_SCOPE", "BLOCKED_DESTINATION", "AUTH_UNAVAILABLE", "OVERSIZED_RESPONSE", "TIMEOUT", "TRANSPORT_ERROR", "CANCELLED", "RUNNING"]},
            "latest_status_by_endpoint": {str(endpoint_id): status for endpoint_id, status in transport_latest.items()},
            "meaning": "COMPLETED is HTTP transport completion only; it is not a vulnerability test pass.",
        },
        "security_test_execution": {
            "taxonomy_version": "OWASP API Security Top 10 2023",
            "owasp_categories": owasp_coverage,
            "registered_tests": [test.identifier for test in applicable_tests],
            "planned": security_planned,
            "completed": security_completed,
            "percentage": int(security_completed * 100 / security_planned + 0.5) if security_planned else 0,
            "outcomes": {outcome.value: sum(run.security_outcome == outcome.value for run in latest_security.values())
                         for outcome in SecurityOutcome},
            "matrix": security_matrix,
            "completed_outcomes": sorted(security_completed_outcomes),
        },
        "reviewed_finding_coverage": {"candidates": len(candidates), "reviewed": reviewed_findings,
                                      "percentage": int(reviewed_findings * 100 / len(candidates) + 0.5) if candidates else 0},
        "matrix": security_matrix,
    }
    from .demo_workspace import build_workflow_preview
    workflow_preview = build_workflow_preview(assessment, endpoints, workflow_runs,
                                               workflow_findings, result)
    if workflow_preview is not None:
        result["workflow_preview"] = workflow_preview
    return result


def _inventory_review_snapshot(assessment_id: int, analyst_id: int, db: Session) -> models.InventoryReview:
    endpoints = (db.query(models.Endpoint).filter_by(assessment_id=assessment_id)
                 .order_by(models.Endpoint.id).all())
    documents = (db.query(models.OpenAPIDocument).filter_by(assessment_id=assessment_id)
                 .order_by(models.OpenAPIDocument.id).all())
    current = [endpoint for endpoint in endpoints if endpoint.inventory_current]
    observations: list[dict] = []

    def add(code: str, count: int, description: str, action: str, endpoint_ids=()):
        if count:
            observations.append({"code": code, "count": count, "description": description,
                                 "recommended_action": action,
                                 "endpoint_ids": list(endpoint_ids)[:100]})

    add("NO_CURRENT_ENDPOINTS", 1 if not current else 0,
        "The assessment has no current endpoint inventory to review.",
        "Import an authorized API inventory and review its source and scope before testing.")

    add("UNREVIEWED_ENDPOINTS", sum(row.review_state not in {"APPROVED", "REJECTED"} for row in current),
        "Current imported operations still need an analyst review decision.",
        "Review each operation and approve only endpoints that are in the written scope.",
        [row.id for row in current if row.review_state not in {"APPROVED", "REJECTED"}])
    add("DEPRECATED_OPERATIONS", sum(row.deprecated for row in current),
        "The current inventory marks one or more operations as deprecated.",
        "Confirm whether deprecated routes remain deployed and document their retirement date.",
        [row.id for row in current if row.deprecated])
    add("MISSING_API_VERSION", sum(not row.api_version.strip() for row in current),
        "Some operations do not carry an API version from their imported source.",
        "Reconcile these operations with the client-owned version and deprecation inventory.",
        [row.id for row in current if not row.api_version.strip()])

    operation_ids: dict[str, list[int]] = {}
    route_shapes: dict[tuple[str, str], list[int]] = {}
    version_sets: dict[str, set[str]] = {}
    for row in current:
        if row.operation_id.strip():
            operation_ids.setdefault(row.operation_id.strip().casefold(), []).append(row.id)
        route_shapes.setdefault((row.method.upper(), row.path.rstrip("/") or "/"), []).append(row.id)
        title = row.api_title.strip().casefold()
        if title and row.api_version.strip():
            version_sets.setdefault(title, set()).add(row.api_version.strip())
    duplicate_operations = [ids for ids in operation_ids.values() if len(ids) > 1]
    duplicate_routes = [ids for ids in route_shapes.values() if len(ids) > 1]
    multi_version_titles = [title for title, versions in version_sets.items() if len(versions) > 1]
    add("DUPLICATE_OPERATION_IDS", len(duplicate_operations),
        "The imported inventory reuses operation identifiers across current operations.",
        "Reconcile duplicate operation identifiers with the API owner before generating client bindings.",
        [value for group in duplicate_operations for value in group])
    add("DUPLICATE_METHOD_PATHS", len(duplicate_routes),
        "The inventory contains repeated method and path pairs.",
        "Confirm whether these are duplicate imports or distinct API versions that need separate inventory labels.",
        [value for group in duplicate_routes for value in group])
    add("MULTIPLE_API_VERSIONS", len(multi_version_titles),
        "A titled API appears with multiple versions in the current endpoint records.",
        "Confirm that every deployed version is authorized, supported, and assigned a retirement policy.")
    add("SUPERSEDED_ENDPOINT_RECORDS", sum(not row.inventory_current for row in endpoints),
        "Older inventory records have been superseded by later imports.",
        "Confirm that superseded routes are no longer deployed or retain them as explicitly deprecated versions.",
        [row.id for row in endpoints if not row.inventory_current])
    add("IMPORT_REVIEW_WARNINGS", sum(len(row.issues or []) for row in documents),
        "One or more imported API documents contain parser or server-declaration review warnings.",
        "Resolve import warnings and verify every declared server against the written engagement scope.")

    canonical = [{"id": row.id, "method": row.method, "path": row.path,
                  "definition_hash": row.definition_hash, "inventory_current": row.inventory_current,
                  "review_state": row.review_state, "api_title": row.api_title,
                  "api_version": row.api_version, "deprecated": row.deprecated,
                  "import_id": row.import_id} for row in endpoints]
    source_state = {"endpoints": canonical,
                    "imports": [{"id": row.id, "hash": row.content_hash, "version": row.openapi_version}
                                for row in documents]}
    digest = hashlib.sha256(json.dumps(source_state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    result = {
        "status": "REVIEW_REQUIRED" if observations else "NO_INVENTORY_ANOMALY_OBSERVED",
        "inventory_digest": digest,
        "summary": {"current_endpoints": len(current), "superseded_records": len(endpoints) - len(current),
                    "openapi_imports": len(documents), "observations": sum(row["count"] for row in observations),
                    "observation_types": len(observations)},
        "observations": observations,
        "authoritative_baseline": "NOT_CONFIGURED",
        "limitations": [
            "This review analyzes imported records only; it does not discover routes or contact the target API.",
            "Completeness, ownership, deployed versions, and deprecation state require comparison with a client-provided source of truth.",
            "No observations does not mean the API inventory is complete or secure.",
        ],
    }
    review = models.InventoryReview(assessment_id=assessment_id, analyst_id=analyst_id,
                                    inventory_digest=digest, result=result)
    db.add(review)
    db.flush()
    review_created_at = review.created_at or datetime.now(UTC)
    review.created_at = review_created_at
    review.result = {**result, "review_id": review.id, "created_at": review_created_at.isoformat()}
    db.commit()
    db.refresh(review)
    return review


@router.post("/assessments/{assessment_id}/inventory-reviews", status_code=201)
def create_inventory_review(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    owned_assessment_or_404(db, assessment_id, analyst_id)
    review = _inventory_review_snapshot(assessment_id, analyst_id, db)
    return review.result


@router.get("/assessments/{assessment_id}/inventory-reviews")
def list_inventory_reviews(assessment_id: int, request: Request, db: Session = Depends(get_db), limit: int = 20):
    if not 1 <= limit <= 100:
        raise HTTPException(422, "limit must be 1-100")
    owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    rows = (db.query(models.InventoryReview).filter_by(assessment_id=assessment_id)
            .order_by(models.InventoryReview.created_at.desc(), models.InventoryReview.id.desc())
            .limit(limit).all())
    return [row.result for row in rows]


@router.get("/coverage/{assessment_id}")
def coverage(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    return build_coverage(assessment_id, db)


@router.get("/security-review/catalog")
def security_review_catalog(request: Request):
    analyst_from_request(request)
    return manual_review_public_catalog()


@router.get("/assessments/{assessment_id}/manual-reviews")
def list_manual_security_reviews(assessment_id: int, request: Request, db: Session = Depends(get_db)):
    owned_assessment_or_404(db, assessment_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    rows = (db.query(models.ManualSecurityReview).filter_by(assessment_id=assessment_id)
            .order_by(models.ManualSecurityReview.framework_id, models.ManualSecurityReview.control_id).all())
    return [schemas.ManualSecurityReviewRead.model_validate(row).model_dump(mode="json") for row in rows]


@router.put("/assessments/{assessment_id}/manual-reviews/{framework_id}/{control_id}")
def update_manual_security_review(assessment_id: int, framework_id: str, control_id: str,
                                 data: schemas.ManualSecurityReviewUpdate, request: Request,
                                 db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id, required_roles=("analyst", "reviewer"))
    if manual_review_control_for(framework_id, control_id) is None:
        raise HTTPException(404, "Manual review control not found")
    if data.linked_finding_id is not None:
        finding = db.query(models.Finding).filter_by(
            id=data.linked_finding_id, assessment_id=assessment_id).first()
        if finding is None:
            raise HTTPException(422, "Linked finding must belong to this assessment")
        if finding.validation_state != "VALIDATED":
            raise HTTPException(409, "Validate the linked finding before recording ISSUE_FOUND")
    row = db.query(models.ManualSecurityReview).filter_by(
        assessment_id=assessment_id, framework_id=framework_id, control_id=control_id).first()
    prior_status = row.status if row else "NOT_REVIEWED"
    if row is None:
        row = models.ManualSecurityReview(assessment_id=assessment_id,
                                          framework_id=framework_id,
                                          control_id=control_id)
        db.add(row)
    row.status = data.status
    row.review_notes = sanitize_evidence(data.review_notes.strip()) if data.status != "NOT_REVIEWED" else ""
    row.evidence_refs = [sanitize_evidence(value) for value in data.evidence_refs] if data.status != "NOT_REVIEWED" else []
    row.linked_finding_id = data.linked_finding_id
    row.reviewed_by_id = analyst_id if data.status != "NOT_REVIEWED" else None
    try:
        db.flush()
        db.add(models.ExecutionAuditEvent(
            actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
            finding_id=data.linked_finding_id, event_type="MANUAL_SECURITY_REVIEW_UPDATED",
            outcome=data.status, metadata_json={"framework_id": framework_id, "control_id": control_id,
                                               "prior_status": prior_status, "new_status": data.status,
                                               "evidence_reference_count": len(row.evidence_refs)}))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "This control was updated at the same time; reload the review and try again") from None
    db.refresh(row)
    return schemas.ManualSecurityReviewRead.model_validate(row).model_dump(mode="json")


@router.get("/findings", response_model=list[schemas.FindingRead])
def findings(request: Request, response: Response, db: Session = Depends(get_db),
             assessment_id: int | None = None, client_id: int | None = None,
             endpoint_id: int | None = None, severity: str = "", confidence: str = "",
             validation_state: str = "", triage_status: str = "", remediation_status: str = "",
             status: str = "", priority: str = "", limit: int = 100, offset: int = 0):
    if limit < 1 or limit > 500 or offset < 0:
        raise HTTPException(422, "limit must be 1-500 and offset must be non-negative")
    analyst_id = analyst_from_request(request).id
    q = db.query(models.Finding).join(models.Assessment).join(models.Client).filter(client_access_filter(analyst_id))
    if assessment_id is not None:
        owned_assessment_or_404(db, assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
        q = q.filter(models.Finding.assessment_id == assessment_id)
    if client_id is not None:
        owned_client_or_404(db, client_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
        q = q.filter(models.Assessment.client_id == client_id)
    if endpoint_id is not None:
        q = q.filter(models.Finding.endpoint_id == endpoint_id)
    if severity:
        if severity not in {"Critical", "High", "Medium", "Low", "Informational"}:
            raise HTTPException(422, "Unsupported severity filter")
        q = q.filter(models.Finding.severity == severity)
    if confidence:
        if confidence not in {"LOW", "MEDIUM", "HIGH", "UNASSESSED"}:
            raise HTTPException(422, "Unsupported confidence filter")
        q = q.filter(models.Finding.confidence == confidence)
    if validation_state:
        if validation_state not in {"PENDING_VALIDATION", "NEEDS_REVIEW", "VALIDATED", "REJECTED", "INCONCLUSIVE"}:
            raise HTTPException(422, "Unsupported validation-state filter")
        q = q.filter(models.Finding.validation_state == validation_state)
    if triage_status or status:
        q = q.filter(models.Finding.status == (triage_status or status))
    if remediation_status:
        if remediation_status not in {"OPEN", "IN_PROGRESS", "PENDING_RETEST", "RESOLVED", "READY_FOR_RETEST", "FIXED_PENDING_VERIFICATION", "VERIFIED_FIXED", "REOPENED", "ACCEPTED_RISK", "CLOSED"}:
            raise HTTPException(422, "Unsupported remediation-state filter")
        q = q.filter(models.Finding.remediation_status == remediation_status)
    if priority:
        if priority not in {"P0", "P1", "P2", "P3", "P4"}:
            raise HTTPException(422, "Unsupported priority filter")
        q = q.filter(models.Finding.priority == priority)
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Next-Offset"] = str(offset + limit if offset + limit < total else "")
    return [_finding_read_payload(row) for row in
            q.order_by(models.Finding.priority, models.Finding.created_at.desc()).offset(offset).limit(limit).all()]


@router.get("/findings/summary")
def finding_summary(request: Request, db: Session = Depends(get_db), assessment_id: int | None = None,
                    client_id: int | None = None):
    analyst_id = analyst_from_request(request).id
    q = db.query(models.Finding).join(models.Assessment).join(models.Client).filter(client_access_filter(analyst_id))
    if assessment_id is not None:
        owned_assessment_or_404(db, assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
        q = q.filter(models.Finding.assessment_id == assessment_id)
    if client_id is not None:
        owned_client_or_404(db, client_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
        q = q.filter(models.Assessment.client_id == client_id)
    rows = q.all()
    def counts(attribute: str) -> dict[str, int]:
        result: dict[str, int] = {}
        for row in rows:
            key = getattr(row, attribute)
            result[key] = result.get(key, 0) + 1
        return result
    return {"total": len(rows), "severity": counts("severity"),
            "validation_state": counts("validation_state"), "triage_status": counts("status"),
            "remediation_status": counts("remediation_status"), "priority": counts("priority"),
            "highest_priority": [_finding_read_payload(row)
                                 for row in sorted(rows, key=lambda item: (item.priority, item.created_at))[:10]]}


@router.get("/findings/{finding_id}", response_model=schemas.FindingRead)
def finding_detail(finding_id: int, request: Request, db: Session = Depends(get_db)):
    finding = owned_finding_or_404(db, finding_id, analyst_from_request(request).id,
                                   required_roles=ALL_CLIENT_ROLES)
    return _finding_read_payload(finding)


@router.post("/findings", response_model=schemas.FindingRead, status_code=201)
def create_finding(data: schemas.FindingCreate, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, data.assessment_id, analyst_id)
    values = data.model_dump(); values["evidence"] = sanitize_evidence(values["evidence"])
    for field in ("title", "endpoint", "description", "impact", "remediation"):
        values[field] = sanitize_evidence(values[field])
    analysis = finding_analysis_fields(
        assessment_id=assessment.id, endpoint_id=None, test_id=None, test_version=None,
        category=values.get("vulnerability_category", ""), severity=values["severity"],
        remediation_guidance_type="ANALYST_PROVIDED" if values.get("remediation") else "UNAVAILABLE",
    )
    cvss_vector = values.pop("cvss_vector", None)
    if cvss_vector:
        analysis["risk_analysis"]["cvss"] = calculate_cvss_v31(cvss_vector)
    obj = models.Finding(**{**values, **analysis}, status="Candidate", history=[])
    db.add(obj); db.flush()
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        finding_id=obj.id, event_type="FINDING_CREATED", outcome="Candidate",
        metadata_json={"source": "analyst_entry", "finding_id": obj.id,
                      "endpoint_id": obj.endpoint_id, "provenance": "No automated provenance supplied"},
    ))
    db.commit(); db.refresh(obj)
    return _finding_read_payload(obj)


@router.post("/findings/import/burp-scanner-xml")
async def import_burp_scanner_findings(
    request: Request,
    assessment_id: int = Query(..., gt=0),
    document: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Import bounded Burp Scanner issue XML as unvalidated candidates; never executes checks."""
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    blob = await document.read(5 * 1024 * 1024 + 1)
    if len(blob) > 5 * 1024 * 1024:
        raise HTTPException(413, "Burp XML exceeds the 5 MiB upload limit")
    try:
        issues = parse_burp_scanner_xml(blob)
    except BurpImportError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not issues:
        raise HTTPException(422, "No supported Burp Scanner issues were found")

    artifact_digest = hashlib.sha256(blob).hexdigest()
    existing = db.query(models.Finding).filter_by(assessment_id=assessment.id).all()
    seen = set()
    for row in existing:
        provenance = (row.evidence or {}).get("external_tool_import") or {}
        key = (provenance.get("adapter_id"), provenance.get("artifact_sha256"),
               provenance.get("external_id"), provenance.get("issue_type"),
               provenance.get("host"), provenance.get("path"))
        if provenance and key[2]:
            seen.add(key)

    imported, skipped, created_ids = 0, 0, []
    try:
        for issue in issues:
            key = (BURP_ADAPTER_ID, artifact_digest, issue["external_id"],
                   issue["issue_type"], issue["host"], issue["path"])
            if issue["external_id"] and key in seen:
                skipped += 1
                continue
            seen.add(key)
            method = issue["method"]
            endpoint_row = None
            if method and issue["host"]:
                imported_host = urlsplit(f"//{issue['host']}")
                endpoint_row = db.query(models.Endpoint).filter(
                    models.Endpoint.assessment_id == assessment.id,
                    models.Endpoint.method == method,
                    models.Endpoint.path == issue["path"],
                    models.Endpoint.inventory_current.is_(True),
                ).all()
                endpoint_row = next((candidate for candidate in endpoint_row
                                     if (candidate_origin := urlsplit(candidate.server_origin or ""))
                                     and (candidate_origin.hostname or "").lower()
                                     == (imported_host.hostname or "").lower()
                                     and candidate_origin.port == imported_host.port), None)

            display = f"{method + ' ' if method else ''}{issue['host']}{issue['path']}" or issue["path"]
            description = sanitize_evidence(issue["detail"] or issue["description"])
            evidence = sanitize_evidence({
                "external_tool_import": {
                    "source": "Burp Suite Professional Scanner issues XML",
                    "adapter_id": BURP_ADAPTER_ID,
                    "adapter_version": BURP_ADAPTER_VERSION,
                    "burp_version": issue["burp_version"],
                    "artifact_sha256": artifact_digest,
                    "external_id": issue["external_id"],
                    "issue_type": issue["issue_type"],
                    "host": issue["host"],
                    "path": issue["path"],
                    "method": method,
                    "external_severity": issue["external_severity"],
                    "external_confidence": issue["external_confidence"],
                    "imported_at": datetime.now(UTC).isoformat(),
                    "analyst_validation_required": True,
                    "raw_request_response_discarded": True,
                },
            })
            if description:
                evidence["external_tool_import"]["scanner_detail"] = description[:12000]
            analysis = finding_analysis_fields(
                assessment_id=assessment.id,
                endpoint_id=endpoint_row.id if endpoint_row else None,
                test_id=None, test_version=None, category="",
                severity=issue["severity"], confidence="UNASSESSED",
            )
            obj = models.Finding(
                assessment_id=assessment.id,
                endpoint_id=endpoint_row.id if endpoint_row else None,
                title=sanitize_evidence(issue["name"])[:300],
                severity=issue["severity"], status="Candidate", endpoint=display[:1000],
                description=description[:12000],
                impact="Imported scanner output is unverified. Analyst validation is required before treating it as a security finding.",
                evidence=evidence,
                remediation=sanitize_evidence(issue["remediation"])[:12000],
                remediation_status="OPEN",
                validation_state="PENDING_VALIDATION", history=[], **analysis,
            )
            db.add(obj)
            db.flush()
            created_ids.append(obj.id)
            db.add(models.ExecutionAuditEvent(
                actor_id=analyst_id, client_id=assessment.client_id,
                assessment_id=assessment.id, finding_id=obj.id,
                event_type="FINDING_EXTERNAL_RESULTS_IMPORTED", outcome="CANDIDATE",
                metadata_json=sanitize_evidence({
                    "adapter_id": BURP_ADAPTER_ID, "adapter_version": BURP_ADAPTER_VERSION,
                    "external_id": issue["external_id"], "artifact_sha256": artifact_digest,
                    "finding_id": obj.id, "validation_state": "PENDING_VALIDATION",
                    "raw_request_response_discarded": True,
                }),
            ))
            imported += 1
        db.add(models.ExecutionAuditEvent(
            actor_id=analyst_id, client_id=assessment.client_id,
            assessment_id=assessment.id, event_type="EXTERNAL_RESULTS_IMPORT_COMPLETED",
            outcome="IMPORTED", metadata_json={
                "adapter_id": BURP_ADAPTER_ID, "adapter_version": BURP_ADAPTER_VERSION,
                "artifact_sha256": artifact_digest, "imported": imported,
                "skipped_duplicates": skipped, "parsed_issues": len(issues),
                "request_execution_started": False,
            },
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {
        "adapter": {"id": BURP_ADAPTER_ID, "version": BURP_ADAPTER_VERSION},
        "assessment_id": assessment.id, "artifact_sha256": artifact_digest,
        "parsed": len(issues), "imported": imported, "skipped_duplicates": skipped,
        "finding_ids": created_ids, "validation_state": "PENDING_VALIDATION",
        "security_checks_executed": False,
    }


@router.patch("/findings/{finding_id}/risk", response_model=schemas.FindingRead)
def update_finding_risk(finding_id: int, data: schemas.FindingRiskUpdate,
                        request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    obj = owned_finding_or_404(db, finding_id, analyst_id, required_roles=("analyst", "reviewer"))
    risk = dict(obj.risk_analysis or {})
    previous = (risk.get("cvss") or {}).get("vector")
    if data.cvss_vector:
        risk["cvss"] = calculate_cvss_v31(data.cvss_vector)
    else:
        risk.pop("cvss", None)
    obj.risk_analysis = risk
    reason = sanitize_evidence(data.reason.strip())
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=obj.assessment.client_id, assessment_id=obj.assessment_id,
        finding_id=obj.id, event_type="FINDING_CVSS_UPDATED", outcome="UPDATED",
        metadata_json={"previous_vector": previous, "current_vector": data.cvss_vector,
                       "reason": reason},
    ))
    try:
        db.commit()
        db.refresh(obj)
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Finding changed during risk update; reload it before saving") from None
    return _finding_read_payload(obj)


def _sanitize_uploaded_screenshot(blob: bytes) -> tuple[bytes, int, int]:
    try:
        from PIL import Image, ImageOps
        Image.MAX_IMAGE_PIXELS = 20_000_000
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(blob)) as source:
                if source.format not in {"PNG", "JPEG"} or getattr(source, "n_frames", 1) != 1:
                    raise ValueError("Only a single-frame PNG or JPEG image is supported")
                source.verify()
            with Image.open(io.BytesIO(blob)) as source:
                source = ImageOps.exif_transpose(source)
                source.thumbnail((1800, 1800), Image.Resampling.LANCZOS)
                if source.mode in {"RGBA", "LA"} or (source.mode == "P" and "transparency" in source.info):
                    rgba = source.convert("RGBA")
                    flattened = Image.new("RGB", rgba.size, "white")
                    flattened.paste(rgba, mask=rgba.getchannel("A"))
                    image = flattened
                else:
                    image = source.convert("RGB")
                width, height = image.size
                output = io.BytesIO()
                image.save(output, format="JPEG", quality=84, optimize=True, progressive=False)
                sanitized = output.getvalue()
    except (ValueError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise HTTPException(422, "Image is invalid or exceeds safe decoding limits") from None
    if len(sanitized) > MAX_FINDING_IMAGE_STORED_BYTES:
        raise HTTPException(413, "Sanitized screenshot exceeds the 2 MiB storage limit")
    return sanitized, width, height


@router.post("/findings/{finding_id}/evidence-attachments", status_code=201)
async def add_finding_evidence_attachment(finding_id: int, request: Request,
                                         image: UploadFile = File(...), caption: str = Form(default=""),
                                         db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    finding = owned_finding_or_404(db, finding_id, analyst_id, required_roles=("analyst", "reviewer"))
    finding = db.query(models.Finding).filter_by(id=finding.id).with_for_update().first()
    count = db.query(models.FindingEvidenceAttachment).filter_by(finding_id=finding.id).count()
    if count >= MAX_FINDING_ATTACHMENTS:
        raise HTTPException(409, f"A finding can have at most {MAX_FINDING_ATTACHMENTS} screenshots")
    if image.content_type not in {"image/png", "image/jpeg", "application/octet-stream"}:
        raise HTTPException(415, "Upload a PNG or JPEG screenshot")
    blob = await image.read(MAX_FINDING_IMAGE_BYTES + 1)
    original_name = image.filename or "evidence-screenshot"
    await image.close()
    if not blob or len(blob) > MAX_FINDING_IMAGE_BYTES:
        raise HTTPException(413, "Screenshot upload limit is 8 MiB")
    sanitized, width, height = _sanitize_uploaded_screenshot(blob)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", original_name.replace("\\", "/").split("/")[-1])[:180].strip("._") or "screenshot"
    row = models.FindingEvidenceAttachment(
        finding_id=finding.id, uploaded_by_id=analyst_id, filename=safe_name,
        mime_type="image/jpeg", caption=sanitize_evidence(caption.strip())[:500],
        sha256=hashlib.sha256(sanitized).hexdigest(), image_bytes=sanitized,
        width=width, height=height,
    )
    db.add(row)
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=finding.assessment.client_id,
        assessment_id=finding.assessment_id, finding_id=finding.id,
        event_type="FINDING_EVIDENCE_ATTACHED", outcome="STORED",
        metadata_json={"mime_type": row.mime_type, "sha256": row.sha256,
                       "bytes": len(sanitized), "caption": row.caption},
    ))
    db.commit()
    db.refresh(row)
    return finding_attachment_metadata(row)


@router.get("/findings/{finding_id}/evidence-attachments/{attachment_id}")
def get_finding_evidence_attachment(finding_id: int, attachment_id: int,
                                    request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    finding = owned_finding_or_404(db, finding_id, analyst_id, required_roles=("viewer", "analyst", "reviewer"))
    item = db.query(models.FindingEvidenceAttachment).filter_by(
        id=attachment_id, finding_id=finding_id).first()
    if item is None:
        raise HTTPException(404, "Evidence image not found")
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=finding.assessment.client_id,
        assessment_id=finding.assessment_id, finding_id=finding.id,
        event_type="FINDING_EVIDENCE_ACCESSED", outcome="VIEWED",
        metadata_json={"attachment_id": item.id, "sha256": item.sha256},
    ))
    db.commit()
    return Response(item.image_bytes, media_type="image/jpeg", headers={
        "Content-Disposition": f'inline; filename="finding-{finding_id}-evidence-{item.id}.jpg"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store",
    })


@router.patch("/findings/{finding_id}/validation", response_model=schemas.FindingRead)
def validate_finding(finding_id: int, data: schemas.FindingValidationUpdate,
                     request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    obj = owned_finding_or_404(db, finding_id, analyst_id, required_roles=("reviewer",))
    if data.validation_state not in VALIDATION_TRANSITIONS.get(obj.validation_state, set()):
        raise HTTPException(409, f"Finding cannot transition validation from {obj.validation_state} to {data.validation_state}")
    rationale = sanitize_evidence(data.rationale.strip())
    if data.validation_state == "VALIDATED":
        evidence = obj.evidence if isinstance(obj.evidence, dict) else {}
        if not evidence:
            raise HTTPException(409, "Validation requires supporting structured evidence")
        if obj.test_run_id is not None:
            run = db.query(models.TestRun).filter_by(id=obj.test_run_id, assessment_id=obj.assessment_id).first()
            if (run is None or run.endpoint_id != obj.endpoint_id or run.test_id != evidence.get("test_id")
                    or run.test_version != evidence.get("test_version") or run.security_outcome != "CANDIDATE_FOUND"
                    or run.completed_at is None):
                raise HTTPException(409, "The originating execution does not meet candidate-validation requirements")
            if not (run.execution_metadata or {}).get("security_evidence"):
                raise HTTPException(409, "The originating execution has no structured check evidence")
        elif not any(value not in {None, "", "[REDACTED]"} for value in evidence.values()):
            raise HTTPException(409, "Validation requires usable evidence, not only redacted placeholders")
    prior_state = obj.validation_state
    obj.validation_state = data.validation_state
    obj.validation_rationale = rationale
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=obj.assessment.client_id,
        assessment_id=obj.assessment_id, finding_id=obj.id,
        event_type="FINDING_VALIDATION", outcome=data.validation_state,
        test_run_id=obj.test_run_id,
        metadata_json={"prior_state": prior_state, "new_state": data.validation_state,
                       "rationale": rationale, "endpoint_id": obj.endpoint_id,
                       "test_run_id": obj.test_run_id,
                       "correlation_key": obj.correlation_key},
    ))
    try:
        db.commit(); db.refresh(obj)
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Finding changed during validation; reload it before applying another decision") from None
    return obj


REMEDIATION_TRANSITIONS = {
    "OPEN": {"IN_PROGRESS", "ACCEPTED_RISK", "CLOSED"},
    "IN_PROGRESS": {"OPEN", "READY_FOR_RETEST", "ACCEPTED_RISK"},
    "READY_FOR_RETEST": {"IN_PROGRESS", "FIXED_PENDING_VERIFICATION"},
    "FIXED_PENDING_VERIFICATION": {"VERIFIED_FIXED", "REOPENED"},
    "VERIFIED_FIXED": {"REOPENED"},
    "REOPENED": {"IN_PROGRESS", "ACCEPTED_RISK", "CLOSED"},
    "ACCEPTED_RISK": {"OPEN", "IN_PROGRESS", "CLOSED"},
    "CLOSED": {"REOPENED"},
    "PENDING_RETEST": {"IN_PROGRESS", "FIXED_PENDING_VERIFICATION", "REOPENED"},
    "RESOLVED": {"REOPENED"},
}


@router.patch("/findings/{finding_id}/remediation", response_model=schemas.FindingRead)
def update_finding_remediation(finding_id: int, data: schemas.FindingRemediationUpdate,
                               request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    elevated = data.status in {"VERIFIED_FIXED", "ACCEPTED_RISK", "CLOSED", "REOPENED"}
    obj = owned_finding_or_404(db, finding_id, analyst_id,
                               required_roles=("reviewer",) if elevated else ("analyst", "reviewer"))
    reason = sanitize_evidence(data.reason.strip())
    if len(reason) < 5:
        raise HTTPException(422, "A remediation rationale of at least 5 characters is required")
    prior_status = obj.remediation_status
    if data.status is not None and data.status != prior_status:
        if data.status not in REMEDIATION_TRANSITIONS.get(prior_status, set()):
            raise HTTPException(409, f"Remediation cannot transition from {prior_status} to {data.status}")
        if data.status == "ACCEPTED_RISK" and obj.validation_state != "VALIDATED":
            raise HTTPException(409, "Accepted risk requires a VALIDATED finding")
        if data.status == "FIXED_PENDING_VERIFICATION":
            latest = db.query(models.Retest).filter_by(finding_id=obj.id).order_by(models.Retest.created_at.desc(), models.Retest.id.desc()).first()
            if latest is None or latest.outcome not in {"NO_ISSUE_OBSERVED", "MANUALLY_RESOLVED"} or not latest.evidence:
                raise HTTPException(409, "Verification pending requires a retest with new, usable evidence")
        if data.status == "VERIFIED_FIXED":
            latest = db.query(models.Retest).filter_by(finding_id=obj.id).order_by(models.Retest.created_at.desc(), models.Retest.id.desc()).first()
            if (len(reason) < 10 or latest is None
                    or latest.outcome not in {"NO_ISSUE_OBSERVED", "MANUALLY_RESOLVED"}
                    or not latest.evidence):
                raise HTTPException(409, "Reviewer closure requires a successful evidence-backed retest and rationale of at least 10 characters")
            obj.remediation_reviewer_notes = reason
            obj.status = "Resolved"
        elif data.status == "REOPENED":
            obj.status = "Retest Required"
        elif data.status == "CLOSED":
            if obj.validation_state not in {"REJECTED", "VALIDATED"}:
                raise HTTPException(409, "Closure requires a validated or rejected finding")
            obj.status = "Closed"
        elif data.status == "ACCEPTED_RISK":
            obj.status = "Accepted Risk"
        elif data.status == "IN_PROGRESS":
            obj.status = "Remediation In Progress"
        elif data.status in {"READY_FOR_RETEST", "FIXED_PENDING_VERIFICATION"}:
            obj.status = "Retest Required" if data.status == "READY_FOR_RETEST" else "Retested"
        elif data.status == "OPEN":
            obj.status = "Needs Review"
        obj.remediation_status = data.status

    if "assigned_owner_id" in data.model_fields_set:
        if data.assigned_owner_id is not None:
            owner = (db.query(models.Analyst).join(models.ClientMembership,
                     models.ClientMembership.analyst_id == models.Analyst.id)
                     .filter(models.ClientMembership.client_id == obj.assessment.client_id,
                             models.Analyst.id == data.assigned_owner_id,
                             models.Analyst.is_active.is_(True)).first())
            if owner is None and obj.assessment.client.owner_user_id != data.assigned_owner_id:
                raise HTTPException(422, "Assigned owner must be an active member of this client")
        obj.assigned_owner_id = data.assigned_owner_id
    if "target_date" in data.model_fields_set:
        obj.remediation_target_date = data.target_date
    if data.notes is not None:
        obj.remediation_notes = sanitize_evidence(data.notes.strip())
    if data.proposed_fix is not None:
        obj.proposed_fix = sanitize_evidence(data.proposed_fix.strip())
    if data.linked_change_reference is not None:
        obj.linked_change_reference = sanitize_evidence(data.linked_change_reference.strip())
    if data.reviewer_notes is not None:
        if _client_role(db, obj.assessment.client, analyst_id) not in {"owner", "reviewer"}:
            raise HTTPException(403, "Reviewer role is required for reviewer notes")
        obj.remediation_reviewer_notes = sanitize_evidence(data.reviewer_notes.strip())
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=obj.assessment.client_id, assessment_id=obj.assessment_id,
        finding_id=obj.id, event_type="FINDING_REMEDIATION_UPDATED",
        outcome=obj.remediation_status,
        metadata_json={"prior_status": prior_status, "new_status": obj.remediation_status,
                       "reason": reason, "assigned_owner_id": obj.assigned_owner_id,
                       "target_date": obj.remediation_target_date.isoformat() if obj.remediation_target_date else None,
                       "linked_change_reference": obj.linked_change_reference},
    ))
    try:
        db.commit(); db.refresh(obj)
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Finding changed during remediation update; reload before retrying") from None
    return obj


@router.patch("/findings/{finding_id}/status", response_model=schemas.FindingRead)
def update_finding(finding_id: int, data: schemas.FindingStatusUpdate, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    decision_roles = ("reviewer",) if data.status in {"Confirmed", "False Positive", "Accepted Risk"} else ("analyst", "reviewer")
    obj = owned_finding_or_404(db, finding_id, analyst_id, required_roles=decision_roles)
    reason = sanitize_evidence(data.reason.strip())
    if len(reason) < 5:
        raise HTTPException(422, "A rationale of at least 5 characters is required")
    if obj.status == data.status or data.status not in FINDING_TRANSITIONS.get(obj.status, set()):
        raise HTTPException(409, f"Finding cannot transition from {obj.status} to {data.status}")
    if data.status in {"Confirmed", "False Positive", "Accepted Risk"} and len(reason) < 10:
        raise HTTPException(422, "Confirmation, false-positive, and accepted-risk decisions require a rationale of at least 10 characters")
    if data.status == "Confirmed" and obj.validation_state != "VALIDATED":
        raise HTTPException(409, "A finding must be independently validated before confirmation")
    if data.status == "False Positive" and obj.validation_state != "REJECTED":
        raise HTTPException(409, "Record a REJECTED validation decision before false-positive triage")
    if data.status == "Accepted Risk" and obj.validation_state != "VALIDATED":
        raise HTTPException(409, "A finding must be validated before risk acceptance")
    if data.status == "Resolved":
        raise HTTPException(409, "Findings can be resolved only by a retest with new evidence")
    prior_status = obj.status
    endpoint = None
    if obj.endpoint_id is not None:
        endpoint = db.query(models.Endpoint).filter_by(id=obj.endpoint_id, assessment_id=obj.assessment_id).first()
    test_run = None
    if obj.test_run_id is not None:
        test_run = db.query(models.TestRun).filter_by(id=obj.test_run_id, assessment_id=obj.assessment_id).first()
    obj.status = data.status
    if data.status == "Remediation In Progress":
        obj.remediation_status = "IN_PROGRESS"
    elif data.status == "Retest Required":
        obj.remediation_status = "PENDING_RETEST"
    elif data.status in {"Resolved", "Fixed"}:
        obj.remediation_status = "RESOLVED"
    elif data.status in {"Needs Review", "Confirmed", "False Positive"}:
        obj.remediation_status = "OPEN"
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=obj.assessment.client_id, assessment_id=obj.assessment_id,
        finding_id=obj.id, event_type="FINDING_TRIAGE", outcome=data.status,
        metadata_json={"prior_status": prior_status, "new_status": data.status,
                      "reason": reason, "endpoint_id": endpoint.id if endpoint else None,
                      "test_run_id": test_run.id if test_run else None,
                      "test_id": test_run.test_id if test_run and test_run.test_id else None,
                      "test_version": test_run.test_version if test_run and test_run.test_version else None,
                      "endpoint_definition_hash": (endpoint.definition_hash if endpoint else
                          (obj.evidence or {}).get("endpoint_definition_hash"))},
    ))
    try:
        db.commit(); db.refresh(obj)
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Finding changed during review; reload it before applying another decision") from None
    return obj


@router.get("/findings/{finding_id}/history")
def finding_history(finding_id: int, request: Request, db: Session = Depends(get_db)):
    finding = owned_finding_or_404(db, finding_id, analyst_from_request(request).id, required_roles=ALL_CLIENT_ROLES)
    events = (db.query(models.ExecutionAuditEvent)
              .filter_by(finding_id=finding.id)
              .order_by(models.ExecutionAuditEvent.created_at, models.ExecutionAuditEvent.id).all())
    return {
        "finding_id": finding.id,
        "legacy_history": sanitize_evidence(finding.history or []),
        "events": [{"id": event.id, "event_type": event.event_type, "outcome": event.outcome,
                    "actor_id": event.actor_id, "created_at": event.created_at,
                    "details": sanitize_evidence(event.metadata_json or {})} for event in events],
    }


@router.get("/retests")
def retests(request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    rows = (
        db.query(models.Retest)
        .join(models.Finding)
        .join(models.Assessment)
        .join(models.Client)
        .filter(client_access_filter(analyst_id))
        .order_by(models.Retest.created_at.desc())
        .all()
    )
    return [{"id": r.id, "finding_id": r.finding_id, "assessment_id": r.assessment_id,
             "test_run_id": r.test_run_id, "endpoint_id": r.endpoint_id,
             "test_id": r.test_id or None, "test_version": r.test_version or None,
             "endpoint_definition_hash": r.endpoint_definition_hash or None,
             "analyst_id": r.analyst_id, "outcome": r.outcome,
             "evidence": sanitize_evidence(r.evidence), "notes": sanitize_evidence(r.notes),
             "created_at": r.created_at} for r in rows]


@router.post("/findings/{finding_id}/retests/request", status_code=202)
def request_finding_retest(finding_id: int, data: schemas.RetestRequest, request: Request,
                           db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    finding = owned_finding_or_404(db, finding_id, analyst_id)
    if finding.status not in {"Confirmed", "Remediation In Progress", "Retest Required", "Retested", "Resolved", "Fixed"}:
        raise HTTPException(409, "Finding must be confirmed and eligible for retest")
    original = finding.evidence if isinstance(finding.evidence, dict) else {}
    original_run = (db.query(models.TestRun)
                    .filter_by(id=finding.test_run_id, assessment_id=finding.assessment_id).first()
                    if finding.test_run_id is not None else None)
    if (original.get("demo_workspace") is True
            or (original_run is not None and original_run.execution_mode == "DEMO")):
        raise HTTPException(409, "Workflow scenario records cannot queue live retests")
    if not finding.endpoint_id or not finding.test_run_id or not original.get("test_id"):
        raise HTTPException(409, "This finding has no compatible registered check and endpoint for a safe retest")
    try:
        definition = resolve_test(original["test_id"])
    except (KeyError, PermissionError):
        raise HTTPException(409, "The original registered check is no longer enabled") from None
    if definition.version != original.get("test_version"):
        raise HTTPException(409, "The original check version is no longer available; manual review is required")
    if db.query(models.Retest).filter_by(finding_id=finding.id, outcome="REQUESTED").first():
        raise HTTPException(409, "A retest is already queued for this finding")
    idempotency_key = request.headers.get("idempotency-key", "").strip()
    if not 8 <= len(idempotency_key) <= 200:
        raise HTTPException(422, "An Idempotency-Key header between 8 and 200 characters is required")
    headers = [(key.lower().encode(), value.encode()) for key, value in request.headers.items()
               if key.lower() != "idempotency-key"]
    headers.append((b"idempotency-key", idempotency_key.encode()))
    queue_request = Request({**request.scope, "headers": headers})
    job = enqueue_http_job(schemas.TestJobCreate(
        assessment_id=finding.assessment_id, endpoint_id=finding.endpoint_id,
        test_id=definition.identifier, path_parameters=data.path_parameters,
        query_parameters=data.query_parameters, header_parameters=data.header_parameters,
    ), queue_request, db)
    existing = db.query(models.Retest).filter_by(test_run_id=job["id"]).first()
    if existing is not None:
        return {"retest_id": existing.id, "test_run_id": job["id"], "status": job["status"]}
    endpoint = db.query(models.Endpoint).filter_by(id=finding.endpoint_id,
                                                    assessment_id=finding.assessment_id).one()
    row = models.Retest(finding_id=finding.id, assessment_id=finding.assessment_id,
        test_run_id=job["id"], endpoint_id=endpoint.id, analyst_id=analyst_id,
        test_id=definition.identifier, test_version=definition.version,
        endpoint_definition_hash=endpoint.definition_hash, outcome="REQUESTED", evidence={},
        notes=sanitize_evidence(data.notes.strip()))
    db.add(row); db.flush()
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=finding.assessment.client_id,
        assessment_id=finding.assessment_id, finding_id=finding.id, test_run_id=job["id"],
        event_type="FINDING_RETEST_REQUESTED", outcome="QUEUED",
        metadata_json={"retest_id": row.id, "test_run_id": job["id"],
                       "test_id": definition.identifier, "test_version": definition.version,
                       "endpoint_id": endpoint.id, "endpoint_definition_hash": endpoint.definition_hash,
                       "request_parameter_names": {"path": sorted(data.path_parameters),
                                                    "query": sorted(data.query_parameters),
                                                    "header": sorted(data.header_parameters)}}))
    persisted_run = db.get(models.TestRun, job["id"])
    if persisted_run is not None:
        finalize_requested_retest(db, row, persisted_run)
    db.commit()
    return {"retest_id": row.id, "finding_id": finding.id, "test_run_id": job["id"],
            "status": job["status"], "outcome": row.outcome}


@router.post("/findings/{finding_id}/retests", status_code=201)
def create_retest(finding_id: int, data: schemas.RetestCreate, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    finding = owned_finding_or_404(db, finding_id, analyst_id)
    if finding.status not in {"Retest Required", "Confirmed", "Remediation In Progress", "Fixed", "Retested"}:
        raise HTTPException(409, "Finding must be confirmed or marked for retest before recording a retest")
    notes = sanitize_evidence(data.notes.strip())
    if len(notes) < 5:
        raise HTTPException(422, "Retest notes of at least 5 characters are required")
    run = None
    endpoint = None
    if data.test_run_id is not None:
        run = db.query(models.TestRun).filter_by(id=data.test_run_id, assessment_id=finding.assessment_id).first()
        if run is None:
            raise HTTPException(404, "TestRun not found in this assessment")
        if not finding.endpoint_id or run.endpoint_id != finding.endpoint_id or not run.test_id:
            raise HTTPException(409, "The TestRun is not linked to the finding's endpoint and registered check")
        if (run.id == finding.test_run_id or run.completed_at is None
                or run.completed_at.replace(tzinfo=None) <= finding.created_at.replace(tzinfo=None)):
            raise HTTPException(409, "A retest must use a new execution completed after the finding was recorded")
        endpoint = db.query(models.Endpoint).filter_by(id=run.endpoint_id, assessment_id=finding.assessment_id).first()
        run_hash = (run.execution_metadata or {}).get("endpoint_definition_hash", "")
        if (endpoint is None or not endpoint.inventory_current or endpoint.review_state != "APPROVED"
                or not endpoint.execution_approved or endpoint.execution_approved_by is None
                or endpoint.execution_approved_at is None or endpoint.definition_hash != run_hash):
            raise HTTPException(409, "The TestRun does not reference the current approved endpoint definition")
        original = finding.evidence or {}
        if (run.test_id != original.get("test_id") or run.test_version != original.get("test_version")):
            raise HTTPException(409, "The TestRun check does not match the originating finding")
        definition = REGISTRY.get(run.test_id)
        if definition is None or definition.version != run.test_version:
            raise HTTPException(409, "The TestRun references an unavailable security-check version")
        security_outcome = run.security_outcome
        if run.status != "COMPLETED":
            outcome = "EXECUTION_ERROR" if run.status in {"TIMEOUT", "TRANSPORT_ERROR", "OVERSIZED_RESPONSE", "ERROR"} else "NOT_EXECUTED"
        else:
            outcome = {
                "CANDIDATE_FOUND": "CONFIRMED_PERSISTENCE",
                "NO_ISSUE_OBSERVED": "NO_ISSUE_OBSERVED",
                "INCONCLUSIVE": "INCONCLUSIVE",
                "ERROR": "EXECUTION_ERROR",
                "NOT_RUN": "NOT_EXECUTED",
            }.get(security_outcome, "NOT_EXECUTED")
        # A linked security result is authoritative. Client-supplied evidence or
        # outcome cannot upgrade transport-only or inconclusive execution.
        check_evidence = (run.execution_metadata or {}).get("security_evidence") or {}
        evidence = sanitize_evidence({"source": "registered_test_run", "security_outcome": security_outcome,
                                      "evidence": check_evidence})
        if outcome == "NO_ISSUE_OBSERVED" and not check_evidence:
            raise HTTPException(409, "The registered check has no supporting evidence for this result")
        test_id, test_version = run.test_id, run.test_version
        endpoint_id, definition_hash = endpoint.id, endpoint.definition_hash
        # The UI-supplied outcome is intentionally ignored when execution is linked.
    else:
        if data.outcome is None:
            raise HTTPException(422, "Select a manual retest outcome or link a registered TestRun")
        evidence = sanitize_evidence(data.evidence)
        if not evidence:
            raise HTTPException(422, "Retest evidence is required")
        if data.outcome == "NO_ISSUE_OBSERVED":
            raise HTTPException(422, "NO_ISSUE_OBSERVED requires evidence from an applicable registered security check")
        outcome = {
            "Resolved": "MANUALLY_RESOLVED",
            "Not Resolved": "CONFIRMED_PERSISTENCE",
            "Partially Resolved": "PARTIALLY_RESOLVED",
            "Inconclusive": "INCONCLUSIVE",
        }.get(data.outcome, data.outcome)
        test_id = test_version = definition_hash = ""
        endpoint_id = finding.endpoint_id
    transitions = {
        "NO_ISSUE_OBSERVED": "Retested",
        "MANUALLY_RESOLVED": "Retested",
        "CONFIRMED_PERSISTENCE": "Retest Required",
        "PARTIALLY_RESOLVED": "Remediation In Progress",
        "INCONCLUSIVE": "Retest Required",
        "EXECUTION_ERROR": "Retest Required",
        "NOT_EXECUTED": "Retest Required",
    }
    prior_status = finding.status
    new_status = transitions[outcome]
    row = models.Retest(finding_id=finding_id, assessment_id=finding.assessment_id,
                        test_run_id=run.id if run else None, endpoint_id=endpoint_id,
                        analyst_id=analyst_id, test_id=test_id, test_version=test_version,
                        endpoint_definition_hash=definition_hash, outcome=outcome,
                        evidence=evidence, notes=notes)
    db.add(row); db.flush()
    finding.status = new_status
    if outcome in {"NO_ISSUE_OBSERVED", "MANUALLY_RESOLVED"}:
        finding.remediation_status = "FIXED_PENDING_VERIFICATION"
    elif outcome == "CONFIRMED_PERSISTENCE" and prior_status in {"Resolved", "Retested", "Fixed"}:
        finding.remediation_status = "REOPENED"
    elif outcome == "CONFIRMED_PERSISTENCE" or new_status == "Remediation In Progress":
        finding.remediation_status = "IN_PROGRESS"
    else:
        finding.remediation_status = "PENDING_RETEST"
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=finding.assessment.client_id,
        assessment_id=finding.assessment_id, finding_id=finding.id,
        event_type="FINDING_RETEST_RECORDED", outcome=outcome,
        test_run_id=run.id if run else None,
        metadata_json={"prior_status": prior_status, "new_status": new_status,
                      "reason": notes, "retest_id": row.id, "test_run_id": run.id if run else None,
                      "test_id": test_id or None, "test_version": test_version or None,
                      "endpoint_id": endpoint_id, "endpoint_definition_hash": definition_hash or None,
                      "evidence_keys": sorted(evidence.keys()) if isinstance(evidence, dict) else []},
    ))
    try:
        db.commit(); db.refresh(row)
    except StaleDataError:
        db.rollback()
        raise HTTPException(409, "Finding changed during retest; reload it before recording another result") from None
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "This TestRun has already been linked to a retest") from None
    return {"id": row.id, "finding_id": finding_id, "assessment_id": row.assessment_id,
            "test_run_id": row.test_run_id, "endpoint_id": row.endpoint_id,
            "test_id": row.test_id or None, "test_version": row.test_version or None,
            "endpoint_definition_hash": row.endpoint_definition_hash or None,
            "outcome": row.outcome, "evidence": sanitize_evidence(row.evidence),
            "notes": sanitize_evidence(row.notes), "created_at": row.created_at}


def finalize_requested_retest(db: Session, row: models.Retest, run: models.TestRun) -> None:
    """Resolve a queued retest from persisted runner results only."""
    if row.outcome != "REQUESTED" or run.completed_at is None:
        return
    previous = db.query(models.Finding).filter_by(id=row.finding_id,
                                                   assessment_id=row.assessment_id).first()
    if previous is None:
        return
    if run.status == "COMPLETED":
        conclusion = {
            "CANDIDATE_FOUND": "CONFIRMED_PERSISTENCE",
            "NO_ISSUE_OBSERVED": "NO_ISSUE_OBSERVED",
            "INCONCLUSIVE": "INCONCLUSIVE",
            "ERROR": "ERROR",
            "NOT_RUN": "NOT_APPLICABLE",
        }.get(run.security_outcome, "INCONCLUSIVE")
    elif run.status in {"BLOCKED_SCOPE", "BLOCKED_DESTINATION", "CANCELLED", "AUTH_UNAVAILABLE", "SKIPPED"}:
        conclusion = "BLOCKED"
    else:
        conclusion = "ERROR"
    metadata = run.execution_metadata or {}
    row.outcome = conclusion
    row.evidence = sanitize_evidence({"source": "registered_test_run", "test_run_id": run.id,
        "security_outcome": run.security_outcome, "transport_outcome": run.status,
        "evidence": metadata.get("security_evidence", {}), "status_code": metadata.get("status_code")})
    row.notes = sanitize_evidence(row.notes)
    prior_status = previous.status
    if conclusion == "NO_ISSUE_OBSERVED":
        previous.status = "Retested"
        previous.remediation_status = "FIXED_PENDING_VERIFICATION"
    elif conclusion == "CONFIRMED_PERSISTENCE":
        previous.status = "Retest Required"
        previous.remediation_status = "REOPENED" if prior_status in {"Resolved", "Retested", "Fixed"} else "IN_PROGRESS"
    elif conclusion == "NOT_APPLICABLE":
        previous.status = "Retest Required"
        previous.remediation_status = "PENDING_RETEST"
    else:
        previous.status = "Retest Required"
        previous.remediation_status = "PENDING_RETEST"
    db.add(models.ExecutionAuditEvent(actor_id=row.analyst_id, client_id=previous.assessment.client_id,
        assessment_id=previous.assessment_id, finding_id=previous.id, test_run_id=run.id,
        event_type="FINDING_RETEST_COMPLETED", outcome=conclusion,
        metadata_json={"retest_id": row.id, "test_run_id": run.id,
                       "prior_status": prior_status, "new_status": previous.status,
                       "remediation_status": previous.remediation_status,
                       "test_id": run.test_id, "test_version": run.test_version,
                       "endpoint_id": run.endpoint_id,
                       "endpoint_definition_hash": metadata.get("endpoint_definition_hash", ""),
                       "evidence_keys": sorted((metadata.get("security_evidence") or {}).keys())}))


def make_report(db, assessment, configuration: schemas.ReportCreate | None = None):
    configuration = configuration or schemas.ReportCreate()
    workflow_scenario = (assessment.target_configs or {}).get("demo_workspace") is True
    include_evidence = configuration.include_evidence and configuration.report_type != "EXECUTIVE_SUMMARY"
    findings_query = db.query(models.Finding).filter_by(assessment_id=assessment.id)
    if configuration.validation_states:
        findings_query = findings_query.filter(models.Finding.validation_state.in_(configuration.validation_states))
    elif configuration.report_type == "EXECUTIVE_SUMMARY":
        findings_query = findings_query.filter(models.Finding.validation_state == "VALIDATED")
    if configuration.severities:
        findings_query = findings_query.filter(models.Finding.severity.in_(configuration.severities))
    findings = findings_query.order_by(models.Finding.priority, models.Finding.created_at).all()
    endpoints = db.query(models.Endpoint).filter_by(assessment_id=assessment.id).all()
    runs = db.query(models.TestRun).filter_by(assessment_id=assessment.id).order_by(models.TestRun.id).all()
    workflow_scenario = workflow_scenario or any(run.execution_mode == "DEMO" for run in runs)
    retests = (db.query(models.Retest).join(models.Finding, models.Retest.finding_id == models.Finding.id)
               .filter(models.Finding.assessment_id == assessment.id).order_by(models.Retest.id).all())
    android_apps = (db.query(models.AndroidApplication).filter_by(assessment_id=assessment.id)
                    .order_by(models.AndroidApplication.id).all())
    ios_apps = (db.query(models.IOSApplication).filter_by(assessment_id=assessment.id)
                .order_by(models.IOSApplication.id).all())
    graphql_schema = (db.query(models.GraphQLSchemaDocument).filter_by(assessment_id=assessment.id)
                      .order_by(models.GraphQLSchemaDocument.id.desc()).first())
    manual_reviews = (db.query(models.ManualSecurityReview).filter_by(assessment_id=assessment.id)
                      .order_by(models.ManualSecurityReview.framework_id,
                                models.ManualSecurityReview.control_id).all())
    from .test_registry import REGISTRY, enabled_test_ids
    enabled = enabled_test_ids()
    authorization = {
        "status": authorization_state(assessment),
        "operator_attestation_recorded": bool(assessment.authorization_recorded_at),
        "legal_authenticity_verified": False,
        "reference_present": bool(assessment.authorization_reference),
        "reference_sha256": hashlib.sha256(assessment.authorization_reference.encode()).hexdigest() if assessment.authorization_reference else "",
        "authorizing_party": assessment.authorization_party,
        "valid_from": assessment.authorization_valid_from.isoformat() if assessment.authorization_valid_from else None,
        "expires_at": assessment.authorization_expires_at.isoformat() if assessment.authorization_expires_at else None,
        "methods": assessment.authorization_methods or [],
        "scope": assessment.authorization_scope_snapshot or {},
    }
    test_runs = []
    for run in runs:
        definition = REGISTRY.get(run.test_id)
        metadata = run.execution_metadata or {}
        test_runs.append({
            "id": run.id, "endpoint_id": run.endpoint_id, "method": run.method,
            "execution_mode": run.execution_mode,
            "test_id": run.test_id or None, "test_version": run.test_version or None,
            "transport_outcome": run.status, "security_outcome": run.security_outcome,
            "status_code": metadata.get("status_code"),
            "duration_ms": metadata.get("duration_ms"),
            "explanation": sanitize_evidence(metadata.get("security_explanation", run.summary)),
            "limitations": sanitize_evidence(metadata.get("security_limitation") or
                                               (definition.limitations if definition else
                                                "Transport-only run; no security conclusion was evaluated.")),
            "security_evidence": sanitize_evidence(metadata.get("security_evidence", {})) if include_evidence else {},
        })
    generated_at = datetime.now(UTC).isoformat()
    report_revision = _report_source_revision(db, assessment)
    evidence_attachments: dict[int, list[dict]] = {}
    if include_evidence and findings:
        attachment_rows = (db.query(models.FindingEvidenceAttachment)
                           .join(models.Finding, models.FindingEvidenceAttachment.finding_id == models.Finding.id)
                           .filter(models.Finding.assessment_id == assessment.id)
                           .order_by(models.FindingEvidenceAttachment.id).all())
        for attachment in attachment_rows:
            evidence_attachments.setdefault(attachment.finding_id, []).append(
                finding_attachment_metadata(attachment))
    content = {
        "report": {"type": configuration.report_type, "generated_at": generated_at,
                   "data_revision": report_revision,
                   "inclusion_policy": {"validation_states": configuration.validation_states or
                                        (["VALIDATED"] if configuration.report_type == "EXECUTIVE_SUMMARY" else "ALL"),
                                        "severities": configuration.severities or "ALL",
                       "evidence_included": include_evidence}},
        "assessment": {"id": assessment.id, "name": assessment.name, "environment": assessment.environment,
                       "assessment_type": assessment.assessment_type,
                       "client_reference": assessment.client.name,
                       "created_at": assessment.created_at.isoformat() if assessment.created_at else None,
                       "dates": {"started": assessment.created_at.isoformat() if assessment.created_at else None,
                                 "completed": None}},
        "engagement": {
            "objectives": sanitize_evidence((assessment.engagement_details or {}).get("work_objectives", "")),
            "out_of_scope": sanitize_evidence((assessment.engagement_details or {}).get("out_of_scope", "")),
            "deliverables": (assessment.engagement_details or {}).get("deliverables", []),
            "planned_start_date": (assessment.engagement_details or {}).get("planned_start_date"),
            "due_date": (assessment.engagement_details or {}).get("due_date"),
            "milestones": sanitize_evidence((assessment.engagement_details or {}).get("milestones", [])),
        },
        "android_applications": [{"package_name": app.package_name, "version_name": app.version_name,
                                  "version_code": app.version_code, "artifact_sha256": app.artifact_sha256,
                                  "api_level": app.api_level, "metadata": sanitize_evidence(app.metadata_json)}
                                 for app in android_apps],
        "ios_applications": [{"bundle_id": app.bundle_id, "display_name": app.display_name,
                              "version_name": app.version_name, "build_number": app.build_number,
                              "minimum_os_version": app.minimum_os_version,
                              "artifact_sha256": app.artifact_sha256,
                              "metadata": sanitize_evidence(app.metadata_json)} for app in ios_apps],
        "graphql_schema_inventory": ({"content_hash": graphql_schema.content_hash,
                                      "created_at": graphql_schema.created_at.isoformat(),
                                      "schema_summary": graphql_schema.schema_summary}
                                     if graphql_schema else None),
        "manual_review_summary": {
            "total_controls": sum(len(framework["controls"]) for framework in MANUAL_REVIEW_FRAMEWORKS.values()),
            "recorded": sum(row.status != "NOT_REVIEWED" for row in manual_reviews),
            "statuses": {status: sum(row.status == status for row in manual_reviews)
                         for status in ("NO_ISSUE_OBSERVED", "ISSUE_FOUND", "NOT_APPLICABLE", "BLOCKED")},
            "meaning": "Analyst-entered review records only. Controls without a saved record are not assessed; these counts do not represent automated coverage.",
        },
        "manual_review_frameworks": [{
            "framework_id": framework_id,
            "name": framework["name"],
            "source": framework["source"],
            "control_count": len(framework["controls"]),
            "recorded_count": sum(row.framework_id == framework_id and row.status != "NOT_REVIEWED"
                                   for row in manual_reviews),
            "unreviewed_count": len(framework["controls"]) - sum(
                row.framework_id == framework_id and row.status != "NOT_REVIEWED" for row in manual_reviews),
            "statuses": {status: sum(row.framework_id == framework_id and row.status == status
                                     for row in manual_reviews)
                         for status in ("NO_ISSUE_OBSERVED", "ISSUE_FOUND", "NOT_APPLICABLE", "BLOCKED")},
        } for framework_id, framework in MANUAL_REVIEW_FRAMEWORKS.items()],
        "manual_reviews": [{
            "framework_id": row.framework_id,
            "framework_name": MANUAL_REVIEW_FRAMEWORKS[row.framework_id]["name"],
            "framework_source": MANUAL_REVIEW_FRAMEWORKS[row.framework_id]["source"],
            "control_id": row.control_id,
            "control_name": manual_review_control_for(row.framework_id, row.control_id)["name"],
            "review_prompt": manual_review_control_for(row.framework_id, row.control_id)["review_prompt"],
            "status": row.status,
            "review_notes": sanitize_evidence(row.review_notes) if include_evidence else "",
            "evidence_refs": sanitize_evidence(row.evidence_refs or []) if include_evidence else [],
            "linked_finding_id": row.linked_finding_id,
            "reviewed_by_id": row.reviewed_by_id,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        } for row in manual_reviews],
        "scope": {"hosts": assessment.allowed_hosts, "paths": assessment.allowed_paths,
                  "exclusions": assessment.excluded_paths},
        "authorization_record": authorization,
        "methodology": {
            "description": "Only server-registered checks were executed against approved, in-scope endpoints.",
            "interpretation": "HTTP transport completion is not a security verdict. Candidates require analyst review; no browser exploitability testing is represented.",
            "checks": [{"test_id": test_id, "version": definition.version, "purpose": definition.purpose,
                        "limitations": definition.limitations,
                        "expected_evidence": list(definition.expected_evidence),
                        "outcome_interpretation": definition.outcome_interpretation}
                       for test_id, definition in sorted(REGISTRY.items())
                       if test_id in enabled and configuration.report_type != "EXECUTIVE_SUMMARY"],
        },
        "coverage": build_coverage(assessment.id, db),
        "endpoint_count": len(endpoints),
        "test_runs": test_runs if configuration.report_type != "EXECUTIVE_SUMMARY" else [],
        "finding_summary": {
            "total": len(findings),
            "severity": {severity: sum(row.severity == severity for row in findings)
                         for severity in ("Critical", "High", "Medium", "Low", "Informational")},
            "validation_state": {state: sum(row.validation_state == state for row in findings)
                                 for state in ("PENDING_VALIDATION", "NEEDS_REVIEW", "VALIDATED", "REJECTED", "INCONCLUSIVE")},
            "priority": {priority: sum(row.priority == priority for row in findings)
                         for priority in ("P0", "P1", "P2", "P3", "P4")},
            "remediation_status": {state: sum(row.remediation_status == state for row in findings)
                                   for state in ("OPEN", "IN_PROGRESS", "PENDING_RETEST", "RESOLVED",
                                                 "READY_FOR_RETEST", "FIXED_PENDING_VERIFICATION",
                                                 "VERIFIED_FIXED", "REOPENED", "ACCEPTED_RISK", "CLOSED")},
            "score_policy": "No platform-inferred risk score. An optional analyst-supplied CVSS v3.1 base vector is recorded per finding; temporal/environmental metrics are not calculated.",
        },
        "risk_summary": {"validated_count": sum(row.validation_state == "VALIDATED" for row in findings),
                         "unvalidated_count": sum(row.validation_state in {"PENDING_VALIDATION", "NEEDS_REVIEW", "INCONCLUSIVE"} for row in findings),
                         "rejected_count": sum(row.validation_state == "REJECTED" for row in findings),
                         "numerical_score": None,
                         "limitations": "The platform does not infer a contextual risk score. CVSS is present only when an analyst supplies a complete base vector; temporal/environmental metrics are not calculated."},
        "findings": [{"id": f.id, "title": sanitize_evidence(f.title), "severity": f.severity, "status": f.status,
                      "endpoint": sanitize_evidence(f.endpoint), "description": sanitize_evidence(f.description),
                      "observed_behavior": sanitize_evidence(f.description),
                      "expected_behavior": (REGISTRY.get((f.evidence or {}).get("test_id", "")).outcome_interpretation.get(
                          "NO_ISSUE_OBSERVED", "No registered expectation is available")
                          if REGISTRY.get((f.evidence or {}).get("test_id", "")) else "No registered expectation is available"),
                      "impact": sanitize_evidence(f.impact),
                      "evidence": sanitize_evidence(f.evidence) if include_evidence else {},
                      "evidence_attachments": evidence_attachments.get(f.id, []) if include_evidence else [],
                      "remediation": sanitize_evidence(f.remediation),
                      "assigned_owner_id": f.assigned_owner_id,
                      "target_date": f.remediation_target_date.isoformat() if f.remediation_target_date else None,
                      "remediation_notes": sanitize_evidence(f.remediation_notes),
                      "proposed_fix": sanitize_evidence(f.proposed_fix),
                      "linked_change_reference": sanitize_evidence(f.linked_change_reference),
                      "reviewer_notes": sanitize_evidence(f.remediation_reviewer_notes),
                      "vulnerability_category": f.vulnerability_category,
                      "owasp_categories": f.owasp_categories or [],
                      "taxonomy_version": f.taxonomy_version,
                      "validation_state": f.validation_state,
                      "validation_rationale": sanitize_evidence(f.validation_rationale),
                      "remediation_status": f.remediation_status,
                      "remediation_guidance_type": f.remediation_guidance_type,
                      "confidence": f.confidence,
                      "confidence_rationale": sanitize_evidence(f.confidence_rationale),
                      "priority": f.priority,
                      "priority_rationale": sanitize_evidence(f.priority_rationale),
                      "risk_analysis": sanitize_evidence(f.risk_analysis or {}),
                      "correlation_key": f.correlation_key,
                      "first_detected_at": f.first_detected_at.isoformat() if f.first_detected_at else None,
                      "last_observed_at": f.last_observed_at.isoformat() if f.last_observed_at else None} for f in findings],
        "retests": [{"id": row.id, "finding_id": row.finding_id, "outcome": row.outcome,
                     "test_run_id": row.test_run_id, "endpoint_id": row.endpoint_id,
                     "test_id": row.test_id or None, "test_version": row.test_version or None,
                     "endpoint_definition_hash": row.endpoint_definition_hash or None,
                     "evidence": sanitize_evidence(row.evidence) if include_evidence else {},
                     "notes": sanitize_evidence(row.notes),
                     "created_at": row.created_at.isoformat() if row.created_at else None}
                    for row in (retests if configuration.report_type != "EXECUTIVE_SUMMARY" else [])],
    }
    if workflow_scenario:
        notice = ("Product walkthrough scenario. Values illustrate workflow states; "
                  "no target request or client engagement took place.")
        content["report"]["demo_workspace"] = True
        content["demo_notice"] = notice
        content["methodology"]["description"] = notice
        content["methodology"]["checks"] = []
    if configuration.report_type == "EXECUTIVE_SUMMARY":
        content["executive_summary"] = {
            "included_findings": len(findings),
            "severity_distribution": content["finding_summary"]["severity"],
            "key_findings": [{"id": item.id, "title": item.title, "severity": item.severity,
                              "priority": item.priority} for item in findings[:5]],
            "remediation_priorities": [{"id": item.id, "priority": item.priority,
                                        "remediation_status": item.remediation_status} for item in findings[:5]],
            "limitations": content["methodology"]["interpretation"],
        }
    if configuration.report_type == "REMEDIATION":
        content["remediation_summary"] = {
            "states": content["finding_summary"]["remediation_status"],
            "assigned_count": sum(row.assigned_owner_id is not None for row in findings),
            "target_date_count": sum(row.remediation_target_date is not None for row in findings),
            "unverified_fixed_count": sum(row.remediation_status == "FIXED_PENDING_VERIFICATION" for row in findings),
            "verified_fixed_count": sum(row.remediation_status == "VERIFIED_FIXED" for row in findings),
        }
    if configuration.report_type == "RETEST_CLOSURE":
        content["retest_closure_summary"] = {
            "total_retests": len(retests),
            "outcomes": {outcome: sum(row.outcome == outcome for row in retests)
                         for outcome in sorted({row.outcome for row in retests})},
            "verified_fixed_findings": [row.id for row in findings if row.remediation_status == "VERIFIED_FIXED"],
            "pending_reviewer_verification": [row.id for row in findings
                                              if row.remediation_status == "FIXED_PENDING_VERIFICATION"],
        }
    return content


def _report_source_revision(db: Session, assessment: models.Assessment) -> str:
    """Fingerprint report inputs so generation can reject a moving source snapshot."""
    findings = db.query(models.Finding).filter_by(assessment_id=assessment.id).order_by(models.Finding.id).all()
    endpoints = db.query(models.Endpoint).filter_by(assessment_id=assessment.id).order_by(models.Endpoint.id).all()
    runs = db.query(models.TestRun).filter_by(assessment_id=assessment.id).order_by(models.TestRun.id).all()
    retests = (db.query(models.Retest).join(models.Finding, models.Retest.finding_id == models.Finding.id)
               .filter(models.Finding.assessment_id == assessment.id).order_by(models.Retest.id).all())
    apps = db.query(models.AndroidApplication).filter_by(assessment_id=assessment.id).order_by(models.AndroidApplication.id).all()
    graphql_schema = (db.query(models.GraphQLSchemaDocument).filter_by(assessment_id=assessment.id)
                      .order_by(models.GraphQLSchemaDocument.id.desc()).first())
    manual_reviews = (db.query(models.ManualSecurityReview).filter_by(assessment_id=assessment.id)
                      .order_by(models.ManualSecurityReview.id).all())
    revision = {
        "assessment": {"id": assessment.id, "authorization_version": assessment.authorization_version,
                       "configuration_version": assessment.configuration_version,
                       "status": assessment.status, "scope": assessment.authorization_scope_snapshot},
        "findings": [(item.id, item.triage_version, item.validation_state, item.remediation_status,
                      item.last_observed_at.isoformat() if item.last_observed_at else None) for item in findings],
        "endpoints": [(item.id, item.definition_hash, item.inventory_current, item.review_state,
                       item.execution_approved, item.scope_status) for item in endpoints],
        "runs": [(item.id, item.status, item.security_outcome, item.completed_at.isoformat() if item.completed_at else None,
                  item.execution_metadata) for item in runs],
        "retests": [(item.id, item.outcome, item.test_run_id, item.evidence, item.notes) for item in retests],
        "android_apps": [(item.id, item.artifact_sha256, item.metadata_json) for item in apps],
        "manual_reviews": [(item.id, item.framework_id, item.control_id, item.status, item.review_notes,
                            item.evidence_refs, item.linked_finding_id, item.reviewed_by_id,
                            item.updated_at.isoformat() if item.updated_at else None) for item in manual_reviews],
        "manual_review_framework_versions": sorted(MANUAL_REVIEW_FRAMEWORKS),
        "ios_apps": [(item.id, item.artifact_sha256, item.metadata_json)
                     for item in db.query(models.IOSApplication).filter_by(assessment_id=assessment.id).all()],
        "graphql_schema_inventory": ((graphql_schema.id, graphql_schema.content_hash,
                                      graphql_schema.schema_summary)
                                     if graphql_schema else None),
        "evidence_attachments": [(item.id, item.finding_id, item.sha256, item.caption)
                                 for item in db.query(models.FindingEvidenceAttachment)
                                 .join(models.Finding, models.FindingEvidenceAttachment.finding_id == models.Finding.id)
                                 .filter(models.Finding.assessment_id == assessment.id).order_by(models.FindingEvidenceAttachment.id).all()],
    }
    return hashlib.sha256(json.dumps(revision, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@router.get("/reports")
def reports(request: Request, response: Response, db: Session = Depends(get_db), assessment_id: int | None = None,
            limit: int = 100, offset: int = 0):
    if limit < 1 or limit > 500 or offset < 0:
        raise HTTPException(422, "limit must be 1-500 and offset must be non-negative")
    analyst_id = analyst_from_request(request).id
    q = db.query(models.Report).join(models.Assessment).join(models.Client).filter(client_access_filter(analyst_id))
    if assessment_id is not None:
        owned_assessment_or_404(db, assessment_id, analyst_id, required_roles=ALL_CLIENT_ROLES)
        q = q.filter(models.Report.assessment_id == assessment_id)
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Next-Offset"] = str(offset + limit if offset + limit < total else "")
    result = []
    for r in q.order_by(models.Report.created_at.desc()).offset(offset).limit(limit).all():
        content = r.content or {}
        summary = content.get("finding_summary", {})
        result.append({"id": r.id, "assessment_id": r.assessment_id,
                       "assessment_name": r.assessment.name, "client_name": r.assessment.client.name,
                       "version": r.version, "status": r.status, "format": r.format,
                       "demo_workspace": content.get("report", {}).get("demo_workspace") is True,
                       "report_type": content.get("report", {}).get("type", "TECHNICAL"),
                       "finding_summary": {"total": summary.get("total", len(content.get("findings", []))),
                                           "severity": summary.get("severity", {})},
                       "created_at": r.created_at})
    return result


@router.get("/reports/{report_id}")
def report_detail(report_id: int, request: Request, db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    row = (db.query(models.Report).join(models.Assessment).join(models.Client)
           .filter(models.Report.id == report_id, client_access_filter(analyst_id)).first())
    if row is None:
        raise HTTPException(404, "Report not found")
    _require_client_role(db, row.assessment.client, analyst_id, ALL_CLIENT_ROLES)
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=row.assessment.client_id,
        assessment_id=row.assessment_id, event_type="REPORT_ACCESSED", outcome="VIEWED",
        metadata_json={"report_id": row.id, "version": row.version}))
    db.commit()
    return {"id": row.id, "assessment_id": row.assessment_id, "version": row.version,
            "status": row.status, "format": row.format, "created_at": row.created_at,
            "content": sanitize_evidence(row.content)}


@router.post("/reports", status_code=201)
def create_report(assessment_id: int, request: Request, data: schemas.ReportCreate = Body(default=schemas.ReportCreate()),
                  db: Session = Depends(get_db)):
    analyst_id = analyst_from_request(request).id
    assessment = owned_assessment_or_404(db, assessment_id, analyst_id)
    db.query(models.Assessment).filter_by(id=assessment_id).with_for_update().first()
    source_revision = _report_source_revision(db, assessment)
    version = (db.query(models.Report.version).filter_by(assessment_id=assessment_id)
               .order_by(models.Report.version.desc()).limit(1).scalar() or 0) + 1
    row = models.Report(assessment_id=assessment_id, version=version,
                        content=make_report(db, assessment, data), status="COMPLETED", format="json")
    if _report_source_revision(db, assessment) != source_revision:
        db.rollback()
        raise HTTPException(409, "Assessment data changed during report generation; retry to create a consistent snapshot")
    db.add(row); db.flush()
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=assessment.client_id,
        assessment_id=assessment.id, event_type="REPORT_GENERATED", outcome="COMPLETED",
        metadata_json={"report_id": row.id, "version": version,
                       "report_type": data.report_type,
                       "data_revision": row.content["report"]["data_revision"]}))
    db.commit(); db.refresh(row)
    return {"id": row.id, "assessment_id": row.assessment_id, "version": row.version,
            "status": row.status, "format": row.format, "report_type": data.report_type,
            "content": row.content}


@router.get("/reports/{report_id}/export")
def export_report(report_id: int, request: Request, format: str = "json", db: Session = Depends(get_db)):
    row = (
        db.query(models.Report)
        .join(models.Assessment)
        .join(models.Client)
        .filter(models.Report.id == report_id, client_access_filter(analyst_from_request(request).id))
        .first()
    )
    if not row: raise HTTPException(404, "Report not found")
    if format not in {"json", "csv", "html", "pdf"}:
        raise HTTPException(422, "Supported formats: json, csv, html, pdf")
    analyst_id = analyst_from_request(request).id
    _require_client_role(db, row.assessment.client, analyst_id, ALL_CLIENT_ROLES)
    db.add(models.ExecutionAuditEvent(actor_id=analyst_id, client_id=row.assessment.client_id,
        assessment_id=row.assessment_id, event_type="REPORT_EXPORTED", outcome=format.upper(),
        metadata_json={"report_id": row.id, "version": row.version, "format": format}))
    db.commit()
    content = sanitize_evidence(row.content)
    attachment_ids = {int(item["id"]) for finding in content.get("findings", [])
                      for item in finding.get("evidence_attachments", [])
                      if isinstance(item, dict) and str(item.get("id", "")).isdigit()}
    report_attachments = {}
    if attachment_ids:
        report_attachments = {item.id: item for item in db.query(models.FindingEvidenceAttachment)
                              .join(models.Finding, models.FindingEvidenceAttachment.finding_id == models.Finding.id)
                              .filter(models.Finding.assessment_id == row.assessment_id,
                                      models.FindingEvidenceAttachment.id.in_(attachment_ids)).all()}
    embedded_bytes = sum(len(item.image_bytes) for item in report_attachments.values())
    if embedded_bytes > 10 * 1024 * 1024:
        raise HTTPException(413, "Report screenshots exceed the 10 MiB export limit; generate a version without evidence images")
    if format == "json": return Response(json.dumps(content, indent=2), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=apisentinel-report-{report_id}.json"})
    if format == "csv":
        out = io.StringIO(); writer = csv.DictWriter(out, fieldnames=["record_type", "id", "title", "severity", "cvss_base_score", "cvss_vector", "confidence", "validation_state", "priority", "status", "remediation_status", "assigned_owner_id", "target_date", "endpoint", "description", "impact", "remediation", "remediation_notes", "proposed_fix", "framework_id", "framework_name", "control_id", "control_name", "review_status", "review_notes", "evidence_refs", "linked_finding_id"]); writer.writeheader()
        for finding in content.get("findings", []):
            row_data = {key: value for key, value in finding.items() if key in writer.fieldnames}
            row_data["record_type"] = "FINDING"
            cvss = ((finding.get("risk_analysis") or {}).get("cvss") or {})
            row_data["cvss_base_score"] = cvss.get("base_score", "")
            row_data["cvss_vector"] = cvss.get("vector", "")
            for key, value in row_data.items():
                if isinstance(value, (dict, list)):
                    row_data[key] = json.dumps(value, ensure_ascii=False)
                if isinstance(row_data.get(key), str) and row_data[key][:1] in {"=", "+", "-", "@", "\t", "\r"}:
                    row_data[key] = "'" + row_data[key]
            writer.writerow(row_data)
        for review in content.get("manual_reviews", []):
            row_data = {"record_type": "MANUAL_REVIEW", "framework_id": review.get("framework_id"),
                        "framework_name": review.get("framework_name"), "control_id": review.get("control_id"),
                        "control_name": review.get("control_name"), "review_status": review.get("status"),
                        "review_notes": review.get("review_notes"),
                        "evidence_refs": json.dumps(review.get("evidence_refs", []), ensure_ascii=False),
                        "linked_finding_id": review.get("linked_finding_id")}
            for key, value in row_data.items():
                if isinstance(value, str) and value[:1] in {"=", "+", "-", "@", "\t", "\r"}:
                    row_data[key] = "'" + value
            writer.writerow(row_data)
        return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=apisentinel-report-{report_id}.csv"})
    if format == "pdf":
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import Image as ReportImage
            from reportlab.platypus import (
                KeepTogether,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:
            raise HTTPException(503, "PDF export is unavailable because its renderer is not installed") from exc

        from xml.sax.saxutils import escape as xml_escape

        def paragraph(value, style="BodyText"):
            text = str(value if value not in (None, "") else "Not recorded")
            return Paragraph(xml_escape(text).replace("\n", "<br/>"), styles[style])

        assessment_info = content.get("assessment", {})
        report_info = content.get("report", {})
        summary = content.get("finding_summary", {})
        authorization = content.get("authorization_record", {})
        authorized_scope = authorization.get("scope", {})
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                                  fontSize=22, leading=27, textColor=colors.HexColor("#12314b"), spaceAfter=8))
        styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold",
                                  fontSize=14, leading=18, textColor=colors.HexColor("#12314b"),
                                  spaceBefore=16, spaceAfter=7, keepWithNext=True))
        styles.add(ParagraphStyle(name="Subsection", parent=styles["Heading3"], fontName="Helvetica-Bold",
                                  fontSize=11, leading=14, textColor=colors.HexColor("#225765"),
                                  spaceBefore=10, spaceAfter=5, keepWithNext=True))
        styles.add(ParagraphStyle(name="SmallMuted", parent=styles["BodyText"], fontSize=8, leading=11,
                                  textColor=colors.HexColor("#5b6d7a")))
        styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontSize=8, leading=10))
        styles.add(ParagraphStyle(name="CellHead", parent=styles["BodyText"], fontName="Helvetica-Bold",
                                  fontSize=8, leading=10, textColor=colors.white))
        styles.add(ParagraphStyle(name="Callout", parent=styles["BodyText"], fontSize=9, leading=13,
                                  borderColor=colors.HexColor("#16877c"), borderWidth=1,
                                  borderPadding=8, backColor=colors.HexColor("#eef7f5"), spaceBefore=5, spaceAfter=8))
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.62*inch, leftMargin=0.62*inch,
                                topMargin=0.68*inch, bottomMargin=0.65*inch,
                                title=f"APISentinel Security Report - {assessment_info.get('name', 'Assessment')}",
                                author="APISentinel")
        story = [paragraph("APISENTINEL · SECURITY ASSESSMENT", "SmallMuted"), Spacer(1, 5),
                 paragraph(assessment_info.get("name", "Security assessment"), "ReportTitle"),
                 paragraph(f"{str(report_info.get('type', 'TECHNICAL')).replace('_', ' ').title()} · Version {row.version}", "Heading3"),
                 paragraph(f"Assessment #{assessment_info.get('id')} · {assessment_info.get('client_reference', 'Client not recorded')} · {assessment_info.get('assessment_type', 'WEB_API')} · {assessment_info.get('environment', 'Environment not recorded')}", "SmallMuted"),
                 paragraph(f"Generated {report_info.get('generated_at', 'Timestamp not recorded')}", "SmallMuted"),
                 paragraph(f"This point-in-time report contains {len(content.get('findings', []))} finding(s). A later data change requires a new report version.", "Callout"),
                 paragraph("Executive summary", "Section")]
        severity_counts = summary.get("severity", {})
        severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
        severity_table = [[paragraph(key, "CellHead") for key in severity_order],
                          [paragraph(severity_counts.get(key, 0), "Cell") for key in severity_order]]
        severity = Table(severity_table, colWidths=[doc.width/5]*5, hAlign="LEFT")
        severity.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17485a")),
                                      ("BACKGROUND", (0,1), (-1,1), colors.HexColor("#f0f5f7")),
                                      ("BOX", (0,0), (-1,-1), .5, colors.HexColor("#d5e0e6")),
                                      ("INNERGRID", (0,0), (-1,-1), .35, colors.HexColor("#d5e0e6")),
                                      ("ALIGN", (0,0), (-1,-1), "CENTER"),
                                      ("TOPPADDING", (0,0), (-1,-1), 7), ("BOTTOMPADDING", (0,0), (-1,-1), 7)]))
        story += [severity, paragraph("Scope and authorization", "Section"),
                  paragraph(f"Authorization status: {authorization.get('status', 'Not recorded')} · Operator attestation: {'Recorded' if authorization.get('operator_attestation_recorded') else 'Not recorded'} · Independent legal authenticity verification: {'Performed' if authorization.get('legal_authenticity_verified') else 'Not performed'}"),
                  paragraph(f"Authorizing party: {authorization.get('authorizing_party') or 'Not recorded'} · Valid from {authorization.get('valid_from') or 'Not recorded'} to {authorization.get('expires_at') or 'Not recorded'}"),
                  paragraph(f"Hosts: {', '.join(authorized_scope.get('hosts', [])) or 'Not recorded'}"),
                  paragraph(f"Allowed paths: {', '.join(authorized_scope.get('paths', [])) or 'Not recorded'} · Exclusions: {', '.join(authorized_scope.get('exclusions', [])) or 'None recorded'} · Methods: {', '.join(authorization.get('methods', [])) or 'Not recorded'}"),
                  paragraph("Authorization metadata records the application's review state; it does not independently establish signer identity or legal authenticity.", "SmallMuted"),
                  paragraph("Methodology and coverage", "Section"),
                  paragraph(content.get("methodology", {}).get("description", "Saved assessment records.")),
                  paragraph(content.get("methodology", {}).get("interpretation", "Transport outcomes are not security verdicts.")),
                  paragraph(f"Endpoint inventory: {content.get('endpoint_count', 0)} · Eligible checks: {content.get('coverage', {}).get('planned', 0)} · Completed checks: {content.get('coverage', {}).get('completed', 0)} · Coverage: {content.get('coverage', {}).get('percentage', 0)}%"),
                  paragraph("Coverage represents completed registered checks against eligible approved endpoint/check combinations. It does not prove that untested behavior is secure.", "SmallMuted"),
                  paragraph("GraphQL schema inventory", "Section")]
        graphql_inventory = content.get("graphql_schema_inventory")
        if graphql_inventory:
            graphql_summary = graphql_inventory.get("schema_summary", {})
            story.append(paragraph(
                f"Client-provided introspection metadata · {graphql_summary.get('type_count', 0)} types · "
                f"{graphql_summary.get('field_count', 0)} fields · SHA-256 {graphql_inventory.get('content_hash', '')}"))
            graphql_types = {item.get("name"): item for item in graphql_summary.get("types", [])}
            operation_rows = [[paragraph(label, "CellHead") for label in ("Operation", "Root type", "Fields")]]
            for operation, root_name in graphql_summary.get("roots", {}).items():
                root = graphql_types.get(root_name, {})
                field_names = ", ".join(field.get("name", "") for field in root.get("fields", [])) or "None recorded"
                operation_rows.append([paragraph(operation.title(), "Cell"), paragraph(root_name, "Cell"),
                                       paragraph(field_names, "Cell")])
            if len(operation_rows) > 1:
                operation_table = Table(operation_rows, colWidths=[.9*inch, 1.3*inch, doc.width-2.2*inch], repeatRows=1)
                operation_table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17485a")),
                                                     ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f4f7f8")]),
                                                     ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#d5e0e6")),
                                                     ("VALIGN", (0,0), (-1,-1), "TOP"), ("PADDING", (0,0), (-1,-1), 5)]))
                story.append(operation_table)
            story.append(paragraph("Schema metadata only. No GraphQL operation was sent and no authorization, exposure, injection, or rate-limit behavior was tested.", "SmallMuted"))
        else:
            story.append(paragraph("No GraphQL schema inventory was imported."))
        engagement = content.get("engagement", {})
        story.append(paragraph("Engagement objectives and delivery", "Section"))
        story.append(paragraph(f"Objectives: {engagement.get('objectives') or 'Not recorded'}"))
        story.append(paragraph(f"Out of scope: {engagement.get('out_of_scope') or 'Not recorded'}"))
        story.append(paragraph(f"Deliverables: {', '.join(engagement.get('deliverables') or []) or 'Not recorded'} · "
                               f"Planned: {engagement.get('planned_start_date') or 'Not recorded'} to {engagement.get('due_date') or 'Not recorded'}"))
        if engagement.get("milestones"):
            story.append(paragraph("Milestones: " + "; ".join(
                f"{item.get('name', 'Milestone')} ({item.get('due_date') or 'date not set'})"
                for item in engagement["milestones"] if isinstance(item, dict))))
        story.append(paragraph("Manual framework reviews", "Section"))
        manual_summary = content.get("manual_review_summary", {})
        manual_frameworks = content.get("manual_review_frameworks", [])
        manual_reviews = content.get("manual_reviews", [])
        story.append(paragraph(
            f"{manual_summary.get('recorded', 0)} of {manual_summary.get('total_controls', 0)} controls have an analyst-entered status. "
            "Controls without a row are not reviewed. Manual records are not automated test results."))
        if manual_frameworks:
            framework_data = [[paragraph(label, "CellHead") for label in ("Framework", "Recorded", "Unreviewed", "Issues linked")]]
            framework_data.extend([[paragraph(item.get("name"), "Cell"), paragraph(item.get("recorded_count"), "Cell"),
                                    paragraph(item.get("unreviewed_count"), "Cell"),
                                    paragraph(item.get("statuses", {}).get("ISSUE_FOUND", 0), "Cell")]
                                   for item in manual_frameworks])
            framework_table = Table(framework_data, colWidths=[doc.width-2.7*inch, .9*inch, .9*inch, .9*inch], repeatRows=1)
            framework_table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17485a")),
                                                 ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f4f7f8")]),
                                                 ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#d5e0e6")),
                                                 ("VALIGN", (0,0), (-1,-1), "TOP"), ("PADDING", (0,0), (-1,-1), 5)]))
            story.append(framework_table)
        if manual_reviews:
            manual_data = [[paragraph(label, "CellHead") for label in ("Framework / control", "Status", "Review notes", "Finding")]]
            manual_data.extend([[paragraph(f"{item.get('framework_name')} · {item.get('control_id')} · {item.get('control_name')}", "Cell"),
                                 paragraph(item.get("status"), "Cell"),
                                 paragraph((item.get("review_notes") or "Evidence omitted") +
                                           ("\nEvidence: " + "; ".join(item.get("evidence_refs") or [])
                                            if item.get("evidence_refs") else ""), "Cell"),
                                 paragraph(item.get("linked_finding_id") or "—", "Cell")]
                                for item in manual_reviews])
            manual_table = Table(manual_data, colWidths=[2.35*inch, .9*inch, doc.width-4.05*inch, .8*inch], repeatRows=1)
            manual_table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17485a")),
                                              ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f4f7f8")]),
                                              ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#d5e0e6")),
                                              ("VALIGN", (0,0), (-1,-1), "TOP"), ("PADDING", (0,0), (-1,-1), 5)]))
            story.append(manual_table)
        else:
            story.append(paragraph("No manual framework review records have been saved."))
        story.append(paragraph("Findings", "Section"))
        android_apps = content.get("android_applications", [])
        ios_apps = content.get("ios_applications", [])
        if android_apps or ios_apps:
            story[-1:] = [paragraph("Mobile application artifacts", "Section")]
            for app in android_apps:
                story.append(paragraph(
                    f"Android · {app.get('package_name')} · {app.get('version_name') or 'Version not recorded'} · "
                    f"API {app.get('api_level') or 'not recorded'} · SHA-256 {app.get('artifact_sha256')}"))
                static = app.get("metadata", {}).get("static_analysis", {})
                if static:
                    story.append(paragraph(
                        "Manifest-only static observations; analyst review required. No code, device, or runtime analysis was performed.",
                        "SmallMuted"))
            for app in ios_apps:
                story.append(paragraph(
                    f"iOS metadata · {app.get('display_name') or app.get('bundle_id')} · {app.get('bundle_id')} · "
                    f"Version {app.get('version_name') or 'not recorded'} · Build {app.get('build_number') or 'not recorded'} · "
                    f"Minimum OS {app.get('minimum_os_version') or 'not recorded'} · SHA-256 {app.get('artifact_sha256')}"))
                story.append(paragraph(
                    "Info.plist metadata only; executable, entitlements, signature, and runtime were not analyzed.",
                    "SmallMuted"))
            story.append(paragraph("Findings", "Section"))
        findings = content.get("findings", [])
        if findings:
            table_data = [[paragraph(label, "CellHead") for label in ("Severity", "Finding", "Endpoint", "Validation / triage")]]
            for item in findings:
                table_data.append([paragraph(item.get("severity"), "Cell"), paragraph(f"{item.get('title', 'Untitled')} (#{item.get('id')})", "Cell"),
                                   paragraph(item.get("endpoint") or "Not recorded", "Cell"),
                                   paragraph(f"{item.get('validation_state', 'Not recorded')} / {item.get('status', 'Not recorded')}", "Cell")])
            findings_table = Table(table_data, colWidths=[0.8*inch, 2.25*inch, 1.65*inch, doc.width-4.7*inch], repeatRows=1, hAlign="LEFT")
            findings_table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17485a")),
                                                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f4f7f8")]),
                                                ("BOX", (0,0), (-1,-1), .5, colors.HexColor("#d5e0e6")),
                                                ("INNERGRID", (0,0), (-1,-1), .35, colors.HexColor("#d5e0e6")),
                                                ("VALIGN", (0,0), (-1,-1), "TOP"),
                                                ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6),
                                                ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6)]))
            story.append(findings_table)
            for item in findings:
                story.append(KeepTogether([
                    paragraph(f"{item.get('title', 'Finding')} · {item.get('severity', 'Unrated')} · {item.get('priority', 'No priority')}", "Subsection"),
                    paragraph(f"Validation: {item.get('validation_state', 'Not recorded')} · Triage: {item.get('status', 'Not recorded')} · Confidence: {item.get('confidence', 'Unknown')} · Remediation: {item.get('remediation_status', 'Not recorded')}", "SmallMuted"),
                    paragraph(f"Endpoint: {item.get('endpoint') or 'Not recorded'}"),
                    paragraph(f"Description: {item.get('description') or 'Not recorded'}"),
                    paragraph(f"Expected behavior: {item.get('expected_behavior') or 'Not documented'}"),
                    paragraph(f"Observed behavior: {item.get('observed_behavior') or 'Not recorded'}"),
                    paragraph(f"Impact: {item.get('impact') or 'Not established'}"),
                    paragraph(f"CVSS v{((item.get('risk_analysis') or {}).get('cvss') or {}).get('version', '3.1')} base score: {((item.get('risk_analysis') or {}).get('cvss') or {}).get('base_score', 'Not supplied')} · {((item.get('risk_analysis') or {}).get('cvss') or {}).get('vector', 'No vector recorded')}"),
                    paragraph(f"Recommended remediation: {item.get('remediation') or 'Not recorded'}"),
                    paragraph(f"Proposed fix: {item.get('proposed_fix') or 'Not recorded'}"),
                    paragraph(f"Taxonomy: {', '.join(item.get('owasp_categories') or []) or 'Not mapped'}"),
                ]))
                if item.get("evidence"):
                    story.append(paragraph("Sanitized evidence", "Subsection"))
                    evidence_lines = json.dumps(item["evidence"], ensure_ascii=False, indent=2).splitlines()
                    for line in evidence_lines[:120]:
                        story.append(paragraph(line, "Code"))
                for attachment in item.get("evidence_attachments", []):
                    stored = report_attachments.get(attachment.get("id"))
                    if stored is None or stored.finding_id != item.get("id"):
                        continue
                    figure = ReportImage(io.BytesIO(stored.image_bytes), width=doc.width,
                                         height=doc.width * stored.height / max(stored.width, 1),
                                         kind="proportional")
                    story.append(KeepTogether([
                        paragraph(f"Figure · {stored.caption or stored.filename}", "SmallMuted"),
                        figure,
                    ]))
        else:
            story.append(paragraph("No findings matched this report's inclusion criteria."))
        story.append(paragraph("Execution outcomes", "Section"))
        test_runs = content.get("test_runs", [])
        if test_runs:
            run_data = [[paragraph(label, "CellHead") for label in ("Check", "Transport", "Security outcome", "Limitations")]]
            run_data.extend([[paragraph(f"{run.get('test_id') or 'Transport only'} {run.get('test_version') or ''}", "Cell"),
                              paragraph(run.get("transport_outcome"), "Cell"), paragraph(run.get("security_outcome"), "Cell"),
                              paragraph(run.get("limitations"), "Cell")] for run in test_runs])
            run_table = Table(run_data, colWidths=[1.65*inch, 1.0*inch, 1.15*inch, doc.width-3.8*inch], repeatRows=1)
            run_table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17485a")),
                                           ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f4f7f8")]),
                                           ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#d5e0e6")),
                                           ("VALIGN", (0,0), (-1,-1), "TOP"), ("PADDING", (0,0), (-1,-1), 6)]))
            story.append(run_table)
        else:
            story.append(paragraph("No execution records are included in this report."))
        story.append(paragraph("Retest history", "Section"))
        retests = content.get("retests", [])
        if retests:
            for item in retests:
                story.append(paragraph(f"Finding #{item.get('finding_id')} · {item.get('outcome')} · TestRun {item.get('test_run_id') or 'Manual / unlinked'} · {item.get('created_at') or 'Date not recorded'}"))
                story.append(paragraph(item.get("notes") or "No retest notes recorded.", "SmallMuted"))
        else:
            story.append(paragraph("No retests have been recorded for the included findings."))
        story += [paragraph("Limitations and interpretation", "Section"),
                  paragraph("Transport completion is not a security verdict. Automated observations are limited to the checks and evidence shown. No broader exploitability, business impact, or remediation claim should be inferred unless supported by recorded evidence and review."),
                  paragraph(f"Source revision: {report_info.get('data_revision', 'Not recorded')}", "SmallMuted")]

        def draw_page(canvas, document):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#d5e0e6"))
            canvas.line(document.leftMargin, 0.48*inch, letter[0]-document.rightMargin, 0.48*inch)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#607386"))
            canvas.drawString(document.leftMargin, 0.31*inch, f"Confidential · APISentinel · Report #{report_id} v{row.version}")
            canvas.drawRightString(letter[0]-document.rightMargin, 0.31*inch, f"Page {document.page}")
            canvas.restoreState()

        doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
        return Response(buffer.getvalue(), media_type="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename=apisentinel-report-{report_id}.pdf",
                                 "X-Content-Type-Options": "nosniff"})
    if format == "html":
        def esc(value, fallback="Not recorded"):
            return escape(str(value if value not in (None, "") else fallback))

        def count_cards(values, order):
            return "".join(
                f"<div class='metric'><span>{escape(label.replace('_', ' ').title())}</span><strong>{int(values.get(key, 0) or 0)}</strong></div>"
                for key, label in order
            )

        findings = content.get("findings", [])
        manual_summary = content.get("manual_review_summary", {})
        manual_frameworks = content.get("manual_review_frameworks", [])
        manual_reviews = content.get("manual_reviews", [])
        framework_summary_html = "".join(
            f"<li>{esc(item.get('name'))}: {int(item.get('recorded_count', 0) or 0)} recorded, "
            f"{int(item.get('unreviewed_count', 0) or 0)} unreviewed, "
            f"{int((item.get('statuses') or {}).get('ISSUE_FOUND', 0) or 0)} issue(s) linked</li>"
            for item in manual_frameworks)
        manual_rows = "".join(
            f"<tr><td>{esc(item.get('framework_name'))}</td><td><b>{esc(item.get('control_id'))}</b><small>{esc(item.get('control_name'))}</small></td>"
            f"<td>{esc(item.get('status'))}</td><td>{esc(item.get('review_notes') or 'Evidence omitted')}"
            f"{('<small>Evidence: ' + esc('; '.join(item.get('evidence_refs') or [])) + '</small>') if item.get('evidence_refs') else ''}"
            f"{('<small>Finding #' + esc(item.get('linked_finding_id')) + '</small>') if item.get('linked_finding_id') else ''}</td></tr>"
            for item in manual_reviews)
        if not manual_rows:
            manual_rows = "<tr><td colspan='4' class='empty'>No manual framework review records have been saved.</td></tr>"
        def image_figures(finding):
            parts = []
            for attachment in finding.get("evidence_attachments", []):
                stored = report_attachments.get(attachment.get("id"))
                if stored is None or stored.finding_id != finding.get("id"):
                    continue
                encoded = base64.b64encode(stored.image_bytes).decode("ascii")
                parts.append("<figure><img alt=\"Sanitized assessment evidence\" src=\"data:image/jpeg;base64," + encoded +
                             "\"><figcaption>Figure · " + escape(stored.caption or stored.filename) +
                             "</figcaption></figure>")
            return "".join(parts)
        rows = "".join(
            f"<tr><td><span class='severity severity-{escape(str(f.get('severity', '')).lower())}'>{esc(f.get('severity'))}</span></td>"
            f"<td><strong>{esc(f.get('title'))}</strong><small>Finding #{esc(f.get('id'))}</small></td>"
            f"<td><code>{esc(f.get('endpoint'))}</code></td>"
            f"<td>{esc(f.get('validation_state'))}<small>Triage: {esc(f.get('status'))}</small></td></tr>"
            for f in findings
        )
        if not rows:
            rows = "<tr><td colspan='4' class='empty'>No findings matched this report's inclusion criteria.</td></tr>"
        finding_details = "".join(
            "<article class='finding'><h3>" + escape(str(item.get("title"))) + " · " +
            escape(str(item.get("severity"))) + " · " + escape(str(item.get("priority"))) +
            "</h3><p><b>Validation:</b> " + escape(str(item.get("validation_state"))) +
            " · <b>Remediation:</b> " + escape(str(item.get("remediation_status"))) +
            " · <b>Confidence:</b> " + escape(str(item.get("confidence"))) +
            "</p><p><b>Endpoint:</b> " + escape(str(item.get("endpoint") or "Not recorded")) +
            "</p><p><b>CVSS v3.1 base score:</b> " + escape(str(((item.get("risk_analysis") or {}).get("cvss") or {}).get("base_score", "Not supplied"))) +
            " · <b>Vector:</b> " + escape(str(((item.get("risk_analysis") or {}).get("cvss") or {}).get("vector", "Not recorded"))) +
            "</p><p>" + escape(str(item.get("description") or "")) +
            "</p><p><b>Expected behavior:</b> " + escape(str(item.get("expected_behavior") or "Not documented")) +
            "</p><p><b>Observed behavior:</b> " + escape(str(item.get("observed_behavior") or "Not recorded")) +
            "</p><p><b>Impact:</b> " + escape(str(item.get("impact") or "Not established")) +
            "</p><p><b>Recommended remediation:</b> " + escape(str(item.get("remediation") or "Not recorded")) +
            "</p><p><b>Proposed fix:</b> " + escape(str(item.get("proposed_fix") or "Not recorded")) +
            "</p><p><b>OWASP:</b> " + escape(", ".join(item.get("owasp_categories") or [])) +
            "</p><details><summary>Sanitized evidence</summary><pre>" +
            escape(json.dumps(item.get("evidence") or {}, indent=2, ensure_ascii=False)) +
            "</pre></details>" + image_figures(item) + "</article>" for item in content.get("findings", []))
        run_rows = "".join(f"<tr><td>{escape(str(run.get('test_id') or 'Transport only'))} {escape(str(run.get('test_version') or ''))}</td><td>{escape(str(run.get('transport_outcome')))}</td><td>{escape(str(run.get('security_outcome')))}</td><td>{escape(str(run.get('limitations') or ''))}</td></tr>" for run in content.get("test_runs", []))
        check_rows = "".join(f"<tr><td>{escape(str(check.get('test_id')))} v{escape(str(check.get('version')))}</td><td>{escape(str(check.get('purpose')))}</td><td>{escape(str(check.get('limitations')))}</td></tr>" for check in content.get("methodology", {}).get("checks", []))
        retests = content.get("retests", [])
        retest_rows = "".join(f"<tr><td>Finding #{esc(retest.get('finding_id'))}</td><td>{esc(retest.get('outcome'))}</td><td>{esc(retest.get('test_run_id'), 'Manual / unlinked')}</td></tr>" for retest in retests)
        if not retest_rows:
            retest_rows = "<tr><td colspan='3' class='empty'>No retests have been recorded for the included findings.</td></tr>"
        methodology_description = esc(content.get("methodology", {}).get("description", "Saved assessment records."))
        methodology = esc(content.get("methodology", {}).get("interpretation", ""))
        authorization = content.get("authorization_record", {})
        authorized_scope = authorization.get("scope", {})
        scope_html = f"<ul><li>Hosts: {escape(', '.join(authorized_scope.get('hosts', [])))}</li><li>Paths: {escape(', '.join(authorized_scope.get('paths', [])))}</li><li>Exclusions: {escape(', '.join(authorized_scope.get('exclusions', [])))}</li><li>Methods: {escape(', '.join(authorization.get('methods', [])))}</li></ul>"
        authorization_html = (f"<p><b>Authorization status:</b> {esc(authorization.get('status'))} · <b>Operator attestation:</b> {'Recorded' if authorization.get('operator_attestation_recorded') else 'Not recorded'} · <b>Independent legal verification:</b> {'Yes' if authorization.get('legal_authenticity_verified') else 'Not performed'}</p><p><b>Authorizing party:</b> {esc(authorization.get('authorizing_party'))} · <b>Valid:</b> {esc(authorization.get('valid_from'))} – {esc(authorization.get('expires_at'))}</p>{scope_html}<p class='notice'>Authorization metadata records the application's review state; it does not independently establish signer identity or legal authenticity.</p>")
        android_rows = "".join(f"<tr><td>{escape(str(app.get('package_name')))}</td><td>{escape(str(app.get('version_name')))}</td><td>{escape(str(app.get('version_code')))}</td><td>{escape(str(app.get('artifact_sha256')))}</td><td>{escape(str(app.get('api_level') or ''))}</td></tr>" for app in content.get("android_applications", []))
        android_html = "" if not android_rows else f"<h2>Android application metadata</h2><p>Manifest metadata was parsed in the isolated APK parser; APK files are never persisted or executed.</p><table><thead><tr><th>Package</th><th>Version</th><th>Version code</th><th>Artifact SHA-256</th><th>API level</th></tr></thead><tbody>{android_rows}</tbody></table>"
        ios_rows = "".join(f"<tr><td>{escape(str(app.get('display_name') or app.get('bundle_id')))}</td><td>{escape(str(app.get('bundle_id')))}</td><td>{escape(str(app.get('version_name')))}</td><td>{escape(str(app.get('build_number')))}</td><td>{escape(str(app.get('minimum_os_version')))}</td><td>{escape(str(app.get('artifact_sha256')))}</td></tr>" for app in content.get("ios_applications", []))
        ios_html = "" if not ios_rows else f"<h2>iOS bundle metadata</h2><p>Only the IPA Info.plist was parsed in the isolated metadata parser; IPA bytes, executable code, and entitlements are not stored or analyzed.</p><table><thead><tr><th>App</th><th>Bundle ID</th><th>Version</th><th>Build</th><th>Minimum iOS</th><th>Artifact SHA-256</th></tr></thead><tbody>{ios_rows}</tbody></table>"
        graphql_inventory = content.get("graphql_schema_inventory")
        if graphql_inventory:
            graphql_summary = graphql_inventory.get("schema_summary", {})
            graphql_types = {item.get("name"): item for item in graphql_summary.get("types", [])}
            graphql_rows = "".join(
                f"<tr><td>{esc(operation.title())}</td><td><code>{esc(root_name)}</code></td><td>{esc(', '.join(field.get('name', '') for field in graphql_types.get(root_name, {}).get('fields', [])) or 'None recorded')}</td></tr>"
                for operation, root_name in graphql_summary.get("roots", {}).items())
            if not graphql_rows:
                graphql_rows = "<tr><td colspan='3'>No operation roots recorded</td></tr>"
            graphql_html = ("<section class='section'><h2>GraphQL schema inventory</h2>"
                f"<p>Client-provided introspection metadata · {int(graphql_summary.get('type_count', 0) or 0)} types · {int(graphql_summary.get('field_count', 0) or 0)} fields · SHA-256 <code>{esc(graphql_inventory.get('content_hash'))}</code></p>"
                f"<table><thead><tr><th>Operation</th><th>Root type</th><th>Fields</th></tr></thead><tbody>{graphql_rows}</tbody></table>"
                "<p class='muted'>Schema metadata only. No GraphQL operation was sent and no authorization, exposure, injection, or rate-limit behavior was tested.</p></section>")
        else:
            graphql_html = ""
        engagement = content.get("engagement", {})
        milestone_items = "".join(f"<li>{esc(item.get('name'))} · {esc(item.get('due_date'))}</li>"
                                   for item in engagement.get("milestones", []) if isinstance(item, dict))
        engagement_html = ("<section class='section'><h2>Engagement objectives and delivery</h2>"
            f"<p><b>Objectives:</b> {esc(engagement.get('objectives'))}</p>"
            f"<p><b>Out of scope:</b> {esc(engagement.get('out_of_scope'))}</p>"
            f"<p><b>Deliverables:</b> {esc(', '.join(engagement.get('deliverables') or []))}<br>"
            f"<b>Planned dates:</b> {esc(engagement.get('planned_start_date'))} – {esc(engagement.get('due_date'))}</p>"
            f"{('<ul>' + milestone_items + '</ul>') if milestone_items else ''}</section>")
        assessment_info = content.get("assessment", {})
        report_info = content.get("report", {})
        summary = content.get("finding_summary", {})
        report_type = report_info.get("type", "TECHNICAL")
        severity_cards = count_cards(summary.get("severity", {}), [(key, key) for key in ("Critical", "High", "Medium", "Low", "Informational")])
        state_labels = {"VALIDATED": "Validated", "NEEDS_REVIEW": "Needs review",
                        "PENDING_VALIDATION": "Pending validation", "INCONCLUSIVE": "Inconclusive",
                        "REJECTED": "Rejected"}
        state_cards = "".join(
            f"<div class='metric'><span>{escape(state_labels[key])}</span><strong>{int(summary.get('validation_state', {}).get(key, 0) or 0)}</strong></div>"
            for key in state_labels
        )
        policy = report_info.get("inclusion_policy", {})
        allowed_methods = ", ".join(authorization.get("methods", [])) or "Not recorded"
        generated = report_info.get("generated_at", "")
        generated_display = esc(generated)
        if generated:
            try:
                from datetime import datetime
                generated_display = datetime.fromisoformat(generated).strftime("%d %B %Y, %H:%M UTC")
            except (ValueError, TypeError):
                pass
        coverage = content.get("coverage", {})
        coverage_pct = coverage.get("percentage", 0)
        test_runs = content.get("test_runs", [])
        check_rows = check_rows or "<tr><td colspan='3' class='empty'>No registered checks were included for this report type.</td></tr>"
        run_rows = run_rows or "<tr><td colspan='4' class='empty'>No execution records are included in this report.</td></tr>"
        android_html = android_html + ios_html
        finding_details = finding_details or "<p class='empty'>No finding details are available.</p>"
        inclusion = f"Validation: {', '.join(policy.get('validation_states', [])) if isinstance(policy.get('validation_states'), list) else policy.get('validation_states', 'ALL')} · Severity: {', '.join(policy.get('severities', [])) if isinstance(policy.get('severities'), list) else policy.get('severities', 'ALL')} · Sanitized evidence: {'Included' if policy.get('evidence_included') else 'Omitted'}"
        endpoint_inventory = coverage.get("endpoint_inventory", {})
        coverage_explainer = ("Coverage is the share of eligible approved endpoint/check combinations with a completed registered security check. "
                              "It does not measure all possible vulnerabilities or guarantee that untested behavior is secure.")
        html = ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">"
            "<title>APISentinel Security Report</title><style>:root{color-scheme:light;--ink:#172b3d;--muted:#607386;--line:#dbe4eb;--accent:#087f78;--soft:#f3f7f9}*{box-sizing:border-box}body{font:15px/1.55 Inter,system-ui,-apple-system,Segoe UI,sans-serif;max-width:1080px;margin:0 auto;padding:38px 34px;color:var(--ink);background:#fff}header{padding:32px 36px;border-radius:14px;background:linear-gradient(135deg,#102c40,#145b62);color:#fff;margin-bottom:28px}header p{margin:0 0 8px}header h1{font-size:30px;line-height:1.2;margin:12px 0}header .meta{color:#d8e8ec}.eyebrow{font-size:12px;letter-spacing:.13em;font-weight:700;color:#65d4c4}h2{font-size:20px;margin:30px 0 12px;color:#14364a}h3{font-size:16px;margin:22px 0 8px}.section{margin:20px 0 26px}.muted,small{color:var(--muted)}small{display:block;font-size:12px;margin-top:4px}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:10px;margin:16px 0}.metric{padding:14px;border:1px solid var(--line);border-radius:10px;background:var(--soft)}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{font-size:23px}.callout,.notice{border-left:4px solid var(--accent);background:#eff8f6;padding:12px 15px;border-radius:4px;margin:14px 0}.notice{font-size:13px}table{border-collapse:collapse;width:100%;margin:12px 0 24px;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:11px 12px;text-align:left;vertical-align:top}th{background:#f1f5f7;color:#40596b;font-size:11px;letter-spacing:.06em;text-transform:uppercase}tbody tr:nth-child(even){background:#fafcfd}.finding{border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0;break-inside:avoid}.finding h3{margin-top:0}.finding figure{margin:18px 0 4px;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--soft)}.finding figure img{display:block;max-width:100%;max-height:720px;margin:auto;object-fit:contain}.finding figcaption{margin-top:8px;color:var(--muted);font-size:12px}.severity{display:inline-block;padding:3px 9px;border-radius:20px;background:#e8eef2;font-weight:700;font-size:12px}.severity-critical,.severity-high{background:#fde8e8;color:#9c2828}.severity-medium{background:#fff0d8;color:#84540b}.severity-low{background:#e8f2ff;color:#285a91}.severity-informational{background:#e8f4f3;color:#24645e}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}code{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6f8;padding:14px;border-radius:8px;font-size:12px}details{margin-top:14px}summary{cursor:pointer;font-weight:650}.empty{padding:16px;color:var(--muted);text-align:center}.footer{margin-top:34px;border-top:1px solid var(--line);padding-top:14px;color:var(--muted);font-size:12px}.scope-list{display:flex;flex-wrap:wrap;gap:8px;list-style:none;padding:0}.scope-list li{background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:6px 9px;font:12px ui-monospace,monospace}@media(max-width:650px){body{padding:18px 14px}header{padding:22px}header h1{font-size:24px}table{display:block;overflow-x:auto}}@media print{body{max-width:none;padding:0;font-size:11pt}header{print-color-adjust:exact;-webkit-print-color-adjust:exact}.finding,table{break-inside:avoid}h2,h3{break-after:avoid}details>pre{display:block}}</style></head><body>"
            f"<header><p class='eyebrow'>APISENTINEL · SECURITY ASSESSMENT</p><h1>{esc(assessment_info.get('name'), 'Security assessment')}</h1>"
            f"<p class='meta'>{esc(report_type.replace('_', ' ').title())} · Report version {row.version} · Generated {generated_display}</p>"
            f"<p class='meta'>Assessment #{esc(assessment_info.get('id'))} · {esc(assessment_info.get('client_reference'))} · {esc(assessment_info.get('assessment_type'))} · {esc(assessment_info.get('environment'))}</p></header>"
            f"<section class='section'><h2>Executive summary</h2><p>This report includes <b>{len(findings)}</b> finding(s) based on persisted assessment records. It is a point-in-time snapshot; later assessment changes require a new report version.</p>"
            f"<div class='metrics'>{severity_cards}</div><p class='muted'>{escape(inclusion)}</p></section>"
            f"<section class='section'><h2>Assessment scope and authorization</h2><p><b>Authorized hosts:</b></p><ul class='scope-list'>{''.join(f'<li>{escape(str(x))}</li>' for x in authorized_scope.get('hosts', [])) or '<li>Not recorded</li>'}</ul>"
            f"<p><b>Allowed paths:</b> {esc(', '.join(authorized_scope.get('paths', [])))}<br><b>Excluded paths:</b> {esc(', '.join(authorized_scope.get('exclusions', [])))}<br><b>Permitted methods:</b> {escape(allowed_methods)}</p>{authorization_html}</section>"
            f"{android_html}{graphql_html}{engagement_html}<section class='section'><h2>Methodology and coverage</h2><p>{methodology_description}</p><p>{methodology}</p><div class='metrics'><div class='metric'><span>Inventory endpoints</span><strong>{int(content.get('endpoint_count') or 0)}</strong></div><div class='metric'><span>Assessment coverage</span><strong>{coverage_pct}%</strong></div><div class='metric'><span>Included findings</span><strong>{len(findings)}</strong></div></div><p class='muted'>{escape(coverage_explainer)}</p>"
            f"<p>{int(endpoint_inventory.get('approved', 0) or 0)} approved endpoints · {int(coverage.get('planned', 0) or 0)} eligible checks · {int(coverage.get('completed', 0) or 0)} completed checks</p>"
            f"<h3>Registered checks</h3><table><thead><tr><th>Check / version</th><th>Purpose</th><th>Limitations</th></tr></thead><tbody>{check_rows}</tbody></table></section>"
            f"<section class='section'><h2>Manual framework reviews</h2><p>{int(manual_summary.get('recorded', 0) or 0)} of {int(manual_summary.get('total_controls', 0) or 0)} controls have an analyst-entered status. Controls without a row are not reviewed. Manual records are not automated test results.</p><ul>{framework_summary_html}</ul><table><thead><tr><th>Framework</th><th>Control</th><th>Status</th><th>Review notes and evidence</th></tr></thead><tbody>{manual_rows}</tbody></table></section>"
            f"<section class='section'><h2>Execution record</h2><p class='muted'>Transport completion describes request handling; it is not itself a security verdict.</p><table><thead><tr><th>Check</th><th>Transport</th><th>Security outcome</th><th>Limitations</th></tr></thead><tbody>{run_rows}</tbody></table></section>"
            f"<section class='section'><h2>Findings</h2><p>Validation and triage are distinct: a validated observation does not necessarily establish exploitability or business impact.</p><div class='metrics'>{state_cards}</div><table><thead><tr><th>Severity</th><th>Finding</th><th>Endpoint</th><th>Validation / triage</th></tr></thead><tbody>{rows}</tbody></table>{finding_details}</section>"
            f"<section class='section'><h2>Retest history</h2><table><thead><tr><th>Finding</th><th>Outcome</th><th>Execution provenance</th></tr></thead><tbody>{retest_rows}</tbody></table></section>"
            f"<section class='section'><h2>Limitations and interpretation</h2><p>Automated observations are limited to the checks and evidence shown. No broader exploitability, business impact, or remediation claim should be inferred unless explicitly supported by the recorded evidence and review.</p><p>Report source revision: <code>{esc(report_info.get('data_revision'))}</code></p></section>"
            "<footer class='footer'>Confidential security assessment information · Generated by APISentinel. Handle and distribute according to the engagement agreement.</footer></body></html>")
        return Response(html, media_type="text/html", headers={"Content-Disposition": f"attachment; filename=apisentinel-report-{report_id}.html",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'",
            "X-Content-Type-Options": "nosniff"})
    raise HTTPException(422, "Supported formats: json, csv, html, pdf")
