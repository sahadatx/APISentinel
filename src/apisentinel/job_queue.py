"""Persistent, bounded queue for explicitly approved safe HTTP requests.

Workers always call the Phase 1 runner; imported definitions never cause a job to
be created or executed on their own.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError

from . import models
from .authorization import authorization_allows
from .config import settings
from .credential_vault import DatabaseCredentialResolver
from .db import SessionLocal
from .finding_analysis import finding_analysis_fields
from .request_builder import RequestBuildError, build_request
from .runner import BearerTokenReference, RequestOutcome, RunnerResult, run_request
from .safety import sanitize_evidence
from .secrets import decrypt_secret
from .test_registry import (
    SecurityOutcome,
    classify_execution,
    evaluate_safely,
    resolve_test,
)

MAX_ATTEMPTS = 2


def idempotency_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(db, run: models.TestRun, event: str, outcome: str, metadata: dict | None = None,
           finding_id: int | None = None):
    assessment = db.get(models.Assessment, run.assessment_id)
    db.add(models.ExecutionAuditEvent(
        actor_id=run.analyst_id, client_id=assessment.client_id if assessment else None,
        assessment_id=run.assessment_id, test_run_id=run.id, finding_id=finding_id, event_type=event,
        outcome=outcome, metadata_json=metadata or {},
    ))


def _claim(db, worker_id: str) -> int | None:
    now = datetime.now(UTC)
    expired_query = db.query(models.TestRun).filter(
        models.TestRun.status == "RUNNING",
        models.TestRun.execution_mode != "DEMO",
        models.TestRun.worker_lease_expires_at.is_not(None),
        models.TestRun.worker_lease_expires_at < now,
    ).order_by(models.TestRun.id).limit(100)
    if db.bind.dialect.name == "postgresql":
        expired_query = expired_query.with_for_update(skip_locked=True)
    expired = expired_query.all()
    for run in expired:
        is_multi_request_check = False
        if run.test_id:
            try:
                is_multi_request_check = bool(resolve_test(run.test_id).workflow)
            except (KeyError, PermissionError):
                pass
        if run.attempt_count < MAX_ATTEMPTS and not is_multi_request_check:
            run.status = "QUEUED"
            run.started_at = None
            run.worker_lease_expires_at = None
            _event(db, run, "HTTP_JOB_RECOVERED", "REQUEUED", {"attempt_count": run.attempt_count})
        else:
            run.status = RequestOutcome.TRANSPORT_ERROR.value
            run.completed_at = now
            run.worker_lease_expires_at = None
            if is_multi_request_check:
                run.encrypted_request_parameters = None
            run.summary = ("Identity comparison worker lease expired; partial requests may have been sent and the check was not replayed"
                           if is_multi_request_check else
                           "Worker lease expired repeatedly; request was not automatically replayed again")
            _event(db, run, "HTTP_JOB_RECOVERED", "FAILED", {"attempt_count": run.attempt_count})
    db.flush()
    query = (db.query(models.TestRun).filter(models.TestRun.status == "QUEUED",
                                           models.TestRun.execution_mode != "DEMO")
             .order_by(models.TestRun.created_at, models.TestRun.id))
    if db.bind.dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    run = query.first()
    if run is None:
        db.commit()
        return None
    run.status = "RUNNING"
    run.started_at = now
    run.attempt_count += 1
    run.worker_lease_expires_at = now + timedelta(seconds=max(60, settings.runner_total_timeout_seconds + 30))
    run.summary = "Safe HTTP request claimed by a worker"
    _event(db, run, "HTTP_JOB_STARTED", "RUNNING", {"worker_id": worker_id, "attempt": run.attempt_count})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return None
    return run.id


def _run_identity_workflow(db, run, endpoint, assessment, definition, supplied, cancelled) -> RunnerResult:
    """Run a registered identity comparison using only bounded safe reads."""
    if definition.workflow not in {"BOLA", "BFLA"}:
        return RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Unsupported identity comparison workflow")
    identity_ids = supplied.get("test_identity_ids")
    if (not isinstance(identity_ids, list) or len(identity_ids) != 2
            or any(not isinstance(identity_id, int) or isinstance(identity_id, bool) for identity_id in identity_ids)
            or len(set(identity_ids)) != 2):
        return RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Stored test identity selection is invalid")
    profiles = (db.query(models.TestIdentityProfile)
                .filter(models.TestIdentityProfile.assessment_id == assessment.id,
                        models.TestIdentityProfile.id.in_(identity_ids),
                        models.TestIdentityProfile.active.is_(True)).all())
    profiles_by_id = {profile.id: {"id": profile.id, "label": profile.label, "role": profile.role}
                       for profile in profiles}
    if len(profiles_by_id) != 2:
        return RunnerResult(RequestOutcome.AUTH_UNAVAILABLE, detail="A selected test identity is unavailable")
    ordered_profiles = [profiles_by_id[identity_id] for identity_id in identity_ids]
    path_parameters = supplied.get("path_parameters", {})
    query_parameters = supplied.get("query_parameters", {})
    header_parameters = supplied.get("header_parameters", {})
    object_ids = supplied.get("synthetic_object_ids", [])
    object_parameter = supplied.get("object_parameter")
    sequence = []
    if definition.workflow == "BOLA":
        if (not isinstance(object_ids, list) or len(object_ids) != 2
                or any(not isinstance(item, str) or not item or len(item) > 200 for item in object_ids)
                or object_ids[0] == object_ids[1] or not isinstance(object_parameter, str)
                or object_parameter in path_parameters):
            return RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Stored synthetic object selection is invalid")
        sequence = [
            (ordered_profiles[0], object_ids[0], "own", ordered_profiles[0]["label"]),
            (ordered_profiles[1], object_ids[1], "own", ordered_profiles[1]["label"]),
            (ordered_profiles[0], object_ids[1], "cross", ordered_profiles[1]["label"]),
            (ordered_profiles[1], object_ids[0], "cross", ordered_profiles[0]["label"]),
        ]
    else:
        expected_allowed_id = supplied.get("expected_allowed_identity_id")
        if expected_allowed_id not in identity_ids:
            return RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Stored role expectation is invalid")
        ordered_role_profiles = sorted(ordered_profiles, key=lambda profile: profile["id"] != expected_allowed_id)
        sequence = [(profile, None, None, None) for profile in ordered_role_profiles]

    from .api import _endpoint_request_url

    base_url = _endpoint_request_url(assessment, endpoint)
    if not base_url:
        return RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Endpoint target cannot be derived safely")
    budget = (run.execution_metadata or {}).get("check_budget") or {}
    total_budget = min(float(budget.get("max_duration_seconds") or definition.max_duration_seconds),
                       float(definition.max_duration_seconds))
    deadline = time.monotonic() + total_budget
    observations = []
    for profile, object_id, relation, object_owner_label in sequence:
        if cancelled.is_set():
            return RunnerResult(RequestOutcome.CANCELLED, detail="Identity comparison was cancelled")
        current_path_parameters = dict(path_parameters)
        if definition.workflow == "BOLA":
            current_path_parameters[object_parameter] = object_id
        expected_allowed = (profile["id"] == supplied.get("expected_allowed_identity_id")) if definition.workflow == "BFLA" else None
        try:
            url, headers = build_request(endpoint, base_url,
                                         path_parameters=current_path_parameters,
                                         query_parameters=query_parameters,
                                         header_parameters=header_parameters)
        except (RequestBuildError, ValueError, TypeError):
            return RunnerResult(RequestOutcome.BLOCKED_SCOPE,
                                detail="Stored identity comparison parameters could not be safely resolved")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return RunnerResult(RequestOutcome.TIMEOUT, detail="Identity comparison time budget was reached")
        auth = BearerTokenReference(f"test-identity:{profile['id']}", DatabaseCredentialResolver(db))
        response = run_request(
            db, assessment.id, run.analyst_id, endpoint.method, url, headers=headers, auth=auth,
            cancelled=cancelled, max_duration_seconds=remaining,
            max_response_bytes=min(definition.max_response_bytes, settings.runner_max_response_bytes),
            max_redirects=0,
        )
        if response.outcome is not RequestOutcome.COMPLETED:
            return RunnerResult(response.outcome, detail="A bounded identity comparison request did not complete")
        if cancelled.is_set():
            return RunnerResult(RequestOutcome.CANCELLED, detail="Identity comparison was cancelled")
        observation = {"identity_label": profile["label"], "role": profile["role"],
                       "status_code": response.status_code}
        if definition.workflow == "BOLA":
            observation.update(relation=relation, object_owner_label=object_owner_label)
        else:
            observation["expected_allowed"] = expected_allowed
        observations.append(observation)
        if ((definition.workflow == "BOLA" and relation == "own")
                or (definition.workflow == "BFLA" and expected_allowed is True)):
            status_code = response.status_code
            if not isinstance(status_code, int) or not 200 <= status_code < 300:
                return RunnerResult(RequestOutcome.COMPLETED,
                                    detail="The expected-access control failed; cross-identity request was not sent",
                                    check_context={"observations": observations})
        # response.body and credential-bearing request state are discarded here.
    return RunnerResult(RequestOutcome.COMPLETED,
                        detail="Bounded status-only identity comparison completed",
                        check_context={"observations": observations})


def run_one(worker_id: str = "local-worker") -> bool:
    """Claim and execute one queued job. Returns false when the queue is empty."""
    with SessionLocal() as db:
        run_id = _claim(db, worker_id)
    if run_id is None:
        return False

    cancelled = threading.Event()
    stop_watcher = threading.Event()

    def watch_cancel():
        while not stop_watcher.wait(0.2):
            with SessionLocal() as watcher_db:
                current = watcher_db.get(models.TestRun, run_id)
                if current is None or current.status != "RUNNING":
                    cancelled.set()
                    return
                if (current.execution_metadata or {}).get("cancel_requested"):
                    cancelled.set()
                    return

    watcher = threading.Thread(target=watch_cancel, name=f"apisentinel-cancel-{run_id}", daemon=True)
    watcher.start()
    try:
        with SessionLocal() as db:
            run = db.get(models.TestRun, run_id)
            if run is None or run.execution_mode == "DEMO":
                return False
            supplied = {}
            endpoint = db.query(models.Endpoint).filter_by(id=run.endpoint_id, assessment_id=run.assessment_id).first()
            assessment = db.get(models.Assessment, run.assessment_id)
            definition = None
            result: RunnerResult
            if endpoint is None or assessment is None:
                result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Endpoint or assessment is unavailable")
            elif run.test_id:
                try:
                    definition = resolve_test(run.test_id)
                except (KeyError, PermissionError):
                    result = RunnerResult(RequestOutcome.SKIPPED, detail="Registered check is no longer enabled")
                else:
                    result = None  # type: ignore[assignment]
            elif not authorization_allows(assessment, endpoint.method):
                result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Current reviewed authorization is missing, expired, revoked, or out of scope")
            elif (not endpoint.execution_approved or endpoint.review_state != "APPROVED"
                  or not endpoint.inventory_current or endpoint.execution_approved_by is None
                  or endpoint.execution_approved_at is None):
                result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Current endpoint execution approval is required")
            elif endpoint.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Only GET, HEAD, and OPTIONS can be queued")
            elif not settings.allow_active_tests:
                result = RunnerResult(RequestOutcome.SKIPPED, detail="HTTP execution is disabled by server policy")
            else:
                result = None  # type: ignore[assignment]

            if result is None and definition is not None:
                budget = (run.execution_metadata or {}).get("check_budget") or {}
                if (endpoint.method.upper() not in definition.supported_methods
                        or assessment.assessment_type not in definition.platforms
                        or bool(endpoint.auth_required) != bool(definition.requires_auth_protected_endpoint)
                        or not authorization_allows(assessment, endpoint.method)
                        or not endpoint.execution_approved or endpoint.review_state != "APPROVED"
                        or not endpoint.inventory_current or endpoint.execution_approved_by is None
                        or endpoint.execution_approved_at is None):
                    result = RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Current authorization or endpoint approval is unavailable")
                elif endpoint.auth_required and not (definition.allows_unauthenticated_probe
                                                     or definition.supports_authenticated_execution):
                    result = RunnerResult(RequestOutcome.AUTH_UNAVAILABLE, detail="This registered check does not support authenticated execution")
                elif not settings.allow_active_tests:
                    result = RunnerResult(RequestOutcome.SKIPPED, detail="HTTP execution is disabled by server policy")
                else:
                    result = None

            if result is None:
                from .api import _endpoint_request_url, finalize_requested_retest

                try:
                    supplied = json.loads(decrypt_secret(run.encrypted_request_parameters,
                                                         purpose="http-job-parameters")) if run.encrypted_request_parameters else {}
                    if definition is not None and definition.workflow:
                        result = _run_identity_workflow(db, run, endpoint, assessment, definition,
                                                        supplied, cancelled)
                    else:
                        url, headers = build_request(
                            endpoint, _endpoint_request_url(assessment, endpoint),
                            path_parameters=supplied.get("path_parameters", {}),
                            query_parameters=supplied.get("query_parameters", {}),
                            header_parameters=supplied.get("header_parameters", {}),
                        )
                        auth = (BearerTokenReference(str(assessment.id), DatabaseCredentialResolver(db))
                                if endpoint.auth_required and definition is None else None)
                        limits = ({"max_duration_seconds": budget.get("max_duration_seconds"),
                                   "max_response_bytes": budget.get("max_response_bytes"),
                                   "max_redirects": budget.get("max_redirects")} if definition else {})
                        result = run_request(db, assessment.id, run.analyst_id, endpoint.method, url,
                                             headers=headers, auth=auth, cancelled=cancelled, **limits)
                except (RequestBuildError, ValueError, TypeError, RuntimeError):
                    result = RunnerResult(RequestOutcome.BLOCKED_SCOPE,
                                          detail="Stored request parameters could not be safely resolved")

            check_result, evaluation_error = (evaluate_safely(definition, result)
                                              if definition is not None else (None, False))

            finished = datetime.now(UTC)
            run.status = result.outcome.value
            run.security_outcome = check_result.outcome.value if check_result else SecurityOutcome.NOT_RUN.value
            run.summary = ("HTTP transport completed; registered security check failed safely during evaluation"
                           if evaluation_error else
                           (check_result.explanation if check_result is not None else result.detail or
                            ("HTTP transport completed; no security conclusion was evaluated"
                             if result.outcome is RequestOutcome.COMPLETED
                             else "HTTP transport did not complete successfully")))
            run.completed_at = finished
            run.worker_lease_expires_at = None
            run.execution_metadata = {
                "endpoint_id": run.endpoint_id, "endpoint_definition_hash": endpoint.definition_hash if endpoint else "",
                "import_id": endpoint.import_id if endpoint else None, "worker_id": worker_id,
                "attempt": run.attempt_count, "policy_outcome": result.outcome.value,
                "status_code": result.status_code, "retained_bytes": len(result.body),
                "response_headers": result.headers or {}, "redirect_count": result.redirect_count,
                "final_scheme": result.final_scheme,
                "request_parameter_names": {
                    key: sorted(value.keys()) for key, value in (supplied if endpoint is not None else {}).items()
                    if isinstance(value, dict)
                } if "supplied" in locals() else {},
            }
            if check_result is not None:
                run.execution_metadata.update({
                    "security_outcome": check_result.outcome.value,
                    "execution_classification": classify_execution(check_result, result.outcome).value,
                    "security_evidence": sanitize_evidence(check_result.evidence),
                    "security_explanation": check_result.explanation,
                    "security_limitation": check_result.limitation,
                })
            elif run.test_id:
                run.execution_metadata["execution_classification"] = (
                    "BLOCKED" if result.outcome in {
                        RequestOutcome.BLOCKED_SCOPE, RequestOutcome.BLOCKED_DESTINATION,
                        RequestOutcome.CANCELLED, RequestOutcome.AUTH_UNAVAILABLE, RequestOutcome.SKIPPED,
                    } else "ERROR"
                )
            if evaluation_error:
                run.execution_metadata["check_evaluation_error"] = True
            if definition is not None and definition.workflow:
                run.encrypted_request_parameters = None
            _event(db, run, "HTTP_JOB_FINISHED", run.status, run.execution_metadata)
            if (definition is not None and check_result is not None
                    and check_result.outcome is SecurityOutcome.CANDIDATE_FOUND):
                evidence = sanitize_evidence({
                    "test_id": definition.identifier, "test_version": definition.version,
                    "assessment_id": assessment.id, "endpoint_id": endpoint.id,
                    "endpoint_definition_hash": endpoint.definition_hash, "import_id": endpoint.import_id,
                    "test_run_id": run.id, "confidence": "Low; analyst review required",
                    **check_result.evidence,
                })
                duplicate = next((finding for finding in db.query(models.Finding).filter_by(
                    assessment_id=assessment.id, endpoint_id=endpoint.id
                ).all() if finding.status not in {"Resolved", "Closed"}
                    and (finding.evidence or {}).get("test_id") == definition.identifier
                    and (finding.evidence or {}).get("test_version") == definition.version
                    and (finding.evidence or {}).get("endpoint_definition_hash") == endpoint.definition_hash), None)
                if duplicate:
                    duplicate.last_observed_at = finished
                    _event(db, run, "SECURITY_CANDIDATE_DUPLICATE_SUPPRESSED", "CANDIDATE_FOUND",
                           {"finding_id": duplicate.id, "test_id": definition.identifier},
                           finding_id=duplicate.id)
                else:
                    finding = models.Finding(
                        assessment_id=assessment.id, endpoint_id=endpoint.id, test_run_id=run.id,
                        title=definition.name, severity="Informational", status="Candidate",
                        endpoint=f"{endpoint.method.upper()} {endpoint.path}",
                        description=check_result.explanation, impact=check_result.limitation,
                        evidence=evidence, remediation=check_result.remediation,
                        **finding_analysis_fields(
                            assessment_id=assessment.id, endpoint_id=endpoint.id,
                            test_id=definition.identifier, test_version=definition.version,
                            category=definition.category, severity="Informational", confidence="LOW",
                            remediation_guidance_type="CHECK_SPECIFIC" if check_result.remediation else "GENERIC",
                        ),
                        history=[{"status": "Candidate", "actor": str(run.analyst_id),
                                  "note": "Created by registered check; analyst validation required"}],
                    )
                    db.add(finding); db.flush()
                    _event(db, run, "SECURITY_CANDIDATE_CREATED", "CANDIDATE_FOUND",
                           {"finding_id": finding.id, "test_id": definition.identifier},
                           finding_id=finding.id)
            pending_retest = db.query(models.Retest).filter_by(test_run_id=run.id,
                                                                outcome="REQUESTED").first()
            if pending_retest is not None:
                from .api import finalize_requested_retest
                finalize_requested_retest(db, pending_retest, run)
            db.commit()
    except Exception:  # noqa: BLE001 - worker errors must not expose request or credential values.
        with SessionLocal() as db:
            run = db.get(models.TestRun, run_id)
            if run and run.status == "RUNNING":
                try:
                    discard_parameters = bool(resolve_test(run.test_id).workflow) if run.test_id else False
                except (KeyError, PermissionError):
                    discard_parameters = False
                if discard_parameters:
                    run.encrypted_request_parameters = None
                run.status = RequestOutcome.TRANSPORT_ERROR.value
                run.summary = "Worker failed safely; inspect the audit event for job lifecycle details"
                run.completed_at = datetime.now(UTC)
                run.worker_lease_expires_at = None
                run.execution_metadata = {"policy_outcome": RequestOutcome.TRANSPORT_ERROR.value,
                                          "worker_error": "internal"}
                _event(db, run, "HTTP_JOB_FINISHED", run.status, {"worker_id": worker_id})
                db.commit()
    finally:
        stop_watcher.set()
        watcher.join(timeout=1)
    return True


def worker_loop(worker_id: str, poll_seconds: float = 1.0) -> None:
    while True:
        if not run_one(worker_id):
            time.sleep(max(0.1, min(poll_seconds, 30.0)))
