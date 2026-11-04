from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.pool import StaticPool

from apisentinel import auth, models
from apisentinel.config import settings
from apisentinel.db import Base, get_db
from apisentinel.main import app


@pytest.fixture
def triage_workspace():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with sessions() as db:
        analyst = models.Analyst(login_normalized="triage@example.test", password_hash=auth.password_hasher.hash("local test password"))
        db.add(analyst)
        db.flush()
        client = models.Client(name="Triage local client", owner_user_id=analyst.id)
        db.add(client)
        db.flush()
        assessment = models.Assessment(client_id=client.id, name="Local triage assessment")
        db.add(assessment)
        db.flush()
        endpoint = models.Endpoint(assessment_id=assessment.id, method="GET", path="/local",
                                   definition_hash="definition-hash-local", inventory_current=True,
                                   review_state="APPROVED", execution_approved=True,
                                   execution_approved_by=analyst.id, execution_approved_at=datetime.now(UTC))
        db.add(endpoint)
        db.flush()
        test_run = models.TestRun(assessment_id=assessment.id, endpoint_id=endpoint.id,
                                  category="Misconfiguration", status="COMPLETED",
                                  execution_mode="HTTP_REQUEST", test_id="response.header.content_type_options",
                                  test_version="1.0.0", security_outcome="CANDIDATE_FOUND",
                                  completed_at=datetime.now(UTC),
                                  execution_metadata={"endpoint_definition_hash": "definition-hash-local",
                                                      "security_evidence": {"status_code": 200,
                                                                            "response_headers": {"content-type": "text/html", "x-content-type-options": None}}})
        db.add(test_run)
        db.flush()
        finding = models.Finding(
            assessment_id=assessment.id, endpoint_id=endpoint.id, test_run_id=test_run.id,
            title="Header observation", severity="Informational", status="Candidate",
            endpoint="GET /local", description="Header absent in local fixture",
            evidence={"test_id": test_run.test_id, "test_version": test_run.test_version,
                      "endpoint_definition_hash": endpoint.definition_hash,
                      "confidence": "Low; analyst review required", "body": "sensitive response body"},
            history=[{"status": "Candidate", "note": "Automated observation"}],
        )
        db.add(finding)
        db.commit()
        identifiers = {"analyst": analyst.id, "assessment": assessment.id, "endpoint": endpoint.id,
                       "test_run": test_run.id, "finding": finding.id}
    try:
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"login": "triage@example.test", "password": "local test password"})
            assert login.status_code == 200
            csrf = client.cookies[settings.csrf_cookie_name]
            headers = {"origin": "http://127.0.0.1:5173", "x-csrf-token": csrf}
            yield client, headers, sessions, identifiers
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_candidate_stays_candidate_and_evidence_provenance_is_preserved(triage_workspace):
    client, _headers, sessions, ids = triage_workspace
    response = client.get(f"/api/v1/findings?assessment_id={ids['assessment']}")
    assert response.status_code == 200
    finding = response.json()[0]
    assert finding["status"] == "Candidate"
    assert finding["endpoint_id"] == ids["endpoint"]
    assert finding["test_run_id"] == ids["test_run"]
    assert finding["evidence"]["test_id"] == "response.header.content_type_options"
    assert finding["evidence"]["endpoint_definition_hash"] == "definition-hash-local"
    assert finding["evidence"]["body"] == "[REDACTED]"
    assert finding["validation_state"] == "PENDING_VALIDATION"
    assert finding["confidence"] == "UNASSESSED"
    assert finding["priority"] == "P4"
    assert finding["risk_analysis"]["numerical_score"] is None
    assert finding["risk_analysis"]["score_status"] == "NOT_SCORED_MISSING_IMPACT_CONTEXT"
    summary = client.get(f"/api/v1/findings/summary?assessment_id={ids['assessment']}").json()
    assert summary["total"] == 1
    assert summary["validation_state"]["PENDING_VALIDATION"] == 1

    with sessions() as db:
        stored = db.get(models.Finding, ids["finding"])
        assert stored.status == "Candidate"
        assert stored.evidence["body"] == "sensitive response body"
        assert db.query(models.ExecutionAuditEvent).filter_by(finding_id=stored.id).count() == 0

    unauthenticated = TestClient(app).patch(f"/api/v1/findings/{ids['finding']}/status", json={"status": "Needs Review", "reason": "Reviewed"})
    assert unauthenticated.status_code == 401


def test_lifecycle_valid_invalid_reason_and_spoofed_actor_or_history(triage_workspace):
    client, headers, sessions, ids = triage_workspace
    route = f"/api/v1/findings/{ids['finding']}/status"
    invalid_direct_confirmation = client.patch(route, headers=headers,
                                               json={"status": "Confirmed", "reason": "Validated locally"})
    assert invalid_direct_confirmation.status_code == 409
    missing_reason = client.patch(route, headers=headers, json={"status": "Needs Review"})
    assert missing_reason.status_code == 422
    spoofed = client.patch(route, headers=headers,
                           json={"status": "Needs Review", "reason": "Reviewed evidence", "actor": "administrator", "history": [{"status": "Confirmed"}]})
    assert spoofed.status_code == 422

    review = client.patch(route, headers=headers,
                          json={"status": "Needs Review", "reason": "Reviewed evidence against the approved endpoint"})
    assert review.status_code == 200
    confirmation_short = client.patch(route, headers=headers,
                                      json={"status": "Confirmed", "reason": "too short"})
    assert confirmation_short.status_code == 422
    unvalidated_confirmation = client.patch(route, headers=headers,
                                            json={"status": "Confirmed", "reason": "Validated using independent response review"})
    assert unvalidated_confirmation.status_code == 409
    validation = client.patch(f"/api/v1/findings/{ids['finding']}/validation", headers=headers,
                              json={"validation_state": "VALIDATED",
                                    "rationale": "Stored response metadata supports the documented header assertion"})
    assert validation.status_code == 200
    assert validation.json()["validation_state"] == "VALIDATED"
    assert validation.json()["validation_rationale"].startswith("Stored response metadata")
    confirmation = client.patch(route, headers=headers,
                                json={"status": "Confirmed", "reason": "Validated using independent response review"})
    assert confirmation.status_code == 200
    repeated = client.patch(route, headers=headers,
                            json={"status": "Confirmed", "reason": "Repeated state change attempt"})
    assert repeated.status_code == 409

    with sessions() as db:
        stored = db.get(models.Finding, ids["finding"])
        assert stored.status == "Confirmed"
        assert stored.evidence["test_id"] == "response.header.content_type_options"
        events = db.query(models.ExecutionAuditEvent).filter_by(finding_id=stored.id, event_type="FINDING_TRIAGE").all()
        assert [(event.metadata_json["prior_status"], event.metadata_json["new_status"]) for event in events] == [
            ("Candidate", "Needs Review"), ("Needs Review", "Confirmed")]
        assert all(event.actor_id == ids["analyst"] for event in events)
        assert all(event.created_at is not None for event in events)

    history = client.get(f"/api/v1/findings/{ids['finding']}/history")
    assert history.status_code == 200
    assert len(history.json()["events"]) == 3
    assert history.json()["events"][1]["event_type"] == "FINDING_VALIDATION"
    assert history.json()["events"][1]["details"]["new_state"] == "VALIDATED"
    assert history.json()["events"][0]["details"]["reason"] == "Reviewed evidence against the approved endpoint"


@pytest.mark.parametrize("decision", ["False Positive", "Accepted Risk"])
def test_false_positive_and_accepted_risk_require_rationale(triage_workspace, decision):
    client, headers, _sessions, ids = triage_workspace
    route = f"/api/v1/findings/{ids['finding']}/status"
    client.patch(route, headers=headers, json={"status": "Needs Review", "reason": "Analyst began review of the observation"})
    insufficient = client.patch(route, headers=headers, json={"status": decision, "reason": "No"})
    assert insufficient.status_code == 422
    validation_state = "REJECTED" if decision == "False Positive" else "VALIDATED"
    validation = client.patch(f"/api/v1/findings/{ids['finding']}/validation", headers=headers,
                              json={"validation_state": validation_state,
                                    "rationale": "Reviewer decision based on the stored local fixture evidence"})
    assert validation.status_code == 200
    accepted = client.patch(route, headers=headers,
                            json={"status": decision, "reason": "Decision supported by documented analyst validation"})
    assert accepted.status_code == 200
    assert accepted.json()["status"] == decision


def test_resolved_requires_retest_and_retest_records_new_evidence_and_audit(triage_workspace):
    client, headers, sessions, ids = triage_workspace
    route = f"/api/v1/findings/{ids['finding']}/status"
    client.patch(route, headers=headers, json={"status": "Needs Review", "reason": "Review the original candidate evidence"})
    client.patch(f"/api/v1/findings/{ids['finding']}/validation", headers=headers,
                 json={"validation_state": "VALIDATED",
                       "rationale": "The bounded response evidence supports analyst validation"})
    client.patch(route, headers=headers, json={"status": "Confirmed", "reason": "Independent validation supports the finding"})
    direct_resolve = client.patch(route, headers=headers, json={"status": "Retest Required", "reason": "Fix reported by the client"})
    assert direct_resolve.status_code == 200
    no_evidence = client.post(f"/api/v1/findings/{ids['finding']}/retests", headers=headers,
                              json={"outcome": "Resolved", "evidence": {}, "notes": "Verified fixed"})
    assert no_evidence.status_code == 422
    retest = client.post(f"/api/v1/findings/{ids['finding']}/retests", headers=headers,
                         json={"outcome": "Resolved", "evidence": {"fixture_result": "header_present"},
                               "notes": "Observed the expected header on the local retest fixture"})
    assert retest.status_code == 201
    assert retest.json()["assessment_id"] == ids["assessment"]
    assert retest.json()["test_run_id"] is None
    assert retest.json()["test_id"] is None
    assert client.patch(route, headers=headers, json={"status": "Resolved", "reason": "No retest evidence"}).status_code == 409
    with sessions() as db:
        stored = db.get(models.Finding, ids["finding"])
        assert stored.status == "Retested"
        assert stored.remediation_status == "FIXED_PENDING_VERIFICATION"
        event = db.query(models.ExecutionAuditEvent).filter_by(finding_id=stored.id, event_type="FINDING_RETEST_RECORDED").one()
        assert event.actor_id == ids["analyst"]
        assert event.metadata_json["prior_status"] == "Retest Required"
        assert event.metadata_json["new_status"] == "Retested"


def test_remediation_closure_requires_evidence_and_reviewer_decision(triage_workspace):
    client, headers, _sessions, ids = triage_workspace
    route = f"/api/v1/findings/{ids['finding']}"
    client.patch(f"{route}/status", headers=headers,
                 json={"status": "Needs Review", "reason": "Review the candidate evidence"})
    client.patch(f"{route}/validation", headers=headers,
                 json={"validation_state": "VALIDATED", "rationale": "Evidence supports the documented observation"})
    client.patch(f"{route}/status", headers=headers,
                 json={"status": "Confirmed", "reason": "Reviewer validated the evidence and outcome"})
    short_close = client.patch(f"{route}/remediation", headers=headers,
        json={"status": "VERIFIED_FIXED", "reason": "No"})
    assert short_close.status_code == 422
    retest = client.post(f"{route}/retests", headers=headers,
        json={"outcome": "Resolved", "evidence": {"fixture": "expected_header_present"},
              "notes": "Manual verification evidence attached for reviewer decision"})
    assert retest.status_code == 201
    assert retest.json()["outcome"] == "MANUALLY_RESOLVED"
    pending = client.get(route, headers=headers)
    assert pending.json()["status"] == "Retested"
    assert pending.json()["remediation_status"] == "FIXED_PENDING_VERIFICATION"
    verified = client.patch(f"{route}/remediation", headers=headers,
        json={"status": "VERIFIED_FIXED", "reason": "Reviewer inspected the evidence and verified the stated fix"})
    assert verified.status_code == 200
    assert verified.json()["status"] == "Resolved"
    assert verified.json()["remediation_status"] == "VERIFIED_FIXED"


def test_report_type_and_inclusion_policy_are_snapshotted(triage_workspace):
    client, headers, _sessions, ids = triage_workspace
    response = client.post(f"/api/v1/reports?assessment_id={ids['assessment']}", headers=headers,
        json={"report_type": "EXECUTIVE_SUMMARY", "include_evidence": False})
    assert response.status_code == 201
    content = response.json()["content"]
    assert content["report"]["type"] == "EXECUTIVE_SUMMARY"
    assert content["report"]["inclusion_policy"]["validation_states"] == ["VALIDATED"]
    assert content["report"]["inclusion_policy"]["evidence_included"] is False
    assert content["findings"] == []
    detail = client.get(f"/api/v1/reports/{response.json()['id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["content"]["report"]["data_revision"] == content["report"]["data_revision"]


def test_html_report_escapes_untrusted_finding_text_and_sets_no_external_content_policy(triage_workspace):
    client, headers, _sessions, ids = triage_workspace
    created = client.post("/api/v1/findings", headers=headers, json={
        "assessment_id": ids["assessment"], "title": "<script>alert('x')</script>",
        "evidence": {"authorization": "Bearer synthetic-report-secret"},
    })
    assert created.status_code == 201
    report = client.post(f"/api/v1/reports?assessment_id={ids['assessment']}", headers=headers, json={})
    exported = client.get(f"/api/v1/reports/{report.json()['id']}/export?format=html", headers=headers)
    assert exported.status_code == 200
    assert "<script>alert" not in exported.text
    assert "&lt;script&gt;alert" in exported.text
    assert "synthetic-report-secret" not in exported.text
    assert "default-src 'none'" in exported.headers["content-security-policy"]
    assert "X-Content-Type-Options" in exported.headers


@pytest.mark.parametrize(("security_outcome", "expected", "status"), [
    ("CANDIDATE_FOUND", "CONFIRMED_PERSISTENCE", "Retest Required"),
    ("INCONCLUSIVE", "INCONCLUSIVE", "Retest Required"),
    ("ERROR", "EXECUTION_ERROR", "Retest Required"),
    ("NO_ISSUE_OBSERVED", "NO_ISSUE_OBSERVED", "Retested"),
])
def test_linked_registered_retest_derives_outcome_and_provenance(triage_workspace, security_outcome, expected, status):
    client, headers, sessions, ids = triage_workspace
    with sessions() as db:
        original = db.get(models.TestRun, ids["test_run"])
        new_run = models.TestRun(assessment_id=ids["assessment"], endpoint_id=ids["endpoint"],
                                 category=original.category, status="COMPLETED", execution_mode="HTTP_REQUEST",
                                 test_id=original.test_id, test_version=original.test_version,
                                 security_outcome=security_outcome, started_at=datetime.now(UTC),
                                 completed_at=datetime.now(UTC),
                                 execution_metadata={"endpoint_definition_hash": "definition-hash-local",
                                                     "security_evidence": {"response_headers": {"content-type": "text/html", "x-content-type-options": None}}})
        if security_outcome == "NO_ISSUE_OBSERVED":
            new_run.execution_metadata["security_evidence"] = {"response_headers": {"content-type": "text/html", "x-content-type-options": "nosniff"}}
        db.add(new_run); db.flush()
        retest_run_id = new_run.id
        db.commit()
    # Enter an eligible source status without changing the original candidate.
    with sessions() as db:
        finding = db.get(models.Finding, ids["finding"])
        finding.status = "Retest Required"
        db.commit()
    response = client.post(f"/api/v1/findings/{ids['finding']}/retests", headers=headers,
                           json={"test_run_id": retest_run_id, "outcome": "NO_ISSUE_OBSERVED",
                                 "evidence": {"fabricated": "client supplied"},
                                 "notes": "Local registered-check retest observation"})
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["outcome"] == expected
    assert payload["test_run_id"] == retest_run_id
    assert payload["test_id"] == "response.header.content_type_options"
    assert payload["test_version"] == "1.0.0"
    assert payload["endpoint_definition_hash"] == "definition-hash-local"
    if security_outcome == "CANDIDATE_FOUND":
        assert payload["outcome"] == "CONFIRMED_PERSISTENCE"
        assert "fabricated" not in str(payload["evidence"])
    with sessions() as db:
        assert db.get(models.Finding, ids["finding"]).status == status
        audit = db.query(models.ExecutionAuditEvent).filter_by(finding_id=ids["finding"], event_type="FINDING_RETEST_RECORDED").one()
        assert audit.test_run_id == retest_run_id
        assert audit.metadata_json["test_version"] == "1.0.0"


def test_transport_only_and_cross_assessment_test_runs_cannot_resolve_finding(triage_workspace):
    client, headers, sessions, ids = triage_workspace
    with sessions() as db:
        endpoint = db.get(models.Endpoint, ids["endpoint"])
        endpoint.execution_approved = True
        transport = models.TestRun(assessment_id=ids["assessment"], endpoint_id=endpoint.id,
                                   category="HTTP_REQUEST", status="COMPLETED", execution_mode="HTTP_REQUEST",
                                   security_outcome="NOT_RUN", execution_metadata={"endpoint_definition_hash": endpoint.definition_hash})
        db.add(transport); db.flush()
        other_client = models.Client(name="Other local", owner_user_id=ids["analyst"])
        db.add(other_client); db.flush()
        other_assessment = models.Assessment(client_id=other_client.id, name="Other assessment")
        db.add(other_assessment); db.flush()
        foreign = models.TestRun(assessment_id=other_assessment.id, endpoint_id=None,
                                 category="Misconfiguration", status="COMPLETED", test_id="response.header.content_type_options",
                                 test_version="1.0.0", security_outcome="NO_ISSUE_OBSERVED")
        wrong_endpoint = models.Endpoint(assessment_id=ids["assessment"], method="GET", path="/different",
                                         definition_hash="different-definition", inventory_current=True,
                                         review_state="APPROVED", execution_approved=True,
                                         execution_approved_by=ids["analyst"], execution_approved_at=datetime.now(UTC))
        db.add_all([foreign, wrong_endpoint]); db.flush()
        wrong_endpoint_run = models.TestRun(assessment_id=ids["assessment"], endpoint_id=wrong_endpoint.id,
                                            category="Misconfiguration", status="COMPLETED",
                                            test_id="response.header.content_type_options", test_version="1.0.0",
                                            security_outcome="NO_ISSUE_OBSERVED",
                                            execution_metadata={"endpoint_definition_hash": wrong_endpoint.definition_hash,
                                                                "security_evidence": {"header": "nosniff"}})
        db.add(wrong_endpoint_run); db.commit()
        transport_id, foreign_id, wrong_endpoint_run_id = transport.id, foreign.id, wrong_endpoint_run.id
        finding = db.get(models.Finding, ids["finding"])
        finding.status = "Retest Required"; db.commit()
    for run_id in (transport_id, foreign_id, wrong_endpoint_run_id):
        response = client.post(f"/api/v1/findings/{ids['finding']}/retests", headers=headers,
                               json={"test_run_id": run_id, "outcome": "NO_ISSUE_OBSERVED",
                                     "evidence": {"fabricated": True}, "notes": "Test no-issue linkage"})
        assert response.status_code in {404, 409}
    with sessions() as db:
        assert db.get(models.Finding, ids["finding"]).status == "Retest Required"


def test_stale_retest_rolls_back_retest_and_audit_together(triage_workspace):
    _client, _headers, sessions, ids = triage_workspace
    first, second = sessions(), sessions()
    try:
        current = first.get(models.Finding, ids["finding"])
        stale = second.get(models.Finding, ids["finding"])
        current.status = "Retest Required"
        first.commit()
        stale.status = "Resolved"
        second.execute(models.Retest.__table__.insert().values(
            finding_id=ids["finding"], assessment_id=ids["assessment"], analyst_id=ids["analyst"],
            outcome="NO_ISSUE_OBSERVED", evidence={"local": True}, notes="Local checked evidence"))
        second.execute(models.ExecutionAuditEvent.__table__.insert().values(
            actor_id=ids["analyst"], assessment_id=ids["assessment"], finding_id=ids["finding"],
            event_type="FINDING_RETEST_RECORDED", outcome="NO_ISSUE_OBSERVED", metadata_json={}))
        with pytest.raises(StaleDataError):
            second.commit()
        second.rollback()
    finally:
        first.close(); second.close()
    with sessions() as db:
        assert db.get(models.Finding, ids["finding"]).status == "Retest Required"
        assert db.query(models.Retest).filter_by(finding_id=ids["finding"]).count() == 0
        assert db.query(models.ExecutionAuditEvent).filter_by(finding_id=ids["finding"], event_type="FINDING_RETEST_RECORDED").count() == 0


def test_concurrent_finding_updates_use_optimistic_versioning(triage_workspace):
    _client, _headers, sessions, ids = triage_workspace
    first, second = sessions(), sessions()
    try:
        finding_a = first.get(models.Finding, ids["finding"])
        finding_b = second.get(models.Finding, ids["finding"])
        finding_a.status = "Needs Review"
        first.commit()
        finding_b.status = "Needs Review"
        with pytest.raises(StaleDataError):
            second.commit()
        second.rollback()
    finally:
        first.close()
        second.close()
