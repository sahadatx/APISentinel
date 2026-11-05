from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apisentinel import auth, models
from apisentinel.authorization import authorization_allows
from apisentinel.db import Base, get_db
from apisentinel.main import app


@pytest.fixture
def authorization_workspace():
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
        analyst = models.Analyst(login_normalized="authorization@example.test", password_hash=auth.password_hasher.hash("local test password"))
        other = models.Analyst(login_normalized="other@example.test", password_hash=auth.password_hasher.hash("local test password"))
        db.add_all([analyst, other]); db.flush()
        client = models.Client(name="Auth scope client", owner_user_id=analyst.id)
        foreign_client = models.Client(name="Foreign client", owner_user_id=other.id)
        db.add_all([client, foreign_client]); db.flush()
        db.add(models.ClientMembership(client_id=client.id, analyst_id=other.id,
                                       role="reviewer", granted_by_id=analyst.id))
        assessment = models.Assessment(client_id=client.id, name="Auth scope", environment="lab",
                                       authorization_confirmed=True, authorization_reference="legacy-ref",
                                       allowed_hosts=["api.local.test"], allowed_paths=["/api/**"],
                                       excluded_paths=["/api/private/**"])
        foreign_assessment = models.Assessment(client_id=foreign_client.id, name="Foreign assessment")
        db.add_all([assessment, foreign_assessment]); db.commit()
        ids = (analyst.id, other.id, assessment.id, foreign_assessment.id)
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/auth/login", json={"login":"authorization@example.test", "password":"local test password"})
            assert response.status_code == 200
            headers = {"origin":"http://127.0.0.1:5173", "x-csrf-token":client.cookies[auth.settings.csrf_cookie_name]}
            yield client, sessions, ids, headers
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def record_body(version=1, **overrides):
    now = datetime.now(UTC)
    body = {"reference":"local-test-authorization", "authorizing_party":"Local API owner",
            "valid_from":(now - timedelta(minutes=1)).isoformat(),
            "expires_at":(now + timedelta(days=2)).isoformat(), "permitted_methods":["GET"],
            "scope_acknowledged":True, "reason":"Verified written authorization for local test fixture",
            "expected_version":version}
    body.update(overrides)
    return body


def review_as_other_analyst(client, assessment_id, ids, version):
    client.post("/api/v1/auth/logout", headers={"origin":"http://127.0.0.1:5173",
                  "x-csrf-token":client.cookies[auth.settings.csrf_cookie_name]})
    assert client.post("/api/v1/auth/login", json={"login":"other@example.test",
                                                   "password":"local test password"}).status_code == 200
    headers = {"origin":"http://127.0.0.1:5173",
               "x-csrf-token":client.cookies[auth.settings.csrf_cookie_name]}
    response = client.post(f"/api/v1/assessments/{assessment_id}/authorization/review", headers=headers,
                           json={"expected_version":version,"reason":"Independent reviewer checked scope and recorded authority",
                                 "scope_and_authority_reviewed":True})
    client.post("/api/v1/auth/logout", headers=headers)
    assert client.post("/api/v1/auth/login", json={"login":"authorization@example.test",
                                                   "password":"local test password"}).status_code == 200
    return response


def test_legacy_boolean_is_not_authorization_and_record_review_are_audited(authorization_workspace):
    client, sessions, ids, headers = authorization_workspace
    assessment_id = ids[2]
    assert client.get(f"/api/v1/assessments/{assessment_id}").json()["authorization_status"] == "REVIEW_REQUIRED"
    assert client.get(f"/api/v1/assessments/{assessment_id}").json()["authorization_confirmed"] is False
    bad = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers,
                      json=record_body(permitted_methods=["POST"]))
    assert bad.status_code == 422
    spoof = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers,
                        json={**record_body(), "actor_id":ids[1]})
    assert spoof.status_code == 422
    recorded = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers, json=record_body())
    assert recorded.status_code == 200
    assert recorded.json()["authorization_status"] == "RECORDED"
    assert recorded.json()["authenticity_verified"] is False
    reviewed = review_as_other_analyst(client, assessment_id, ids, recorded.json()["authorization_version"])
    assert reviewed.status_code == 200
    assert reviewed.json()["authorization_status"] == "ACTIVE"
    assert reviewed.json()["authorization_recorded_by_id"] == ids[0]
    assert reviewed.json()["authorization_reviewed_by_id"] == ids[1]
    history = client.get(f"/api/v1/assessments/{assessment_id}/authorization/history").json()
    assert [event["event_type"] for event in history] == ["AUTHORIZATION_RECORDED", "AUTHORIZATION_REVIEWED"]
    assert [event["actor_id"] for event in history] == [ids[0], ids[1]]
    assert all("local-test-authorization" not in str(event["metadata"]) for event in history)
    with sessions() as db:
        assessment = db.get(models.Assessment, assessment_id)
        assert authorization_allows(assessment, "GET")
        assert not authorization_allows(assessment, "HEAD")


def test_expired_record_scope_mismatch_ownership_and_stale_versions_fail_closed(authorization_workspace):
    client, sessions, ids, headers = authorization_workspace
    assessment_id = ids[2]
    expired = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers,
                          json=record_body(valid_from=(datetime.now(UTC)-timedelta(days=2)).isoformat(),
                                           expires_at=(datetime.now(UTC)-timedelta(days=1)).isoformat()))
    assert expired.status_code == 200 and expired.json()["authorization_status"] == "EXPIRED"
    review = review_as_other_analyst(client, assessment_id, ids, expired.json()["authorization_version"])
    assert review.status_code == 409
    headers = {"origin":"http://127.0.0.1:5173", "x-csrf-token":client.cookies[auth.settings.csrf_cookie_name]}

    current = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers,
                          json=record_body(version=expired.json()["authorization_version"],
                                           expires_at=(datetime.now(UTC)+timedelta(days=1)).isoformat()))
    assert current.status_code == 200
    active = review_as_other_analyst(client, assessment_id, ids, current.json()["authorization_version"])
    assert active.status_code == 200
    headers = {"origin":"http://127.0.0.1:5173", "x-csrf-token":client.cookies[auth.settings.csrf_cookie_name]}

    with sessions() as db:
        assessment = db.get(models.Assessment, assessment_id)
        assessment.allowed_paths = ["/changed/**"]
        db.commit()
        assert not authorization_allows(assessment, "GET")
    assert client.get(f"/api/v1/assessments/{ids[3]}/authorization").status_code == 404
    stale = client.post(f"/api/v1/assessments/{assessment_id}/authorization/revoke", headers=headers, json={
        "expected_version":current.json()["authorization_version"], "reason":"Stale revocation attempt"})
    assert stale.status_code == 409


def test_revocation_is_audited_and_blocks_current_authorization(authorization_workspace):
    client, sessions, ids, headers = authorization_workspace
    assessment_id = ids[2]
    recorded = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers, json=record_body())
    reviewed = review_as_other_analyst(client, assessment_id, ids, recorded.json()["authorization_version"])
    headers = {"origin":"http://127.0.0.1:5173", "x-csrf-token":client.cookies[auth.settings.csrf_cookie_name]}
    revoked = client.post(f"/api/v1/assessments/{assessment_id}/authorization/revoke", headers=headers, json={
        "expected_version":reviewed.json()["authorization_version"], "reason":"Client withdrew testing permission"})
    assert revoked.status_code == 200 and revoked.json()["authorization_status"] == "REVOKED"
    with sessions() as db:
        assessment = db.get(models.Assessment, assessment_id)
        assert not authorization_allows(assessment, "GET")
        events = db.query(models.ExecutionAuditEvent).filter_by(assessment_id=assessment_id).all()
        assert [row.event_type for row in events] == ["AUTHORIZATION_RECORDED", "AUTHORIZATION_REVIEWED", "AUTHORIZATION_REVOKED"]
