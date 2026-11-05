import hashlib
import logging
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apisentinel import auth, models
from apisentinel.config import Settings, settings
from apisentinel.db import Base, get_db
from apisentinel.main import app


@pytest.fixture
def workspace():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    test_sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        db = test_sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with test_sessions() as db:
        alice = models.Analyst(login_normalized="alice@example.test", password_hash=auth.password_hasher.hash("correct horse battery staple"))
        bob = models.Analyst(login_normalized="bob@example.test", password_hash=auth.password_hasher.hash("another safe test password"))
        db.add_all([alice, bob])
        db.flush()
        alice_client = models.Client(name="Alice client", owner_user_id=alice.id)
        bob_client = models.Client(name="Bob client", owner_user_id=bob.id)
        legacy_client = models.Client(name="Legacy unowned client")
        db.add_all([alice_client, bob_client, legacy_client])
        db.flush()
        alice_assessment = models.Assessment(client_id=alice_client.id, name="Alice assessment")
        bob_assessment = models.Assessment(client_id=bob_client.id, name="Bob assessment")
        legacy_assessment = models.Assessment(client_id=legacy_client.id, name="Legacy assessment")
        db.add_all([alice_assessment, bob_assessment, legacy_assessment])
        db.flush()
        alice_endpoint = models.Endpoint(assessment_id=alice_assessment.id, method="GET", path="/alice")
        bob_endpoint = models.Endpoint(assessment_id=bob_assessment.id, method="GET", path="/bob")
        db.add_all([alice_endpoint, bob_endpoint])
        db.flush()
        alice_finding = models.Finding(assessment_id=alice_assessment.id, title="Alice finding", history=[])
        bob_finding = models.Finding(assessment_id=bob_assessment.id, title="Bob finding", history=[])
        db.add_all([alice_finding, bob_finding])
        db.flush()
        alice_report = models.Report(assessment_id=alice_assessment.id, version=1, content={"marker": "alice"})
        bob_report = models.Report(assessment_id=bob_assessment.id, version=1, content={"marker": "bob-secret-report"})
        db.add_all([alice_report, bob_report])
        db.flush()
        alice_retest = models.Retest(finding_id=alice_finding.id, outcome="Inconclusive")
        bob_retest = models.Retest(finding_id=bob_finding.id, outcome="Inconclusive")
        db.add_all([alice_retest, bob_retest])
        db.commit()
        ids = {
            "alice_id": alice.id, "bob_id": bob.id,
            "alice_client": alice_client.id, "bob_client": bob_client.id,
            "alice_assessment": alice_assessment.id, "bob_assessment": bob_assessment.id,
            "alice_endpoint": alice_endpoint.id, "bob_endpoint": bob_endpoint.id,
            "alice_finding": alice_finding.id, "bob_finding": bob_finding.id,
            "alice_report": alice_report.id, "bob_report": bob_report.id,
            "alice_retest": alice_retest.id, "bob_retest": bob_retest.id,
        }
    try:
        with TestClient(app) as client:
            yield client, test_sessions, ids
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def sign_in(client: TestClient, login="alice@example.test", password="correct horse battery staple"):
    response = client.post("/api/v1/auth/login", json={"login": login, "password": password})
    return response


def mutation_headers(client: TestClient, origin="http://127.0.0.1:5173"):
    return {"origin": origin, "x-csrf-token": client.cookies[settings.csrf_cookie_name]}


def test_dashboard_and_audit_aggregate_only_authorized_client_records(workspace):
    client, sessions, ids = workspace
    with sessions() as db:
        alice_event = models.ExecutionAuditEvent(actor_id=ids["alice_id"], client_id=ids["alice_client"],
                                                assessment_id=ids["alice_assessment"], event_type="FINDING_UPDATED",
                                                outcome="UPDATED", metadata_json={"api_key": "must-not-leak"})
        bob_event = models.ExecutionAuditEvent(actor_id=ids["bob_id"], client_id=ids["bob_client"],
                                              assessment_id=ids["bob_assessment"], event_type="FINDING_UPDATED",
                                              outcome="UPDATED", metadata_json={"safe": "foreign"})
        db.add_all([alice_event, bob_event])
        db.flush()
        audit_ids = (alice_event.id, bob_event.id)
        db.commit()
    assert sign_in(client).status_code == 200
    dashboard = client.get("/api/v1/dashboard").json()
    assert dashboard["clients"] == 1
    assert dashboard["assessments"] == 1
    assert dashboard["assessment_type"] == {"WEB_API": 1}
    assert dashboard["findings"] == 1  # canonical findings, never one row per retest/run
    assert dashboard["finding_severity"] == {"Medium": 1}
    assert dashboard["retest_outcome"] == {"Inconclusive": 1}
    assert dashboard["recent_activity"][0]["metadata"]["api_key"] == "[REDACTED]"
    future = client.get("/api/v1/dashboard?start_at=2030-01-01T00:00:00Z&end_at=2031-01-01T00:00:00Z").json()
    assert future["clients"] == future["assessments"] == future["findings"] == 0
    assert future["endpoints"] == 1  # current inventory has no created_at column and is explicitly all-time
    assert "not date-filtered" in future["time_range"]["endpoint_inventory"]

    page = client.get("/api/v1/audit/events?limit=1&offset=0&event_type=FINDING_UPDATED").json()
    assert page["total"] == 1 and len(page["items"]) == 1
    assert page["items"][0]["client_id"] == ids["alice_client"]
    assert "must-not-leak" not in str(page)
    details = client.get(f"/api/v1/audit/events/{audit_ids[0]}")
    assert details.status_code == 200 and details.json()["metadata"]["api_key"] == "[REDACTED]"
    assert client.get(f"/api/v1/audit/events/{audit_ids[1]}").status_code == 404
    assert client.get(f"/api/v1/audit/events?client_id={ids['bob_client']}").status_code == 404
    assert client.get(f"/api/v1/audit/events?assessment_id={ids['bob_assessment']}").status_code == 404
    assert client.get("/api/v1/audit/events?start_at=2030-01-02T00:00:00Z&end_at=2030-01-01T00:00:00Z").status_code == 422
    assert client.post("/api/v1/audit/events", json={}).status_code == 405


def test_dashboard_returns_real_zeroes_for_empty_accessible_workspace(workspace):
    client, sessions, _ids = workspace
    with sessions() as db:
        db.add(models.Analyst(login_normalized="empty@example.test",
                              password_hash=auth.password_hasher.hash("empty workspace test password")))
        db.commit()
    assert sign_in(client, login="empty@example.test", password="empty workspace test password").status_code == 200
    data = client.get("/api/v1/dashboard").json()
    assert (data["clients"], data["assessments"], data["findings"], data["reports"]) == (0, 0, 0, 0)
    assert data["assessment_type"] == data["finding_severity"] == data["retest_outcome"] == {}
    assert data["recent_activity"] == []


def test_login_me_logout_password_rejection_disabled_user_and_cookie_flags(workspace, caplog):
    client, sessions, ids = workspace
    response = sign_in(client, login="  ALICE@EXAMPLE.TEST ")
    assert response.status_code == 200
    assert client.get("/api/v1/ready").json() == {"status": "ready"}
    assert response.json()["login"] == "alice@example.test"
    assert client.get("/api/v1/auth/me").json()["id"] == ids["alice_id"]
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(value for value in cookies if value.startswith(settings.session_cookie_name + "="))
    csrf_cookie = next(value for value in cookies if value.startswith(settings.csrf_cookie_name + "="))
    assert "httponly" in session_cookie.lower()
    assert "samesite=lax" in session_cookie.lower()
    assert "httponly" not in csrf_cookie.lower()
    raw_session = client.cookies[settings.session_cookie_name]
    raw_csrf = client.cookies[settings.csrf_cookie_name]
    with sessions() as db:
        analyst = db.get(models.Analyst, ids["alice_id"])
        session = db.query(models.AuthSession).filter_by(analyst_id=analyst.id).one()
        assert "$argon2id$" in analyst.password_hash
        assert analyst.password_hash != "correct horse battery staple"
        assert session.token_hash != raw_session
        assert session.csrf_token_hash != raw_csrf

    secret = "this-is-a-never-log-password"
    with caplog.at_level(logging.DEBUG):
        bad = sign_in(client, password=secret)
    assert bad.status_code == 401
    assert secret not in bad.text
    assert secret not in caplog.text

    with sessions() as db:
        bob = db.get(models.Analyst, ids["bob_id"])
        bob.is_active = False
        db.commit()
    disabled = sign_in(client, login="bob@example.test", password="another safe test password")
    assert disabled.status_code == 401
    assert "Invalid login or password" == disabled.json()["detail"]

    logout = client.post("/api/v1/auth/logout", headers=mutation_headers(client))
    assert logout.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_expired_session_and_unauthenticated_protected_access(workspace):
    client, sessions, _ = workspace
    client.cookies.set(settings.session_cookie_name, "invalid-session-value")
    assert client.get("/api/v1/auth/me").status_code == 401
    client.cookies.delete(settings.session_cookie_name)
    for path in ("/api/v1/dashboard", "/api/v1/clients", "/api/v1/assessments", "/api/v1/findings", "/api/v1/reports"):
        assert client.get(path).status_code == 401
    assert client.post("/api/v1/clients", json={"name": "No auth"}).status_code == 401

    assert sign_in(client).status_code == 200
    raw_session = client.cookies[settings.session_cookie_name]
    with sessions() as db:
        session = db.query(models.AuthSession).filter_by(token_hash=auth._hash(raw_session)).one()
        session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_mutating_requests_require_valid_csrf_token_and_allowed_origin(workspace):
    client, _, _ = workspace
    assert sign_in(client).status_code == 200
    no_csrf = client.post("/api/v1/clients", json={"name": "No CSRF"})
    assert no_csrf.status_code == 403
    bad_origin = client.post("/api/v1/clients", headers=mutation_headers(client, "https://attacker.example"), json={"name": "Bad origin"})
    assert bad_origin.status_code == 403
    good = client.post("/api/v1/clients", headers=mutation_headers(client), json={"name": "Authorized client"})
    assert good.status_code == 201


def test_dashboard_origin_cors_preflight_and_authenticated_api(workspace):
    client, sessions, ids = workspace
    origin = "http://127.0.0.1:5173"
    preflight = client.options(
        "/api/v1/clients",
        headers={
            "origin": origin,
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type,x-csrf-token",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == origin
    assert preflight.headers["access-control-allow-credentials"] == "true"

    assert sign_in(client).status_code == 200
    result = client.get("/api/v1/clients", headers={"origin": origin})
    assert result.status_code == 200
    assert all(row["name"] == "Alice client" for row in result.json())
    created = client.post("/api/v1/clients", headers=mutation_headers(client), json={"name": "Owned client", "owner_user_id": ids["bob_id"]})
    assert created.status_code == 201
    with sessions() as db:
        assert db.get(models.Client, created.json()["id"]).owner_user_id == ids["alice_id"]


def test_all_client_scoped_routes_hide_foreign_and_unowned_legacy_records(workspace):
    client, _, ids = workspace
    assert sign_in(client).status_code == 200
    assert [row["name"] for row in client.get("/api/v1/clients").json()] == ["Alice client"]
    assert [row["name"] for row in client.get("/api/v1/assessments").json()] == ["Alice assessment"]
    assert client.get(f"/api/v1/assessments?client_id={ids['bob_client']}").status_code == 404
    assert client.get(f"/api/v1/assessments/{ids['bob_assessment']}").status_code == 404
    assert client.get(f"/api/v1/discovery/endpoints?assessment_id={ids['bob_assessment']}").status_code == 404
    assert client.get(f"/api/v1/testing/runs?assessment_id={ids['bob_assessment']}").status_code == 404
    assert client.get(f"/api/v1/coverage/{ids['bob_assessment']}").status_code == 404
    assert client.get(f"/api/v1/findings?assessment_id={ids['bob_assessment']}").status_code == 404
    assert client.get(f"/api/v1/reports?assessment_id={ids['bob_assessment']}").status_code == 404
    assert client.get("/api/v1/dashboard").json()["clients"] == 1

    headers = mutation_headers(client)
    assert client.post("/api/v1/assessments", headers=headers, json={"client_id": ids["bob_client"], "name": "Cross client"}).status_code == 404
    assert client.post(f"/api/v1/assessments/{ids['bob_assessment']}/scope-check?target=https://api.example.test/v1", headers=headers).status_code == 404
    assert client.post("/api/v1/discovery/openapi", headers=headers, json={"assessment_id": ids["bob_assessment"], "document": {"paths": {}}}).status_code == 404
    assert client.post(f"/api/v1/discovery/endpoints/{ids['bob_endpoint']}/execution-approval", headers=headers,
                       json={"approved": True, "reason": "Cross client must be denied"}).status_code == 404
    assert client.post("/api/v1/testing/runs", headers=headers, json={"assessment_id": ids["bob_assessment"], "endpoint_id": ids["bob_endpoint"], "category": "Authentication"}).status_code == 404
    assert client.post("/api/v1/findings", headers=headers, json={"assessment_id": ids["bob_assessment"], "title": "Cross client"}).status_code == 404
    assert client.patch(f"/api/v1/findings/{ids['bob_finding']}/status", headers=headers, json={"status": "Confirmed"}).status_code == 404
    assert client.get(f"/api/v1/findings/{ids['bob_finding']}/history", headers=headers).status_code == 404
    assert client.post(f"/api/v1/findings/{ids['bob_finding']}/retests", headers=headers, json={"outcome": "Resolved"}).status_code == 404
    export = client.get(f"/api/v1/reports/{ids['bob_report']}/export?format=json")
    assert export.status_code == 404
    assert "bob-secret-report" not in export.text
    assert client.get(f"/api/v1/reports/{ids['bob_report']}").status_code == 404
    assert client.post(f"/api/v1/reports?assessment_id={ids['bob_assessment']}", headers=headers, json={}).status_code == 404
    assert client.patch(f"/api/v1/findings/{ids['bob_finding']}/remediation", headers=headers,
                        json={"reason": "Cross-tenant remediation is denied"}).status_code == 404
    assert client.post(f"/api/v1/findings/{ids['bob_finding']}/retests/request", headers=headers,
                       json={}).status_code == 404


def test_discovery_coverage_is_assessment_scoped_and_inventory_filters_validate(workspace):
    client, _, ids = workspace
    assert sign_in(client).status_code == 200
    coverage = client.get(f"/api/v1/discovery/coverage?assessment_id={ids['alice_assessment']}")
    assert coverage.status_code == 200
    assert coverage.json()["unique_current_endpoints"] == 1
    assert "not proof" in coverage.json()["coverage_basis"]
    assert client.get(f"/api/v1/discovery/coverage?assessment_id={ids['bob_assessment']}").status_code == 404
    assert client.get(f"/api/v1/discovery/endpoints/{ids['alice_endpoint']}/history").json() == []
    assert client.get(f"/api/v1/discovery/endpoints/{ids['bob_endpoint']}/history").status_code == 404
    assert client.get(f"/api/v1/discovery/endpoints?assessment_id={ids['alice_assessment']}&scope_status=INVALID").status_code == 422

    retests = client.get("/api/v1/retests").json()
    assert [row["finding_id"] for row in retests] == [ids["alice_finding"]]


def test_endpoint_test_run_cannot_cross_assessment_even_for_same_owner(workspace):
    client, sessions, ids = workspace
    assert sign_in(client).status_code == 200
    with sessions() as db:
        second_assessment = models.Assessment(client_id=ids["alice_client"], name="Alice second assessment")
        db.add(second_assessment)
        db.flush()
        foreign_endpoint = models.Endpoint(assessment_id=second_assessment.id, method="GET", path="/other")
        db.add(foreign_endpoint)
        db.commit()
        endpoint_id = foreign_endpoint.id
    result = client.post(
        "/api/v1/testing/runs",
        headers=mutation_headers(client),
        json={"assessment_id": ids["alice_assessment"], "endpoint_id": endpoint_id, "category": "Authentication"},
    )
    assert result.status_code == 404


def test_configuration_rejects_wildcard_credentialed_cors_and_insecure_production_cookie():
    with pytest.raises(ValueError, match="wildcard"):
        Settings(cors_origins="*")
    with pytest.raises(ValueError, match="COOKIE_SECURE"):
        Settings(environment="production", cookie_secure=False, runner_egress_allowed_cidrs="203.0.113.0/24",
                 apk_parser_url="http://apk-parser:8090", database_url="postgresql+psycopg://localhost/test")
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(environment="production", cookie_secure=True, cors_origins="http://127.0.0.1:5173",
                 runner_egress_allowed_cidrs="203.0.113.0/24", apk_parser_url="http://apk-parser:8090",
                 database_url="postgresql+psycopg://localhost/test")
    with pytest.raises(ValueError, match="RUNNER_EGRESS_ALLOWED_CIDRS"):
        Settings(environment="production", cookie_secure=True, cors_origins="https://dashboard.example.test",
                 runner_egress_allowed_cidrs="", apk_parser_url="http://apk-parser:8090",
                 database_url="postgresql+psycopg://localhost/test")
    with pytest.raises(ValueError, match="Managed KMS"):
        Settings(environment="production", cookie_secure=True, cors_origins="https://dashboard.example.test",
                 runner_egress_allowed_cidrs="203.0.113.0/24", apk_parser_url="http://apk-parser:8090",
                 database_url="postgresql+psycopg://localhost/test")
    with pytest.raises(ValueError, match="valid Fernet key"):
        Settings(credential_encryption_key="invalid")
    with pytest.raises(ValueError, match="origin URLs"):
        Settings(cors_origins="https://dashboard.example.test/path")
    with pytest.raises(ValueError, match="ENVIRONMENT"):
        Settings(environment="unknown")


def test_android_metadata_is_type_gated_owned_sanitized_and_audited(workspace):
    client, sessions, ids = workspace
    sign_in(client)
    headers = mutation_headers(client)
    created = client.post("/api/v1/assessments", headers=headers, json={
        "client_id": ids["alice_client"], "name": "Mobile API", "assessment_type": "ANDROID_API",
    })
    assert created.status_code == 201
    assessment_id = created.json()["id"]
    body = {"package_name": "com.example.mobile", "version_name": "1.2", "version_code": "12",
            "artifact_sha256": "a" * 64, "api_level": 35,
            "metadata": {"auth": {"access_token": "synthetic-secret"}, "hosts": ["api.example.test"]}}
    response = client.post(f"/api/v1/assessments/{assessment_id}/android-applications", headers=headers, json=body)
    assert response.status_code == 201
    assert response.json()["metadata"]["auth"]["access_token"] == "[REDACTED]"
    assert client.get(f"/api/v1/assessments/{assessment_id}/android-applications").json()[0]["package_name"] == body["package_name"]
    assert "synthetic-secret" not in str(response.json())
    duplicate = client.post(f"/api/v1/assessments/{assessment_id}/android-applications", headers=headers, json=body)
    assert duplicate.status_code == 409
    assert client.post(f"/api/v1/assessments/{ids['alice_assessment']}/android-applications", headers=headers, json=body).status_code == 409
    assert client.get(f"/api/v1/assessments/{ids['bob_assessment']}/android-applications").status_code == 404
    with sessions() as db:
        event = db.query(models.ExecutionAuditEvent).filter_by(assessment_id=assessment_id,
                                                                event_type="ANDROID_METADATA_RECORDED").one()
        assert event.metadata_json["package_name"] == body["package_name"]
        assert "synthetic-secret" not in str(event.metadata_json)
    report = client.post(f"/api/v1/reports?assessment_id={assessment_id}", headers=headers)
    assert report.status_code == 201
    assert report.json()["content"]["assessment"]["assessment_type"] == "ANDROID_API"
    assert report.json()["content"]["android_applications"][0]["metadata"]["auth"]["access_token"] == "[REDACTED]"
    listed = client.get("/api/v1/reports", headers=headers).json()
    report_row = next(item for item in listed if item["id"] == report.json()["id"])
    assert report_row["assessment_name"] == "Mobile API"
    assert report_row["client_name"]
    assert report_row["finding_summary"]["total"] == 0
    html = client.get(f"/api/v1/reports/{report.json()['id']}/export?format=html").text
    assert "APK files are never persisted or executed." in html
    assert "synthetic-secret" not in html
    pdf = client.get(f"/api/v1/reports/{report.json()['id']}/export?format=pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content.startswith(b"%PDF-")
    assert b"synthetic-secret" not in pdf.content


def test_apk_import_calls_isolated_parser_and_persists_only_sanitized_metadata(workspace, monkeypatch):
    import asyncio

    from apisentinel import api

    client, sessions, ids = workspace
    sign_in(client)
    headers = mutation_headers(client)
    created = client.post("/api/v1/assessments", headers=headers, json={
        "client_id": ids["alice_client"], "name": "Android parser fixture", "assessment_type": "ANDROID_API",
    })
    assert created.status_code == 201
    assessment_id = created.json()["id"]
    monkeypatch.setattr(api, "_parse_apk_isolated", lambda blob: asyncio.sleep(0, result={
        "package_name": "com.example.parsed", "version_name": "3.2", "version_code": 32,
        "api_level": 34, "metadata": {"target_sdk": 34, "manifest_sha256": "b" * 64, "parser_version": "1",
                                          "static_analysis": {"review_state": "REVIEW_REQUIRED"}},
    }))
    uploaded = b"PK\x03\x04synthetic apk bytes"
    result = client.post(f"/api/v1/assessments/{assessment_id}/android-applications/apk", headers=headers,
                         files={"apk": ("sample.apk", uploaded, "application/vnd.android.package-archive")})
    assert result.status_code == 201, result.text
    assert result.json()["package_name"] == "com.example.parsed"
    assert result.json()["artifact_sha256"] == hashlib.sha256(uploaded).hexdigest()
    assert result.json()["metadata"]["static_analysis"]["review_state"] == "REVIEW_REQUIRED"
    with sessions() as db:
        row = db.query(models.AndroidApplication).filter_by(assessment_id=assessment_id).one()
        assert uploaded.decode("latin1") not in str(row.metadata_json)
        assert db.query(models.ExecutionAuditEvent).filter_by(assessment_id=assessment_id,
                                                               event_type="ANDROID_APK_PARSED").count() == 1


def test_ipa_metadata_import_is_tenant_scoped_and_discards_upload(workspace, monkeypatch):
    import asyncio

    from apisentinel import api

    client, sessions, ids = workspace
    sign_in(client)
    headers = mutation_headers(client)
    created = client.post("/api/v1/assessments", headers=headers, json={
        "client_id": ids["alice_client"], "name": "Combined mobile fixture", "assessment_type": "BOTH",
    })
    assert created.status_code == 201
    assessment_id = created.json()["id"]
    monkeypatch.setattr(api, "_parse_ipa_isolated", lambda blob: asyncio.sleep(0, result={
        "bundle_id": "com.example.iosapp", "display_name": "Example iOS", "version_name": "1.4",
        "build_number": "14", "minimum_os_version": "16.0",
        "metadata": {"parser_version": "1", "review_state": "REVIEW_REQUIRED"},
    }))
    uploaded = b"synthetic IPA bytes that must not persist"
    response = client.post(f"/api/v1/assessments/{assessment_id}/ios-applications/ipa", headers=headers,
                           files={"ipa": ("sample.ipa", uploaded, "application/octet-stream")})
    assert response.status_code == 201, response.text
    assert response.json()["bundle_id"] == "com.example.iosapp"
    assert response.json()["artifact_sha256"] == hashlib.sha256(uploaded).hexdigest()
    assert response.json()["metadata"]["review_state"] == "REVIEW_REQUIRED"
    assert client.get(f"/api/v1/assessments/{assessment_id}/ios-applications").json()[0]["bundle_id"] == "com.example.iosapp"
    report = client.post(f"/api/v1/reports?assessment_id={assessment_id}", headers=headers)
    assert report.status_code == 201
    assert report.json()["content"]["ios_applications"][0]["bundle_id"] == "com.example.iosapp"
    html = client.get(f"/api/v1/reports/{report.json()['id']}/export?format=html")
    assert html.status_code == 200 and "Info.plist was parsed" in html.text
    with sessions() as db:
        row = db.query(models.IOSApplication).filter_by(assessment_id=assessment_id).one()
        assert uploaded.decode() not in str(row.metadata_json)
        assert db.query(models.ExecutionAuditEvent).filter_by(
            assessment_id=assessment_id, event_type="IOS_IPA_METADATA_IMPORTED").count() == 1


def test_authorization_pdf_is_fingerprinted_audited_and_discarded(workspace):
    client, sessions, ids = workspace
    sign_in(client)
    created = client.post("/api/v1/assessments", headers=mutation_headers(client), json={
        "client_id": ids["alice_client"], "name": "Authorization evidence fixture",
    })
    assessment_id = created.json()["id"]
    document = b"%PDF-1.7\nsynthetic authorization evidence\n"
    response = client.post(f"/api/v1/assessments/{assessment_id}/authorization/evidence",
                           headers=mutation_headers(client),
                           files={"document": ("engagement.pdf", document, "application/pdf")})
    assert response.status_code == 200, response.text
    assert response.json()["sha256"] == hashlib.sha256(document).hexdigest()
    assert response.json()["document_persisted"] is False
    assert response.json()["authorization_version"] == 2
    with sessions() as db:
        assessment = db.get(models.Assessment, assessment_id)
        assert assessment.authorization_evidence_sha256 == hashlib.sha256(document).hexdigest()
        assert assessment.authorization_evidence_size == len(document)
        event = db.query(models.ExecutionAuditEvent).filter_by(assessment_id=assessment_id,
                                                                event_type="AUTHORIZATION_EVIDENCE_FINGERPRINTED").one()
        assert event.metadata_json["document_persisted"] is False
        assert document.decode() not in str(event.metadata_json)
    invalid = client.post(f"/api/v1/assessments/{assessment_id}/authorization/evidence",
                          headers=mutation_headers(client),
                          files={"document": ("fake.pdf", b"not a pdf", "application/pdf")})
    assert invalid.status_code == 422


def test_production_authorization_requires_fingerprinted_source_document(workspace, monkeypatch):
    client, _sessions, ids = workspace
    sign_in(client)
    headers = mutation_headers(client)
    created = client.post("/api/v1/assessments", headers=headers, json={
        "client_id": ids["alice_client"], "name": "Production evidence gate",
        "allowed_hosts": ["api.example.test"], "allowed_paths": ["/api/**"],
    })
    assessment_id = created.json()["id"]
    monkeypatch.setattr(settings, "environment", "staging")
    record = {"reference": "engagement-42", "authorizing_party": "Example owner",
              "valid_from": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
              "expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
              "permitted_methods": ["GET"], "scope_acknowledged": True,
              "reason": "Verified the approved assessment target and paths", "expected_version": 1}
    blocked = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers, json=record)
    assert blocked.status_code == 409
    evidence = client.post(f"/api/v1/assessments/{assessment_id}/authorization/evidence", headers=headers,
                           files={"document": ("authorization.pdf", b"%PDF-1.7\nproof", "application/pdf")})
    assert evidence.status_code == 200
    record["expected_version"] = evidence.json()["authorization_version"]
    accepted = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers, json=record)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["authorization_evidence_sha256"] == hashlib.sha256(b"%PDF-1.7\nproof").hexdigest()


def test_bearer_credential_profile_is_encrypted_owned_revokeable_and_never_echoed(workspace, monkeypatch):
    from apisentinel import cli
    from apisentinel.credential_vault import DatabaseCredentialResolver

    client, sessions, ids = workspace
    monkeypatch.setattr(settings, "credential_encryption_key", "")
    sign_in(client)
    headers = mutation_headers(client)
    secret = "fixture-bearer-token-never-return-this"
    assert client.put(f"/api/v1/assessments/{ids['alice_assessment']}/credential-profile",
                      headers=headers, json={"token": secret}).status_code == 503
    old_key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "credential_encryption_key", old_key)
    saved = client.put(f"/api/v1/assessments/{ids['alice_assessment']}/credential-profile",
                       headers=headers, json={"token": secret})
    assert saved.status_code == 200 and saved.json()["configured"] is True
    assert secret not in saved.text
    with sessions() as db:
        profile = db.query(models.CredentialProfile).filter_by(assessment_id=ids["alice_assessment"]).one()
        assert secret not in profile.encrypted_secret
        assert DatabaseCredentialResolver(db).resolve_bearer(str(ids["alice_assessment"]),
                                                               analyst_id=ids["alice_id"],
                                                               assessment_id=ids["alice_assessment"]) == secret
        with pytest.raises(ValueError):
            DatabaseCredentialResolver(db).resolve_bearer(str(ids["alice_assessment"]),
                                                           analyst_id=ids["bob_id"],
                                                           assessment_id=ids["alice_assessment"])
    new_key = Fernet.generate_key().decode()
    monkeypatch.setattr(cli, "SessionLocal", sessions)
    assert cli.rotate_credential_keys(old_key, new_key) == 1
    monkeypatch.setattr(settings, "credential_encryption_key", new_key)
    with sessions() as db:
        assert DatabaseCredentialResolver(db).resolve_bearer(str(ids["alice_assessment"]),
                                                               analyst_id=ids["alice_id"],
                                                               assessment_id=ids["alice_assessment"]) == secret
    assert client.get(f"/api/v1/assessments/{ids['alice_assessment']}/credential-profile").json()["configured"]
    assert client.get(f"/api/v1/assessments/{ids['bob_assessment']}/credential-profile").status_code == 404
    assert client.delete(f"/api/v1/assessments/{ids['alice_assessment']}/credential-profile",
                         headers=headers).json()["configured"] is False
    with sessions() as db:
        with pytest.raises(ValueError):
            DatabaseCredentialResolver(db).resolve_bearer(str(ids["alice_assessment"]),
                                                           analyst_id=ids["alice_id"],
                                                           assessment_id=ids["alice_assessment"])
        events = db.query(models.ExecutionAuditEvent).filter(
            models.ExecutionAuditEvent.assessment_id == ids["alice_assessment"],
            models.ExecutionAuditEvent.event_type.like("CREDENTIAL_PROFILE_%"),
        ).all()
        assert len(events) == 2
        assert secret not in str([event.metadata_json for event in events])


def test_credential_key_generation_writes_private_file_without_overwrite(tmp_path):
    from apisentinel.cli import create_credential_key_file

    path = tmp_path / "credential.env"
    create_credential_key_file(str(path))
    assert path.stat().st_mode & 0o777 == 0o600
    value = path.read_text().strip().split("=", 1)[1]
    Fernet(value.encode())
    with pytest.raises(ValueError, match="overwrite"):
        create_credential_key_file(str(path))


def test_totp_mfa_enrollment_login_replay_protection_disable_and_key_rotation(workspace, monkeypatch):
    import time

    from apisentinel import cli
    from apisentinel.mfa import totp_code

    client, sessions, ids = workspace
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "credential_encryption_key", old_key)
    monkeypatch.setattr(cli, "SessionLocal", sessions)
    sign_in(client)
    headers = mutation_headers(client)
    enrollment = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert enrollment.status_code == 200
    secret = enrollment.json()["secret"]
    with sessions() as db:
        analyst = db.get(models.Analyst, ids["alice_id"])
        assert analyst.mfa_enabled is False
        assert secret not in analyst.mfa_secret_encrypted

    counter = int(time.time() // 30)
    clock = [counter]
    monkeypatch.setattr("apisentinel.mfa.time.time", lambda: clock[0] * 30 + 1)
    confirmed = client.post("/api/v1/auth/mfa/confirm", headers=headers,
                            json={"code": totp_code(secret, counter)})
    assert confirmed.status_code == 200 and confirmed.json()["enabled"] is True
    recovery_code = confirmed.json()["recovery_codes"][0]
    assert "secret" not in client.get("/api/v1/auth/mfa/status").text

    client.post("/api/v1/auth/logout", headers=headers)
    assert sign_in(client).status_code == 401
    login_code = totp_code(secret, counter + 1)
    assert client.post("/api/v1/auth/login", json={"login": "alice@example.test",
                                                   "password": "correct horse battery staple",
                                                   "otp": login_code}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"login": "alice@example.test",
                                                   "password": "correct horse battery staple",
                                                   "otp": login_code}).status_code == 401
    client.post("/api/v1/auth/logout", headers=mutation_headers(client))
    recovery_login = client.post("/api/v1/auth/login", json={"login": "alice@example.test",
                                                              "password": "correct horse battery staple",
                                                              "recovery_code": recovery_code})
    assert recovery_login.status_code == 200
    client.post("/api/v1/auth/logout", headers=mutation_headers(client))
    assert client.post("/api/v1/auth/login", json={"login": "alice@example.test",
                                                   "password": "correct horse battery staple",
                                                   "recovery_code": recovery_code}).status_code == 401
    clock[0] = counter + 1
    assert client.post("/api/v1/auth/login", json={"login": "alice@example.test",
                                                   "password": "correct horse battery staple",
                                                   "otp": totp_code(secret, counter + 2)}).status_code == 200
    headers = mutation_headers(client)
    assert cli.rotate_credential_keys(old_key, new_key) == 1
    monkeypatch.setattr(settings, "credential_encryption_key", new_key)
    with sessions() as db:
        analyst = db.get(models.Analyst, ids["alice_id"])
        assert analyst.mfa_enabled is True
        assert analyst.mfa_secret_encrypted
    clock[0] = counter + 2
    disable_code = totp_code(secret, counter + 3)
    disabled = client.post("/api/v1/auth/mfa/disable", headers=headers,
                           json={"password": "correct horse battery staple", "code": disable_code})
    assert disabled.status_code == 200 and disabled.json()["enabled"] is False
    assert client.get("/api/v1/auth/mfa/status").json()["enabled"] is False


def test_client_membership_roles_share_only_assigned_workspace_and_enforce_write_permissions(workspace):
    client, _sessions, ids = workspace
    assert sign_in(client).status_code == 200
    owner_headers = mutation_headers(client)
    invite = client.post(f"/api/v1/clients/{ids['alice_client']}/members", headers=owner_headers,
                         json={"login": "BOB@example.test", "role": "viewer"})
    assert invite.status_code == 201 and invite.json()["role"] == "viewer"
    assert client.get(f"/api/v1/clients/{ids['alice_client']}/members").json()[0]["role"] == "viewer"

    client.post("/api/v1/auth/logout", headers=owner_headers)
    assert sign_in(client, "bob@example.test", "another safe test password").status_code == 200
    bob_headers = mutation_headers(client)
    assert {row["id"] for row in client.get("/api/v1/clients").json()} == {ids["alice_client"], ids["bob_client"]}
    assert client.get(f"/api/v1/assessments/{ids['alice_assessment']}").status_code == 200
    assert client.get("/api/v1/assessments/999999").status_code == 404
    denied = client.post("/api/v1/assessments", headers=bob_headers,
                         json={"client_id": ids["alice_client"], "name": "viewer cannot write"})
    assert denied.status_code == 403
    assert client.post(f"/api/v1/clients/{ids['alice_client']}/members", headers=bob_headers,
                       json={"login": "alice@example.test", "role": "analyst"}).status_code == 404

    client.post("/api/v1/auth/logout", headers=bob_headers)
    assert sign_in(client).status_code == 200
    owner_headers = mutation_headers(client)
    changed = client.post(f"/api/v1/clients/{ids['alice_client']}/members", headers=owner_headers,
                          json={"login": "bob@example.test", "role": "analyst"})
    assert changed.status_code == 201 and changed.json()["role"] == "analyst"
    client.post("/api/v1/auth/logout", headers=owner_headers)
    assert sign_in(client, "bob@example.test", "another safe test password").status_code == 200
    bob_headers = mutation_headers(client)
    created = client.post("/api/v1/assessments", headers=bob_headers,
                          json={"client_id": ids["alice_client"], "name": "analyst workspace access"})
    assert created.status_code == 201

    client.post("/api/v1/auth/logout", headers=bob_headers)
    assert sign_in(client).status_code == 200
    assert client.delete(f"/api/v1/clients/{ids['alice_client']}/members/bob%40example.test",
                         headers=mutation_headers(client)).status_code == 200


def test_assessment_management_configuration_history_archive_and_tenant_isolation(workspace):
    client, _sessions, ids = workspace
    sign_in(client)
    headers = mutation_headers(client)
    created = client.post("/api/v1/assessments", headers=headers, json={
        "client_id": ids["alice_client"], "name": "Combined mobile and web",
        "description": "Authorized test planning record", "assessment_type": "BOTH",
        "environment": "staging",
        "target_configs": {
            "web_api": {"base_url": "https://web.example.test/api", "api_version": "v2"},
            "android_api": {"base_url": "https://mobile.example.test/v4", "api_version": "v4",
                            "package_name": "com.example.mobile", "app_version": "2.1"},
        },
        "allowed_hosts": ["web.example.test", "mobile.example.test"],
        "allowed_paths": ["/api/**"], "excluded_paths": [],
    })
    assert created.status_code == 201, created.text
    value = created.json()
    assessment_id = value["id"]
    assert value["configuration_version"] == 1
    assert value["created_by_id"] == ids["alice_id"]
    assert value["authorization_status"] == "REVIEW_REQUIRED"
    assert value["target_configs"]["web_api"]["base_url"] == "https://web.example.test/api"
    assert value["target_configs"]["android_api"]["base_url"] == "https://mobile.example.test/v4"
    assert client.get("/api/v1/testing/runs", headers=headers).json() == []
    history = client.get(f"/api/v1/assessments/{assessment_id}/history", headers=headers).json()
    assert history[0]["event_type"] == "ASSESSMENT_CREATED"
    assert history[0]["metadata"]["network_execution"] is False

    updated = client.patch(f"/api/v1/assessments/{assessment_id}", headers=headers, json={
        "expected_configuration_version": 1, "description": "Updated setup",
        "allowed_hosts": ["web.example.test"],
    })
    assert updated.status_code == 200, updated.text
    assert updated.json()["configuration_version"] == 2
    assert updated.json()["description"] == "Updated setup"
    assert updated.json()["authorization_status"] == "REVIEW_REQUIRED"
    stale = client.patch(f"/api/v1/assessments/{assessment_id}", headers=headers, json={
        "expected_configuration_version": 1, "name": "Stale update",
    })
    assert stale.status_code == 409
    assert client.get(f"/api/v1/assessments/{assessment_id}/history", headers=headers).json()[0]["event_type"] == "ASSESSMENT_UPDATED"
    listing = client.get("/api/v1/assessments?search=Combined&assessment_type=BOTH&limit=1", headers=headers)
    assert listing.status_code == 200 and listing.headers["x-total-count"] == "1"

    sign_in(client, "bob@example.test", "another safe test password")
    bob_headers = mutation_headers(client)
    assert client.get(f"/api/v1/assessments/{assessment_id}", headers=bob_headers).status_code == 404
    assert client.patch(f"/api/v1/assessments/{assessment_id}", headers=bob_headers, json={
        "expected_configuration_version": 2, "name": "Cross-tenant edit",
    }).status_code == 404

    sign_in(client)
    headers = mutation_headers(client)
    archived = client.post(f"/api/v1/assessments/{assessment_id}/archive", headers=headers, json={})
    assert archived.status_code == 200 and archived.json()["status"] == "Archived"
    assert client.patch(f"/api/v1/assessments/{assessment_id}", headers=headers, json={
        "expected_configuration_version": 3, "name": "Should stay archived",
    }).status_code == 409
    assert client.get(f"/api/v1/assessments/{assessment_id}/history", headers=headers).json()[0]["event_type"] == "ASSESSMENT_ARCHIVED"


def test_assessment_target_validation_is_typed_and_non_authorizing(workspace):
    client, _sessions, ids = workspace
    sign_in(client)
    headers = mutation_headers(client)
    wrong_platform = client.post("/api/v1/assessments", headers=headers, json={
        "client_id": ids["alice_client"], "name": "Wrong platform", "assessment_type": "WEB_API",
        "target_configs": {"android_api": {"package_name": "com.example.app"}},
    })
    assert wrong_platform.status_code == 422
    unsafe_production_url = client.post("/api/v1/assessments", headers=headers, json={
        "client_id": ids["alice_client"], "name": "HTTP production", "environment": "production",
        "target_configs": {"web_api": {"base_url": "http://api.example.test"}},
    })
    assert unsafe_production_url.status_code == 422
    credential_url = client.post("/api/v1/assessments", headers=headers, json={
        "client_id": ids["alice_client"], "name": "Credential URL",
        "target_configs": {"web_api": {"base_url": "https://user:secret@api.example.test"}},
    })
    assert credential_url.status_code == 422
