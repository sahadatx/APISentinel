import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apisentinel import api, auth, job_queue, models
from apisentinel.config import settings
from apisentinel.db import Base, get_db
from apisentinel.main import app


class LocalHandler(BaseHTTPRequestHandler):
    hits = 0
    body_marker = "sensitive-local-fixture-body"
    nosniff = False
    status_code = 200
    x_header_values = None
    seen_auth: ClassVar[list[str | None]] = []

    def do_GET(self):
        type(self).hits += 1
        type(self).seen_auth.append(self.headers.get("Authorization"))
        data = type(self).body_marker.encode()
        self.send_response(type(self).status_code)
        self.send_header("Content-Type", "text/plain")
        if type(self).x_header_values is not None:
            for value in type(self).x_header_values:
                self.send_header("X-Content-Type-Options", value)
        elif type(self).nosniff:
            self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


def mutation_headers(client):
    return {"origin": "http://127.0.0.1:5173", "x-csrf-token": client.cookies[settings.csrf_cookie_name]}


def test_endpoint_target_uses_reviewed_import_server_origin():
    assessment = models.Assessment(client_id=1, name="multi-host", allowed_hosts=["first.example", "second.example"])
    endpoint = models.Endpoint(assessment_id=1, method="GET", path="/v1/items",
                              server_origin="https://second.example", server_base_path="/api",
                              scope_status="IN_SCOPE")
    assert api._endpoint_request_url(assessment, endpoint) == "https://second.example/api/v1/items"
    endpoint.server_origin = "https://second.example/other"
    assert api._endpoint_request_url(assessment, endpoint) == ""
    endpoint.server_origin = "https://second.example"
    endpoint.scope_status = "OUT_OF_SCOPE"
    assert api._endpoint_request_url(assessment, endpoint) == ""


def test_shared_execution_source_context_preserves_sanitized_android_provenance():
    assessment = models.Assessment(client_id=1, name="Android fixture", assessment_type="ANDROID_API")
    endpoint = models.Endpoint(
        assessment_id=1, method="GET", path="/api/mobile", source="android_http_capture_v1",
        source_provenance=[{"source": "android_http_capture_v1", "import_id": 17,
                            "artifact_sha256": "a" * 64,
                            "artifact_metadata": {"android_app": {
                                "package_name": "com.example.fixture", "version_name": "3.2"}}}],
    )
    context = api._endpoint_source_metadata(endpoint, assessment)
    assert context["assessment_type"] == "ANDROID_API"
    assert context["endpoint_source"] == "android_http_capture_v1"
    assert context["source_provenance"][0]["artifact_metadata"]["android_app"] == {
        "package_name": "com.example.fixture", "version_name": "3.2"}


def test_api_to_runner_persists_transport_outcome_audit_and_not_response_body(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(job_queue, "SessionLocal", sessions)

    def override_db():
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(settings, "allow_local_lab", True)
    monkeypatch.setattr(settings, "runner_lab_allow_http", True)
    monkeypatch.setattr(settings, "allow_active_tests", False)
    monkeypatch.setattr(settings, "openapi_max_document_bytes", 1024)
    monkeypatch.setattr(settings, "runner_lab_allowed_ports", str(server.server_port))
    LocalHandler.hits = 0
    LocalHandler.nosniff = False
    LocalHandler.status_code = 200
    LocalHandler.x_header_values = None
    LocalHandler.seen_auth = []
    app.dependency_overrides[get_db] = override_db
    try:
        with sessions() as db:
            analyst = models.Analyst(login_normalized="http-runner@example.test", password_hash=auth.password_hasher.hash("local-only test password"))
            reviewer = models.Analyst(login_normalized="http-reviewer@example.test", password_hash=auth.password_hasher.hash("local-only reviewer password"))
            db.add_all([analyst, reviewer])
            db.flush()
            client_record = models.Client(name="Local integration", owner_user_id=analyst.id)
            db.add(client_record)
            db.flush()
            assessment = models.Assessment(
                client_id=client_record.id, name="Local lab", environment="lab",
                authorization_confirmed=False, authorization_reference="",
                allowed_hosts=["127.0.0.1"], allowed_paths=["/api/**"],
            )
            db.add(assessment)
            db.flush()
            db.add(models.ClientMembership(client_id=client_record.id, analyst_id=reviewer.id,
                                           role="reviewer", granted_by_id=analyst.id))
            db.commit()
            assessment_id = assessment.id

        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"login": "http-runner@example.test", "password": "local-only test password"})
            assert login.status_code == 200
            preflight = client.options("/api/v1/testing/jobs", headers={
                "origin": "http://127.0.0.1:5173", "access-control-request-method": "POST",
                "access-control-request-headers": "content-type,x-csrf-token,idempotency-key",
            })
            assert preflight.status_code == 200
            assert "idempotency-key" in preflight.headers.get("access-control-allow-headers", "").lower()
            csrf = client.cookies[settings.csrf_cookie_name]
            headers = {"origin": "http://127.0.0.1:5173", "x-csrf-token": csrf}
            oversized_headers = {**headers, "content-type": "application/json"}
            oversized = client.post("/api/v1/discovery/openapi", headers=oversized_headers,
                                    content=b"{" + b" " * 1100 + b"}")
            assert oversized.status_code == 413
            imported = client.post("/api/v1/discovery/openapi", headers=headers, json={
                "assessment_id": assessment_id,
                "document": {"openapi": "3.0.3", "info": {"title": "Local fixture", "version": "1"},
                             "paths": {"/api/health": {"get": {"operationId": "health"}}}},
            })
            assert imported.status_code == 201
            assert LocalHandler.hits == 0
            assert imported.json()["endpoints"][0]["review_state"] == "IMPORTED"
            imported_collection = client.post("/api/v1/discovery/openapi", headers=headers, json={
                "assessment_id": assessment_id,
                "source": "postman_v2.1",
                "document": {"info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
                             "item": [{"name": "local passive import", "request": {
                                 "method": "GET", "url": {"raw": "http://127.0.0.1:8000/api/health?token=VALUE"},
                                 "header": [{"key": "Authorization", "value": "Bearer SECRET"}],
                             }}]},
            })
            assert imported_collection.status_code == 201
            assert imported_collection.json()["endpoints"][0]["auth_required"] is True
            assert "SECRET" not in imported_collection.text and "VALUE" not in imported_collection.text
            assert LocalHandler.hits == 0
            imported_har = client.post("/api/v1/discovery/openapi", headers=headers, json={
                "assessment_id": assessment_id,
                "source": "browser_har_1.2",
                "document": {"log": {"entries": [{"_initiator": {"url": "https://browser.example.test/app?token=private"},
                    "request": {"method": "GET", "url": "http://127.0.0.1:8000/api/observed?q=private",
                                "headers": [{"name": "Cookie", "value": "session=private"}]}}]}},
            })
            assert imported_har.status_code == 201
            assert imported_har.json()["source"] == "browser_har_1.2"
            assert "private" not in imported_har.text
            har_import_history = client.get(f"/api/v1/discovery/imports?assessment_id={assessment_id}").json()
            har_history = next(row for row in har_import_history if row["id"] == imported_har.json()["import_id"])
            assert har_history["artifact_metadata"]["browser_origins"] == ["https://browser.example.test"]
            imported_android = client.post("/api/v1/discovery/openapi", headers=headers, json={
                "assessment_id": assessment_id,
                "source": "android_http_capture_v1",
                "document": {"format": "apisentinel.android_http_capture.v1", "package_name": "test.local.app",
                             "version_name": "1", "requests": [{"method": "GET",
                             "url": "http://127.0.0.1:8000/api/mobile"}]},
            })
            assert imported_android.status_code == 201
            assert imported_android.json()["source"] == "android_http_capture_v1"
            android_history = client.get(f"/api/v1/discovery/imports?assessment_id={assessment_id}").json()
            android_row = next(row for row in android_history if row["id"] == imported_android.json()["import_id"])
            assert android_row["artifact_metadata"]["android_app"] == {
                "package_name": "test.local.app", "version_name": "1"}
            assert LocalHandler.hits == 0
            inventory_page = client.get(f"/api/v1/discovery/endpoints?assessment_id={assessment_id}&limit=1&offset=0")
            assert inventory_page.status_code == 200 and len(inventory_page.json()) == 1
            assert int(inventory_page.headers["x-total-count"]) >= 4
            endpoint_id = imported.json()["endpoints"][0]["id"]
            unapproved = client.post("/api/v1/testing/runs", headers=headers,
                                     json={"assessment_id": assessment_id, "endpoint_id": endpoint_id, "category": "Authentication"})
            assert unapproved.status_code == 201
            assert unapproved.json()["status"] == "BLOCKED_SCOPE"
            assert "authorization" in unapproved.json()["summary"].lower()
            assert LocalHandler.hits == 0

            denied_approval = client.post(f"/api/v1/discovery/endpoints/{endpoint_id}/execution-approval", headers=headers, json={"approved": True, "reason": "Reviewed local test scope"})
            assert denied_approval.status_code == 409
            now = datetime.now(UTC)
            recorded = client.post(f"/api/v1/assessments/{assessment_id}/authorization/record", headers=headers, json={
                "reference": "local-test-authorization-record",
                "authorizing_party": "Local integration fixture owner",
                "valid_from": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(days=1)).isoformat(),
                "permitted_methods": ["GET"], "scope_acknowledged": True,
                "reason": "Authorized isolated local integration target", "expected_version": 1,
            })
            assert recorded.status_code == 200
            assert recorded.json()["authorization_status"] == "RECORDED"
            client.post("/api/v1/auth/logout", headers=headers)
            assert client.post("/api/v1/auth/login", json={"login":"http-reviewer@example.test",
                                                           "password":"local-only reviewer password"}).status_code == 200
            reviewer_headers = mutation_headers(client)
            reviewed = client.post(f"/api/v1/assessments/{assessment_id}/authorization/review", headers=reviewer_headers, json={
                "expected_version": recorded.json()["authorization_version"],
                "reason": "Reviewed fixture authority and exact in-scope target",
                "scope_and_authority_reviewed": True,
            })
            assert reviewed.status_code == 200
            assert reviewed.json()["authorization_status"] == "ACTIVE"
            assert reviewed.json()["authenticity_verified"] is False
            client.post("/api/v1/auth/logout", headers=reviewer_headers)
            assert client.post("/api/v1/auth/login", json={"login":"http-runner@example.test",
                                                           "password":"local-only test password"}).status_code == 200
            headers = mutation_headers(client)

            approval = client.post(f"/api/v1/discovery/endpoints/{endpoint_id}/execution-approval", headers=headers, json={"approved": True, "reason": "Reviewed local test scope"})
            assert approval.status_code == 200
            monkeypatch.setattr(settings, "allow_active_tests", True)
            queued = client.post("/api/v1/testing/jobs", headers={**headers, "Idempotency-Key": "queue-test-key-001"},
                                 json={"assessment_id": assessment_id, "endpoint_id": endpoint_id})
            assert queued.status_code == 202 and queued.json()["status"] == "QUEUED"
            duplicate_job = client.post("/api/v1/testing/jobs", headers={**headers, "Idempotency-Key": "queue-test-key-001"},
                                        json={"assessment_id": assessment_id, "endpoint_id": endpoint_id})
            assert duplicate_job.json()["id"] == queued.json()["id"]
            assert LocalHandler.hits == 0
            assert job_queue.run_one("integration-worker") is True
            completed_job = client.get(f"/api/v1/testing/jobs/{queued.json()['id']}")
            assert completed_job.json()["status"] == "COMPLETED"
            assert LocalHandler.body_marker not in completed_job.text

            # Caller values are accepted only for declared parameters and stored encrypted at rest.
            monkeypatch.setattr(settings, "credential_encryption_key", Fernet.generate_key().decode())
            with sessions() as db:
                endpoint = db.get(models.Endpoint, endpoint_id)
                endpoint.path = "/api/users/{user_id}"
                endpoint.parameters = [
                    {"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "filter", "in": "query", "required": False, "schema": {"type": "string"}},
                    {"name": "X-Trace", "in": "header", "required": False, "schema": {"type": "string"}},
                ]
                db.commit()
            parameterized_job = client.post("/api/v1/testing/jobs",
                headers={**headers, "Idempotency-Key": "parameterized-job-001"},
                json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                      "path_parameters": {"user_id": "alice example"},
                      "query_parameters": {"filter": "active users"},
                      "header_parameters": {"X-Trace": "trace-123"}})
            assert parameterized_job.status_code == 202
            with sessions() as db:
                stored = db.get(models.TestRun, parameterized_job.json()["id"])
                assert "alice example" not in stored.encrypted_request_parameters
                assert "active users" not in stored.encrypted_request_parameters
                assert "trace-123" not in stored.encrypted_request_parameters
            assert job_queue.run_one("parameterized-worker") is True
            parameterized_result = client.get(f"/api/v1/testing/jobs/{parameterized_job.json()['id']}")
            assert parameterized_result.json()["status"] == "COMPLETED"
            assert "alice example" not in parameterized_result.text
            assert "active users" not in parameterized_result.text
            with sessions() as db:
                stored = db.get(models.TestRun, parameterized_job.json()["id"])
                assert stored.execution_metadata["request_parameter_names"] == {
                    "header_parameters": ["X-Trace"], "path_parameters": ["user_id"],
                    "query_parameters": ["filter"],
                }
                endpoint = db.get(models.Endpoint, endpoint_id)
                endpoint.path = "/api/health"
                endpoint.parameters = []
                db.commit()
            cancelled_job = client.post("/api/v1/testing/jobs", headers={**headers, "Idempotency-Key": "queue-test-key-002"},
                                        json={"assessment_id": assessment_id, "endpoint_id": endpoint_id})
            cancelled = client.post(f"/api/v1/testing/jobs/{cancelled_job.json()['id']}/cancel", headers=headers)
            assert cancelled.json()["status"] == "CANCELLED"
            assert job_queue.run_one("integration-worker") is False
            monkeypatch.setattr(settings, "allow_active_tests", False)
            registry = client.get("/api/v1/testing/registry")
            assert registry.status_code == 200
            assert any(item["identifier"] == "response.header.content_type_options" for item in registry.json())
            assert any(item["identifier"] == "response.header.strict_transport_security"
                       and item["required_scheme"] == "https" for item in registry.json())
            cors_observation = next(item for item in registry.json()
                                    if item["identifier"] == "response.header.cors_policy")
            cookie_observation = next(item for item in registry.json()
                                      if item["identifier"] == "response.cookie.session_flags")
            assert cors_observation["max_requests"] == cookie_observation["max_requests"] == 1
            assert cors_observation["enabled"] is False
            assert cookie_observation["enabled"] is False
            error_disclosure = next(item for item in registry.json()
                                    if item["identifier"] == "server.error.verbose_exception")
            assert error_disclosure["enabled"] is ("server.error.verbose_exception" in
                                                   settings.enabled_security_tests.split(","))
            assert error_disclosure["max_requests"] == 1
            assert error_disclosure["max_response_bytes"] == 65_536
            unknown = client.post("/api/v1/testing/runs", headers=headers,
                                  json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                        "category": "Misconfiguration", "test_id": "unknown.test"})
            assert unknown.status_code == 422
            configured_tests = settings.enabled_security_tests
            monkeypatch.setattr(settings, "enabled_security_tests", "")
            disabled_check = client.post("/api/v1/testing/runs", headers=headers,
                                         json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                               "category": "Misconfiguration", "test_id": "response.header.content_type_options"})
            assert disabled_check.status_code == 409
            monkeypatch.setattr(settings, "enabled_security_tests", configured_tests)
            disabled = client.post("/api/v1/testing/runs", headers=headers,
                                   json={"assessment_id": assessment_id, "endpoint_id": endpoint_id, "category": "Authentication"})
            assert disabled.json()["status"] == "SKIPPED"
            assert LocalHandler.hits == 2  # The baseline and parameterized queued fixture requests ran.
            monkeypatch.setattr(settings, "allow_active_tests", True)
            result = client.post("/api/v1/testing/runs", headers=headers,
                                 json={"assessment_id": assessment_id, "endpoint_id": endpoint_id, "category": "Misconfiguration"})
            assert result.status_code == 201
            payload = result.json()
            assert payload["status"] == "COMPLETED"
            assert payload["execution_mode"] == "HTTP_REQUEST"
            assert payload["security_outcome"] == "NOT_RUN"
            assert payload["execution_classification"] == "NOT_APPLICABLE"
            assert payload["execution_metadata"]["status_code"] == 200
            assert payload["execution_metadata"]["policy"]["allowed_methods"] == ["GET"]
            assert len(payload["execution_metadata"]["policy_reference"]) == 64
            assert payload["execution_metadata"]["source_context"]["assessment_type"] == "WEB_API"
            source_record = payload["execution_metadata"]["source_context"]["source_provenance"][0]
            assert source_record["import_id"] == imported.json()["import_id"]
            assert payload["execution_metadata"]["retained_bytes"] == len(LocalHandler.body_marker)
            assert LocalHandler.body_marker not in result.text
            detail = client.get(f"/api/v1/testing/runs/{payload['id']}")
            assert detail.status_code == 200
            assert detail.json()["execution_metadata"] == payload["execution_metadata"]
            assert detail.json()["execution_metadata"]["response_headers"]["content-type"] == "text/plain"
            assert LocalHandler.body_marker not in detail.text
            assert client.get("/api/v1/testing/runs/99999999").status_code == 404

            candidate = client.post("/api/v1/testing/runs", headers=headers,
                                    json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                          "category": "Misconfiguration", "test_id": "response.header.content_type_options"})
            assert candidate.status_code == 201
            candidate_payload = candidate.json()
            assert candidate_payload["status"] == "COMPLETED"
            assert candidate_payload["security_outcome"] == "CANDIDATE_FOUND"
            assert candidate_payload["execution_classification"] == "FAIL"
            assert candidate_payload["execution_metadata"]["execution_classification"] == "FAIL"
            assert candidate_payload["execution_metadata"]["policy"]["max_requests"] == 1
            assert candidate_payload["execution_metadata"]["policy"]["max_redirects"] == 0
            assert candidate_payload["finding_id"] is not None
            assert LocalHandler.body_marker not in candidate.text

            repeated_candidate = client.post("/api/v1/testing/runs", headers=headers,
                                             json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                                   "category": "Misconfiguration", "test_id": "response.header.content_type_options"})
            assert repeated_candidate.json()["security_outcome"] == "CANDIDATE_FOUND"
            assert repeated_candidate.json()["finding_id"] == candidate_payload["finding_id"]

            LocalHandler.nosniff = True
            no_issue = client.post("/api/v1/testing/runs", headers=headers,
                                   json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                         "category": "Misconfiguration", "test_id": "response.header.content_type_options"})
            assert no_issue.json()["status"] == "COMPLETED"
            assert no_issue.json()["security_outcome"] == "NO_ISSUE_OBSERVED"
            assert no_issue.json()["execution_classification"] == "PASS"
            coverage = client.get(f"/api/v1/coverage/{assessment_id}")
            assert coverage.json()["transport_execution"]["completed"] == 1
            assert coverage.json()["completed"] == 1
            assert coverage.json()["security_test_execution"]["planned"] == 1
            assert coverage.json()["security_test_execution"]["completed"] == 1
            api8_coverage = coverage.json()["security_test_execution"]["owasp_categories"]["API8:2023"]
            all_categories = coverage.json()["security_test_execution"]["owasp_categories"]
            assert set(all_categories) == {f"API{i}:2023" for i in range(1, 11)}
            for category in all_categories.values():
                assert category["review_check"]["check_id"]
                assert category["review_check"]["prerequisites"]
                assert category["review_check"]["expected_behavior"]
            bola = all_categories["API1:2023"]["review_check"]
            assert bola["mode"] == "PARTIAL_AUTOMATION"
            assert any("disposable bearer identities" in item.lower() for item in bola["prerequisites"])
            assert any("synthetic records" in item.lower() for item in bola["prerequisites"])
            assert all_categories["API5:2023"]["review_check"]["mode"] == "PARTIAL_AUTOMATION"
            assert all_categories["API8:2023"]["registered_check_details"]
            assert api8_coverage["implemented_checks"] == [
                "response.header.cors_policy", "response.cookie.session_flags",
                "response.header.content_type_options", "response.header.strict_transport_security",
                "server.error.verbose_exception",
            ]
            assert api8_coverage["planned"] == 1
            assert api8_coverage["passed"] == 1
            assert api8_coverage["candidate_findings"] == 1
            assert coverage.json()["security_test_execution"]["owasp_categories"]["API1:2023"]["uncovered_endpoints"] == 1
            assert coverage.json()["reviewed_finding_coverage"] == {"candidates": 1, "reviewed": 0, "percentage": 0}
            reviewed = client.patch(f"/api/v1/findings/{candidate_payload['finding_id']}/status", headers=headers,
                                    json={"status": "Needs Review", "reason": "Analyst reviewed the header observation"})
            assert reviewed.status_code == 200
            assert reviewed.json()["status"] == "Needs Review"
            reviewed_coverage = client.get(f"/api/v1/coverage/{assessment_id}")
            assert reviewed_coverage.json()["reviewed_finding_coverage"] == {"candidates": 1, "reviewed": 1, "percentage": 100}

            # This authorized lab assessment resolves to HTTP. The HSTS check
            # executes only through the same runner and remains inconclusive;
            # it is not planned coverage for an HTTP target.
            hsts_run = client.post("/api/v1/testing/runs", headers=headers,
                                   json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                         "category": "Misconfiguration",
                                         "test_id": "response.header.strict_transport_security"})
            assert hsts_run.status_code == 201
            assert hsts_run.json()["status"] == "COMPLETED"
            assert hsts_run.json()["security_outcome"] == "INCONCLUSIVE"
            assert hsts_run.json()["execution_metadata"]["final_scheme"] == "http"
            assert hsts_run.json()["finding_id"] is None
            hsts_coverage = client.get(f"/api/v1/coverage/{assessment_id}").json()["security_test_execution"]
            assert hsts_coverage["planned"] == 1
            assert hsts_coverage["completed"] == 1

            LocalHandler.nosniff = False
            LocalHandler.x_header_values = ["nosniff", "nosniff"]
            duplicate = client.post("/api/v1/testing/runs", headers=headers,
                                    json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                          "category": "Misconfiguration", "test_id": "response.header.content_type_options"})
            assert duplicate.json()["security_outcome"] == "INCONCLUSIVE"
            LocalHandler.x_header_values = ["invalid-value"]
            incorrect = client.post("/api/v1/testing/runs", headers=headers,
                                    json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                          "category": "Misconfiguration", "test_id": "response.header.content_type_options"})
            assert incorrect.json()["security_outcome"] == "INCONCLUSIVE"
            LocalHandler.x_header_values = None
            LocalHandler.status_code = 404
            not_found = client.post("/api/v1/testing/runs", headers=headers,
                                    json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                          "category": "Misconfiguration", "test_id": "response.header.content_type_options"})
            assert not_found.json()["security_outcome"] == "INCONCLUSIVE"
            assert not_found.json()["finding_id"] is None

            report = client.post(f"/api/v1/reports?assessment_id={assessment_id}", headers=headers, json={})
            assert report.status_code == 201
            report_content = report.json()["content"]
            assert report_content["authorization_record"]["status"] == "ACTIVE"
            assert report_content["authorization_record"]["legal_authenticity_verified"] is False
            assert report_content["authorization_record"]["scope"]["hosts"] == ["127.0.0.1"]
            assert report_content["methodology"]["interpretation"].find("not a security verdict") >= 0
            assert any(item["test_id"] == "response.header.content_type_options"
                       for item in report_content["methodology"]["checks"])
            assert any(item["test_id"] == "response.header.strict_transport_security"
                       and "browser behavior" in item["limitations"]
                       for item in report_content["methodology"]["checks"])
            assert any(item["security_outcome"] == "INCONCLUSIVE" for item in report_content["test_runs"])
            exported_html = client.get(f"/api/v1/reports/{report.json()['id']}/export?format=html")
            assert exported_html.status_code == 200
            assert "Methodology and coverage" in exported_html.text
            assert "response.header.strict_transport_security" in exported_html.text
            assert "does not test browser behavior" in exported_html.text
            assert "Security outcome" in exported_html.text
            assert "Assessment scope and authorization" in exported_html.text
            assert "127.0.0.1" in exported_html.text

            LocalHandler.status_code = 200
            check_job = client.post("/api/v1/testing/jobs",
                                    headers={**headers, "Idempotency-Key": "registered-check-job-01"},
                                    json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                          "test_id": "response.header.content_type_options"})
            assert check_job.status_code == 202
            assert check_job.json()["test_id"] == "response.header.content_type_options"
            assert job_queue.run_one("check-worker") is True
            completed_check_job = client.get(f"/api/v1/testing/jobs/{check_job.json()['id']}")
            assert completed_check_job.json()["status"] == "COMPLETED"
            assert completed_check_job.json()["security_outcome"] == "CANDIDATE_FOUND"
            assert completed_check_job.json()["execution_classification"] == "FAIL"
            assert LocalHandler.body_marker not in completed_check_job.text

            candidate_id = candidate_payload["finding_id"]
            assert client.patch(f"/api/v1/findings/{candidate_id}/validation", headers=headers,
                json={"validation_state": "VALIDATED",
                      "rationale": "The registered local response evidence supports this observation"}).status_code == 200
            assert client.patch(f"/api/v1/findings/{candidate_id}/status", headers=headers,
                json={"status": "Confirmed", "reason": "Reviewer validated the local test evidence"}).status_code == 200
            retest_request = client.post(f"/api/v1/findings/{candidate_id}/retests/request",
                headers={**headers, "Idempotency-Key": "finding-retest-queue-001"}, json={})
            assert retest_request.status_code == 202
            assert retest_request.json()["status"] == "QUEUED"
            with sessions() as db:
                queued_retest = db.query(models.Retest).filter_by(id=retest_request.json()["retest_id"]).one()
                assert queued_retest.outcome == "REQUESTED"
                assert queued_retest.test_run_id == retest_request.json()["test_run_id"]
            assert job_queue.run_one("finding-retest-worker") is True
            completed_retest = client.get(f"/api/v1/testing/jobs/{retest_request.json()['test_run_id']}")
            assert completed_retest.status_code == 200
            with sessions() as db:
                queued_retest = db.get(models.Retest, retest_request.json()["retest_id"])
                persisted_finding = db.get(models.Finding, candidate_id)
                assert queued_retest.outcome in {"NO_ISSUE_OBSERVED", "CONFIRMED_PERSISTENCE", "INCONCLUSIVE"}
                assert queued_retest.evidence
                assert persisted_finding.remediation_status != "VERIFIED_FIXED"

            registered_id = "response.header.content_type_options"
            original_definition = api.REGISTRY[registered_id]

            def broken_evaluator(_result):
                raise RuntimeError("fixture secret must not escape")

            monkeypatch.setitem(api.REGISTRY, registered_id,
                                replace(original_definition, evaluate=broken_evaluator))
            evaluation_error = client.post("/api/v1/testing/runs", headers=headers,
                                           json={"assessment_id": assessment_id, "endpoint_id": endpoint_id,
                                                 "category": "Misconfiguration", "test_id": registered_id})
            assert evaluation_error.status_code == 201
            error_payload = evaluation_error.json()
            assert error_payload["status"] == "COMPLETED"  # transport is independent
            assert error_payload["security_outcome"] == "ERROR"
            assert error_payload["execution_classification"] == "ERROR"
            assert error_payload["finding_id"] is None
            assert error_payload["execution_metadata"]["check_evaluation_error"] is True
            assert "fixture secret" not in evaluation_error.text
            monkeypatch.setitem(api.REGISTRY, registered_id, original_definition)

            with sessions() as db:
                endpoint = db.get(models.Endpoint, endpoint_id)
                endpoint.auth_required = True
                db.commit()
            monkeypatch.setattr(settings, "credential_encryption_key", Fernet.generate_key().decode())
            bearer = "integration-bearer-secret-do-not-log"
            saved_credential = client.put(f"/api/v1/assessments/{assessment_id}/credential-profile",
                                          headers=headers, json={"token": bearer})
            assert saved_credential.status_code == 200 and bearer not in saved_credential.text
            authenticated_transport = client.post("/api/v1/testing/runs", headers=headers,
                                                  json={"assessment_id": assessment_id,
                                                        "endpoint_id": endpoint_id,
                                                        "category": "Misconfiguration"})
            assert authenticated_transport.json()["status"] == "COMPLETED"
            assert LocalHandler.seen_auth[-1] == f"Bearer {bearer}"
            assert bearer not in authenticated_transport.text
            with sessions() as db:
                profile = db.query(models.CredentialProfile).filter_by(assessment_id=assessment_id).one()
                assert bearer not in profile.encrypted_secret
                assert bearer not in str(db.query(models.ExecutionAuditEvent).all())

            with sessions() as db:
                stale = models.TestRun(assessment_id=assessment_id, endpoint_id=endpoint_id,
                                       category="HTTP_REQUEST", status="RUNNING",
                                       summary="Interrupted fixture run", analyst_id=1,
                                       execution_mode="HTTP_REQUEST", method="GET",
                                       started_at=datetime.now(UTC) - timedelta(minutes=10),
                                       execution_metadata={})
                db.add(stale); db.commit(); stale_run_id = stale.id
            recovered_request = client.post("/api/v1/testing/runs", headers=headers,
                                            json={"assessment_id": assessment_id,
                                                  "endpoint_id": endpoint_id,
                                                  "category": "Misconfiguration"})
            assert recovered_request.json()["status"] == "COMPLETED"
            with sessions() as db:
                stale = db.get(models.TestRun, stale_run_id)
                assert stale.status == "TRANSPORT_ERROR"
                assert stale.execution_metadata["recovery"] == "STALE_RUNNING_REQUEST"
                assert db.query(models.ExecutionAuditEvent).filter_by(
                    test_run_id=stale_run_id, event_type="HTTP_REQUEST_RECOVERED").count() == 1

            authorization = client.get(f"/api/v1/assessments/{assessment_id}/authorization").json()
            pending_after_revoke = client.post("/api/v1/testing/jobs",
                headers={**headers, "Idempotency-Key": "queue-revocation-test-003"},
                json={"assessment_id": assessment_id, "endpoint_id": endpoint_id})
            assert pending_after_revoke.status_code == 202
            revoked = client.post(f"/api/v1/assessments/{assessment_id}/authorization/revoke", headers=headers, json={
                "expected_version": authorization["authorization_version"],
                "reason":"Local fixture authorization was revoked for regression test",
            })
            assert revoked.status_code == 200 and revoked.json()["authorization_status"] == "REVOKED"
            hits_before_revoked_run = LocalHandler.hits
            assert job_queue.run_one("integration-worker") is True
            blocked_job = client.get(f"/api/v1/testing/jobs/{pending_after_revoke.json()['id']}")
            assert blocked_job.json()["status"] == "BLOCKED_SCOPE"
            assert LocalHandler.hits == hits_before_revoked_run
            revoked_run = client.post("/api/v1/testing/runs", headers=headers, json={
                "assessment_id":assessment_id, "endpoint_id":endpoint_id, "category":"Misconfiguration",
            })
            assert revoked_run.status_code == 201
            assert revoked_run.json()["status"] == "BLOCKED_SCOPE"
            assert LocalHandler.hits == hits_before_revoked_run

        with sessions() as db:
            run = db.query(models.TestRun).filter_by(test_id="response.header.content_type_options").order_by(models.TestRun.id.desc()).first()
            assert run.analyst_id is not None and run.started_at and run.completed_at
            assert run.execution_metadata["policy_outcome"] == "COMPLETED"
            assert LocalHandler.body_marker not in str(run.execution_metadata)
            finding = db.query(models.Finding).filter_by(test_run_id=candidate_payload["id"]).one()
            assert finding.status == "Retest Required"
            assert finding.endpoint_id == endpoint_id
            assert finding.evidence["test_id"] == "response.header.content_type_options"
            assert LocalHandler.body_marker not in str(finding.evidence)
            events = db.query(models.ExecutionAuditEvent).order_by(models.ExecutionAuditEvent.id).all()
            event_types = [event.event_type for event in events]
            assert event_types.count("SECURITY_CANDIDATE_CREATED") == 1
            assert event_types.count("SECURITY_CANDIDATE_DUPLICATE_SUPPRESSED") == 3
            assert event_types.count("HTTP_REQUEST_STARTED") == 14
            assert event_types.count("HTTP_REQUEST_FINISHED") == 14
            triage_events = [event for event in events if event.event_type == "FINDING_TRIAGE"]
            assert [event.outcome for event in triage_events] == ["Needs Review", "Confirmed"]
            assert sum(event.event_type == "SECURITY_CANDIDATE_DUPLICATE_SUPPRESSED"
                       and event.finding_id == candidate_payload["finding_id"] for event in events) == 3
    finally:
        app.dependency_overrides.pop(get_db, None)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        engine.dispose()
