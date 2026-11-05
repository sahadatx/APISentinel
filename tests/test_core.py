from types import SimpleNamespace

import pytest
from authorization_helpers import activate_local_authorization
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apisentinel import models, schemas
from apisentinel.api import coverage, start_test
from apisentinel.db import Base
from apisentinel.discovery import import_openapi
from apisentinel.models import Assessment, Client, Endpoint
from apisentinel.safety import sanitize_evidence, validate_target


def test_scope_requires_authorization_and_exact_host_boundary():
    assessment = Assessment(
        authorization_confirmed=False,
        authorization_reference="",
        allowed_hosts=["client.example"],
        allowed_paths=["/api/**"],
        excluded_paths=[],
    )
    try:
        validate_target(assessment, "https://client.example/api/users")
    except HTTPException as exc:
        assert exc.status_code == 403
        assert "authorization" in exc.detail.lower()
    else:
        raise AssertionError("Scope accepted missing authorization")

    activate_local_authorization(assessment, analyst_id=1)
    assert validate_target(assessment, "https://api.client.example/api/users") == "https://api.client.example/api/users"
    for target in ["http://client.example/api/users", "https://client.example.attacker.test/api/users", "https://client.example/admin"]:
        try:
            validate_target(assessment, target)
        except HTTPException as exc:
            assert exc.status_code == 403
        else:
            raise AssertionError(f"Out-of-scope URL accepted: {target}")


def test_evidence_masks_common_secret_fields_recursively():
    value = {"Authorization": "Bearer abc", "nested": [{"api-key": "xyz", "message": "Bearer xyz"}], "access_token": "token", "response_body": "raw body"}
    assert sanitize_evidence(value) == {"Authorization": "[REDACTED]", "nested": [{"api-key": "[REDACTED]", "message": "[REDACTED]"}], "access_token": "[REDACTED]", "response_body": "[REDACTED]"}


def test_openapi_import_creates_inventory_without_network_requests():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        client = Client(name="Fixture client")
        db.add(client)
        db.flush()
        analyst = models.Analyst(login_normalized="fixture@example.test", password_hash="unused")
        db.add(analyst)
        db.flush()
        client.owner_user_id = analyst.id
        assessment = Assessment(client_id=client.id, name="Fixture assessment")
        db.add(assessment)
        db.flush()
        imported = import_openapi(db, assessment, {
            "openapi": "3.0.0",
            "info": {"title": "Fixture API", "version": "1"},
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearerAuth": []}],
            "paths": {"/api/users/{id}": {"get": {"summary": "Get user", "operationId": "getUser", "parameters": [{"name": "id", "in": "path", "required": True}]}}},
        }, analyst_id=analyst.id)
        endpoints = imported["endpoints"]
        assert len(endpoints) == 1
        assert endpoints[0].method == "GET"
        assert endpoints[0].auth_required is True
        assert endpoints[0].parameters == [{"name": "id", "in": "path", "required": True, "schema": {}}]
        assert endpoints[0].review_state == "REJECTED"
        assert "path parameters" in endpoints[0].review_reason
        assert endpoints[0].execution_approved is False
        assert imported["content_hash"] == imported["version_id"]


def test_coverage_ignores_legacy_transport_labels_as_security_test_results():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        client = Client(name="Coverage fixture")
        db.add(client)
        db.flush()
        analyst = models.Analyst(login_normalized="a@example.test", password_hash="not-used")
        db.add(analyst)
        db.flush()
        client.owner_user_id = analyst.id
        assessment = Assessment(client_id=client.id, name="Assessment A")
        other_assessment = Assessment(client_id=client.id, name="Assessment B")
        db.add_all([assessment, other_assessment])
        db.flush()
        first = Endpoint(assessment_id=assessment.id, method="GET", path="/one")
        second = Endpoint(assessment_id=assessment.id, method="GET", path="/two")
        other = Endpoint(assessment_id=other_assessment.id, method="GET", path="/other")
        db.add_all([first, second, other])
        db.flush()
        db.add_all([
            models.TestRun(assessment_id=assessment.id, endpoint_id=first.id, category="Authentication", status="Passed"),
            models.TestRun(assessment_id=assessment.id, endpoint_id=first.id, category="Authentication", status="Skipped"),
            models.TestRun(assessment_id=assessment.id, endpoint_id=second.id, category="Authentication", status="Failed"),
            models.TestRun(assessment_id=assessment.id, endpoint_id=first.id, category="Input Validation", status="Error"),
            models.TestRun(assessment_id=assessment.id, endpoint_id=None, category="Authorization", status="Passed"),
            models.TestRun(assessment_id=other_assessment.id, endpoint_id=other.id, category="Authorization", status="Passed"),
        ])
        db.commit()

        request = SimpleNamespace(state=SimpleNamespace(analyst=analyst))
        result = coverage(assessment.id, request, db)

        assert result["planned"] == 0
        assert result["completed"] == 0
        assert result["percentage"] == 0
        assert result["unassigned_runs"] == 1
        assert result["endpoint_inventory"]["current"] == 2
        assert result["security_test_execution"]["matrix"] == []


def test_test_run_rejects_endpoint_from_another_assessment_and_requires_approval():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        client = Client(name="Scope fixture")
        db.add(client)
        db.flush()
        analyst = models.Analyst(login_normalized="a@example.test", password_hash="not-used")
        db.add(analyst)
        db.flush()
        client.owner_user_id = analyst.id
        assessment = Assessment(client_id=client.id, name="Assessment A")
        other_assessment = Assessment(client_id=client.id, name="Assessment B")
        db.add_all([assessment, other_assessment])
        db.flush()
        endpoint = Endpoint(assessment_id=assessment.id, method="GET", path="/allowed")
        outside = Endpoint(assessment_id=other_assessment.id, method="GET", path="/outside")
        db.add_all([endpoint, outside])
        db.commit()

        request = SimpleNamespace(state=SimpleNamespace(analyst=analyst))
        result = start_test(schemas.TestRunCreate(assessment_id=assessment.id, endpoint_id=endpoint.id, category="Authentication"), request, db)
        assert result["endpoint_id"] == endpoint.id
        assert result["status"] == "BLOCKED_SCOPE"
        assert "authorization" in result["summary"].lower()
        with pytest.raises(HTTPException) as exc_info:
            start_test(schemas.TestRunCreate(assessment_id=assessment.id, endpoint_id=outside.id, category="Authentication"), request, db)
        assert exc_info.value.status_code == 404


def test_database_prevents_duplicate_active_http_run_for_same_endpoint():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        client = Client(name="Lock fixture")
        db.add(client)
        db.flush()
        assessment = Assessment(client_id=client.id, name="Lock assessment")
        db.add(assessment)
        db.flush()
        endpoint = Endpoint(assessment_id=assessment.id, method="GET", path="/health")
        db.add(endpoint)
        db.flush()
        db.add(models.TestRun(assessment_id=assessment.id, endpoint_id=endpoint.id, category="HTTP_REQUEST", execution_mode="HTTP_REQUEST", status="RUNNING"))
        db.commit()
        db.add(models.TestRun(assessment_id=assessment.id, endpoint_id=endpoint.id, category="HTTP_REQUEST", execution_mode="HTTP_REQUEST", status="RUNNING"))
        with pytest.raises(IntegrityError):
            db.commit()
    engine.dispose()
