import json

import pytest
from authorization_helpers import activate_local_authorization
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from apisentinel import models
from apisentinel.collection_import import (
    android_capture_to_openapi,
    burp_to_openapi,
    har_to_openapi,
    postman_to_openapi,
)
from apisentinel.db import Base
from apisentinel.discovery import import_openapi, parse_import_envelope


def _workspace():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = Session(engine)
    analyst = models.Analyst(login_normalized="openapi@example.test", password_hash="unused")
    db.add(analyst)
    db.flush()
    client = models.Client(name="OpenAPI fixture", owner_user_id=analyst.id)
    db.add(client)
    db.flush()
    assessment = models.Assessment(
        client_id=client.id, name="OpenAPI lab", environment="lab",
        authorization_confirmed=True, authorization_reference="local-fixture",
        allowed_hosts=["api.scope.example.test"], allowed_paths=["/api/**"],
    )
    db.add(assessment)
    activate_local_authorization(assessment, analyst.id)
    db.commit()
    db.refresh(assessment)
    return engine, db, analyst, assessment


def _spec(*, version="3.1.0", summary="Read item", server="https://api.scope.example.test/api"):
    return {
        "openapi": version,
        "info": {"title": "Fixture API", "version": "1"},
        "servers": [{"url": server}] if server is not None else [],
        "components": {
            "parameters": {"ItemId": {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}},
            "schemas": {"Item": {"type": "object", "properties": {"name": {"type": "string", "default": "not-retained"}}}},
            "securitySchemes": {"session": {"type": "apiKey", "in": "header", "name": "X-Session"}},
        },
        "security": [{"session": []}],
        "paths": {
            "/items": {
                "get": {
                    "summary": summary,
                    "operationId": "readItem",
                    "tags": ["items"],
                    "parameters": [{"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                                   {"name": "id", "in": "query", "schema": {"$ref": "#/components/schemas/Item"}},
                                   {"name": "X-Trace", "in": "header", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}}},
                },
                "post": {
                    "operationId": "createItem", "requestBody": {"required": True, "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Item"}},
                    }}, "responses": {"201": {"description": "created"}},
                },
            },
        },
    }


def test_import_extracts_parameters_body_tags_security_and_scrubs_schema_examples():
    engine, db, analyst, assessment = _workspace()
    try:
        result = import_openapi(db, assessment, _spec(), analyst_id=analyst.id)
        get_endpoint, post_endpoint = result["endpoints"]
        assert result["openapi_version"] == "3.1.0"
        assert get_endpoint.method == "GET" and get_endpoint.review_state == "IMPORTED"
        assert get_endpoint.server_base_path == "/api"
        assert {(p["in"], p["name"]) for p in get_endpoint.parameters} == {
            ("query", "id"), ("query", "verbose"), ("header", "X-Trace"),
        }
        assert get_endpoint.tags == ["items"]
        assert get_endpoint.auth_required is True
        assert get_endpoint.security_requirements == [{"session": []}]
        assert "default" not in json.dumps(get_endpoint.request_body)
        assert post_endpoint.method == "POST" and post_endpoint.review_state == "REJECTED"
        assert "inventory-only" in post_endpoint.review_reason
        assert get_endpoint.execution_approved is False
        assert get_endpoint.scope_status == "IN_SCOPE"
        assert get_endpoint.server_origin == "https://api.scope.example.test"
        assert get_endpoint.api_title == "Fixture API"
        assert get_endpoint.api_version == "1"
        assert get_endpoint.content_types == ["application/json"]
        assert "200:application/json" in get_endpoint.response_schemas
        assert result["summary"]["raw_candidates"] == 2
        assert result["summary"]["unique_endpoints"] == 2
    finally:
        db.close(); engine.dispose()


@pytest.mark.parametrize("spec, message", [
    ({"swagger": "2.0", "paths": {}}, "3.0.x and 3.1.x"),
    ({"openapi": "3.2.0", "info": {"title": "x"}, "paths": {}}, "3.0.x and 3.1.x"),
    ({"openapi": "3.0.3", "info": {"title": "x"}, "paths": {"/a/../b": {"get": {}}}}, "traversal"),
    ({"openapi": "3.0.3", "info": {"title": "x"}, "paths": {"/a%2fb": {"get": {}}}}, "Percent-encoded"),
    ({"openapi": "3.0.3", "info": {"title": "x"}, "paths": {"/a": {"get": {"parameters": [{"$ref": "https://evil.test/schema"}]}}}}, "Only local"),
    ({"openapi": "3.0.3", "info": {"title": "x"}, "paths": {"/a": {"get": {"parameters": [{"$ref": "#/components/parameters/missing"}]}}}}, "unresolved"),
    ({"openapi": "3.0.3", "info": {"title": "x"}, "servers": [{"url": "https://user:pass@api.scope.example.test"}], "paths": {"/a": {"get": {}}}}, "user information"),
    ({"openapi": "3.0.3", "info": {"title": "x"}, "paths": {"/a/{id}": {"get": {}}}}, "path parameters"),
])
def test_import_rejects_unsupported_or_unsafe_documents(spec, message):
    engine, db, analyst, assessment = _workspace()
    try:
        with pytest.raises(HTTPException, match=message):
            import_openapi(db, assessment, spec, analyst_id=analyst.id)
        assert db.query(models.OpenAPIDocument).count() == 0
        assert db.query(models.Endpoint).count() == 0
    finally:
        db.close(); engine.dispose()


def test_multiple_and_out_of_scope_servers_require_review_without_broadening_scope():
    engine, db, analyst, assessment = _workspace()
    try:
        spec = _spec(server="https://outside.invalid/api")
        spec["servers"].append({"url": "https://api.scope.example.test/api"})
        result = import_openapi(db, assessment, spec, analyst_id=analyst.id)
        endpoint = next(row for row in result["endpoints"] if row.method == "GET")
        assert endpoint.review_state == "NEEDS_REVIEW"
        assert endpoint.server_base_path == ""
        assert any("Multiple server" in issue for issue in endpoint.server_review_issues)
        assert any("outside" in issue for issue in endpoint.server_review_issues)
        assert assessment.allowed_hosts == ["api.scope.example.test"]
        assert result["issues"]
        assert endpoint.scope_status == "UNRESOLVED"
    finally:
        db.close(); engine.dispose()


def test_required_path_parameters_are_inventoried_but_not_approvable():
    engine, db, analyst, assessment = _workspace()
    try:
        spec = _spec()
        path_item = spec["paths"].pop("/items")
        path_item["parameters"] = [{"$ref": "#/components/parameters/ItemId"}]
        spec["paths"]["/items/{id}"] = path_item
        result = import_openapi(db, assessment, spec, analyst_id=analyst.id)
        endpoint = next(row for row in result["endpoints"] if row.method == "GET")
        path_parameter = next(parameter for parameter in endpoint.parameters if parameter["in"] == "path")
        assert path_parameter["name"] == "id"
        assert endpoint.review_state == "REJECTED"
        assert "cannot be populated" in endpoint.review_reason
    finally:
        db.close(); engine.dispose()


def test_reimport_invalidates_changed_approval_and_reimporting_same_definition_keeps_it():
    engine, db, analyst, assessment = _workspace()
    try:
        original = import_openapi(db, assessment, _spec(), analyst_id=analyst.id)
        endpoint = next(row for row in original["endpoints"] if row.method == "GET")
        endpoint.review_state = "APPROVED"
        endpoint.execution_approved = True
        endpoint.execution_approved_by = analyst.id
        endpoint.execution_approved_at = models.now()
        db.commit()

        same = import_openapi(db, assessment, _spec(), analyst_id=analyst.id)
        assert next(row for row in same["endpoints"] if row.method == "GET").id == endpoint.id
        assert endpoint.execution_approved is True

        changed_spec = _spec(summary="Changed contract")
        changed = import_openapi(db, assessment, changed_spec, analyst_id=analyst.id)
        current = next(row for row in changed["endpoints"] if row.method == "GET")
        assert current.id != endpoint.id
        assert current.review_state == "IMPORTED" and current.execution_approved is False
        assert endpoint.inventory_current is False and endpoint.review_state == "REJECTED"
        assert endpoint.execution_approved is False
        assert endpoint.execution_approved_by == analyst.id
        assert db.query(models.ExecutionAuditEvent).filter_by(event_type="ENDPOINT_REVIEW_INVALIDATED").count() >= 1
        assert db.query(models.OpenAPIDocument).count() == 3
    finally:
        db.close(); engine.dispose()


def test_import_body_limit_and_duplicate_json_keys_are_rejected():
    with pytest.raises(HTTPException) as exc:
        parse_import_envelope(b"{" + b" " * 32 + b"}", 16)
    assert exc.value.status_code == 413
    with pytest.raises(HTTPException, match="duplicate"):
        parse_import_envelope(b'{"assessment_id":1,"assessment_id":2}', 128)
    deeply_nested = b'{"nested":' * 2000 + b"0" + b"}" * 2000
    with pytest.raises(HTTPException, match="nesting"):
        parse_import_envelope(deeply_nested, 50_000)


def test_recursive_local_schema_is_bounded_and_import_never_resolves_network(monkeypatch):
    import socket

    engine, db, analyst, assessment = _workspace()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("discovery import attempted network activity")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    recursive = _spec()
    recursive["components"]["schemas"]["Item"]["properties"]["parent"] = {"$ref": "#/components/schemas/Item"}
    try:
        result = import_openapi(db, assessment, recursive, analyst_id=analyst.id)
        endpoint = next(row for row in result["endpoints"] if row.method == "GET")
        assert "recursive" in json.dumps(endpoint.response_schemas)
    finally:
        db.close(); engine.dispose()


def test_postman_import_discards_values_and_keeps_approval_boundary():
    engine, db, analyst, assessment = _workspace()
    try:
        collection = {
            "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [{"name": "private request", "request": {
                "method": "GET", "url": {"raw": "https://api.scope.example.test/api/items?access_token=SECRET"},
                "header": [{"key": "Authorization", "value": "Bearer SECRET"}],
            }}],
        }
        converted = postman_to_openapi(collection)
        result = import_openapi(db, assessment, converted, analyst_id=analyst.id, source="postman_v2.1")
        endpoint = result["endpoints"][0]
        assert result["source"] == "postman_v2.1"
        assert endpoint.source == "postman_v2.1"
        assert endpoint.auth_required is True
        assert endpoint.execution_approved is False
        assert "SECRET" not in json.dumps(endpoint.parameters)
        assert "access_token" in json.dumps(endpoint.parameters)
        assert db.query(models.OpenAPIDocument).one().source == "postman_v2.1"
    finally:
        db.close(); engine.dispose()


def test_burp_structured_import_is_separate_and_rejects_unsafe_input():
    engine, db, analyst, assessment = _workspace()
    try:
        burp = {"items": [{"request": {"method": "GET", "url": "https://api.scope.example.test/api/items",
                                          "headers": [{"name": "Cookie", "value": "session=SECRET"}]}}]}
        converted = burp_to_openapi(burp)
        result = import_openapi(db, assessment, converted, analyst_id=analyst.id, source="burp_http_history")
        assert result["endpoints"][0].auth_required is True
        assert result["endpoints"][0].execution_approved is False
        assert "SECRET" not in json.dumps(result["endpoints"][0].parameters)
        openapi = import_openapi(db, assessment, _spec(), analyst_id=analyst.id)
        assert all(row.source == "openapi" for row in openapi["endpoints"])
        assert db.query(models.Endpoint).filter_by(source="burp_http_history", inventory_current=True).count() == 1
        assert db.query(models.Endpoint).filter_by(source="openapi", inventory_current=True).count() == 2
        with pytest.raises(HTTPException, match="user information"):
            burp_to_openapi({"items": [{"method": "GET", "url": "https://user:pass@api.scope.example.test/a"}]})
        with pytest.raises(HTTPException, match="traversal"):
            burp_to_openapi({"items": [{"method": "GET", "url": "https://api.scope.example.test/a/../b"}]})
    finally:
        db.close(); engine.dispose()


def test_har_and_android_capture_imports_are_passive_and_scrub_secrets():
    har = {"log": {"entries": [{"pageref": "tab-1", "_initiator": {"url": "https://app.example.test/page?session=secret"},
                                  "request": {"method": "GET", "url": "https://api.scope.example.test/api/items?q=secret",
                                              "headers": [{"name": "Cookie", "value": "sid=secret"}]}}]}}
    converted = har_to_openapi(har)
    endpoint = converted["paths"]["/api/items"]["get"]
    assert endpoint["x-apisentinel-browser-origin"] == "https://app.example.test"
    assert "secret" not in json.dumps(converted)
    with pytest.raises(HTTPException, match="malformed"):
        har_to_openapi({"log": {"entries": [None]}})

    android = {"format": "apisentinel.android_http_capture.v1", "package_name": "com.example.app",
               "version_name": "2.1", "requests": [{"method": "GET", "url": "https://api.scope.example.test/api/items",
                                                         "headers": [{"name": "Authorization", "value": "Bearer private"}],
                                                         "auth_scheme": "bearer"}]}
    converted = android_capture_to_openapi(android)
    assert converted["info"]["x-apisentinel-app"] == {"package_name": "com.example.app", "version_name": "2.1"}
    assert "private" not in json.dumps(converted)
    with pytest.raises(HTTPException, match="v1"):
        android_capture_to_openapi({"format": "unknown", "requests": []})


def test_scope_classification_and_assessment_origin_are_part_of_inventory_identity():
    engine, db, analyst, assessment = _workspace()
    try:
        first = import_openapi(db, assessment, _spec(), analyst_id=analyst.id)
        assert {e.scope_status for e in first["endpoints"]} == {"IN_SCOPE"}

        other = _spec(server="https://other.scope.example.test/api")
        second = import_openapi(db, assessment, other, analyst_id=analyst.id)
        outside = next(row for row in second["endpoints"] if row.method == "GET")
        assert outside.scope_status == "OUT_OF_SCOPE"
        assert outside.server_origin == "https://other.scope.example.test"
        assert outside.id != next(row for row in first["endpoints"] if row.method == "GET").id

        no_server = _spec(server=None)
        third = import_openapi(db, assessment, no_server, analyst_id=analyst.id)
        unresolved = next(row for row in third["endpoints"] if row.method == "GET")
        assert unresolved.scope_status == "UNRESOLVED"
        assert "not inferred" in unresolved.scope_reason

        assessment.excluded_paths = ["/api/items"]
        excluded = import_openapi(db, assessment, _spec(), analyst_id=analyst.id)
        excluded_item = next(row for row in excluded["endpoints"] if row.method == "GET")
        assert excluded_item.scope_status == "EXCLUDED"
    finally:
        db.close(); engine.dispose()


def test_collection_import_identifies_auth_schemes_without_retaining_values():
    collection = {"info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"request": {"method": "GET", "url": f"https://api.scope.example.test/api/{name}",
                               "header": headers}} for name, headers in (
            ("bearer", [{"key": "Authorization", "value": "Bearer bearer-secret"}]),
            ("basic", [{"key": "Authorization", "value": "Basic basic-secret"}]),
            ("key", [{"key": "X-API-Key", "value": "api-key-secret"}]),
            ("cookie", [{"key": "Cookie", "value": "sid=cookie-secret"}]),
        )]}
    converted = postman_to_openapi(collection)
    schemes = converted["components"]["securitySchemes"]
    assert schemes["imported_bearer"] == {"type": "http", "scheme": "bearer"}
    assert schemes["imported_basic"] == {"type": "http", "scheme": "basic"}
    assert schemes["imported_header_x_api_key"] == {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    assert schemes["imported_cookie_sid"] == {"type": "apiKey", "in": "cookie", "name": "sid"}
    assert "secret" not in json.dumps(converted)


def test_import_provenance_merges_exact_definition_without_cross_source_replacement():
    engine, db, analyst, assessment = _workspace()
    try:
        first = import_openapi(db, assessment, _spec(), analyst_id=analyst.id)
        endpoint = next(row for row in first["endpoints"] if row.method == "GET")
        same_spec = _spec()
        same_spec["info"]["title"] = "Different artifact title"
        second = import_openapi(db, assessment, same_spec, analyst_id=analyst.id, source="browser_har_1.2")
        equivalent = next(row for row in second["endpoints"] if row.method == "GET")
        # Definition fingerprints are source-independent; provenance points to both imports.
        assert equivalent.id == endpoint.id
        assert {item["source"] for item in endpoint.source_provenance} == {"inline_json", "browser_har_1.2"}
        assert db.query(models.Endpoint).filter_by(assessment_id=assessment.id, path="/items", method="GET", inventory_current=True).count() == 1
    finally:
        db.close(); engine.dispose()
