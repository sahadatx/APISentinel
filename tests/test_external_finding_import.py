
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apisentinel import auth, models
from apisentinel.burp_findings_import import BurpImportError, parse_burp_scanner_xml
from apisentinel.config import settings
from apisentinel.db import Base, get_db
from apisentinel.main import app

SAMPLE = b'''<?xml version="1.0"?>
<!DOCTYPE issues SYSTEM "https://invalid.example/burp.dtd">
<issues burpVersion="2026.10">
 <issue><serialNumber>17</serialNumber><type>1049088</type>
  <name>Missing response header</name><host>https://api.local.test</host>
  <path>/v1/items?token=secret#fragment</path><location>/v1/items</location>
  <severity>Low</severity><confidence>Certain</confidence>
  <issueBackground><![CDATA[The header was missing.]]></issueBackground>
  <issueDetail><![CDATA[Observed on one response. Cookie: session=private-value]]></issueDetail>
  <remediationDetail>Configure the response header.</remediationDetail>
  <request>R0VUIC92MS9pdGVtcz9zZWNyZXQ9eCBIVFRQLzEuMQ0K</request>
  <response>c2VjcmV0IHJlc3BvbnNl</response>
 </issue>
</issues>'''


@pytest.fixture
def import_workspace():
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
        analyst = models.Analyst(login_normalized="import@example.test", password_hash=auth.password_hasher.hash("local test password"))
        other = models.Analyst(login_normalized="other@example.test", password_hash=auth.password_hasher.hash("other password"))
        db.add_all([analyst, other]); db.flush()
        client = models.Client(name="Import fixture", owner_user_id=analyst.id)
        other_client = models.Client(name="Other fixture", owner_user_id=other.id)
        db.add_all([client, other_client]); db.flush()
        assessment = models.Assessment(client_id=client.id, name="Local fixture assessment")
        other_assessment = models.Assessment(client_id=other_client.id, name="Private assessment")
        db.add_all([assessment, other_assessment]); db.flush()
        db.add(models.Endpoint(assessment_id=assessment.id, method="GET", path="/v1/items",
                               server_origin="https://api.local.test", definition_hash="fixture",
                               inventory_current=True, review_state="NEEDS_REVIEW"))
        db.commit()
        ids = {"assessment": assessment.id, "other_assessment": other_assessment.id}
    try:
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"login": "import@example.test", "password": "local test password"})
            assert login.status_code == 200
            csrf = client.cookies[settings.csrf_cookie_name]
            yield client, {"origin": "http://127.0.0.1:5173", "x-csrf-token": csrf}, sessions, ids
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_parser_extracts_safe_fields_and_discards_query():
    issue = parse_burp_scanner_xml(SAMPLE)[0]
    assert issue["name"] == "Missing response header"
    assert issue["severity"] == "Low"
    assert issue["burp_version"] == "2026.10"
    assert issue["host"] == "api.local.test"
    assert issue["path"] == "/v1/items"
    assert issue["method"] == "GET"
    assert "secret" not in str(issue)
    assert "private-value" not in str(issue)


def test_parser_rejects_entity_declarations_and_wrong_document():
    with pytest.raises(BurpImportError):
        parse_burp_scanner_xml(b'<!DOCTYPE issues [<!ENTITY x "boom">]><issues/>')
    with pytest.raises(BurpImportError):
        parse_burp_scanner_xml(b'<not-burp/>')


def test_import_creates_unvalidated_finding_with_provenance_and_no_run(import_workspace):
    client, headers, sessions, ids = import_workspace
    response = client.post(
        f"/api/v1/findings/import/burp-scanner-xml?assessment_id={ids['assessment']}",
        headers=headers, files={"document": ("burp.xml", SAMPLE, "application/xml")},
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["imported"] == 1 and result["security_checks_executed"] is False
    with sessions() as db:
        finding = db.get(models.Finding, result["finding_ids"][0])
        assert finding.status == "Candidate"
        assert finding.validation_state == "PENDING_VALIDATION"
        assert finding.confidence == "UNASSESSED"
        assert finding.endpoint_id is not None
        provenance = finding.evidence["external_tool_import"]
        assert provenance["adapter_id"] == "burp_scanner_issues_xml"
        assert provenance["adapter_version"] == "1"
        assert provenance["burp_version"] == "2026.10"
        assert provenance["raw_request_response_discarded"] is True
        assert "secret" not in str(finding.evidence)
        assert "private-value" not in str(finding.evidence)
        assert db.query(models.TestRun).count() == 0
        events = db.query(models.ExecutionAuditEvent).filter_by(finding_id=finding.id).all()
        assert [event.event_type for event in events] == ["FINDING_EXTERNAL_RESULTS_IMPORTED"]

    duplicate = client.post(
        f"/api/v1/findings/import/burp-scanner-xml?assessment_id={ids['assessment']}",
        headers=headers, files={"document": ("burp.xml", SAMPLE, "application/xml")},
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["imported"] == 0
    assert duplicate.json()["skipped_duplicates"] == 1


def test_import_cannot_access_another_clients_assessment(import_workspace):
    client, headers, _sessions, ids = import_workspace
    response = client.post(
        f"/api/v1/findings/import/burp-scanner-xml?assessment_id={ids['other_assessment']}",
        headers=headers, files={"document": ("burp.xml", SAMPLE, "application/xml")},
    )
    assert response.status_code == 404
