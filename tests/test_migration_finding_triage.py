import os
import subprocess
import sys

from sqlalchemy import create_engine, text


def test_finding_triage_migration_preserves_legacy_finding_and_does_not_invent_audit_links(tmp_path):
    database = tmp_path / "legacy-triage.db"
    database_url = f"sqlite:///{database}"
    env = {**os.environ, "APISENTINEL_DATABASE_URL": database_url}
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "0006_test_registry_outcomes"],
                   check=True, env=env, capture_output=True, text=True)
    engine = create_engine(database_url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO analysts (id,login_normalized,password_hash,role,is_active,created_at,updated_at) VALUES (1,'legacy@example.test','hash','analyst',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO clients (id,name,organization,contact_email,status,created_at,owner_user_id) VALUES (1,'Legacy client','','','Active',CURRENT_TIMESTAMP,1)"))
        conn.execute(text("INSERT INTO assessments (id,client_id,name,environment,status,authorization_reference,authorization_confirmed,allowed_hosts,allowed_paths,excluded_paths,max_requests_per_minute,testing_window_start,testing_window_end,created_at) VALUES (1,1,'Legacy assessment','staging','Draft','',0,'[]','[]','[]',30,'','',CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO findings (id,assessment_id,title,severity,status,endpoint,description,impact,evidence,remediation,history,created_at) VALUES (1,1,'Legacy candidate','Medium','Candidate','GET /legacy','','','{}','','[]',CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO retests (id,finding_id,outcome,evidence,notes,created_at) VALUES (1,1,'Inconclusive','{}','legacy note',CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO execution_audit_events (id,actor_id,client_id,assessment_id,test_run_id,event_type,outcome,metadata_json,created_at) VALUES (1,1,1,1,NULL,'LEGACY_FINDING_EVENT','Candidate',:metadata,CURRENT_TIMESTAMP)"),
                     {"metadata": '{"finding_id":1}'})
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                   check=True, env=env, capture_output=True, text=True)
    subprocess.run([sys.executable, "-m", "alembic", "check"],
                   check=True, env=env, capture_output=True, text=True)
    with engine.connect() as conn:
        finding = conn.execute(text("SELECT status,triage_version,history,validation_state,remediation_status,"
                                   "confidence,priority,first_detected_at,last_observed_at "
                                   "FROM findings WHERE id=1")).one()
        event = conn.execute(text("SELECT finding_id,metadata_json FROM execution_audit_events WHERE id=1")).one()
        retest = conn.execute(text("SELECT assessment_id,test_run_id,endpoint_id,analyst_id,test_id,test_version,endpoint_definition_hash,outcome FROM retests WHERE id=1")).one()
        assert finding.status == "Candidate"
        assert finding.triage_version == 1
        assert finding.history == "[]"
        assert finding.validation_state == "PENDING_VALIDATION"
        assert finding.remediation_status == "OPEN"
        assert finding.confidence == "UNASSESSED" and finding.priority == "P3"
        assert finding.first_detected_at is not None and finding.last_observed_at is not None
        assert event.finding_id is None
        assert '"finding_id":1' in event.metadata_json
        assert retest.assessment_id is None and retest.test_run_id is None and retest.endpoint_id is None
        assert retest.analyst_id is None and retest.test_id == "" and retest.test_version == ""
        assert retest.endpoint_definition_hash == "" and retest.outcome == "Inconclusive"
    engine.dispose()
