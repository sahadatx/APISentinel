import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def _alembic(root: Path, database: Path, *args: str) -> None:
    env = {**os.environ, "APISENTINEL_DATABASE_URL": f"sqlite:///{database}"}
    result = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=root, env=env,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            check=False)
    assert result.returncode == 0, result.stdout


def test_authorization_migration_preserves_legacy_attestation_but_requires_review(tmp_path):
    root = Path(__file__).resolve().parents[1]
    database = tmp_path / "legacy-authorization.db"
    _alembic(root, database, "upgrade", "0008_retest_execution_provenance")
    connection = sqlite3.connect(database)
    connection.execute(
        "INSERT INTO clients (id,name,organization,contact_email,status,created_at) "
        "VALUES (1,'Legacy client','','','Active',CURRENT_TIMESTAMP)"
    )
    connection.execute(
        "INSERT INTO assessments (id,client_id,name,environment,status,authorization_reference,"
        "authorization_confirmed,allowed_hosts,allowed_paths,excluded_paths,max_requests_per_minute,"
        "testing_window_start,testing_window_end,created_at) VALUES "
        "(1,1,'Legacy assessment','staging','Draft','old-ref',1,?,?,?,30,'','',CURRENT_TIMESTAMP)",
        (json.dumps(["api.legacy.test"]), json.dumps(["/api/**"]), json.dumps([])),
    )
    connection.commit()
    connection.close()

    _alembic(root, database, "upgrade", "0020_assessment_configuration")
    connection = sqlite3.connect(database)
    connection.execute(
        "INSERT INTO endpoints (id,assessment_id,method,path,summary,operation_id,parameters,auth_required,source) "
        "VALUES (1,1,'GET','/api/legacy','','legacyOperation','[]',0,'openapi')"
    )
    connection.commit()
    connection.close()

    _alembic(root, database, "upgrade", "head")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    row = connection.execute(
        "SELECT authorization_reference, authorization_confirmed, authorization_status, "
        "authorization_scope_hash, authorization_scope_snapshot FROM assessments WHERE id=1"
    ).fetchone()
    events = connection.execute(
        "SELECT count(*) FROM execution_audit_events WHERE assessment_id=1 "
        "AND event_type LIKE 'AUTHORIZATION_%'"
    ).fetchone()[0]
    revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
    config = connection.execute(
        "SELECT description, target_configs, configuration_version, created_by_id, updated_at "
        "FROM assessments WHERE id=1"
    ).fetchone()
    endpoint = connection.execute(
        "SELECT path,scope_status,scope_reason,last_discovered_at FROM endpoints WHERE id=1"
    ).fetchone()
    connection.close()
    assert row == ("old-ref", 1, "REVIEW_REQUIRED", "", "{}")
    assert events == 0
    current_head = ScriptDirectory.from_config(Config(str(root / "alembic.ini"))).get_current_head()
    assert revision == current_head
    assert config[0:4] == ("", "{}", 1, None)
    assert config[4]
    assert endpoint[:2] == ("/api/legacy", "UNRESOLVED")
    assert "revalidation" in endpoint[2].lower()
    assert endpoint[3]

    _alembic(root, database, "downgrade", "0019_encrypted_http_request_parameters")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    columns = {item[1] for item in connection.execute("PRAGMA table_info(assessments)")}
    legacy = connection.execute(
        "SELECT authorization_reference, authorization_confirmed, status FROM assessments WHERE id=1"
    ).fetchone()
    connection.close()
    assert not {"description", "target_configs", "configuration_version", "created_by_id", "updated_at"} & columns
    assert legacy == ("old-ref", 1, "Draft")
