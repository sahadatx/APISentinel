import threading
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from apisentinel import models
from apisentinel.db import Base
from apisentinel.job_queue import MAX_ATTEMPTS, _claim
from apisentinel.runner import RequestOutcome, RunnerResult


def test_expired_worker_lease_is_reclaimed_once_then_failed_without_another_replay(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'queue-recovery.db'}")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            analyst = models.Analyst(login_normalized="recovery@example.test", password_hash="unused")
            db.add(analyst)
            db.flush()
            client = models.Client(name="recovery", owner_user_id=analyst.id)
            db.add(client)
            db.flush()
            assessment = models.Assessment(client_id=client.id, name="recovery drill")
            db.add(assessment)
            db.flush()
            run = models.TestRun(assessment_id=assessment.id, analyst_id=analyst.id,
                                 category="HTTP_REQUEST", execution_mode="HTTP_REQUEST", method="GET",
                                 status="RUNNING", attempt_count=1,
                                 worker_lease_expires_at=datetime.now(UTC) - timedelta(seconds=1),
                                 idempotency_key="recovery-job-hash")
            db.add(run)
            db.commit()
            run_id = run.id

        with Session(engine) as db:
            assert _claim(db, "recovery-worker") == run_id
            run = db.get(models.TestRun, run_id)
            assert run.status == "RUNNING" and run.attempt_count == MAX_ATTEMPTS
            assert db.query(models.ExecutionAuditEvent).filter_by(
                test_run_id=run_id, event_type="HTTP_JOB_RECOVERED", outcome="REQUEUED").count() == 1
            run.worker_lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            db.commit()

        with Session(engine) as db:
            assert _claim(db, "recovery-worker-after-second-crash") is None
            run = db.get(models.TestRun, run_id)
            assert run.status == "TRANSPORT_ERROR"
            assert run.completed_at is not None
            assert db.query(models.ExecutionAuditEvent).filter_by(
                test_run_id=run_id, event_type="HTTP_JOB_RECOVERED", outcome="FAILED").count() == 1
    finally:
        engine.dispose()


def test_running_job_cancellation_reaches_active_runner(tmp_path, monkeypatch):
    import apisentinel.api as api_module
    import apisentinel.job_queue as queue_module
    from apisentinel.config import settings

    engine = create_engine(f"sqlite:///{tmp_path / 'queue-cancel.db'}", connect_args={"timeout": 10})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(queue_module, "SessionLocal", sessions)
    monkeypatch.setattr(queue_module, "authorization_allows", lambda *_args: True)
    monkeypatch.setattr(api_module, "_endpoint_request_url", lambda *_args: "https://api.example.test/health")
    monkeypatch.setattr(settings, "allow_active_tests", True)
    started = threading.Event()

    def wait_for_cancel(_db, _assessment_id, _analyst_id, _method, _url, *, auth=None, headers=None, cancelled=None, **_limits):
        started.set()
        assert cancelled is not None
        deadline = time.monotonic() + 5
        while not cancelled.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)
        return RunnerResult(RequestOutcome.CANCELLED if cancelled.is_set() else RequestOutcome.TIMEOUT)

    monkeypatch.setattr(queue_module, "run_request", wait_for_cancel)
    try:
        with Session(engine) as db:
            analyst = models.Analyst(login_normalized="cancel@example.test", password_hash="unused")
            db.add(analyst)
            db.flush()
            client = models.Client(name="cancel", owner_user_id=analyst.id)
            db.add(client)
            db.flush()
            assessment = models.Assessment(client_id=client.id, name="active cancellation")
            db.add(assessment)
            db.flush()
            endpoint = models.Endpoint(assessment_id=assessment.id, method="GET", path="/health",
                                       review_state="APPROVED", execution_approved=True,
                                       execution_approved_by=analyst.id, execution_approved_at=datetime.now(UTC),
                                       inventory_current=True, parameters=[])
            db.add(endpoint)
            db.flush()
            run = models.TestRun(assessment_id=assessment.id, endpoint_id=endpoint.id, analyst_id=analyst.id,
                                 category="Misconfiguration", execution_mode="HTTP_REQUEST", method="GET",
                                 test_id="response.header.content_type_options", test_version="1.0.0",
                                 status="QUEUED", idempotency_key="active-cancel-job",
                                 execution_metadata={"check_budget": {"max_duration_seconds": 15,
                                                                       "max_response_bytes": 1024,
                                                                       "max_redirects": 0}})
            db.add(run)
            db.commit()
            run_id = run.id

        worker = threading.Thread(target=queue_module.run_one, args=("cancel-worker",), daemon=True)
        worker.start()
        assert started.wait(5)
        with Session(engine) as db:
            run = db.get(models.TestRun, run_id)
            assert run.status == "RUNNING"
            run.execution_metadata = {**(run.execution_metadata or {}), "cancel_requested": True}
            db.commit()
        worker.join(timeout=5)
        assert not worker.is_alive()
        with Session(engine) as db:
            run = db.get(models.TestRun, run_id)
            assert run.status == RequestOutcome.CANCELLED.value
            assert run.security_outcome == "NOT_RUN"
            assert run.execution_metadata["execution_classification"] == "BLOCKED"
            assert run.completed_at is not None
    finally:
        engine.dispose()
