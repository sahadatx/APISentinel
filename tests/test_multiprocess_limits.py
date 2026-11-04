import multiprocessing
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from apisentinel import models
from apisentinel.db import Base
from apisentinel.runner import RequestPolicy, RunnerBlocked, _acquire


def _worker_acquire(database_url: str, assessment_id: int, queue, schema: str | None = None) -> None:
    connect_args = {"timeout": 10} if database_url.startswith("sqlite:") else {"options": f"-csearch_path={schema or 'public'}"}
    engine = create_engine(database_url, connect_args=connect_args)
    policy = RequestPolicy(
        analyst_id=1, assessment_id=assessment_id, allowed_methods=frozenset({"GET"}),
        allowed_schemes=frozenset({"https"}), allowed_hosts=frozenset({"api.example.test"}),
        allowed_ports=frozenset({443}), allowed_paths=("/**",), excluded_paths=(),
        requests_per_minute=1, max_concurrency=2,
    )
    try:
        with Session(engine) as db:
            try:
                reservation_id = _acquire(db, policy)
                queue.put(("reserved", reservation_id))
            except RunnerBlocked as exc:
                queue.put(("blocked", exc.detail))
    finally:
        engine.dispose()


def _worker_claim(database_url: str, queue, schema: str) -> None:
    from apisentinel.job_queue import _claim

    engine = create_engine(database_url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        with Session(engine) as db:
            queue.put(_claim(db, f"pg-claim-{multiprocessing.current_process().pid}"))
    finally:
        engine.dispose()


def test_rate_reservations_coordinate_independent_processes(tmp_path: Path):
    database_path = tmp_path / "shared.sqlite"
    database_url = f"sqlite:///{database_path}"
    engine = create_engine(database_url, connect_args={"timeout": 10})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        analyst = models.Analyst(login_normalized="process@example.test", password_hash="unused")
        db.add(analyst)
        db.flush()
        client = models.Client(name="process fixture", owner_user_id=analyst.id)
        db.add(client)
        db.flush()
        assessment = models.Assessment(client_id=client.id, name="shared limit fixture")
        db.add(assessment)
        db.commit()
        assessment_id = assessment.id
    engine.dispose()

    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    workers = [ctx.Process(target=_worker_acquire, args=(database_url, assessment_id, queue)) for _ in range(8)]
    for worker in workers:
        worker.start()
    results = [queue.get(timeout=40) for _ in workers]
    for worker in workers:
        worker.join(timeout=40)
        assert worker.exitcode == 0

    assert sum(outcome == "reserved" for outcome, _value in results) == 1
    assert sum(outcome == "blocked" for outcome, _value in results) == 7
    engine = create_engine(database_url)
    with Session(engine) as db:
        assert db.query(models.ExecutionReservation).filter_by(assessment_id=assessment_id).count() == 1
    engine.dispose()


def test_postgres_multiprocess_limits_and_restore_can_run_on_disposable_service(monkeypatch):
    import os
    import uuid

    import pytest

    database_url = os.getenv("APISENTINEL_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("Set APISENTINEL_TEST_POSTGRES_URL to a disposable PostgreSQL database")
    schema = "apisentinel_test_" + uuid.uuid4().hex
    admin_engine = create_engine(database_url)
    with admin_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    engine = create_engine(database_url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            analyst = models.Analyst(login_normalized="pg-process@example.test", password_hash="unused")
            db.add(analyst); db.flush()
            client = models.Client(name="PostgreSQL stress fixture", owner_user_id=analyst.id)
            db.add(client); db.flush()
            assessment = models.Assessment(client_id=client.id, name="shared postgres limits")
            db.add(assessment); db.commit(); assessment_id = assessment.id; analyst_id = analyst.id
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        workers = [ctx.Process(target=_worker_acquire, args=(database_url, assessment_id, queue, schema)) for _ in range(8)]
        for worker in workers:
            worker.start()
        results = [queue.get(timeout=60) for _ in workers]
        for worker in workers:
            worker.join(timeout=60)
            assert worker.exitcode == 0
        assert sum(outcome == "reserved" for outcome, _value in results) == 1
        assert sum(outcome == "blocked" for outcome, _value in results) == 7
        with Session(engine) as db:
            assert db.query(models.ExecutionReservation).filter_by(assessment_id=assessment_id).count() == 1

        # Exercise the durable queue's PostgreSQL SKIP LOCKED claim path across independent processes.
        with Session(engine) as db:
            db.add_all([
                models.TestRun(assessment_id=assessment_id, analyst_id=analyst_id,
                               category="HTTP_REQUEST", execution_mode="HTTP_REQUEST", method="GET",
                               status="QUEUED", idempotency_key=f"pg-queue-{index:04d}")
                for index in range(16)
            ])
            db.commit()
        claim_queue = ctx.Queue()
        claimers = [ctx.Process(target=_worker_claim, args=(database_url, claim_queue, schema))
                    for _ in range(16)]
        for worker in claimers:
            worker.start()
        claimed_ids = [claim_queue.get(timeout=60) for _ in claimers]
        for worker in claimers:
            worker.join(timeout=60)
            assert worker.exitcode == 0
        assert len(set(claimed_ids)) == 16
        assert None not in claimed_ids
        with Session(engine) as db:
            assert db.query(models.TestRun).filter_by(assessment_id=assessment_id, status="RUNNING").count() == 16
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        admin_engine.dispose()
