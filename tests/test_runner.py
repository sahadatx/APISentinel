from __future__ import annotations

import logging
import socket
import ssl
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit

import pytest
from authorization_helpers import activate_local_authorization
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from apisentinel import models, runner
from apisentinel.config import Settings, settings
from apisentinel.db import Base
from apisentinel.runner import (
    BearerTokenReference,
    RequestOutcome,
    RequestPolicy,
    RunnerBlocked,
    _validate_url,
    run_request,
)
from apisentinel.test_registry import REGISTRY, SecurityOutcome


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen_auth: ClassVar[list[str | None]] = []
    seen_cookie: ClassVar[list[str | None]] = []
    seen_hosts: ClassVar[list[str | None]] = []
    seen_client_ports: ClassVar[list[int]] = []
    seen_proxy_form: ClassVar[list[bool]] = []
    closed_early: ClassVar[threading.Event] = threading.Event()
    stream_started: ClassVar[threading.Event] = threading.Event()
    stream_release: ClassVar[threading.Event] = threading.Event()
    downgrade_target_port: ClassVar[int] = 0
    hsts_value: ClassVar[str | None] = None

    def do_GET(self):
        parts = urlsplit(self.path)
        self.__class__.seen_auth.append(self.headers.get("Authorization"))
        self.__class__.seen_cookie.append(self.headers.get("Cookie"))
        self.__class__.seen_hosts.append(self.headers.get("Host"))
        self.__class__.seen_client_ports.append(self.client_address[1])
        self.__class__.seen_proxy_form.append(self.path.startswith(("http://", "https://")))
        if parts.path == "/api/redirect-out":
            self.send_response(302); self.send_header("Location", "https://outside.example/api/data"); self.end_headers(); return
        if parts.path == "/api/redirect-loop":
            self.send_response(302); self.send_header("Location", "/api/redirect-loop"); self.end_headers(); return
        if parts.path == "/api/redirect-private":
            self.send_response(302); self.send_header("Location", "https://api.client.example/api/hidden"); self.end_headers(); return
        if parts.path == "/api/downgrade":
            self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{self.downgrade_target_port}/api/final"); self.end_headers(); return
        if parts.path == "/api/redirect-relative":
            self.send_response(302); self.send_header("Location", "../api/final"); self.send_header("Content-Length", str(8 * 1024 * 1024)); self.end_headers()
            try:
                for _ in range(128): self.wfile.write(b"i" * 65536)
            except OSError: self.__class__.closed_early.set()
            return
        if parts.path == "/api/redirect-absolute":
            self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/api/final"); self.end_headers(); return
        if parts.path == "/api/redirect-origin":
            port = self.server.server_port
            self.send_response(302); self.send_header("Location", f"http://localhost:{port}/api/final"); self.end_headers(); return
        if parts.path == "/api/slow":
            threading.Event().wait(0.2)
        if parts.path == "/api/interrupted":
            # Send a deliberately incomplete fixed-length body.
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"partial")
            self.close_connection = True
            return
        if parts.path == "/api/cancel-stream":
            self.send_response(200); self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
            self.wfile.write(b"5\r\nfirst\r\n"); self.wfile.flush()
            self.__class__.stream_started.set()
            self.__class__.stream_release.wait(2)
            try:
                self.wfile.write(b"6\r\nsecond\r\n0\r\n\r\n"); self.wfile.flush()
            except OSError:
                self.__class__.closed_early.set()
            return
        if parts.path in {"/api/gzip", "/api/bad-gzip"}:
            import gzip
            body = gzip.compress(b"z" * 2048) if parts.path == "/api/gzip" else b"bad-gzip"
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Encoding", "gzip"); self.send_header("Content-Length", str(len(body))); self.end_headers()
            try: self.wfile.write(body)
            except OSError: self.__class__.closed_early.set()
            return
        body_size = {"/api/large": 1025, "/api/exact-limit": 1024, "/api/huge": 8 * 1024 * 1024}.get(parts.path, 2)
        self.send_response(200); self.send_header("Content-Type", "text/plain"); self.send_header("Set-Cookie", "server-secret-cookie=do-not-return")
        if type(self).hsts_value is not None:
            self.send_header("Strict-Transport-Security", type(self).hsts_value)
        self.send_header("Content-Length", str(body_size)); self.end_headers()
        try:
            if parts.path == "/api/large": self.wfile.write(b"x" * 1025)
            elif parts.path == "/api/exact-limit": self.wfile.write(b"x" * 1024)
            elif parts.path == "/api/huge":
                for _ in range(128): self.wfile.write(b"x" * 65536)
            else: self.wfile.write(b"ok")
        except OSError:
            self.__class__.closed_early.set()

    def log_message(self, *_):
        pass


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


@pytest.fixture
def local_workspace(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Handler.seen_auth = []
    Handler.seen_cookie = []
    Handler.seen_hosts = []
    Handler.seen_client_ports = []
    Handler.seen_proxy_form = []
    Handler.closed_early = threading.Event()
    Handler.stream_started = threading.Event()
    Handler.stream_release = threading.Event()
    Handler.hsts_value = None
    server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    monkeypatch.setattr(settings, "allow_local_lab", True)
    monkeypatch.setattr(settings, "runner_lab_allow_http", True)
    monkeypatch.setattr(settings, "runner_lab_allowed_ports", str(server.server_port))
    monkeypatch.setattr(settings, "runner_max_response_bytes", 1024)
    monkeypatch.setattr(settings, "runner_read_timeout_seconds", 0.05)
    try:
        with Session(engine) as db:
            analyst = models.Analyst(login_normalized="runner@example.test", password_hash="test")
            db.add(analyst); db.flush()
            client = models.Client(name="Local lab", owner_user_id=analyst.id)
            db.add(client); db.flush()
            assessment = models.Assessment(
                client_id=client.id, name="Local lab", environment="lab",
                authorization_reference="test-only", authorization_confirmed=True,
                allowed_hosts=["127.0.0.1", "localhost"], allowed_paths=["/api/**"],
                excluded_paths=["/api/excluded/**"], max_requests_per_minute=30,
            )
            activate_local_authorization(assessment, analyst.id)
            db.add(assessment); db.commit()
            yield db, assessment, analyst, server.server_port
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2); engine.dispose()


def test_runner_sends_in_scope_request_to_pinned_local_address(local_workspace):
    db, assessment, analyst, port = local_workspace
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok")
    assert result.outcome is RequestOutcome.COMPLETED
    assert result.status_code == 200 and result.body == b"ok"


def test_real_tcp_peer_tls_sni_and_host_header_use_approved_origin(local_workspace, monkeypatch):
    db, assessment, analyst, http_port = local_workspace
    fixtures = Path(__file__).parent / "fixtures" / "tls"
    cert = fixtures / "localhost-cert.pem"
    key = fixtures / "localhost-key.pem"
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certfile=cert, keyfile=key)
    sni_names = []
    tls_context.set_servername_callback(lambda _sock, name, _ctx: sni_names.append(name))
    server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    monkeypatch.setattr(settings, "runner_lab_allowed_ports", f"{http_port},{server.server_port}")

    tcp_peers = []
    backend_type = runner._PinnedBackend

    class RecordingBackend(backend_type):
        def connect_tcp(self, *args, **kwargs):
            stream = super().connect_tcp(*args, **kwargs)
            peer = stream.get_extra_info("socket").getpeername()
            tcp_peers.append(peer)
            return stream

    monkeypatch.setattr(runner, "_PinnedBackend", RecordingBackend)
    Handler.seen_hosts.clear()
    Handler.hsts_value = None
    try:
        result = run_request(db, assessment.id, analyst.id, "GET", f"https://localhost:{server.server_port}/api/ok")
        missing_hsts = REGISTRY["response.header.strict_transport_security"].evaluate(result)
        Handler.hsts_value = "max-age=31536000"
        valid_hsts_transport = run_request(db, assessment.id, analyst.id, "GET", f"https://localhost:{server.server_port}/api/ok")
        valid_hsts = REGISTRY["response.header.strict_transport_security"].evaluate(valid_hsts_transport)
        http_transport = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{http_port}/api/ok")
        http_hsts = REGISTRY["response.header.strict_transport_security"].evaluate(http_transport)
    finally:
        Handler.hsts_value = None
        server.shutdown(); server.server_close(); thread.join(timeout=2)
    assert result.outcome is RequestOutcome.COMPLETED
    assert result.final_scheme == "https"
    assert missing_hsts.outcome is SecurityOutcome.CANDIDATE_FOUND
    assert valid_hsts_transport.final_scheme == "https"
    assert valid_hsts.outcome is SecurityOutcome.NO_ISSUE_OBSERVED
    assert http_transport.final_scheme == "http"
    assert http_hsts.outcome is SecurityOutcome.INCONCLUSIVE
    assert tcp_peers and all(peer[0] == "127.0.0.1" for peer in tcp_peers)
    assert sum(peer[1] == server.server_port for peer in tcp_peers) == 2
    assert sum(peer[1] == http_port for peer in tcp_peers) == 1
    assert sni_names == ["localhost", "localhost"]
    assert f"localhost:{server.server_port}" in Handler.seen_hosts
    successful_requests = len(Handler.seen_hosts)
    invalid_hostname = run_request(db, assessment.id, analyst.id, "GET", f"https://127.0.0.1:{server.server_port}/api/ok")
    assert invalid_hostname.outcome is RequestOutcome.TRANSPORT_ERROR
    assert len(Handler.seen_hosts) == successful_requests


def test_https_downgrade_requires_explicit_lab_http_policy(local_workspace, monkeypatch):
    db, assessment, analyst, http_port = local_workspace
    fixtures = Path(__file__).parent / "fixtures" / "tls"
    cert = fixtures / "localhost-cert.pem"
    key = fixtures / "localhost-key.pem"
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    Handler.downgrade_target_port = http_port
    monkeypatch.setattr(settings, "runner_lab_allowed_ports", f"{http_port},{server.server_port}")
    try:
        url = f"https://localhost:{server.server_port}/api/downgrade"
        monkeypatch.setattr(settings, "runner_lab_allow_http", False)
        blocked = run_request(db, assessment.id, analyst.id, "GET", url)
        assert blocked.outcome is RequestOutcome.BLOCKED_SCOPE
        monkeypatch.setattr(settings, "runner_lab_allow_http", True)
        permitted_lab = run_request(db, assessment.id, analyst.id, "GET", url)
        assert permitted_lab.outcome is RequestOutcome.COMPLETED
        assert permitted_lab.redirect_count == 1
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_connection_pools_are_not_shared_between_assessment_policies(local_workspace):
    db, assessment, analyst, port = local_workspace
    second = models.Assessment(
        client_id=assessment.client_id, name="Second policy", environment="lab",
        authorization_reference="test-only", authorization_confirmed=True,
        allowed_hosts=["127.0.0.1"], allowed_paths=["/api/**"],
        max_requests_per_minute=30,
    )
    activate_local_authorization(second, analyst.id)
    db.add(second); db.commit(); db.refresh(second)
    Handler.seen_client_ports.clear()
    one = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok")
    two = run_request(db, second.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok")
    assert one.outcome is two.outcome is RequestOutcome.COMPLETED
    assert len(Handler.seen_client_ports) == 2
    assert Handler.seen_client_ports[0] != Handler.seen_client_ports[1]


def test_dns_change_after_validation_cannot_change_the_pinned_connection(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace

    calls = []
    dns_changed = False

    def answers(host, target_port, *args, **kwargs):
        nonlocal dns_changed
        calls.append(host)
        if host == "localhost":
            if len([entry for entry in calls if entry == "localhost"]) == 2:
                dns_changed = True
            return [(2, 1, 6, "", ("127.0.0.1", target_port))]
        if host == "127.0.0.1" and dns_changed:
            return [(2, 1, 6, "", ("10.0.0.9", target_port))]
        raise AssertionError(f"Transport unexpectedly resolved {host!r} after DNS pinning")

    monkeypatch.setattr(runner.socket, "getaddrinfo", answers)
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://localhost:{port}/api/ok")
    assert result.outcome is RequestOutcome.COMPLETED
    assert calls.count("localhost") == 2
    assert "127.0.0.1" not in calls


def test_dns_answer_change_to_private_ip_is_blocked_before_connection(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace

    calls = []

    def changing_answers(host, target_port, *args, **kwargs):
        if host == "localhost":
            calls.append(host)
            address = "127.0.0.1" if len(calls) == 1 else "10.0.0.9"
            return [(2, 1, 6, "", (address, target_port))]
        raise AssertionError("The transport must not independently resolve the origin hostname")

    monkeypatch.setattr(runner.socket, "getaddrinfo", changing_answers)
    Handler.seen_auth.clear()
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://localhost:{port}/api/ok")
    assert result.outcome is RequestOutcome.BLOCKED_DESTINATION
    assert calls == ["localhost", "localhost"]
    assert Handler.seen_auth == []


@pytest.mark.parametrize("url,method", [
    ("http://127.0.0.1:1/api/ok", "POST"),
    ("https://127.0.0.1/api/ok", "CONNECT"),
    ("http://user:pass@127.0.0.1/api/ok", "GET"),
    ("http://127.0.0.1/api/excluded/x", "GET"),
    ("http://127.0.0.1/api/%2e%2e/admin", "GET"),
    ("http://outside.example/api/ok", "GET"),
])
def test_scope_method_and_url_constraints_block_before_connection(local_workspace, url, method):
    db, assessment, analyst, _ = local_workspace
    result = run_request(db, assessment.id, analyst.id, method, url)
    assert result.outcome is RequestOutcome.BLOCKED_SCOPE


def test_http_requires_lab_exception_and_production_mode_disallows_it(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace
    monkeypatch.setattr(settings, "runner_lab_allow_http", False)
    assert run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok").outcome is RequestOutcome.BLOCKED_SCOPE
    monkeypatch.setattr(settings, "allow_local_lab", False)
    assert run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok").outcome is RequestOutcome.BLOCKED_SCOPE


def test_redirect_scope_loop_and_hop_limit(local_workspace):
    db, assessment, analyst, port = local_workspace
    outside = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/redirect-out")
    assert outside.outcome is RequestOutcome.BLOCKED_SCOPE
    assert REGISTRY["response.header.strict_transport_security"].evaluate(outside).outcome is SecurityOutcome.NOT_RUN
    loop = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/redirect-loop")
    assert loop.outcome is RequestOutcome.TRANSPORT_ERROR
    assert "hop limit" in loop.detail.lower()
    relative = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/redirect-relative")
    assert relative.outcome is RequestOutcome.COMPLETED and relative.redirect_count == 1
    redirected_check = REGISTRY["response.header.content_type_options"].evaluate(relative)
    assert redirected_check.outcome is SecurityOutcome.CANDIDATE_FOUND
    assert relative.final_scheme == "http"
    assert REGISTRY["response.header.strict_transport_security"].evaluate(relative).outcome is SecurityOutcome.INCONCLUSIVE
    assert Handler.closed_early.wait(2), "Intermediate redirect body was not closed when discarded"
    absolute = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/redirect-absolute")
    assert absolute.outcome is RequestOutcome.COMPLETED and absolute.redirect_count == 1
    assert REGISTRY["response.header.content_type_options"].evaluate(absolute).outcome is SecurityOutcome.CANDIDATE_FOUND


def test_redirect_to_prohibited_dns_address_is_blocked(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace
    assessment.allowed_hosts = [*assessment.allowed_hosts, "api.client.example"]
    activate_local_authorization(assessment, analyst.id)
    db.commit()
    original = socket.getaddrinfo

    def answers(host, target_port, *args, **kwargs):
        if host == "api.client.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.9", target_port))]
        return original(host, target_port, *args, **kwargs)

    monkeypatch.setattr(runner.socket, "getaddrinfo", answers)
    Handler.seen_hosts.clear()
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/redirect-private")
    assert result.outcome is RequestOutcome.BLOCKED_DESTINATION
    assert len(Handler.seen_hosts) == 1


def test_authorization_is_reloaded_before_each_redirect(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace
    original = runner._PinnedTransport.handle_request
    calls = 0

    def revoke_after_first_request(self, request):
        nonlocal calls
        response = original(self, request)
        calls += 1
        if calls == 1:
            assessment.authorization_status = "REVOKED"
            assessment.authorization_confirmed = False
            assessment.authorization_revoked_at = models.now()
            db.commit()
        return response

    monkeypatch.setattr(runner._PinnedTransport, "handle_request", revoke_after_first_request)
    Handler.seen_hosts.clear()
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/redirect-relative")
    assert result.outcome is RequestOutcome.BLOCKED_SCOPE
    assert result.redirect_count == 1
    assert len(Handler.seen_hosts) == 1


def test_environment_proxy_settings_cannot_redirect_pinned_transport(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    Handler.seen_proxy_form.clear()
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok")
    assert result.outcome is RequestOutcome.COMPLETED
    assert Handler.seen_proxy_form == [False]


def test_redirect_origin_change_strips_bearer_credentials(local_workspace, caplog):
    db, assessment, analyst, port = local_workspace

    class Resolver:
        def resolve_bearer(self, reference, *, analyst_id, assessment_id):
            assert reference == "vault://test/token"
            assert analyst_id == analyst.id and assessment_id == assessment.id
            return "test-secret-token"

    class TestCredentialAdapter(BearerTokenReference):
        def headers(self, *, url, policy):
            return {**super().headers(url=url, policy=policy), "Cookie": "session=private-cookie"}

    Handler.seen_auth.clear()
    Handler.seen_cookie.clear()
    with caplog.at_level(logging.DEBUG):
        result = run_request(
            db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/redirect-origin",
            headers={"Cookie": "untrusted-request-cookie", "Authorization": "untrusted-token"},
            auth=TestCredentialAdapter("vault://test/token", Resolver()),
        )
    assert result.outcome is RequestOutcome.COMPLETED
    assert Handler.seen_auth == ["Bearer test-secret-token", None]
    assert Handler.seen_cookie == ["session=private-cookie", None]
    assert "test-secret-token" not in result.detail
    assert "test-secret-token" not in caplog.text
    assert "private-cookie" not in caplog.text
    assert all("set-cookie" not in header.lower() for header in (result.headers or {}))


def test_unavailable_bearer_reference_fails_without_request(local_workspace, caplog):
    db, assessment, analyst, port = local_workspace

    class MissingResolver:
        def resolve_bearer(self, *_args, **_kwargs):
            raise RuntimeError("never disclose secret backend detail")

    Handler.seen_auth.clear()
    with caplog.at_level(logging.DEBUG):
        result = run_request(
            db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok",
            auth=BearerTokenReference("vault://missing", MissingResolver()),
        )
    assert result.outcome is RequestOutcome.AUTH_UNAVAILABLE
    assert "never disclose" not in result.detail
    assert "never disclose" not in caplog.text
    assert Handler.seen_auth == []


def test_missing_or_blank_written_authorization_blocks_before_network(local_workspace):
    db, assessment, analyst, port = local_workspace
    Handler.seen_hosts.clear()
    assessment.authorization_reference = "   "
    db.commit()
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok")
    assert result.outcome is RequestOutcome.BLOCKED_SCOPE
    assert Handler.seen_hosts == []


def test_cancellation_is_distinct_and_sends_no_request(local_workspace):
    db, assessment, analyst, port = local_workspace
    Handler.seen_auth.clear()
    cancelled = threading.Event(); cancelled.set()
    result = run_request(
        db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok", cancelled=cancelled,
    )
    assert result.outcome is RequestOutcome.CANCELLED
    assert Handler.seen_auth == []


def test_cancellation_during_stream_closes_response(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace
    assessment_id = assessment.id
    analyst_id = analyst.id
    cancelled = threading.Event()
    result_box = []
    stream_closed = threading.Event()
    original_close = runner._CoreByteStream.close

    def tracked_close(stream):
        stream_closed.set()
        return original_close(stream)

    monkeypatch.setattr(runner._CoreByteStream, "close", tracked_close)
    worker = threading.Thread(target=lambda: result_box.append(run_request(
        db, assessment_id, analyst_id, "GET", f"http://127.0.0.1:{port}/api/cancel-stream", cancelled=cancelled,
    )))
    worker.start()
    assert Handler.stream_started.wait(2)
    cancelled.set()
    Handler.stream_release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert result_box[0].outcome is RequestOutcome.CANCELLED
    assert stream_closed.wait(1)


def test_limits_timeouts_connection_errors_and_assessment_ownership(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace
    oversized = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/large")
    assert oversized.outcome is RequestOutcome.OVERSIZED_RESPONSE
    timeout = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/slow")
    assert timeout.outcome is RequestOutcome.TIMEOUT
    monkeypatch.setattr(runner._PinnedBackend, "connect_tcp", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("deliberate transport error")))
    failed = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/ok")
    assert failed.outcome is RequestOutcome.TRANSPORT_ERROR
    assert run_request(db, assessment.id, analyst.id + 999, "GET", f"http://127.0.0.1:{port}/api/ok").outcome is RequestOutcome.BLOCKED_SCOPE


def test_registered_check_budgets_cap_response_time_and_redirects(local_workspace):
    db, assessment, analyst, port = local_workspace
    policy = RequestPolicy.from_assessment(
        assessment, analyst.id, allow_local_lab=True,
        max_duration_seconds=2, max_response_bytes=128, max_redirects=0,
    )
    assert policy.total_timeout == 2
    assert policy.max_response_bytes == 128
    assert policy.max_redirects == 0

    oversized = run_request(db, assessment.id, analyst.id, "GET",
                            f"http://127.0.0.1:{port}/api/large",
                            max_duration_seconds=2, max_response_bytes=128, max_redirects=0)
    assert oversized.outcome is RequestOutcome.OVERSIZED_RESPONSE

    redirected = run_request(db, assessment.id, analyst.id, "GET",
                             f"http://127.0.0.1:{port}/api/redirect-out",
                             max_duration_seconds=2, max_response_bytes=128, max_redirects=0)
    assert redirected.outcome is RequestOutcome.TRANSPORT_ERROR
    assert redirected.redirect_count == 0


def test_compressed_expansion_and_malformed_content_are_rejected_before_decode(local_workspace):
    db, assessment, analyst, port = local_workspace
    base = f"http://127.0.0.1:{port}/api"
    exact = run_request(db, assessment.id, analyst.id, "GET", f"{base}/exact-limit")
    assert exact.outcome is RequestOutcome.COMPLETED and len(exact.body) == 1024
    compressed = run_request(db, assessment.id, analyst.id, "GET", f"{base}/gzip")
    assert compressed.outcome is RequestOutcome.TRANSPORT_ERROR
    assert "compressed" in compressed.detail.lower()
    malformed = run_request(db, assessment.id, analyst.id, "GET", f"{base}/bad-gzip")
    assert malformed.outcome is RequestOutcome.TRANSPORT_ERROR


def test_oversized_response_closes_stream_without_unbounded_fallback(local_workspace):
    db, assessment, analyst, port = local_workspace
    Handler.closed_early.clear()
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/huge")
    assert result.outcome is RequestOutcome.OVERSIZED_RESPONSE
    assert len(result.body) == 0
    assert Handler.closed_early.wait(2), "Oversized response stream was not closed promptly"


def test_rate_and_concurrency_limits_are_enforced_before_transport(local_workspace, monkeypatch):
    db, assessment, analyst, port = local_workspace
    monkeypatch.setattr(settings, "max_requests_per_minute", 1)
    url = f"http://127.0.0.1:{port}/api/ok"
    assert run_request(db, assessment.id, analyst.id, "GET", url).outcome is RequestOutcome.COMPLETED
    limited = run_request(db, assessment.id, analyst.id, "GET", url)
    assert limited.outcome is RequestOutcome.BLOCKED_SCOPE
    assert "rate" in limited.detail.lower()
    monkeypatch.setattr(settings, "max_requests_per_minute", 10)
    now = models.now()
    limiter_state = db.get(models.ExecutionLimiterState, assessment.id)
    if limiter_state is None:
        db.add(models.ExecutionLimiterState(assessment_id=assessment.id, touched_at=now))
    else:
        limiter_state.touched_at = now
    db.add_all([models.ExecutionReservation(assessment_id=assessment.id, requested_at=now,
                                            expires_at=now + timedelta(minutes=2))
                for _ in range(settings.runner_max_concurrency)])
    db.commit()
    # A separate ORM session models another worker using the same database.
    with Session(bind=db.get_bind()) as other_worker_db:
        concurrent = run_request(other_worker_db, assessment.id, analyst.id, "GET", url)
    assert concurrent.outcome is RequestOutcome.BLOCKED_SCOPE
    assert "concurrency" in concurrent.detail.lower()


def test_prohibited_dns_answers_and_policy_bounds(local_workspace, monkeypatch):
    db, assessment, analyst, _ = local_workspace
    monkeypatch.setattr(settings, "allow_local_lab", False)
    assessment.allowed_hosts = ["api.client.example"]
    activate_local_authorization(assessment, analyst.id)
    monkeypatch.setattr("apisentinel.runner.socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.4", 443))])
    result = run_request(db, assessment.id, analyst.id, "GET", "https://api.client.example/api/x")
    assert result.outcome is RequestOutcome.BLOCKED_DESTINATION
    policy = RequestPolicy.from_assessment(assessment, analyst.id)
    assert policy.verify_tls is True
    assert policy.allowed_methods == frozenset({"GET", "HEAD", "OPTIONS"})
    assert policy.max_redirects <= 3 and policy.max_concurrency <= 4


def test_configured_egress_cidr_blocks_global_addresses_outside_allowlist(local_workspace, monkeypatch):
    _db, assessment, analyst, _ = local_workspace
    assessment.allowed_hosts = ["api.client.example"]
    activate_local_authorization(assessment, analyst.id)
    monkeypatch.setattr("apisentinel.runner.socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    policy = RequestPolicy.from_assessment(assessment, analyst.id)
    policy = policy.__class__(**{**policy.__dict__, "egress_allowed_cidrs": ("198.51.100.0/24",)})
    with pytest.raises(RunnerBlocked, match="egress allowlist"):
        _validate_url(assessment, policy, "GET", "https://api.client.example/api/x")


def test_local_lab_exceptions_cannot_be_enabled_in_production():
    base = {"environment": "production", "cookie_secure": True, "cors_origins": "https://dashboard.example",
            "runner_egress_allowed_cidrs": "203.0.113.0/24", "credential_encryption_provider": "aws_kms",
            "credential_kms_key_id": "alias/test", "credential_kms_region": "us-east-1",
            "apk_parser_url": "http://apk-parser:8090", "database_url": "postgresql+psycopg://localhost/test"}
    with pytest.raises(ValueError, match="ALLOW_LOCAL_LAB"):
        Settings(**base, allow_local_lab=True)
    with pytest.raises(ValueError, match="LAB_ALLOW_HTTP"):
        Settings(**base, runner_lab_allow_http=True)


def test_incomplete_response_is_not_completed(local_workspace):
    db, assessment, analyst, port = local_workspace
    result = run_request(db, assessment.id, analyst.id, "GET", f"http://127.0.0.1:{port}/api/interrupted")
    assert result.outcome is RequestOutcome.TRANSPORT_ERROR
