"""Bounded, scope-checked HTTP transport foundation; this module does not run security checks."""
from __future__ import annotations

import ipaddress
import queue
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpcore
import httpx
from fastapi import HTTPException
from httpcore._backends.sync import SyncBackend, SyncStream
from httpx._transports.default import map_httpcore_exceptions
from sqlalchemy import or_

from . import models
from .access import client_access_filter
from .authorization import authorization_allows
from .safety import validate_target

if httpx.__version__ != "0.28.1" or httpcore.__version__ != "1.0.9":
    raise RuntimeError("Pinned runner requires httpx==0.28.1 and httpcore==1.0.9")

_DNS_LOOKUP_SLOTS = threading.BoundedSemaphore(8)


class RequestOutcome(StrEnum):
    SKIPPED = "SKIPPED"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_DESTINATION = "BLOCKED_DESTINATION"
    COMPLETED = "COMPLETED"
    OVERSIZED_RESPONSE = "OVERSIZED_RESPONSE"
    TIMEOUT = "TIMEOUT"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    CANCELLED = "CANCELLED"
    AUTH_UNAVAILABLE = "AUTH_UNAVAILABLE"


@dataclass(frozen=True)
class RequestPolicy:
    analyst_id: int
    assessment_id: int
    allowed_methods: frozenset[str]
    allowed_schemes: frozenset[str]
    allowed_hosts: frozenset[str]
    allowed_ports: frozenset[int]
    allowed_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    connect_timeout: float = 3.0
    read_timeout: float = 5.0
    write_timeout: float = 5.0
    pool_timeout: float = 2.0
    total_timeout: float = 90.0
    max_response_bytes: int = 1_000_000
    requests_per_minute: int = 30
    max_concurrency: int = 2
    max_redirects: int = 3
    verify_tls: bool = True
    allow_local_lab: bool = False
    egress_allowed_cidrs: tuple[str, ...] = ()

    @classmethod
    def from_assessment(cls, assessment: models.Assessment, analyst_id: int, *, allow_local_lab: bool = False,
                        max_duration_seconds: float | None = None,
                        max_response_bytes: int | None = None,
                        max_redirects: int | None = None) -> RequestPolicy:
        from .config import settings

        return cls(
            analyst_id=analyst_id,
            assessment_id=assessment.id,
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}) & frozenset(assessment.authorization_methods or []),
            allowed_schemes=frozenset({"https", "http"} if allow_local_lab and settings.allow_local_lab and settings.runner_lab_allow_http and assessment.environment.lower() in {"development", "lab"} else {"https"}),
            allowed_hosts=frozenset(_normalized_host(host) for host in (assessment.allowed_hosts or [])),
            allowed_ports=frozenset({443} | (set(settings.lab_allowed_ports) if allow_local_lab and settings.allow_local_lab and assessment.environment.lower() in {"development", "lab"} else set())),
            allowed_paths=tuple(assessment.allowed_paths or ["/**"]),
            excluded_paths=tuple(assessment.excluded_paths or []),
            connect_timeout=settings.runner_connect_timeout_seconds,
            read_timeout=settings.runner_read_timeout_seconds,
            write_timeout=settings.runner_write_timeout_seconds,
            pool_timeout=settings.runner_pool_timeout_seconds,
            total_timeout=min(settings.runner_total_timeout_seconds, max_duration_seconds) if max_duration_seconds else settings.runner_total_timeout_seconds,
            max_response_bytes=min(settings.runner_max_response_bytes, max_response_bytes) if max_response_bytes else settings.runner_max_response_bytes,
            requests_per_minute=max(1, min(assessment.max_requests_per_minute, settings.max_requests_per_minute, 60)),
            max_concurrency=settings.runner_max_concurrency,
            max_redirects=min(settings.runner_max_redirects, max_redirects) if max_redirects is not None else settings.runner_max_redirects,
            allow_local_lab=allow_local_lab and settings.allow_local_lab and assessment.environment.lower() in {"development", "lab"},
            egress_allowed_cidrs=tuple(str(network) for network in settings.egress_allowed_networks),
        )


class SecretResolver(Protocol):
    def resolve_bearer(self, reference: str, *, analyst_id: int, assessment_id: int) -> str: ...


class AuthAdapter(Protocol):
    def headers(self, *, url: str, policy: RequestPolicy) -> dict[str, str]: ...


class NoAuth:
    def headers(self, *, url: str, policy: RequestPolicy) -> dict[str, str]:
        return {}


@dataclass(frozen=True)
class BearerTokenReference:
    reference: str
    resolver: SecretResolver

    def headers(self, *, url: str, policy: RequestPolicy) -> dict[str, str]:
        token = self.resolver.resolve_bearer(self.reference, analyst_id=policy.analyst_id, assessment_id=policy.assessment_id)
        if not token or "\r" in token or "\n" in token:
            raise AuthenticationUnavailable("Bearer token reference could not be resolved")
        return {"Authorization": f"Bearer {token}"}


@dataclass(frozen=True)
class RunnerResult:
    outcome: RequestOutcome
    status_code: int | None = None
    headers: dict[str, str] | None = None
    body: bytes = b""
    redirect_count: int = 0
    detail: str = ""
    final_scheme: str | None = None
    # Evaluator-only metadata for bounded multi-request checks. This context is
    # never serialized by the runner; callers must reduce it to safe evidence.
    check_context: dict | None = None


def _safe_response_headers(headers: httpx.Headers) -> dict[str, str]:
    # Keep only bounded security-relevant metadata. Cookie values are never
    # copied into run records; retain cookie names and flag names only.
    allowed = ("content-type", "content-length", "x-content-type-options",
               "strict-transport-security", "access-control-allow-origin",
               "access-control-allow-credentials", "access-control-allow-methods",
               "access-control-allow-headers", "access-control-expose-headers",
               "access-control-max-age", "vary", "cache-control", "pragma",
               "expires")
    result = {key: headers.get(key, "")[:2048] for key in allowed if key in headers}
    cookies = []
    for raw in headers.get_list("set-cookie")[:20]:
        parts = [part.strip() for part in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip()[:128] if parts else ""
        flags = [part.split("=", 1)[0].strip().lower() for part in parts[1:]
                 if part.split("=", 1)[0].strip().lower() in {"secure", "httponly", "samesite", "partitioned"}]
        if name:
            cookies.append(name + (";" + ";".join(sorted(set(flags))) if flags else ""))
    if cookies:
        result["cookie-metadata"] = "\n".join(cookies)
    return result


class RunnerBlocked(Exception):
    def __init__(self, outcome: RequestOutcome, detail: str):
        super().__init__(detail)
        self.outcome = outcome
        self.detail = detail


class AuthenticationUnavailable(Exception):
    """A server-side secret reference could not be resolved safely."""


def _acquire(db, policy: RequestPolicy) -> int:
    """Reserve shared DB-backed rate/concurrency capacity; never fall back locally."""
    now = models.now()
    try:
        state = (db.query(models.ExecutionLimiterState)
                 .filter_by(assessment_id=policy.assessment_id).with_for_update().first())
        if state is None:
            state = models.ExecutionLimiterState(assessment_id=policy.assessment_id, touched_at=now)
            db.add(state)
            db.flush()
        else:
            state.touched_at = now  # SQLite obtains a write lock here; row lock serializes PostgreSQL callers.
            db.flush()
        cutoff = now - timedelta(seconds=60)
        db.query(models.ExecutionReservation).filter(
            models.ExecutionReservation.requested_at <= cutoff,
            or_(models.ExecutionReservation.released_at.is_not(None),
                models.ExecutionReservation.expires_at <= now),
        ).delete(synchronize_session=False)
        requests = db.query(models.ExecutionReservation).filter(
            models.ExecutionReservation.assessment_id == policy.assessment_id,
            models.ExecutionReservation.requested_at > cutoff,
        ).count()
        active = db.query(models.ExecutionReservation).filter(
            models.ExecutionReservation.assessment_id == policy.assessment_id,
            models.ExecutionReservation.released_at.is_(None),
            models.ExecutionReservation.expires_at > now,
        ).count()
        if requests >= policy.requests_per_minute:
            db.rollback()
            raise RunnerBlocked(RequestOutcome.BLOCKED_SCOPE, "Assessment request-rate limit reached")
        if active >= policy.max_concurrency:
            db.rollback()
            raise RunnerBlocked(RequestOutcome.BLOCKED_SCOPE, "Assessment concurrency limit reached")
        reservation = models.ExecutionReservation(
            assessment_id=policy.assessment_id,
            requested_at=now,
            expires_at=now + timedelta(seconds=policy.total_timeout + policy.connect_timeout + policy.read_timeout + 10),
        )
        db.add(reservation)
        db.commit()
        return reservation.id
    except RunnerBlocked:
        raise
    except Exception:  # noqa: BLE001 - DB errors must fail closed without exposing details.
        db.rollback()
        raise RunnerBlocked(RequestOutcome.BLOCKED_SCOPE, "Shared execution limits are unavailable") from None


def _release(db, reservation_id: int) -> None:
    try:
        reservation = db.get(models.ExecutionReservation, reservation_id)
        if reservation is not None and reservation.released_at is None:
            reservation.released_at = models.now()
            db.commit()
    except Exception:  # noqa: BLE001 - expiry bounds recovery after a process/database failure.
        db.rollback()


def _normalized_host(host: str) -> str:
    return host.rstrip(".").encode("idna").decode("ascii").lower()


def _origin_key(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if not parsed.hostname:
        raise ValueError("Redirect URL has no hostname")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    return parsed.scheme.lower(), host, parsed.port or (443 if parsed.scheme.lower() == "https" else 80)


def _resolve_addresses(host: str, port: int, deadline: float | None) -> list:
    if deadline is None:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _DNS_LOOKUP_SLOTS.acquire(timeout=max(0.0, remaining)):
        raise RunnerBlocked(RequestOutcome.TIMEOUT, "Total request time limit reached during destination resolution")
    result_queue: queue.Queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result_queue.put_nowait((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except Exception as exc:  # noqa: BLE001 - resolver details are not exposed.
            try:
                result_queue.put_nowait((False, exc))
            except queue.Full:
                pass
        finally:
            _DNS_LOOKUP_SLOTS.release()

    try:
        threading.Thread(target=resolve, name="apisentinel-dns", daemon=True).start()
    except RuntimeError:
        _DNS_LOOKUP_SLOTS.release()
        raise RunnerBlocked(RequestOutcome.BLOCKED_DESTINATION, "Destination resolution could not be started") from None
    try:
        succeeded, result = result_queue.get(timeout=max(0.0, deadline - time.monotonic()))
    except queue.Empty:
        raise RunnerBlocked(RequestOutcome.TIMEOUT, "Total request time limit reached during destination resolution") from None
    if time.monotonic() >= deadline:
        raise RunnerBlocked(RequestOutcome.TIMEOUT, "Total request time limit reached during destination resolution")
    if succeeded:
        return result
    if isinstance(result, OSError):
        raise result
    raise OSError("Destination resolution failed")


def _validate_url(assessment: models.Assessment, policy: RequestPolicy, method: str, url: str,
                  *, deadline: float | None = None) -> tuple[str, int, tuple[str, ...]]:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in policy.allowed_schemes:
            raise ValueError
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError
        host = _normalized_host(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port not in policy.allowed_ports:
            raise ValueError
        if parsed.fragment:
            parsed = parsed._replace(fragment="")
        clean_url = urlunsplit(parsed)
    except (ValueError, UnicodeError):
        raise RunnerBlocked(RequestOutcome.BLOCKED_SCOPE, "Malformed or prohibited URL") from None
    if method.upper() not in policy.allowed_methods:
        raise RunnerBlocked(RequestOutcome.BLOCKED_SCOPE, "HTTP method is not allowed by assessment policy")
    if policy.allow_local_lab:
        lab_names = {"localhost", "127.0.0.1", "::1"}
        if host not in lab_names:
            # Other explicitly scoped names still require public addresses.
            pass
    try:
        validate_target(assessment, clean_url, allow_http=policy.allow_local_lab, method=method)
    except HTTPException:
        raise RunnerBlocked(RequestOutcome.BLOCKED_SCOPE, "Target is outside the authorized assessment scope") from None
    try:
        infos = _resolve_addresses(host, port, deadline)
    except OSError:
        raise RunnerBlocked(RequestOutcome.BLOCKED_DESTINATION, "Destination could not be resolved") from None
    addresses = tuple(sorted({info[4][0].split("%", 1)[0] for info in infos}))
    if not addresses:
        raise RunnerBlocked(RequestOutcome.BLOCKED_DESTINATION, "Destination has no usable addresses")
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            raise RunnerBlocked(RequestOutcome.BLOCKED_DESTINATION, "Destination resolution returned an invalid address") from None
        if not address.is_global and not (policy.allow_local_lab and host in {"localhost", "127.0.0.1", "::1"} and address.is_loopback):
            raise RunnerBlocked(RequestOutcome.BLOCKED_DESTINATION, "Destination resolves to a prohibited IP address")
        if policy.egress_allowed_cidrs:
            permitted = False
            for cidr in policy.egress_allowed_cidrs:
                try:
                    network = ipaddress.ip_network(cidr, strict=True)
                except ValueError:
                    raise RunnerBlocked(RequestOutcome.BLOCKED_DESTINATION, "Egress policy is invalid") from None
                if address.version == network.version and address in network:
                    permitted = True
                    break
            if not permitted:
                raise RunnerBlocked(RequestOutcome.BLOCKED_DESTINATION, "Destination is outside the configured egress allowlist")
    return host, port, addresses


class _PinnedBackend(SyncBackend):
    """Connect only to the addresses approved for this request; TLS still uses origin hostname."""
    def __init__(self, approved: dict[tuple[str, int], tuple[str, ...]]):
        self.approved = approved

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        key = (_normalized_host(host), port)
        addresses = self.approved.get(key)
        if not addresses:
            raise OSError("Unapproved connection destination")
        last_error = None
        for ip in addresses:
            sock = None
            try:
                address = ipaddress.ip_address(ip)
                family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if local_address is not None:
                    local_ip = ipaddress.ip_address(local_address)
                    if local_ip.version != address.version:
                        raise OSError("Local bind address family does not match destination")
                    sock.bind((str(local_ip), 0))
                for option in socket_options or ():
                    sock.setsockopt(*option)
                sockaddr = (str(address), port, 0, 0) if address.version == 6 else (str(address), port)
                sock.connect(sockaddr)
                peer = ipaddress.ip_address(sock.getpeername()[0].split("%", 1)[0])
                if str(peer) != str(ipaddress.ip_address(ip)):
                    raise OSError("Connected peer does not match approved destination")
                return SyncStream(sock)
            except OSError as exc:
                last_error = exc
                if sock is not None:
                    sock.close()
        raise last_error or OSError("Unable to connect to approved destination")


class _CoreByteStream(httpx.SyncByteStream):
    def __init__(self, stream): self.stream = stream
    def __iter__(self):
        with map_httpcore_exceptions():
            yield from self.stream
    def close(self):
        self.stream.close()


class _PinnedTransport(httpx.BaseTransport):
    def __init__(self, approved: dict[tuple[str, int], tuple[str, ...]], timeout: httpx.Timeout):
        context = ssl.create_default_context()
        self.pool = httpcore.ConnectionPool(ssl_context=context, max_connections=1, max_keepalive_connections=0, retries=0, network_backend=_PinnedBackend(approved))
        self.timeout = timeout

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=str(request.url),
            headers=request.headers.raw,
            content=request.stream,
            extensions={"timeout": {"connect": self.timeout.connect, "read": self.timeout.read, "write": self.timeout.write, "pool": self.timeout.pool}},
        )
        with map_httpcore_exceptions():
            response = self.pool.handle_request(core_request)
        return httpx.Response(response.status, headers=response.headers, stream=_CoreByteStream(response.stream), extensions=response.extensions, request=request)

    def close(self): self.pool.close()


def run_request(
    db,
    assessment_id: int,
    analyst_id: int,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    auth: AuthAdapter | None = None,
    cancelled: threading.Event | None = None,
    max_duration_seconds: float | None = None,
    max_response_bytes: int | None = None,
    max_redirects: int | None = None,
) -> RunnerResult:
    """Issue one bounded request after reloading owner, authorization, scope and DNS."""
    assessment = db.query(models.Assessment).populate_existing().join(models.Client).filter(
        models.Assessment.id == assessment_id, client_access_filter(analyst_id, ("analyst",)),
    ).first()
    if assessment is None:
        return RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="Assessment not found")
    if not authorization_allows(assessment, method):
        return RunnerResult(RequestOutcome.BLOCKED_SCOPE, detail="A current reviewed authorization for this method and scope is required")
    from .config import settings

    effective = RequestPolicy.from_assessment(
        assessment, analyst_id, allow_local_lab=settings.allow_local_lab,
        max_duration_seconds=max_duration_seconds, max_response_bytes=max_response_bytes,
        max_redirects=max_redirects,
    )
    authorization_version = assessment.authorization_version
    authorization_hash = assessment.authorization_scope_hash
    reservation_id = None
    try:
        current_method = method.upper()
        request_deadline = time.monotonic() + effective.total_timeout
        reservation_id = _acquire(db, effective)
        if time.monotonic() >= request_deadline:
            return RunnerResult(RequestOutcome.TIMEOUT, detail="Total request time limit reached")
        _validate_url(assessment, effective, current_method, url, deadline=request_deadline)
        request_headers = {k: v for k, v in (headers or {}).items() if k.lower() not in {"host", "proxy-authorization", "authorization", "cookie"}}
        request_headers["Accept-Encoding"] = "identity"
        credential_origin = _origin_key(url)
        credentials_allowed = auth is not None
        current_url = url
        redirects = 0
        while True:
            if time.monotonic() >= request_deadline:
                return RunnerResult(RequestOutcome.TIMEOUT, redirect_count=redirects, detail="Total request time limit reached")
            if cancelled and cancelled.is_set():
                return RunnerResult(RequestOutcome.CANCELLED, redirect_count=redirects)
            # The API commits its TestRun/start audit before entering the runner.
            # Release any read snapshot and reload authorization before each
            # hop so revocation or a scope change stops the next transmission.
            db.rollback()
            assessment = (db.query(models.Assessment).populate_existing().join(models.Client).filter(
                models.Assessment.id == assessment_id, client_access_filter(analyst_id, ("analyst",)),
            ).first())
            if (assessment is None or assessment.authorization_version != authorization_version
                    or assessment.authorization_scope_hash != authorization_hash
                    or not authorization_allows(assessment, current_method)):
                return RunnerResult(RequestOutcome.BLOCKED_SCOPE, redirect_count=redirects,
                                    detail="Authorization changed or is no longer current")
            effective = RequestPolicy.from_assessment(
                assessment, analyst_id, allow_local_lab=settings.allow_local_lab,
                max_duration_seconds=max_duration_seconds, max_response_bytes=max_response_bytes,
                max_redirects=max_redirects,
            )
            if credentials_allowed and auth is not None:
                try:
                    request_headers = {k: v for k, v in request_headers.items() if k.lower() != "authorization"}
                    request_headers.update(auth.headers(url=current_url, policy=effective))
                except Exception:  # noqa: BLE001 - adapter errors may contain secrets.
                    return RunnerResult(RequestOutcome.AUTH_UNAVAILABLE, redirect_count=redirects,
                                        detail="Authentication reference unavailable; no request was sent")
            host, port, addresses = _validate_url(
                assessment, effective, current_method, current_url, deadline=request_deadline,
            )
            transport = _PinnedTransport({(host, port): addresses}, httpx.Timeout(connect=effective.connect_timeout, read=effective.read_timeout, write=effective.write_timeout, pool=effective.pool_timeout))
            try:
                with httpx.Client(transport=transport, follow_redirects=False, trust_env=False) as client, client.stream(current_method, current_url, headers=request_headers) as response:
                    final_scheme = urlsplit(current_url).scheme.lower()
                    if response.is_redirect and response.headers.get("location"):
                        if redirects >= effective.max_redirects:
                            return RunnerResult(RequestOutcome.TRANSPORT_ERROR, status_code=response.status_code, redirect_count=redirects, detail="Redirect hop limit reached")
                        next_url = urljoin(current_url, response.headers["location"])
                        if _origin_key(next_url) != credential_origin:
                            credentials_allowed = False
                            request_headers = {k: v for k, v in request_headers.items() if k.lower() not in {"authorization", "cookie"}}
                        current_url = next_url
                        redirects += 1
                        continue
                    if response.headers.get("content-encoding", "identity").strip().lower() not in {"", "identity"}:
                        return RunnerResult(RequestOutcome.TRANSPORT_ERROR, status_code=response.status_code, headers=_safe_response_headers(response.headers), redirect_count=redirects, detail="Compressed response encoding is not supported", final_scheme=final_scheme)
                    chunks = []
                    total = 0
                    try:
                        for chunk in response.iter_bytes():
                            if time.monotonic() >= request_deadline:
                                return RunnerResult(RequestOutcome.TIMEOUT, status_code=response.status_code,
                                                    redirect_count=redirects, detail="Total request time limit reached",
                                                    final_scheme=final_scheme)
                            if cancelled and cancelled.is_set():
                                return RunnerResult(RequestOutcome.CANCELLED, status_code=response.status_code, redirect_count=redirects, final_scheme=final_scheme)
                            total += len(chunk)
                            if total > effective.max_response_bytes:
                                return RunnerResult(RequestOutcome.OVERSIZED_RESPONSE, status_code=response.status_code, headers=_safe_response_headers(response.headers), redirect_count=redirects, detail="Decoded response body limit exceeded", final_scheme=final_scheme)
                            chunks.append(chunk)
                    except httpx.ReadTimeout:
                        return RunnerResult(RequestOutcome.TIMEOUT, status_code=response.status_code, redirect_count=redirects, detail="Response read timed out", final_scheme=final_scheme)
                    return RunnerResult(RequestOutcome.COMPLETED, status_code=response.status_code, headers=_safe_response_headers(response.headers), body=b"".join(chunks), redirect_count=redirects, final_scheme=final_scheme)
            except httpx.TimeoutException:
                return RunnerResult(RequestOutcome.TIMEOUT, redirect_count=redirects, detail="Request timed out")
            except (httpx.HTTPError, OSError):
                return RunnerResult(RequestOutcome.TRANSPORT_ERROR, redirect_count=redirects, detail="HTTP transport failed")
            finally:
                transport.close()
    except RunnerBlocked as exc:
        return RunnerResult(exc.outcome, detail=exc.detail)
    except Exception as exc:  # noqa: BLE001 - never expose transport or resolver exception text.
        # Do not include exception text: adapters and transports can contain secrets.
        return RunnerResult(RequestOutcome.TRANSPORT_ERROR, detail=f"Request failed ({type(exc).__name__})")
    finally:
        if reservation_id is not None:
            _release(db, reservation_id)
