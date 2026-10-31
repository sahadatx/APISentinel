import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from hmac import compare_digest

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .db import get_db
from .mfa import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    new_totp_secret,
    provisioning_uri,
    verify_totp,
)
from .models import Analyst, AuthSession

password_hasher = PasswordHash.recommended()
_dummy_password_hash = password_hasher.hash(secrets.token_urlsafe(32))
auth_router = APIRouter(prefix="/auth", tags=["authentication"])
LOGIN_FAILURE_LIMIT = 8
LOGIN_FAILURE_WINDOW = timedelta(minutes=15)
LOGIN_LOCK_DURATION = timedelta(minutes=15)


class LoginRequest(BaseModel):
    login: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    otp: str = Field(default="", max_length=6)
    recovery_code: str = Field(default="", max_length=32)


class MfaCode(BaseModel):
    code: str = Field(pattern=r"^[0-9]{6}$")


class MfaDisable(MfaCode):
    password: str = Field(min_length=1, max_length=1024)


def normalize_login(login: str) -> str:
    return login.strip().casefold()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _unauthorized():
    return HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Session"})


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _record_login_failure(db: Session, analyst: Analyst, now: datetime) -> None:
    window_started = _as_utc(analyst.login_failure_window_started_at)
    if window_started is None or now - window_started >= LOGIN_FAILURE_WINDOW:
        analyst.login_failure_window_started_at = now
        analyst.login_failure_count = 0
    analyst.login_failure_count = min(analyst.login_failure_count + 1, LOGIN_FAILURE_LIMIT)
    if analyst.login_failure_count >= LOGIN_FAILURE_LIMIT:
        analyst.login_locked_until = now + LOGIN_LOCK_DURATION
    try:
        db.commit()
    except Exception:  # noqa: BLE001 - authentication throttling must fail closed.
        db.rollback()
        raise HTTPException(status_code=503, detail="Sign-in is temporarily unavailable") from None


def require_analyst(request: Request, db: Session = Depends(get_db)) -> Analyst:
    raw_token = request.cookies.get(settings.session_cookie_name)
    if not raw_token:
        raise _unauthorized()
    session = db.query(AuthSession).filter_by(token_hash=_hash(raw_token)).first()
    if session is None:
        raise _unauthorized()
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(UTC):
        db.delete(session)
        db.commit()
        raise _unauthorized()
    analyst = db.get(Analyst, session.analyst_id)
    if analyst is None or not analyst.is_active:
        db.delete(session)
        db.commit()
        raise _unauthorized()

    request.state.analyst = analyst
    request.state.auth_session = session
    if request.method.upper() not in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") not in settings.allowed_origins:
            raise HTTPException(status_code=403, detail="Request origin is not allowed")
        csrf_cookie = request.cookies.get(settings.csrf_cookie_name, "")
        csrf_header = request.headers.get("x-csrf-token", "")
        if not csrf_cookie or not csrf_header or not compare_digest(csrf_cookie, csrf_header) or not compare_digest(_hash(csrf_header), session.csrf_token_hash):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
    return analyst


def analyst_from_request(request: Request) -> Analyst:
    analyst = getattr(request.state, "analyst", None)
    if analyst is None:
        raise _unauthorized()
    return analyst


@auth_router.post("/login")
def login(data: LoginRequest, response: Response, db: Session = Depends(get_db)):
    login_name = normalize_login(data.login)
    now = datetime.now(UTC)
    analyst = db.query(Analyst).filter_by(login_normalized=login_name).with_for_update().first()
    if analyst is not None:
        locked_until = _as_utc(analyst.login_locked_until)
        if locked_until and locked_until > now:
            db.rollback()
            raise HTTPException(status_code=401, detail="Invalid login or password")
        if locked_until:
            analyst.login_locked_until = None
    password_hash = analyst.password_hash if analyst else _dummy_password_hash
    try:
        valid_password = password_hasher.verify(data.password, password_hash)
    except UnknownHashError:
        valid_password = False
    if analyst is None or not analyst.is_active or not valid_password:
        if analyst is not None:
            _record_login_failure(db, analyst, now)
        raise HTTPException(status_code=401, detail="Invalid login or password")

    verified_counter = None
    if analyst.mfa_enabled:
        recovered = False
        try:
            secret = decrypt_totp_secret(analyst.mfa_secret_encrypted or "")
            verified_counter = verify_totp(secret, data.otp, last_counter=analyst.mfa_last_counter)
        except (RuntimeError, ValueError):
            verified_counter = None
        if verified_counter is None and data.recovery_code:
            recovery_hash = _hash(data.recovery_code.strip().upper())
            hashes = list(analyst.mfa_recovery_hashes or [])
            for index, saved_hash in enumerate(hashes):
                if compare_digest(saved_hash, recovery_hash):
                    hashes.pop(index)
                    analyst.mfa_recovery_hashes = hashes
                    db.add(models.ExecutionAuditEvent(actor_id=analyst.id, event_type="MFA_RECOVERY_CODE_USED",
                                                      outcome="SUCCESS", metadata_json={"codes_remaining": len(hashes)}))
                    recovered = True
                    break
        if verified_counter is None and not recovered:
            _record_login_failure(db, analyst, now)
            raise HTTPException(status_code=401, detail="Invalid login, password, or authenticator code")

    raw_session = secrets.token_urlsafe(32)
    raw_csrf = secrets.token_urlsafe(32)
    expires_at = now + timedelta(minutes=settings.session_ttl_minutes)
    session = AuthSession(
        analyst_id=analyst.id,
        token_hash=_hash(raw_session),
        csrf_token_hash=_hash(raw_csrf),
        expires_at=expires_at,
    )
    if verified_counter is not None:
        analyst.mfa_last_counter = verified_counter
    analyst.login_failure_count = 0
    analyst.login_failure_window_started_at = None
    analyst.login_locked_until = None
    db.add(session)
    db.commit()

    cookie_options = {
        "secure": settings.cookie_secure,
        "samesite": "lax",
        "path": "/",
        "max_age": settings.session_ttl_minutes * 60,
    }
    response.set_cookie(settings.session_cookie_name, raw_session, httponly=True, **cookie_options)
    response.set_cookie(settings.csrf_cookie_name, raw_csrf, httponly=False, **cookie_options)
    return {"id": analyst.id, "login": analyst.login_normalized, "role": analyst.role, "expires_at": expires_at}


@auth_router.get("/me")
def current_analyst(analyst: Analyst = Depends(require_analyst)):
    return {"id": analyst.id, "login": analyst.login_normalized, "role": analyst.role}


@auth_router.post("/logout")
def logout(request: Request, response: Response, analyst: Analyst = Depends(require_analyst), db: Session = Depends(get_db)):
    del analyst
    session = getattr(request.state, "auth_session", None)
    if session is not None:
        db.delete(session)
        db.commit()
    response.delete_cookie(settings.session_cookie_name, path="/", secure=settings.cookie_secure, httponly=True, samesite="lax")
    response.delete_cookie(settings.csrf_cookie_name, path="/", secure=settings.cookie_secure, httponly=False, samesite="lax")
    return {"logged_out": True}


@auth_router.get("/mfa/status")
def mfa_status(analyst: Analyst = Depends(require_analyst)):
    return {"enabled": bool(analyst.mfa_enabled)}


@auth_router.post("/mfa/enroll")
def mfa_enroll(request: Request, analyst: Analyst = Depends(require_analyst), db: Session = Depends(get_db)):
    if analyst.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    try:
        secret = new_totp_secret()
        analyst.mfa_secret_encrypted = encrypt_totp_secret(secret)
        analyst.mfa_last_counter = None
        db.add(models.ExecutionAuditEvent(actor_id=analyst.id, event_type="MFA_ENROLLMENT_STARTED",
                                          outcome="PENDING", metadata_json={}))
        db.commit()
    except RuntimeError:
        db.rollback()
        raise HTTPException(status_code=503, detail="MFA encryption is not configured") from None
    return {"secret": secret, "provisioning_uri": provisioning_uri(secret, analyst.login_normalized),
            "message": "Store this authenticator secret securely; it is shown only for enrollment."}


@auth_router.post("/mfa/confirm")
def mfa_confirm(data: MfaCode, analyst: Analyst = Depends(require_analyst), db: Session = Depends(get_db)):
    if analyst.mfa_enabled or not analyst.mfa_secret_encrypted:
        raise HTTPException(status_code=409, detail="Start MFA enrollment before confirming it")
    try:
        secret = decrypt_totp_secret(analyst.mfa_secret_encrypted)
    except (RuntimeError, ValueError):
        raise HTTPException(status_code=503, detail="MFA enrollment is unavailable") from None
    counter = verify_totp(secret, data.code)
    if counter is None:
        raise HTTPException(status_code=422, detail="Authenticator code is invalid or expired")
    analyst.mfa_enabled = True
    analyst.mfa_last_counter = counter
    recovery_codes = [secrets.token_hex(12).upper() for _ in range(10)]
    analyst.mfa_recovery_hashes = [_hash(code) for code in recovery_codes]
    db.add(models.ExecutionAuditEvent(actor_id=analyst.id, event_type="MFA_ENABLED",
                                      outcome="SUCCESS", metadata_json={}))
    db.commit()
    return {"enabled": True, "recovery_codes": recovery_codes,
            "message": "Store these one-time recovery codes securely. They are shown only once."}


@auth_router.post("/mfa/disable")
def mfa_disable(data: MfaDisable, request: Request, analyst: Analyst = Depends(require_analyst), db: Session = Depends(get_db)):
    try:
        password_valid = password_hasher.verify(data.password, analyst.password_hash)
        secret = decrypt_totp_secret(analyst.mfa_secret_encrypted or "")
    except (UnknownHashError, RuntimeError, ValueError):
        password_valid = False
        secret = ""
    counter = verify_totp(secret, data.code, last_counter=analyst.mfa_last_counter) if password_valid else None
    if not analyst.mfa_enabled or counter is None:
        raise HTTPException(status_code=401, detail="Current password and authenticator code are required")
    analyst.mfa_enabled = False
    analyst.mfa_secret_encrypted = None
    analyst.mfa_last_counter = None
    analyst.mfa_recovery_hashes = []
    current = getattr(request.state, "auth_session", None)
    sessions = db.query(AuthSession).filter(AuthSession.analyst_id == analyst.id)
    if current is not None:
        sessions = sessions.filter(AuthSession.id != current.id)
    sessions.delete(synchronize_session=False)
    db.add(models.ExecutionAuditEvent(actor_id=analyst.id, event_type="MFA_DISABLED",
                                      outcome="SUCCESS", metadata_json={}))
    db.commit()
    return {"enabled": False}
