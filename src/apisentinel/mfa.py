"""Small RFC 6238 TOTP implementation for account MFA."""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from urllib.parse import quote

from .config import settings
from .secrets import decrypt_secret, encrypt_secret


def _encryption_ready() -> None:
    if settings.credential_encryption_provider == "fernet" and not settings.credential_encryption_key:
        raise RuntimeError("MFA encryption is not configured")
    if settings.credential_encryption_provider == "aws_kms" and not settings.credential_kms_key_id:
        raise RuntimeError("MFA encryption is not configured")


def encrypt_totp_secret(secret: str) -> str:
    _encryption_ready()
    return encrypt_secret(secret.encode("ascii"), purpose="totp-mfa")


def decrypt_totp_secret(encrypted: str) -> str:
    try:
        return decrypt_secret(encrypted, purpose="totp-mfa").decode("ascii")
    except (UnicodeError, ValueError):
        raise ValueError("MFA secret unavailable") from None


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, counter: int) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def verify_totp(secret: str, code: str, *, timestamp: float | None = None, last_counter: int | None = None) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code or ""):
        return None
    current = int((time.time() if timestamp is None else timestamp) // 30)
    for counter in (current - 1, current, current + 1):
        if counter <= (last_counter if last_counter is not None else -1):
            continue
        if hmac.compare_digest(totp_code(secret, counter), code):
            return counter
    return None


def provisioning_uri(secret: str, login: str) -> str:
    label = quote(f"APISentinel:{login}", safe="")
    issuer = quote("APISentinel", safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
