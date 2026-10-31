"""Secret encryption providers: local Fernet for development and AWS KMS envelope encryption."""
from __future__ import annotations

import base64
import json
import secrets

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

_KMS_PREFIX = "kms:v1:"


def encryption_configured() -> bool:
    if settings.credential_encryption_provider == "aws_kms":
        return bool(settings.credential_kms_key_id and settings.credential_kms_region)
    return bool(settings.credential_encryption_key)


def _kms_client():
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise RuntimeError("AWS KMS support is unavailable") from None
    return boto3.client("kms", region_name=settings.credential_kms_region,
                        config=Config(connect_timeout=3, read_timeout=5,
                                      retries={"max_attempts": 2, "mode": "standard"}))


def encrypt_secret(value: bytes, *, purpose: str, key_id: str | None = None) -> str:
    if settings.credential_encryption_provider == "fernet":
        if not settings.credential_encryption_key:
            raise RuntimeError("Credential encryption is not configured")
        return Fernet(settings.credential_encryption_key.encode("ascii")).encrypt(value).decode("ascii")
    selected_key = key_id or settings.credential_kms_key_id
    if not selected_key:
        raise RuntimeError("AWS KMS key is not configured")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    context = {"application": "apisentinel", "purpose": purpose}
    generated = _kms_client().generate_data_key(KeyId=selected_key, KeySpec="AES_256", EncryptionContext=context)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(generated["Plaintext"]).encrypt(nonce, value, purpose.encode("utf-8"))
    payload = {"key": base64.b64encode(generated["CiphertextBlob"]).decode("ascii"),
               "nonce": base64.b64encode(nonce).decode("ascii"),
               "ciphertext": base64.b64encode(ciphertext).decode("ascii")}
    return _KMS_PREFIX + base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def decrypt_secret(encoded: str, *, purpose: str) -> bytes:
    if not encoded.startswith(_KMS_PREFIX):
        if not settings.credential_encryption_key:
            raise ValueError("Encrypted secret unavailable")
        try:
            return Fernet(settings.credential_encryption_key.encode("ascii")).decrypt(encoded.encode("ascii"))
        except (InvalidToken, UnicodeError, ValueError):
            raise ValueError("Encrypted secret unavailable") from None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        payload = json.loads(base64.urlsafe_b64decode(encoded[len(_KMS_PREFIX):]))
        context = {"application": "apisentinel", "purpose": purpose}
        data_key = _kms_client().decrypt(CiphertextBlob=base64.b64decode(payload["key"], validate=True),
                                         EncryptionContext=context)["Plaintext"]
        nonce = base64.b64decode(payload["nonce"], validate=True)
        ciphertext = base64.b64decode(payload["ciphertext"], validate=True)
        return AESGCM(data_key).decrypt(nonce, ciphertext, purpose.encode("utf-8"))
    except Exception:  # noqa: BLE001 - hide provider, parsing, and authentication errors.
        raise ValueError("Encrypted secret unavailable") from None
