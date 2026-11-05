import secrets

import pytest

from apisentinel import secrets as secret_service
from apisentinel.config import settings


class FakeKms:
    def __init__(self):
        self.keys = {}

    def generate_data_key(self, *, KeyId, KeySpec, EncryptionContext):
        assert KeySpec == "AES_256"
        key = secrets.token_bytes(32)
        wrapped = secrets.token_bytes(48)
        self.keys[wrapped] = (key, EncryptionContext)
        return {"Plaintext": key, "CiphertextBlob": wrapped}

    def decrypt(self, *, CiphertextBlob, EncryptionContext):
        key, expected_context = self.keys[CiphertextBlob]
        if expected_context != EncryptionContext:
            raise ValueError("wrong context")
        return {"Plaintext": key}


def test_aws_kms_envelope_encrypts_and_authenticates_secret_context(monkeypatch):
    kms = FakeKms()
    monkeypatch.setattr(secret_service, "_kms_client", lambda: kms)
    monkeypatch.setattr(settings, "credential_encryption_provider", "aws_kms")
    monkeypatch.setattr(settings, "credential_kms_key_id", "alias/test")
    monkeypatch.setattr(settings, "credential_kms_region", "us-east-1")
    token = "test bearer secret"
    encrypted = secret_service.encrypt_secret(token.encode(), purpose="credential-profile")
    assert encrypted.startswith("kms:v1:")
    assert token not in encrypted
    assert secret_service.decrypt_secret(encrypted, purpose="credential-profile") == token.encode()
    with pytest.raises(ValueError, match="unavailable"):
        secret_service.decrypt_secret(encrypted, purpose="totp-mfa")


def test_kms_provider_fails_closed_without_a_key_id(monkeypatch):
    monkeypatch.setattr(settings, "credential_encryption_provider", "aws_kms")
    monkeypatch.setattr(settings, "credential_kms_key_id", "")
    with pytest.raises(RuntimeError, match="not configured"):
        secret_service.encrypt_secret(b"secret", purpose="credential-profile")
