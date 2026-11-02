"""Encrypted, assessment-bound bearer credential storage and resolution."""
from . import models
from .access import client_access_filter
from .secrets import decrypt_secret, encrypt_secret


def encrypt_bearer(token: str) -> str:
    return encrypt_secret(token.encode("utf-8"), purpose="credential-profile")


class DatabaseCredentialResolver:
    """Resolve active bearer profiles owned by the caller and bound to one assessment."""

    def __init__(self, db):
        self.db = db

    def resolve_bearer(self, reference: str, *, analyst_id: int, assessment_id: int) -> str:
        if reference.startswith("test-identity:"):
            try:
                identity_id = int(reference.split(":", 1)[1])
            except (TypeError, ValueError):
                raise ValueError("Credential reference mismatch") from None
            profile = (self.db.query(models.TestIdentityProfile)
                       .join(models.Assessment, models.TestIdentityProfile.assessment_id == models.Assessment.id)
                       .join(models.Client, models.Assessment.client_id == models.Client.id)
                       .filter(models.TestIdentityProfile.id == identity_id,
                               models.TestIdentityProfile.assessment_id == assessment_id,
                               models.TestIdentityProfile.active.is_(True),
                               client_access_filter(analyst_id, ("analyst",)))
                       .first())
            if profile is None:
                raise ValueError("Test identity unavailable")
            try:
                return decrypt_secret(profile.encrypted_secret, purpose="test-identity-profile").decode("utf-8")
            except (UnicodeError, ValueError):
                raise ValueError("Test identity unavailable") from None
        if reference != str(assessment_id):
            raise ValueError("Credential reference mismatch")
        profile = (self.db.query(models.CredentialProfile)
                   .join(models.Assessment, models.CredentialProfile.assessment_id == models.Assessment.id)
                   .join(models.Client, models.Assessment.client_id == models.Client.id)
                   .filter(models.CredentialProfile.assessment_id == assessment_id,
                           models.CredentialProfile.active.is_(True),
                           models.CredentialProfile.auth_type == "BEARER",
                           client_access_filter(analyst_id, ("analyst",)))
                   .first())
        if profile is None:
            raise ValueError("Credential profile unavailable")
        try:
            return decrypt_secret(profile.encrypted_secret, purpose="credential-profile").decode("utf-8")
        except (UnicodeError, ValueError):
            raise ValueError("Credential profile unavailable") from None
