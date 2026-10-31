import argparse
import os
from getpass import getpass
from pathlib import Path

import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .auth import normalize_login, password_hasher
from .config import settings
from .db import SessionLocal
from .db_ops import backup_sqlite, restore_sqlite, sqlite_path
from .models import Analyst, AuthSession, CredentialProfile
from .secrets import decrypt_secret, encrypt_secret


def provision_user(login: str) -> int:
    normalized = normalize_login(login)
    if not normalized:
        raise ValueError("Login cannot be empty")
    password = getpass("New password (12+ characters): ")
    confirm = getpass("Confirm password: ")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if password != confirm:
        raise ValueError("Passwords do not match")
    with SessionLocal() as db:
        analyst = Analyst(login_normalized=normalized, password_hash=password_hasher.hash(password), role="analyst")
        db.add(analyst)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise ValueError("That login is already provisioned") from exc
        db.refresh(analyst)
        return analyst.id


def reset_user_password(login: str | None = None) -> tuple[int, bool]:
    """Reset one provisioned analyst password from the local operator CLI."""
    normalized = normalize_login(login if login is not None else input("Analyst login/email: "))
    if not normalized:
        raise ValueError("Login cannot be empty")
    password = getpass("New password (12+ characters): ")
    confirm = getpass("Confirm password: ")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if password != confirm:
        raise ValueError("Passwords do not match")
    with SessionLocal() as db:
        analyst = db.query(Analyst).filter_by(login_normalized=normalized).with_for_update().first()
        if analyst is None:
            raise ValueError("No analyst account matches that login")
        analyst.password_hash = password_hasher.hash(password)
        analyst.login_failure_count = 0
        analyst.login_failure_window_started_at = None
        analyst.login_locked_until = None
        mfa_enabled = analyst.mfa_enabled
        db.query(AuthSession).filter_by(analyst_id=analyst.id).delete(synchronize_session=False)
        db.commit()
        return analyst.id, mfa_enabled


def rotate_credential_keys(old_key: str, new_key: str) -> int:
    old_cipher, new_cipher = Fernet(old_key.encode("ascii")), Fernet(new_key.encode("ascii"))
    with SessionLocal() as db:
        profiles = db.query(CredentialProfile).all()
        analysts = db.query(Analyst).filter(Analyst.mfa_secret_encrypted.is_not(None)).all()
        try:
            for profile in profiles:
                token = old_cipher.decrypt(profile.encrypted_secret.encode("ascii"))
                profile.encrypted_secret = new_cipher.encrypt(token).decode("ascii")
            for analyst in analysts:
                secret = old_cipher.decrypt(analyst.mfa_secret_encrypted.encode("ascii"))
                analyst.mfa_secret_encrypted = new_cipher.encrypt(secret).decode("ascii")
            db.commit()
        except (InvalidToken, UnicodeDecodeError, SQLAlchemyError, ValueError):
            db.rollback()
            raise ValueError("Credential key rotation failed; stored data was not committed") from None
        return len(profiles) + len(analysts)


def rotate_kms_key(next_key_id: str) -> int:
    with SessionLocal() as db:
        profiles = db.query(CredentialProfile).all()
        analysts = db.query(Analyst).filter(Analyst.mfa_secret_encrypted.is_not(None)).all()
        try:
            for profile in profiles:
                clear = decrypt_secret(profile.encrypted_secret, purpose="credential-profile")
                profile.encrypted_secret = encrypt_secret(clear, purpose="credential-profile", key_id=next_key_id)
            for analyst in analysts:
                clear = decrypt_secret(analyst.mfa_secret_encrypted, purpose="totp-mfa")
                analyst.mfa_secret_encrypted = encrypt_secret(clear, purpose="totp-mfa", key_id=next_key_id)
            db.commit()
        except Exception:  # noqa: BLE001 - rollback on any KMS/provider/database failure.
            db.rollback()
            raise ValueError("KMS key rotation failed; stored data was not committed") from None
        return len(profiles) + len(analysts)


def create_credential_key_file(path: str) -> None:
    key = Fernet.generate_key()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError("Refusing to overwrite an existing key file") from None
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(f"APISENTINEL_CREDENTIAL_ENCRYPTION_KEY={key.decode('ascii')}\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise ValueError("Could not safely write the credential key file") from None


def main():
    parser = argparse.ArgumentParser(prog="apisentinel", description="APISentinel API security workspace")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Run the local API server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    worker = sub.add_parser("worker", help="Run a persistent safe HTTP execution queue worker")
    worker.add_argument("--worker-id", default=f"worker-{os.getpid()}")
    worker.add_argument("--poll-seconds", type=float, default=1.0)
    user = sub.add_parser("create-user", help="Provision an analyst interactively in the local database")
    user.add_argument("login", help="Unique email or username; normalized to lowercase")
    reset_user = sub.add_parser("reset-password", help="Reset an analyst password from the local operator CLI")
    reset_user.add_argument("login", nargs="?", help="Email or username; prompts if omitted")
    sub.add_parser("rotate-credential-key", help="Re-encrypt stored credentials with the preconfigured next key")
    keyfile = sub.add_parser("generate-credential-key", help="Create a protected environment file without printing the key")
    keyfile.add_argument("--path", required=True, help="New private file path; existing files are never overwritten")
    backup = sub.add_parser("backup-database", help="Create and verify a private SQLite backup")
    backup.add_argument("--path", required=True, help="New backup path; existing files are never overwritten")
    restore = sub.add_parser("restore-database", help="Restore a verified SQLite backup to a new path")
    restore.add_argument("--source", required=True, help="Existing backup file")
    restore.add_argument("--target", required=True, help="New database path; existing files are never overwritten")
    args = parser.parse_args()
    if args.command == "serve":
        uvicorn.run("apisentinel.main:app", host=args.host, port=args.port, reload=False)
    elif args.command == "worker":
        from .job_queue import worker_loop
        worker_loop(args.worker_id, args.poll_seconds)
    elif args.command == "create-user":
        try:
            analyst_id = provision_user(args.login)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Provisioned analyst account id={analyst_id} login={normalize_login(args.login)}")
    elif args.command == "reset-password":
        try:
            analyst_id, mfa_enabled = reset_user_password(args.login)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Password reset for analyst account id={analyst_id}; all existing sessions were revoked.")
        if mfa_enabled:
            print("Multi-factor authentication remains enabled; sign-in still requires its authenticator or a recovery code.")
    elif args.command == "rotate-credential-key":
        if settings.credential_encryption_provider == "aws_kms":
            if not settings.credential_kms_key_id or not settings.credential_kms_key_id_next:
                parser.error("Set current and next KMS key IDs before rotation")
            try:
                count = rotate_kms_key(settings.credential_kms_key_id_next)
            except ValueError as exc:
                parser.error(str(exc))
            print(f"Re-encrypted {count} stored secret(s). Switch APISENTINEL_CREDENTIAL_KMS_KEY_ID to the next key before restarting APISentinel.")
            return
        if not settings.credential_encryption_key or not settings.credential_encryption_key_next:
            parser.error("Set current and next credential encryption keys before rotation")
        try:
            count = rotate_credential_keys(settings.credential_encryption_key,
                                           settings.credential_encryption_key_next)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Re-encrypted {count} stored secret(s). Set the primary key to the next key before restarting APISentinel.")
    elif args.command == "generate-credential-key":
        try:
            create_credential_key_file(args.path)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Protected credential environment file created at {args.path}; key material was not printed.")
    elif args.command == "backup-database":
        try:
            destination = Path(args.path).expanduser().resolve()
            backup_sqlite(sqlite_path(settings.database_url), destination)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Verified database backup created at {destination} (mode 0600).")
    elif args.command == "restore-database":
        try:
            source = Path(args.source).expanduser().resolve()
            target = Path(args.target).expanduser().resolve()
            restore_sqlite(source, target)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Verified database restored to new path {target} (mode 0600); configured database was not replaced.")


if __name__ == "__main__":
    main()
