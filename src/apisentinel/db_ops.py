"""Safe SQLite backup and restore helpers used by operator CLI commands."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from sqlalchemy.engine import make_url


def sqlite_path(database_url: str) -> Path:
    url = make_url(database_url)
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        raise ValueError("Database backup and restore commands currently require a file-backed SQLite database")
    return Path(url.database).expanduser().resolve()


def _integrity_check(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchone()
    if result is None or result[0] != "ok":
        raise ValueError("SQLite database integrity check failed")


def backup_sqlite(source: Path, destination: Path) -> None:
    source, destination = source.resolve(), destination.resolve()
    if source == destination:
        raise ValueError("Backup destination must differ from the configured database")
    if not source.is_file():
        raise ValueError("Configured SQLite database file does not exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError("Refusing to overwrite an existing backup file") from None
    os.close(fd)
    try:
        with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=10) as src, sqlite3.connect(destination, timeout=10) as dst:
            _integrity_check(src)
            src.backup(dst)
            _integrity_check(dst)
        os.chmod(destination, 0o600)
    except (OSError, sqlite3.Error, ValueError):
        destination.unlink(missing_ok=True)
        raise ValueError("SQLite backup failed its integrity or I/O checks") from None


def restore_sqlite(source: Path, destination: Path) -> None:
    """Restore into a new path only; never replace an existing database."""
    source, destination = source.resolve(), destination.resolve()
    if source == destination:
        raise ValueError("Restore source and destination must differ")
    if not source.is_file():
        raise ValueError("Restore source does not exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError("Refusing to overwrite an existing restore destination") from None
    os.close(fd)
    try:
        with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=10) as src, sqlite3.connect(destination, timeout=10) as dst:
            _integrity_check(src)
            src.backup(dst)
            _integrity_check(dst)
        os.chmod(destination, 0o600)
    except (OSError, sqlite3.Error, ValueError):
        destination.unlink(missing_ok=True)
        raise ValueError("SQLite restore failed its integrity or I/O checks") from None
