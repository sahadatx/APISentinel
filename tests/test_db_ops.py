import sqlite3
import stat

import pytest

from apisentinel.db_ops import backup_sqlite, restore_sqlite, sqlite_path


def test_sqlite_backup_and_restore_are_verified_private_and_non_overwriting(tmp_path):
    source = tmp_path / "source database.sqlite"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO sample(value) VALUES ('preserved')")

    backup = tmp_path / "backup.sqlite"
    restored = tmp_path / "restored.sqlite"
    backup_sqlite(source, backup)
    restore_sqlite(backup, restored)

    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600
    with sqlite3.connect(restored) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT value FROM sample").fetchone()[0] == "preserved"
    with pytest.raises(ValueError, match="overwrite"):
        backup_sqlite(source, backup)
    with pytest.raises(ValueError, match="overwrite"):
        restore_sqlite(backup, restored)


def test_backup_rejects_same_or_invalid_source(tmp_path):
    database = tmp_path / "database.sqlite"
    with sqlite3.connect(database):
        pass
    with pytest.raises(ValueError, match="differ"):
        backup_sqlite(database, database)
    with pytest.raises(ValueError, match="file-backed SQLite"):
        sqlite_path("postgresql://user:secret@localhost/db")
