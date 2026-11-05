# Database backup and restore

## SQLite

The operator CLI creates a consistent SQLite snapshot using SQLite's online backup API. It validates the source and output with `PRAGMA integrity_check`, creates output files with mode `0600`, and refuses to overwrite an existing path.

```bash
apisentinel backup-database --path /secure-backup/apisentinel-$(date -u +%Y%m%dT%H%M%SZ).sqlite
apisentinel restore-database --source /secure-backup/apisentinel-backup.sqlite --target /var/tmp/apisentinel-restore-check.sqlite
```

Restore always targets a new file and never changes the configured live database. To perform a recovery, stop the service, retain the original database, restore to a new path, check the restored contents and Alembic revision, then configure the service to use the reviewed restored file. Keep the matching credential-encryption key in a separate protected backup; encrypted credentials cannot be recovered from the database alone. Protect and retention-manage the backup directory because database snapshots may contain client records and credential ciphertext.

Run a drill against a disposable database before storing client data. The unit workflow is `pytest -q tests/test_db_ops.py`; a local operator drill can also restore a generated backup into a separate temporary path and compare `PRAGMA integrity_check`, Alembic revision, and expected record counts. Never use the configured live database as the restore target.

The built-in commands currently support file-backed SQLite only. For PostgreSQL, use the organization's controlled `pg_dump`/`pg_restore` procedures, verify them on a disposable instance, and preserve the same database-plus-encryption-key recovery relationship.

## PostgreSQL

Use the PostgreSQL client tools matching the server major version. Keep credentials in a protected `PGPASSFILE`/secret manager and use a separate, encrypted backup destination. The commands below use libpq-style `PG_URL` and a new restore database; they do not target the configured live database:

```bash
export PG_URL='postgresql://apisentinel@db.example.internal:5432/apisentinel'
export BACKUP_FILE='/secure-backup/apisentinel.dump'
pg_dump --format=custom --no-owner --dbname="$PG_URL" --file="$BACKUP_FILE"
createdb --host=db.example.internal --username=apisentinel apisentinel_restore_check
pg_restore --exit-on-error --no-owner \
  --dbname='postgresql://apisentinel@db.example.internal:5432/apisentinel_restore_check' \
  "$BACKUP_FILE"
```

Verify that the source and restored database report the same `alembic_version.version_num`, compare expected table/record counts, and run `alembic check` with `APISENTINEL_DATABASE_URL` pointed at the restored database. Restore the matching AWS KMS key policy and workload identity separately; encrypted secret rows alone are not recoverable. Retain the old KMS key and decrypt permission for as long as any retained backup depends on it.

CI and local validation exercise a disposable PostgreSQL 16 migration, eight-process reservation contention, and `pg_dump`/`pg_restore` into a second database. This is a schema/recovery drill; production restore acceptance must also validate application connections, KMS decryption, permissions, monitoring, and the deployment's recovery objectives.
