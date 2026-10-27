# Backups and restore

PostgreSQL is authoritative for configuration, run metadata, evidence hashes and audit events. Use encrypted managed backups or `pg_dump`/`pg_restore` with tested retention.

A restore drill should:

1. restore into an isolated database;
2. run `alembic current` and `alembic upgrade head`;
3. verify organization/project counts and foreign-key integrity;
4. verify encrypted provider secrets can be decrypted with the separately stored encryption key;
5. verify recent report hashes and audit events;
6. reconnect a non-production runner.

Loss of the encryption key makes encrypted credentials unrecoverable by design, so key backup belongs in a KMS/HSM process separate from database backups.


## Executable backup tooling

`python scripts/database_backup.py --database-url "$DATABASE_URL" --output /secure/path/accessproof.dump` creates a consistent backup and a SHA-256 manifest. PostgreSQL uses `pg_dump --format=custom` without placing the password on the command line; `PGPASSWORD` is supplied only to the subprocess environment. Development SQLite uses the SQLite online backup API and can be verified with `--verify`.

A production restore drill should use an isolated PostgreSQL database, for example `pg_restore --no-owner --no-privileges --dbname "$RESTORE_DATABASE_URL" /secure/path/accessproof.dump`, then run `alembic upgrade head` and the verification checks above. Never restore over the live production database as a routine validation step. `pg_dump`/`pg_restore` are not available in every development environment; when unavailable, PostgreSQL restore validation must be marked blocked rather than simulated.
