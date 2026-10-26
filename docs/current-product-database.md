# Current-product database cutover

AccessProof keeps the existing database intact and uses a separate database for
the current Guard control plane.  The Compose default is `accessproof_current`;
the former `accessproof` database and its Docker volume are never deleted by
the cutover.

Start the current product with:

```bash
docker compose --profile current up -d --build
```

The API creates `accessproof_current` if needed, then applies Alembic
migrations before it accepts traffic.  The current UI is available on port
`3001` by default.  Register the first workspace administrator through that UI;
the clean database intentionally does not copy users, sessions, encrypted
credentials, campaigns, runs, reports, or legacy projects.

To use an explicitly managed database, set
`ACCESSPROOF_CURRENT_DATABASE_URL` to its PostgreSQL SQLAlchemy URL before
starting the stack.  To roll back the application configuration, stop the
current stack and remove that environment variable or point it at the prior
database URL.  Do not delete the `accessproof_pg` Docker volume as part of this
procedure.
