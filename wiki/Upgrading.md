# Upgrading Nyx

The safe procedure for moving to a newer version.

---

## Standard upgrade (minor / patch)

```bash
cd nyx
git fetch origin
git log HEAD..origin/main --oneline   # eyeball what you're pulling
git pull
./nyx.sh build
./nyx.sh restart
./nyx.sh check
```

Alembic migrations run automatically on backend startup. Logs live in `./nyx.sh logs` if something fails.

---

## Major upgrade (breaking changes)

Back up first, always:

```bash
# Postgres
docker compose exec -T postgres pg_dump -U nyx nyx | gzip > /tmp/nyx-before-upgrade.sql.gz

# SQLite
cp backend/data/nyx.db /tmp/nyx-before-upgrade.db

# .env
cp .env /tmp/nyx-env-before-upgrade
```

Read the release changelog for the target version — look for:

- Config variable renames
- New required env variables
- Model / schema changes that require manual data migration
- Breaking API changes

Then:

```bash
git fetch origin
git checkout vX.Y.Z        # or 'main' if cutting edge
./nyx.sh build
./nyx.sh restart
./nyx.sh check
```

---

## Rollback

If the upgrade goes wrong:

```bash
# Stop everything
./nyx.sh stop

# Revert the checkout
git checkout <previous-sha-or-tag>

# Restore the DB backup (Postgres)
gunzip -c /tmp/nyx-before-upgrade.sql.gz | \
  docker compose exec -T postgres psql -U nyx nyx

# Or for SQLite
cp /tmp/nyx-before-upgrade.db backend/data/nyx.db

# Restart
./nyx.sh build
./nyx.sh restart
```

> **Always back up the DB before downgrading a migration.** Alembic downgrades are not guaranteed to be lossless.

---

## Rebuilding from scratch

Sometimes the cleanest path is a full reset:

```bash
./nyx.sh stop
docker compose down -v     # also wipes the database volume
docker system prune -af    # optional, reclaims disk
rm -f .env                 # force setup.sh to regenerate secrets
./setup.sh
```

You will lose all findings, audit history, and API keys. Only do this if you have a backup or you're rebuilding an evaluation instance.

---

## Rolling upgrades

Nyx runs a single-leader backend (the in-process worker loops are not coordinated across replicas), so upgrades are a brief maintenance window rather than a blue/green rotation:

1. Announce the window and quiesce CI scan submissions.
2. `git pull && ./nyx.sh build && ./nyx.sh restart` — Alembic migrations run automatically on container start.
3. Run `./nyx.sh doctor` — the end-to-end canary catches broken migrations, auth regressions, and integration failures in one shot.
4. Unblock CI and announce completion.

For multi-hop version upgrades (skipping a minor), always back up first (see [Deployment → Backups](Deployment.md#5-backups)) and skim the changelog for migrations that rewrite existing rows.

---

## What next

- **Full production procedure →** [Deployment](Deployment.md)
- **Troubleshooting upgrade failures →** [Troubleshooting](Troubleshooting.md)
