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

## CI/CD and rolling upgrades

For production with multiple backend replicas:

1. Drain traffic from one replica.
2. Upgrade and let migrations run on it. `NYX_WORKER_LEADER=true` on this instance so migrations gate worker activity.
3. Confirm `./nyx.sh check` is green.
4. Bring back traffic.
5. Upgrade remaining replicas one at a time.

Migrations are written to be **forward-compatible** within a single minor version — older replicas can run against a DB that has been migrated forward for at least one hop. For multi-hop upgrades, take a brief maintenance window.

---

## What next

- **Full production procedure →** [Deployment](Deployment.md)
- **Troubleshooting upgrade failures →** [Troubleshooting](Troubleshooting.md)
