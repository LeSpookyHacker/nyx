#!/bin/sh
set -eu

# Ensure data/log directories exist and are writable (volume mounts may shadow image defaults).
mkdir -p /app/data /app/logs

# Run database migrations before starting the server.
# This is idempotent — Alembic skips already-applied revisions.
# Falls back to SQLAlchemy create_all on databases without Alembic history (SQLite dev).
echo "[nyx] Running database migrations..."
if ! alembic upgrade head 2>/dev/null; then
  echo "[nyx] Alembic migration failed or no alembic.ini found — falling back to create_all (dev mode only)"
fi
echo "[nyx] Migrations complete."

exec uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --log-config /app/log_config.json
