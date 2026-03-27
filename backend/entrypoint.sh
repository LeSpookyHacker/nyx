#!/bin/sh
set -eu
# Fix data/log directory ownership and set explicit permissions (M13).
# Only root can write here; the nyx user gets rwx on directories, no world access.
chown -R nyx:nyx /app/data
chmod 700 /app/data
mkdir -p /app/logs && chown -R nyx:nyx /app/logs && chmod 700 /app/logs
exec gosu nyx uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --log-config /app/log_config.json
