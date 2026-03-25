#!/bin/sh
set -eu
# Fix data/log directory ownership at startup, then drop to nyx user
chown -R nyx:nyx /app/data
mkdir -p /app/logs && chown -R nyx:nyx /app/logs
exec gosu nyx uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --log-config /app/log_config.json
