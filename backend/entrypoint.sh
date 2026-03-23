#!/bin/sh
set -eu
# Fix data directory ownership at startup, then drop to nyx user
chown -R nyx:nyx /app/data
exec gosu nyx uvicorn app.main:app --host 0.0.0.0 --port 8000
