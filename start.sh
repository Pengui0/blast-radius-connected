#!/bin/sh
# Container entrypoint: make sure preset snapshots exist, then start UI + API.
if ! ls backend/cache/snapshot_*.json >/dev/null 2>&1; then
  echo "No preset snapshots found, seeding (needs network access to deps.dev and OSV)..."
  python -m backend.ingest seed || echo "WARN: seeding failed. Presets stay unavailable until it succeeds."
fi
exec node_modules/.bin/tsx server.ts
