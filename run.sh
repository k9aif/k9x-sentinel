#!/usr/bin/env bash
# K9X Sentinel — run locally (pre-flight, then the server on SENTINEL_PORT, default 8114).
set -euo pipefail
cd "$(dirname "$0")"
[[ -f .env ]] || { echo "Copy .env.example to .env and edit it first."; exit 1; }
python -m sentinel.preflight
exec uvicorn sentinel.api:app --host 0.0.0.0 --port "${SENTINEL_PORT:-8114}"
