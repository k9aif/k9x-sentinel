#!/usr/bin/env bash
# K9X Sentinel — run locally (pre-flight, then the server on SENTINEL_PORT, default 8114).
# Uses this project's .venv when present, whatever virtualenv the shell has
# active (another project's venv may carry an older k9-aif).
set -euo pipefail
cd "$(dirname "$0")"
[[ -f .env ]] || { echo "Copy .env.example to .env and edit it first."; exit 1; }
PY=python3
[[ -x .venv/bin/python ]] && PY=.venv/bin/python
"$PY" -c 'import k9_aif_abb.k9_security.tool_result_guard' 2>/dev/null || {
  echo "k9-aif in $("$PY" -c 'import sys; print(sys.prefix)') is older than 1.14 (or missing)."
  echo "Run: python3.11 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt"
  exit 1; }
port=$(grep -E '^SENTINEL_PORT=' .env | tail -1 | cut -d= -f2)
"$PY" -m sentinel.preflight
exec "$PY" -m uvicorn sentinel.api:app --host 0.0.0.0 --port "${port:-8114}"
