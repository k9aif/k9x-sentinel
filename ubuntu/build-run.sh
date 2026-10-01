#!/usr/bin/env bash
# K9X Sentinel — build and run helper (single container, no pod needed)
# Run from any directory on the Podman host (the script uses sudo itself).
#
# Commands:
#   build   — build the k9x-sentinel container image
#   start   — start the container (port 8114, LAN only: do not put it on a public tunnel)
#   stop    — stop the container
#   logs    — tail logs (pre-flight results appear here first)
#   run     — trigger a run now (needs SENTINEL_USER/SENTINEL_PASSWORD in .env)
#   all     — build + start

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="k9x-sentinel:latest"
CONTAINER="k9x-sentinel"
PORT=8114
# Findings, pending HIL cases and run history live here.
RUNTIME_HOST_DIR="${HOME}/containers/volumes/k9x-sentinel/runtime"
ENV_FILE="$PROJECT_DIR/.env"

env_get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed -e "s/^['\"]//" -e "s/['\"]$//"; }

cmd="${1:-help}"

case "$cmd" in

  build)
    echo "Building $IMAGE (context: $PROJECT_DIR) ..."
    cd "$PROJECT_DIR"
    sudo podman build -t "$IMAGE" -f ubuntu/Containerfile .
    echo "Build complete: $IMAGE"
    ;;

  start)
    [[ -f "$ENV_FILE" ]] || { echo "Error: $ENV_FILE not found. Copy .env.example to .env and edit it."; exit 1; }
    sudo mkdir -p "$RUNTIME_HOST_DIR"
    # The container runs as UID 1001 (not root), so it must be able to write here.
    sudo chown -R 1001:0 "$RUNTIME_HOST_DIR"
    echo "Starting $CONTAINER on port $PORT ..."
    sudo podman rm -f "$CONTAINER" 2>/dev/null || true
    sudo podman run -d \
      --name "$CONTAINER" \
      --restart=always \
      -p "$PORT:8114" \
      -v "$RUNTIME_HOST_DIR":/app/runtime:Z \
      --env-file "$ENV_FILE" \
      -e SENTINEL_DB_PATH=/app/runtime/sentinel.db \
      -e SENTINEL_HIL_DB_PATH=/app/runtime/hil_pending.db \
      "$IMAGE"
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  K9X Sentinel (private — LAN only)"
    echo "  Web UI:  http://${HOST_IP}:${PORT}/"
    echo "  Health:  http://${HOST_IP}:${PORT}/api/health"
    echo "  Check the pre-flight: $0 logs"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ;;

  stop)
    sudo podman stop "$CONTAINER" && sudo podman rm "$CONTAINER"
    ;;

  logs)
    sudo podman logs -f "$CONTAINER"
    ;;

  run)
    user=$(env_get SENTINEL_USER); pass=$(env_get SENTINEL_PASSWORD)
    curl -fsS -u "${user:-admin}:${pass}" -H 'X-Sentinel-Client: build-run.sh' -X POST -H 'Content-Type: application/json' -d '{}' \
      "http://localhost:${PORT}/api/run" && echo
    ;;

  all)
    "$0" build
    "$0" start
    ;;

  *)
    sed -n '2,12p' "$0"
    ;;
esac
