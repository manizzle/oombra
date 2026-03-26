#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/smoke-image.sh [--image IMAGE] [--pull] [--keep-up] [--port PORT] [--project-name NAME]

Defaults:
  - Builds the current workspace into image tag `nur-smoke-local`
  - Boots `docker-compose.prod.yml` on port 18000
  - Verifies:
      GET  /health
      GET  /contribute
      POST /contribute
      POST /contribute/voice

Examples:
  scripts/smoke-image.sh
  scripts/smoke-image.sh --image ghcr.io/manizzle/nur:<sha> --pull
  scripts/smoke-image.sh --image nur-smoke --keep-up
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return
  fi
  echo "Neither 'docker compose' nor 'docker-compose' is available." >&2
  exit 1
}

IMAGE=""
PULL_IMAGE=0
KEEP_UP=0
PORT=18000
PROJECT_NAME="nursmoke$RANDOM$RANDOM"
LOCAL_TAG="nur-smoke-local"

while [ $# -gt 0 ]; do
  case "$1" in
    --image)
      IMAGE="${2:-}"
      shift 2
      ;;
    --pull)
      PULL_IMAGE=1
      shift
      ;;
    --keep-up)
      KEEP_UP=1
      shift
      ;;
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --project-name)
      PROJECT_NAME="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "$IMAGE" ]; then
  IMAGE="$LOCAL_TAG"
fi

require_command docker
require_command curl
COMPOSE_CMD="$(detect_compose)"
BASE_URL="http://localhost:${PORT}"
COMPOSE_FILE="docker-compose.prod.yml"

cleanup() {
  if [ "$KEEP_UP" -eq 1 ]; then
    echo "Leaving stack running for debugging."
    echo "Base URL: $BASE_URL"
    echo "Project:  $PROJECT_NAME"
    return
  fi
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" $COMPOSE_CMD -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}

dump_logs() {
  echo "--- docker compose ps ---" >&2
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" $COMPOSE_CMD -f "$COMPOSE_FILE" ps -a >&2 || true
  echo "--- nur-prod logs ---" >&2
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" $COMPOSE_CMD -f "$COMPOSE_FILE" logs --tail=200 nur-prod >&2 || true
  echo "--- postgres logs ---" >&2
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" $COMPOSE_CMD -f "$COMPOSE_FILE" logs --tail=100 postgres >&2 || true
}

on_exit() {
  status=$?
  if [ "$status" -ne 0 ]; then
    dump_logs
  fi
  cleanup
  exit "$status"
}

trap on_exit EXIT

if [ "$PULL_IMAGE" -eq 1 ]; then
  echo "Pulling image: $IMAGE"
  docker pull "$IMAGE"
elif [ "$IMAGE" = "$LOCAL_TAG" ]; then
  echo "Building local image: $IMAGE"
  docker build -t "$IMAGE" .
else
  echo "Using existing local image: $IMAGE"
fi

echo "Starting stack with image: $IMAGE"
COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
NUR_IMAGE="$IMAGE" \
NUR_PORT="$PORT" \
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-nur}" \
NUR_API_KEY="${NUR_API_KEY:-}" \
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d postgres nur-prod

for i in $(seq 1 40); do
  if curl -fsS --max-time 5 "$BASE_URL/health" >/dev/null; then
    echo "Backend healthy on attempt $i/40"
    break
  fi
  sleep 2
done

curl -fsS --max-time 5 "$BASE_URL/health" >/dev/null

contribute_page="$(mktemp)"
curl -fsS --max-time 10 "$BASE_URL/contribute" -o "$contribute_page"
grep -q "Submit voice eval" "$contribute_page"

contribute_headers="$(mktemp)"
curl -sS --max-time 10 \
  -D "$contribute_headers" \
  -o /dev/null \
  -X POST \
  -F "vendor=CrowdStrike" \
  -F "category=edr" \
  -F "overall_score=8" \
  -F "would_buy=yes" \
  -F "support_quality=9" \
  "$BASE_URL/contribute"
grep -q "^HTTP/.* 303" "$contribute_headers"
grep -qi "^location: /contribute/thanks?" "$contribute_headers"

voice_fixture="$(mktemp "${TMPDIR:-/tmp}/nur-voice-smoke.XXXXXX.webm")"
printf 'smoke voice payload' > "$voice_fixture"
voice_response="$(mktemp)"
curl -fsS --max-time 10 \
  -o "$voice_response" \
  -X POST \
  -F "audio=@$voice_fixture;type=audio/webm" \
  "$BASE_URL/contribute/voice"
grep -q '"status":"accepted"' "$voice_response"
grep -q '"receipt_id":' "$voice_response"
grep -q '"audio_id":' "$voice_response"

echo "Smoke checks passed for $IMAGE"
