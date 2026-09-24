#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=postgres:18-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2
container="peerward-test-postgres-$(id -u)-$$"

if (( $# == 0 )); then
  echo "usage: scripts/with-postgres.sh COMMAND [ARG ...]" >&2
  exit 64
fi
command -v docker >/dev/null 2>&1 || {
  echo "docker is required to provision PostgreSQL 18" >&2
  exit 69
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  docker rm --force "$container" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker run --detach --rm --name "$container" \
  --env POSTGRES_PASSWORD=peerward_test \
  --env POSTGRES_DB=peerward_test \
  --publish 127.0.0.1::5432 \
  "$image" >/dev/null

ready_seconds=${PEERWARD_TEST_POSTGRES_READY_SECONDS:-120}
case "$ready_seconds" in
  ''|*[!0-9]*) echo "PEERWARD_TEST_POSTGRES_READY_SECONDS must be an integer" >&2; exit 64 ;;
esac
if (( ready_seconds < 5 || ready_seconds > 300 )); then
  echo "PEERWARD_TEST_POSTGRES_READY_SECONDS must be 5..300" >&2
  exit 64
fi
ready_deadline=$((SECONDS + ready_seconds))
while (( SECONDS < ready_deadline )); do
  if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -d peerward_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -d peerward_test >/dev/null; then
  echo "Disposable PostgreSQL failed to become ready: $container" >&2
  docker logs --tail 80 "$container" >&2 || true
  exit 70
fi
binding=$(docker port "$container" 5432/tcp)
port=${binding##*:}
case "$port" in
  ''|*[!0-9]*) echo "could not resolve the disposable PostgreSQL port" >&2; exit 70 ;;
esac

export PEERWARD_TEST_DATABASE_URL="postgres://postgres:peerward_test@127.0.0.1:$port/peerward_test"
cd "$root"
"$@"
