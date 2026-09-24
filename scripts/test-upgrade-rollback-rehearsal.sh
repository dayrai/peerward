#!/usr/bin/env bash
# Disposable Linux updater/systemd rehearsal. This is not a production upgrade proof.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
usage() {
  cat <<'USAGE'
usage: scripts/test-upgrade-rollback-rehearsal.sh [--output PATH]

Builds the isolated systemd test image and runs the signed updater apply/rollback
fixture. The fixture uses synthetic role executables and does not prove a full
Peerward cross-version application or database migration.
USAGE
}

output=
while (( $# )); do
  case "$1" in
    --output)
      (( $# >= 2 )) || { echo "--output requires a path" >&2; exit 64; }
      output=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

for command_name in cargo docker python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required for the upgrade/rollback rehearsal" >&2
    exit 69
  }
done

stamp=$(date -u +%Y%m%dT%H%M%SZ)
if [[ -z "$output" ]]; then
  output="$root/artifacts/upgrade-rollback/$stamp"
elif [[ "$output" != /* ]]; then
  output="$root/$output"
fi
[[ ! -e "$output" ]] || {
  echo "output path already exists: $output" >&2
  exit 73
}
mkdir -p "$(dirname "$output")"

base_image=peerward-netns-test:ubuntu26
updater_image="peerward-update-systemd-test:rc-$$"
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  docker image rm --force "$updater_image" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$root"
printf 'Building isolated updater rehearsal images...\n'
docker build --tag "$base_image" --file packaging/docker/netns-test.Dockerfile .
docker build --tag "$updater_image" --file deploy/tests/updater-systemd.Dockerfile .

printf 'Building the updater CLI used by the fixture...\n'
cargo build --locked -p peerward-cli --bin peerward

printf 'Running signed apply/rollback/systemd recovery rehearsal...\n'
python3 scripts/test-linux-updater.py \
  --image "$updater_image" \
  --binary target/debug/peerward \
  --output "$output"

printf 'upgrade/rollback rehearsal record: %s\n' "$output/verification.json"
printf '%s\n' 'boundary: synthetic role executables; not full application migration or production rollback evidence'
