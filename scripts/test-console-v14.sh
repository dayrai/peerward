#!/usr/bin/env bash
# Builds and tests only a disposable fixture, never an existing deployment.
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace"
if [[ ${1:-} != --fixture ]]; then
  cargo build --locked -p peerward-console --target wasm32-unknown-unknown --no-default-features --features web --bin peerward-console-web
  cargo build --locked -p peerward-console --bin peerward-console -p peerward-control --example console_review_fixture
  scripts/with-postgres.sh bash "$0" --fixture
  exec scripts/with-postgres.sh node apps/peerward-console/e2e/run-console-lock.mjs
fi
[[ ${PEERWARD_TEST_DATABASE_URL:-} == *'/peerward_test' ]] || { echo 'disposable database required' >&2; exit 64; }
work=$(mktemp -d /tmp/peerward-console-v14.XXXXXXXX)
fixture_pid=
console_pid=
cleanup() {
  status=$?
  trap - EXIT
  for pid in "$console_pid" "$fixture_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  if (( status == 0 )); then rm -rf -- "$work"; else echo "Fixture logs: $work" >&2; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
read -r api_port console_port < <(python3 - <<'PY'
import socket
with socket.socket() as api, socket.socket() as console:
    api.bind(('127.0.0.1', 0)); console.bind(('127.0.0.1', 0))
    print(api.getsockname()[1], console.getsockname()[1])
PY
)
mkdir "$work/assets"
wasm-bindgen target/wasm32-unknown-unknown/debug/peerward-console-web.wasm --target web --out-dir "$work/assets" --out-name peerward-console-web
cp apps/peerward-console/assets/main.css "$work/assets/main.css"
PEERWARD_CONSOLE_FIXTURE_LISTEN="127.0.0.1:$api_port" target/debug/examples/console_review_fixture > "$work/api.log" 2>&1 &
fixture_pid=$!
PEERWARD_CONTROL_URL="http://127.0.0.1:$api_port" PEERWARD_DEV_BEARER=console-review-test \
  PEERWARD_CONSOLE_LISTEN="127.0.0.1:$console_port" PEERWARD_CONSOLE_ASSET_DIR="$work/assets" \
  target/debug/peerward-console > "$work/console.log" 2>&1 &
console_pid=$!
ready=false
for attempt in $(seq 1 60); do
  kill -0 "$fixture_pid" "$console_pid" 2>/dev/null || { echo 'fixture process exited' >&2; exit 1; }
  if curl --fail --silent "http://127.0.0.1:$console_port/api/v1/meshes" > "$work/meshes.json"; then ready=true; break; fi
  sleep 1
done
[[ $ready == true ]] || { echo 'fixture startup timed out' >&2; exit 1; }
cd apps/peerward-console/e2e
[[ -d node_modules/@playwright/test ]] || npm ci
filters=()
if [[ ${PEERWARD_CONSOLE_UPDATE_SNAPSHOTS:-} == 1 ]]; then filters+=(--update-snapshots); fi
if [[ -n ${PEERWARD_CONSOLE_E2E_GREP:-} ]]; then filters+=(--grep "$PEERWARD_CONSOLE_E2E_GREP"); fi
PEERWARD_CONSOLE_E2E_URL="http://127.0.0.1:$console_port" PEERWARD_NETWORK_MANAGEMENT_E2E=1 PEERWARD_CONSOLE_V14_E2E=1 PEERWARD_DEVICE_DETAILS_E2E=1 \
  PEERWARD_EVIDENCE_SCREENSHOT_DIR="${PEERWARD_EVIDENCE_SCREENSHOT_DIR:-$workspace/artifacts/console-v14/screenshots}" \
  npx playwright test console-v14.spec.mjs sharing-prototype.spec.mjs sharing-edit.spec.mjs device-prototype.spec.mjs prototype-pages.spec.mjs network-management.spec.mjs controlled-enrollment.spec.mjs guided-enrollment.spec.mjs enrollment-prototype.spec.mjs \
    client-upgrade.spec.mjs device-details.spec.mjs event-recovery.spec.mjs \
    mesh-delete.spec.mjs mesh-provisioning.spec.mjs peer-delete.spec.mjs visual.spec.mjs --reporter=line "${filters[@]}"
