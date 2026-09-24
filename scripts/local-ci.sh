#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:-standard}
PEERWARD_LOCAL_CLEANUP_PATH=

cleanup_local_path() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$PEERWARD_LOCAL_CLEANUP_PATH" ]]; then
    rm -rf -- "$PEERWARD_LOCAL_CLEANUP_PATH"
    PEERWARD_LOCAL_CLEANUP_PATH=
  fi
  return "$status"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required for local target '$mode'" >&2
    exit 69
  }
}

verify_standard() {
  local signing_count=0 variable
  for variable in \
    PEERWARD_ANDROID_KEYSTORE PEERWARD_ANDROID_KEY_ALIAS \
    PEERWARD_ANDROID_STORE_PASSWORD PEERWARD_ANDROID_KEY_PASSWORD
  do
    [[ -n "${!variable:-}" ]] && signing_count=$((signing_count + 1))
  done
  (( signing_count == 0 || signing_count == 4 )) || {
    echo "Android signing variables must be complete or absent" >&2
    exit 64
  }
  if (( signing_count == 4 )); then
    "$root/scripts/verify.sh" all
    return
  fi
  require_command keytool
  require_command openssl
  local signing_directory password
  signing_directory=$(mktemp -d "${TMPDIR:-/tmp}/peerward-local-signing.XXXXXXXX")
  PEERWARD_LOCAL_CLEANUP_PATH=$signing_directory
  trap cleanup_local_path EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  password=$(openssl rand -hex 24)
  keytool -genkeypair -noprompt \
    -keystore "$signing_directory/verification-release.p12" \
    -storetype PKCS12 -storepass "$password" -keypass "$password" \
    -alias peerward-local-verification -keyalg EC -groupname secp256r1 \
    -validity 1 -dname "CN=Peerward Local Build Verification" >/dev/null 2>&1
  PEERWARD_ANDROID_KEYSTORE="$signing_directory/verification-release.p12" \
  PEERWARD_ANDROID_KEY_ALIAS=peerward-local-verification \
  PEERWARD_ANDROID_STORE_PASSWORD="$password" \
  PEERWARD_ANDROID_KEY_PASSWORD="$password" \
    "$root/scripts/verify.sh" all
  rm -rf -- "$signing_directory"
  PEERWARD_LOCAL_CLEANUP_PATH=
  trap - EXIT INT TERM
}

verify_privileged_network() {
  cd "$root"
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n env "PATH=$PATH" PEERWARD_RUN_PRIVILEGED=1 \
      cargo test --locked -p peerward-platform --features privileged-netns \
        --test netns -- --nocapture
    return
  fi
  require_command docker
  require_command cargo
  require_command rustup
  local cargo_home rustup_home target_dir image uid gid
  cargo_home=$(cd "$(dirname "$(command -v cargo)")/.." && pwd)
  rustup_home=$(rustup show home)
  target_dir=$(mktemp -d "${TMPDIR:-/tmp}/peerward-netns-target.XXXXXXXX")
  image=peerward-netns-test:ubuntu26
  uid=$(id -u)
  gid=$(id -g)
  PEERWARD_LOCAL_CLEANUP_PATH=$target_dir
  trap cleanup_local_path EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  docker build --tag "$image" --file packaging/docker/netns-test.Dockerfile .
  docker run --rm --privileged --network host \
    --volume "$root:/workspace:ro" \
    --volume "$cargo_home:/cargo" \
    --volume "$rustup_home:/rustup:ro" \
    --volume "$target_dir:/target" \
    --env CARGO_HOME=/cargo --env RUSTUP_HOME=/rustup \
    --env CARGO_TARGET_DIR=/target --env CARGO_NET_OFFLINE=true \
    --env PEERWARD_RUN_PRIVILEGED=1 \
    --env PEERWARD_HOST_UID="$uid" --env PEERWARD_HOST_GID="$gid" \
    --workdir /workspace "$image" \
    bash -euo pipefail -c '
      cleanup() { chown -R "$PEERWARD_HOST_UID:$PEERWARD_HOST_GID" /target; }
      trap cleanup EXIT
      export PATH=/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
      cargo test --locked -p peerward-platform --features privileged-netns --test netns -- --nocapture
    '
  rm -rf -- "$target_dir"
  PEERWARD_LOCAL_CLEANUP_PATH=
  trap - EXIT INT TERM
}

verify_console_e2e() {
  require_command docker
  require_command npm
  cd "$root"
  cargo build --locked -p peerward-cli
  python3 "$root/scripts/dynamic-mesh/console-e2e.py" \
    --output "$root/artifacts/dynamic-mesh/console-e2e-$(date -u +%Y%m%dT%H%M%SZ)-$$"
}

verify_android_web() {
  require_command npm
  "$root/scripts/verify.sh" android
  (
    cd "$root/apps/peerward-console/e2e"
    npm ci
    npx playwright install chromium
    npm run test:android-web
  )
}

verify_wcag_visual() {
  local started_at stamp directory
  started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  directory=${PEERWARD_WCAG_OUTPUT_DIR:-$root/artifacts/wcag-visual/$stamp}
  mkdir -p "$directory"
  PEERWARD_EVIDENCE_SCREENSHOT_DIR="$directory" verify_console_e2e
  PEERWARD_EVIDENCE_SCREENSHOT_DIR="$directory" verify_android_web
  "$root/scripts/write-wcag-visual-candidate.py" \
    --screenshots "$directory" --output "$directory/evidence-wcag-visual-candidate.json" \
    --started-at "$started_at" \
    --artifact-set-sha256 "${PEERWARD_ARTIFACT_SET_SHA256:-$(printf '0%.0s' {1..64})}"
}

verify_android_target() {
  local expected_api=${2:?usage: scripts/local-ci.sh android-target API_LEVEL}
  require_command adb
  mapfile -t devices < <(adb devices | awk 'NR > 1 && $2 == "device" { print $1 }')
  local serial=${ANDROID_SERIAL:-}
  if [[ -n "$serial" ]]; then
    printf '%s\n' "${devices[@]}" | grep -Fqx -- "$serial" || {
      echo "ANDROID_SERIAL does not select an authorized online target" >&2
      exit 65
    }
  else
    (( ${#devices[@]} == 1 )) || {
      echo "android-target requires one target or an explicit ANDROID_SERIAL" >&2
      exit 65
    }
    serial=${devices[0]}
  fi
  local actual_api=${actual_api:-}
  actual_api=$(adb -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r')
  [[ "$actual_api" == "$expected_api" ]] || {
    echo "connected Android target is API $actual_api, expected API $expected_api" >&2
    exit 65
  }
  local underlay_arguments=()
  if [[ -n "${PEERWARD_ANDROID_LAN_ADDRESS:-}" ]]; then
    underlay_arguments+=(--lan-address "$PEERWARD_ANDROID_LAN_ADDRESS")
  fi
  "$root/scripts/run-android-physical.sh" --serial "$serial" "${underlay_arguments[@]}"
}

verify_android_emulator() {
  local expected_api=${2:?usage: scripts/local-ci.sh android-emulator API_LEVEL}
  "$root/scripts/run-android-emulator.sh" "$expected_api"
}

verify_fuzz_smoke() {
  require_command cargo
  cd "$root"
  python3 "$root/scripts/seed-fuzz-corpus.py"
  local target
  for target in \
    credential_codecs gateway_mapping_codecs packet_and_directory \
    v2_documents wire_reassembly_update wireguard_and_stun quic_fragments
  do
    cargo +nightly fuzz run --sanitizer address "$target" -- \
      -max_total_time="${PEERWARD_FUZZ_SMOKE_SECONDS:-30}" -timeout=2
  done
}

verify_nightly() {
  local nightly_mode=${2:?usage: scripts/local-ci.sh nightly fuzz|miri|coverage}
  case "$nightly_mode" in
    fuzz|miri|coverage) ;;
    *) echo "nightly mode must be fuzz, miri, or coverage" >&2; exit 64 ;;
  esac
  require_command cargo
  "$root/scripts/verify-nightly.sh" "$nightly_mode"
}

verify_component_load() {
  require_command jq
  local stamp directory hardware tier report
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  directory=${PEERWARD_COMPONENT_LOAD_OUTPUT_DIR:-$root/artifacts/component-load/$stamp}
  mkdir -p "$directory"
  hardware="$(uname -m); $(nproc) logical CPUs; $(awk '/MemTotal/ {print $2 " kB RAM"; exit}' /proc/meminfo)"
  cd "$root"
  for tier in 100 1000 10000; do
    report="$directory/noise-component-$tier.json"
    cargo run --release --locked -p peerward-load -- \
      --peers "$tier" --messages-per-peer 100 --reconnect-rounds 1 \
      --hardware "$hardware" \
      --traffic-model "uniform 1200-byte Noise component traffic" \
      --output "$report"
    jq -e --argjson tier "$tier" '
      .schema_version == 1 and .status == "unverified" and
      .scope == "noise_component" and .peers == $tier and .failures == 0 and
      .scenarios.noise_ik_and_framing == "passed" and
      .scenarios.deployed_relay_forwarding == "missing" and
      .scenarios.postgresql_failure_recovery == "missing"
    ' "$report" >/dev/null
  done
  printf 'component-load reports: %s\n' "$directory"
}

verify_deployment_runtime() {
  require_command docker
  cd "$root"
  scripts/compose-smoke.sh
  docker buildx build --check -f packaging/docker/peerward.Dockerfile .
  docker buildx build --check -f packaging/docker/console.Dockerfile .
  cargo build --locked -p peerward-cli --bin peerward
  cargo build --locked -p peerward-console --features ssr --bin peerward-console
  if command -v systemd-analyze >/dev/null 2>&1; then
    local stage
    stage=$(mktemp -d "${TMPDIR:-/tmp}/peerward-systemd.XXXXXXXX")
    PEERWARD_LOCAL_CLEANUP_PATH=$stage
    trap cleanup_local_path EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir -p "$stage/usr/bin" "$stage/etc/systemd/system" "$stage/etc/peerward"
    install -m 0755 "$root/target/debug/peerward" \
      "$root/target/debug/peerward-console" "$stage/usr/bin/"
    install -m 0644 "$root"/deploy/systemd/*.service "$stage/etc/systemd/system/"
    local sysinit_unit=
    for sysinit_unit in \
      /usr/lib/systemd/system/sysinit.target /lib/systemd/system/sysinit.target
    do
      [[ -f "$sysinit_unit" ]] && break
      sysinit_unit=
    done
    [[ -n "$sysinit_unit" ]] || {
      echo "systemd sysinit.target was not found" >&2
      return 69
    }
    install -m 0644 "$sysinit_unit" "$stage/etc/systemd/system/sysinit.target"
    : >"$stage/etc/peerward/control.toml"
    : >"$stage/etc/peerward/relay.toml"
    : >"$stage/etc/peerward/peer.toml"
    : >"$stage/etc/peerward/update.toml"
    systemd-analyze verify --root="$stage" "$stage"/etc/systemd/system/*.service
    rm -rf -- "$stage"
    PEERWARD_LOCAL_CLEANUP_PATH=
    trap - EXIT INT TERM
  fi
}

case "$mode" in
  standard) verify_standard ;;
  privileged-network) verify_privileged_network ;;
  console-e2e) verify_console_e2e ;;
  android-web) verify_android_web ;;
  wcag-visual) verify_wcag_visual ;;
  android-target) verify_android_target "$@" ;;
  android-emulator) verify_android_emulator "$@" ;;
  fuzz-smoke) verify_fuzz_smoke ;;
  nightly) verify_nightly "$@" ;;
  component-load) verify_component_load ;;
  deployment-runtime) verify_deployment_runtime ;;
  full)
    verify_standard
    verify_privileged_network
    verify_wcag_visual
    verify_fuzz_smoke
    verify_component_load
    verify_deployment_runtime
    ;;
  *)
    echo "usage: scripts/local-ci.sh [standard|privileged-network|console-e2e|android-web|wcag-visual|android-target API_LEVEL|android-emulator API_LEVEL|fuzz-smoke|nightly fuzz|miri|coverage|component-load|deployment-runtime|full]" >&2
    exit 64
    ;;
esac
