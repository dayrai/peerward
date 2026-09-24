#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:-core}
PEERWARD_VERIFY_CLEANUP_PATH=

cleanup_verify_path() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$PEERWARD_VERIFY_CLEANUP_PATH" ]]; then
    rm -rf -- "$PEERWARD_VERIFY_CLEANUP_PATH"
    PEERWARD_VERIFY_CLEANUP_PATH=
  fi
  return "$status"
}

show_versions() {
  rustc --version
  cargo --version
  python3 --version
  git --version
}

verify_core() {
  show_versions
  cd "$root"
  sha256sum --check SPEC.lock
  python3 scripts/sync-release-metadata.py --check
  python3 scripts/test-release-metadata.py
  python3 scripts/test-release-archive.py
  python3 scripts/test-release-evidence.py
  python3 scripts/test-stability-lab.py
  python3 scripts/test-wireguard-gate-state.py
  python3 scripts/test-compose-bootstrap.py
  python3 scripts/test-deployment-preflight.py
  python3 scripts/validate-release-evidence.py release/release-evidence.preview.json
  python3 scripts/check-unsafe-boundary.py
  python3 scripts/check-observability-assets.py
  python3 scripts/test-documentation.py
  python3 scripts/check-documentation.py
  scripts/check-dioxus-version.sh
  cargo fmt --all -- --check
  scripts/check-source-size.sh
  local isolated_target
  isolated_target=$(mktemp -d "${TMPDIR:-/tmp}/peerward-clippy.XXXXXXXX")
  PEERWARD_VERIFY_CLEANUP_PATH=$isolated_target
  trap cleanup_verify_path EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  CARGO_TARGET_DIR="$isolated_target" \
    cargo clippy --locked --workspace --all-targets -- -D warnings
  cargo test --locked --workspace --all-targets
  cargo test --locked --workspace --doc
  cargo build --locked -p peerward-console --features ssr
  rm -rf -- "$isolated_target"
  PEERWARD_VERIFY_CLEANUP_PATH=
  trap - EXIT INT TERM
}

verify_postgres() {
  cd "$root"
  : "${PEERWARD_TEST_DATABASE_URL:?PEERWARD_TEST_DATABASE_URL is required}"
  cargo test --locked -p peerward-store --features postgres-integration --test postgres
  cargo test --locked -p peerward-store --features postgres-integration --test postgres_provision
  cargo test --locked -p peerward-store --features postgres-integration --test postgres_presence
  cargo test --locked -p peerward-store --features postgres-integration \
    --test postgres_scale -- --test-threads=1
  cargo test --locked -p peerward-control --features postgres-integration --lib
  cargo test --locked -p peerward-control --features postgres-integration --test network_management_postgres
  cargo test --locked -p peerward-control --features postgres-integration --test join_postgres
  cargo test --locked -p peerward-control --features postgres-integration --test controlled_join_postgres
  cargo test --locked -p peerward-control --features postgres-integration --test peer_delete_postgres
  cargo test --locked -p peerward-control --features postgres-integration --test mesh_delete_postgres
  cargo test --locked -p peerward-control --features postgres-integration --test mesh_provisioning_postgres
  cargo test --locked -p peerward-control --features postgres-integration --test oidc_postgres
  cargo test --locked -p peerward-relay --features postgres-integration \
    --test postgres_network -- --test-threads=1
  cargo run --locked -p peerward-cli -- db migrate --database-url "$PEERWARD_TEST_DATABASE_URL"
}

verify_postgres_available() {
  if [[ -n "${PEERWARD_TEST_DATABASE_URL:-}" ]]; then
    verify_postgres
  else
    "$root/scripts/with-postgres.sh" "$root/scripts/verify.sh" postgres
  fi
}

verify_android() {
  cd "$root/apps/peerward-android"
  local android_tasks=(
    lintDebug testDebugUnitTest assembleDebug assembleDebugAndroidTest buildPeerwardNativeRelease
  )
  local signing_count=0
  local variable
  for variable in \
    PEERWARD_ANDROID_KEYSTORE \
    PEERWARD_ANDROID_KEY_ALIAS \
    PEERWARD_ANDROID_STORE_PASSWORD \
    PEERWARD_ANDROID_KEY_PASSWORD
  do
    if [[ -n "${!variable:-}" ]]; then
      signing_count=$((signing_count + 1))
    fi
  done
  if (( signing_count != 0 && signing_count != 4 )); then
    echo "Android release signing variables must be either complete or absent" >&2
    return 1
  fi
  if (( signing_count == 4 )); then
    android_tasks+=(lintRelease assembleRelease bundleRelease)
  fi
  ./gradlew --no-daemon "${android_tasks[@]}"
  cd "$root"
  python3 scripts/verify-android-native-artifacts.py debug \
    apps/peerward-android/app/build/outputs/apk/debug/app-debug.apk
  python3 scripts/verify-android-web-assets.py \
    apps/peerward-android/app/build/outputs/apk/debug/app-debug.apk
  test -f apps/peerward-android/app/build/generated/peerwardJni/release/arm64-v8a/libpeerward_android_core.so
  test -f apps/peerward-android/app/build/generated/peerwardJni/release/x86_64/libpeerward_android_core.so
  if (( signing_count == 4 )); then
    local release_apk=apps/peerward-android/app/build/outputs/apk/release/app-release.apk
    local release_aab=apps/peerward-android/app/build/outputs/bundle/release/app-release.aab
    local apksigner_path
    apksigner_path=$(find "${ANDROID_HOME:?ANDROID_HOME is required}" \
      -type f -name apksigner -print | sort -V | tail -n 1)
    test -n "$apksigner_path"
    "$apksigner_path" verify --verbose "$release_apk"
    # Android application certificates are intentionally self-signed. Verify
    # the AAB's JAR signature integrity without applying the public-CA chain
    # warnings enabled by jarsigner's unrelated -strict mode.
    jarsigner -verify "$release_aab" >/dev/null
    python3 scripts/verify-android-native-artifacts.py release "$release_apk"
    python3 scripts/verify-android-native-artifacts.py release "$release_aab"
  fi
}

verify_supply_chain() {
  cd "$root"
  scripts/audit-dependencies.sh
}

verify_deployment() {
  cd "$root"
  python3 scripts/check-compose-deployment.py
  scripts/validate-release-artifacts.sh --repository-only
}

case "$mode" in
  core) verify_core ;;
  postgres) verify_postgres ;;
  android) verify_android ;;
  supply-chain) verify_supply_chain ;;
  deployment) verify_deployment ;;
  all)
    verify_core
    verify_postgres_available
    verify_android
    verify_supply_chain
    verify_deployment
    ;;
  *)
    echo "usage: scripts/verify.sh [core|postgres|android|supply-chain|deployment|all]" >&2
    exit 2
    ;;
esac
