#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
api=${1:-}
case "$api" in
  28|36) ;;
  *) echo "usage: scripts/run-android-emulator.sh 28|36" >&2; exit 64 ;;
esac

android_sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
[[ -n "$android_sdk" ]] || {
  echo "ANDROID_HOME or ANDROID_SDK_ROOT is required" >&2
  exit 69
}
for command_path in \
  "$android_sdk/emulator/emulator" \
  "$android_sdk/platform-tools/adb" \
  "$android_sdk/cmdline-tools/latest/bin/avdmanager"
do
  [[ -x "$command_path" ]] || {
    echo "required Android SDK command is missing: $command_path" >&2
    exit 69
  }
done

if [[ -n "${PEERWARD_ANDROID_SYSTEM_IMAGE_TAG:-}" ]]; then
  image_tag=$PEERWARD_ANDROID_SYSTEM_IMAGE_TAG
elif [[ "$api" == 28 ]]; then
  image_tag=google_apis_playstore
else
  image_tag=google_apis
fi
package="system-images;android-$api;$image_tag;x86_64"
image="$android_sdk/system-images/android-$api/$image_tag/x86_64"
[[ -d "$image" ]] || {
  echo "Android system image is missing: $package" >&2
  echo "install it with: sdkmanager '$package'" >&2
  exit 69
}

# Finish CPU/memory-heavy compilation before booting the disposable emulator.
# A heavily stalled emulator can lose wall-clock synchronization during linking;
# that is a clock failure, not evidence of a bad credential signature.
"$root/apps/peerward-android/gradlew" -p "$root/apps/peerward-android" \
  --no-daemon -Pkotlin.compiler.execution.strategy=in-process \
  -PpeerwardValidation=true assembleDebug assembleDebugAndroidTest
(cd "$root" && cargo build --locked -p peerward-cli)

stage=$(mktemp -d "${TMPDIR:-/tmp}/peerward-avd-$api.XXXXXXXX")
avd_home="$stage/avd"
mkdir -p "$avd_home"
name="peerward-api-$api-$$"
port=
for candidate in $(seq 5554 2 5682); do
  if ! "$android_sdk/platform-tools/adb" devices | awk 'NR > 1 {print $1}' \
    | grep -Fqx "emulator-$candidate"
  then
    port=$candidate
    break
  fi
done
[[ -n "$port" ]] || {
  echo "no free Android emulator console port" >&2
  exit 75
}
serial="emulator-$port"
emulator_pid=

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  local owned_name
  owned_name=$("$android_sdk/platform-tools/adb" -s "$serial" emu avd name 2>/dev/null | head -n 1 | tr -d '\r' || true)
  if [[ "$owned_name" == "$name" ]]; then
    "$android_sdk/platform-tools/adb" -s "$serial" emu kill >/dev/null 2>&1 || true
  fi
  if [[ -n "$emulator_pid" ]]; then
    kill "$emulator_pid" >/dev/null 2>&1 || true
    wait "$emulator_pid" >/dev/null 2>&1 || true
  fi
  if (( status != 0 )) && [[ -s "$stage/emulator.log" ]]; then
    tail -n 120 "$stage/emulator.log" >&2
  fi
  rm -rf -- "$stage"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ANDROID_AVD_HOME="$avd_home" \
  printf 'no\n' | ANDROID_AVD_HOME="$avd_home" \
  "$android_sdk/cmdline-tools/latest/bin/avdmanager" create avd --force \
    --name "$name" --package "$package" --device pixel_2 >/dev/null

cat >>"$avd_home/$name.avd/config.ini" <<'EOF'
disk.dataPartition.size=4096M
hw.gpu.enabled=yes
hw.keyboard=yes
hw.ramSize=3072
showDeviceFrame=no
EOF

ANDROID_AVD_HOME="$avd_home" \
  "$android_sdk/emulator/emulator" -avd "$name" -port "$port" \
    -no-window -no-audio -no-boot-anim -no-snapshot -wipe-data \
    -gpu swiftshader_indirect -no-metrics >"$stage/emulator.log" 2>&1 &
emulator_pid=$!

deadline=$((SECONDS + 420))
while (( SECONDS < deadline )); do
  if ! kill -0 "$emulator_pid" 2>/dev/null; then
    echo "Android emulator exited before boot completed" >&2
    exit 70
  fi
  state=$("$android_sdk/platform-tools/adb" -s "$serial" get-state 2>/dev/null || true)
  booted=$("$android_sdk/platform-tools/adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)
  [[ "$state" == device && "$booted" == 1 ]] && break
  sleep 2
done
[[ "${booted:-}" == 1 ]] || {
  echo "Android API $api emulator did not boot within 420 seconds" >&2
  exit 70
}

owned_name=$("$android_sdk/platform-tools/adb" -s "$serial" emu avd name 2>/dev/null | head -n 1 | tr -d '\r')
[[ "$owned_name" == "$name" ]] || { echo "emulator identity differs from this disposable fixture" >&2; exit 65; }

# A cold virtual-device boot can leave its RTC behind the host even without
# concurrent compilation. Synchronize only this newly created debuggable AVD,
# before installing any identity. Physical devices and production trust checks
# are untouched. The gate records host/device clock observations throughout.
if [[ "$image_tag" == google_apis ]]; then
  # adbd may close the transport while switching uid; verify the resulting uid.
  "$android_sdk/platform-tools/adb" -s "$serial" root >/dev/null 2>&1 || true
  timeout 30 "$android_sdk/platform-tools/adb" -s "$serial" wait-for-device
  [[ $("$android_sdk/platform-tools/adb" -s "$serial" shell id -u | tr -d '\r') == 0 ]] || {
    echo 'Disposable google_apis image could not synchronize its clock.' >&2
    exit 69
  }
  "$android_sdk/platform-tools/adb" -s "$serial" shell settings put global auto_time 0
  "$android_sdk/platform-tools/adb" -s "$serial" shell date -u "$(date -u +%m%d%H%M%Y.%S)"
fi

"$android_sdk/platform-tools/adb" -s "$serial" shell input keyevent 82 >/dev/null
for scale in window_animation_scale transition_animation_scale animator_duration_scale; do
  "$android_sdk/platform-tools/adb" -s "$serial" shell settings put global "$scale" 0
done
"$android_sdk/platform-tools/adb" -s "$serial" shell settings put global verifier_verify_adb_installs 0 || true

echo "Android API $api emulator booted; running the real backend instrumentation target."
webview_package=$("$android_sdk/platform-tools/adb" -s "$serial" shell dumpsys webviewupdate 2>/dev/null \
  | awk '/Current WebView package/ {sub(/^[[:space:]]*/, ""); print; exit}' | tr -d '\r')
printf 'Android WebView provider: %s\n' "${webview_package:-unknown}"
ANDROID_SERIAL="$serial" "$root/scripts/local-ci.sh" android-target "$api"
