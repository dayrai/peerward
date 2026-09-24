#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Physical gates use the isolated Wire 5 backend and separate validation app.
# The old Compose/bootstrap path read the live root .env and exercised USB Relay
# forwarding; neither is appropriate evidence for real protected Network sockets.
for argument in "$@"; do
  case "$argument" in
    -h|--help)
      exec python3 "$root/scripts/test-android-wireguard.py" --help ;;
    --network-profile|--passed-scenario|--artifact-set-sha256|--no-evidence)
      echo "Legacy physical-runner flags were retired; use --serial and --lan-address. Observed evidence is always retained; signed release review remains separate." >&2
      exit 64 ;;
  esac
done
ANDROID_HOME=${ANDROID_HOME:?ANDROID_HOME must point to the Android SDK} \
  "$root/apps/peerward-android/gradlew" -p "$root/apps/peerward-android" \
    --no-daemon -Pkotlin.compiler.execution.strategy=in-process \
    -PpeerwardValidation=true assembleDebug assembleDebugAndroidTest
exec python3 "$root/scripts/test-android-wireguard.py" --allow-physical --validation-app "$@"
