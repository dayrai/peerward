#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:-help}
output=${2:-$root/dist}
output=$(realpath -m -- "$output")

case "$output" in
  /|"$root") echo "release output must be a dedicated child directory" >&2; exit 64 ;;
esac

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required for local release stage '$mode'" >&2
    exit 69
  }
}

require_clean_commit() {
  git -C "$root" diff --quiet
  git -C "$root" diff --cached --quiet
  [[ -z "$(git -C "$root" status --porcelain --untracked-files=normal)" ]] || {
    echo "release assembly requires a clean committed worktree" >&2
    exit 65
  }
}

release_value() {
  python3 -c \
    'import sys,tomllib; print(tomllib.load(open(sys.argv[1], "rb"))[sys.argv[2]])' \
    "$root/release.toml" "$1"
}

prepare() {
  require_clean_commit
  require_command cargo
  require_command rustup
  require_command jq
  require_command nfpm
  require_command syft
  require_command java
  : "${PEERWARD_ANDROID_KEYSTORE:?protected Android keystore path is required}"
  : "${PEERWARD_ANDROID_KEY_ALIAS:?Android key alias is required}"
  : "${PEERWARD_ANDROID_STORE_PASSWORD:?Android keystore password is required}"
  : "${PEERWARD_ANDROID_KEY_PASSWORD:?Android key password is required}"
  : "${PEERWARD_UPDATE_SIGNING_KEY_FILE:?updater private-key file is required}"
  [[ -f "$PEERWARD_ANDROID_KEYSTORE" && -f "$PEERWARD_UPDATE_SIGNING_KEY_FILE" ]] || {
    echo "release signing key files are missing" >&2
    exit 66
  }
  mkdir -p "$output"
  [[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "artifact stage requires an empty output directory: $output" >&2
    exit 73
  }
}

build_artifacts() {
  prepare
  cd "$root"
  local version epoch target arch binary name size digest artifacts
  version=$(python3 "$root/scripts/release-version.py" "$(release_value product_version)")
  epoch=$(git show -s --format=%ct HEAD)
  export VERSION="$version" SOURCE_DATE_EPOCH="$epoch"

  if [[ "${PEERWARD_SKIP_LOCAL_VERIFY:-0}" == 1 && "$(release_value channel)" == stable ]]; then
    echo "stable release artifact assembly cannot skip local verification" >&2
    exit 65
  fi
  if [[ "${PEERWARD_SKIP_LOCAL_VERIFY:-0}" != 1 ]]; then
    scripts/local-ci.sh standard
  fi

  rustup target list --installed | grep -Fxq x86_64-unknown-linux-gnu
  rustup target list --installed | grep -Fxq aarch64-unknown-linux-gnu
  require_command aarch64-linux-gnu-gcc
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
  for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
    cargo build --locked --release --target "$target" \
      -p peerward-cli -p peerward-console --features peerward-console/ssr
    scripts/release-archive.sh "$target" "$version" "$output"
    install -m 0755 "target/$target/release/peerward" \
      "$output/peerward-$version-$target"
  done

  cargo build --locked --release -p peerward-cli \
    -p peerward-console --features peerward-console/ssr
  apps/peerward-console/build-web.sh
  ARCH=amd64 nfpm package --config packaging/nfpm/peerward-deb.yaml \
    --packager deb --target "$output/"
  ARCH=x86_64 nfpm package --config packaging/nfpm/peerward-rpm.yaml \
    --packager rpm --target "$output/"
  ARCH=x86_64 nfpm package --config packaging/nfpm/peerward-apk.yaml \
    --packager apk --target "$output/"
  tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    -C apps/peerward-console -czf "$output/peerward-console-web-$version.tar.gz" dist

  (
    cd apps/peerward-android
    ./gradlew --no-daemon lintRelease testDebugUnitTest assembleRelease bundleRelease
  )
  install -m 0644 apps/peerward-android/app/build/outputs/apk/release/app-release.apk \
    "$output/peerward-android.apk"
  install -m 0644 apps/peerward-android/app/build/outputs/bundle/release/app-release.aab \
    "$output/peerward-android.aab"
  local apksigner_path
  apksigner_path=$(find "${ANDROID_HOME:?ANDROID_HOME is required}" \
    -type f -name apksigner -print | sort -V | tail -n 1)
  [[ -n "$apksigner_path" ]]
  "$apksigner_path" verify --verbose --print-certs "$output/peerward-android.apk"
  jarsigner -verify "$output/peerward-android.aab" >/dev/null
  scripts/verify-android-native-artifacts.py release "$output/peerward-android.apk"
  scripts/verify-android-native-artifacts.py release "$output/peerward-android.aab"

  artifacts='[]'
  for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
    binary="$output/peerward-$version-$target"
    name=$(basename "$binary")
    arch=${target%%-*}
    size=$(stat -c %s "$binary")
    digest=$(sha256sum "$binary" | cut -d' ' -f1)
    local base_url=${PEERWARD_RELEASE_BASE_URL:-https://github.com/dayrai/peerward/releases/download/v$version}
    artifacts=$(jq \
      --arg platform linux --arg architecture "$arch" --arg name "$name" \
      --arg url "$base_url/$name" --arg sha "$digest" --argjson size "$size" \
      '. + [{platform:$platform,architecture:$architecture,kind:"binary",name:$name,url:$url,sha256:$sha,size:$size}]' \
      <<<"$artifacts")
  done
  local sequence=${PEERWARD_RELEASE_SEQUENCE:?monotonic PEERWARD_RELEASE_SEQUENCE is required}
  [[ "$sequence" =~ ^[1-9][0-9]*$ ]] || {
    echo "PEERWARD_RELEASE_SEQUENCE must be a positive integer" >&2
    exit 64
  }
  local published expires schema wire floor channel
  published=$(date +%s)
  expires=$((published + 2592000))
  schema=$(release_value schema_version)
  wire=$(release_value wire_major)
  floor=$(release_value rollback_floor)
  channel=$(release_value channel)
  jq -cn \
    --arg version "$version" --arg channel "$channel" --arg floor "$floor" \
    --argjson schema "$schema" --argjson wire "$wire" --argjson sequence "$sequence" \
    --argjson published "$published" --argjson expires "$expires" \
    --argjson artifacts "$artifacts" \
    '{schema_version:1,sequence:$sequence,version:$version,channel:$channel,published_at:$published,expires_at:$expires,schema_compatibility:{min:$schema,max:$schema},wire_compatibility:{min:$wire,max:$wire},rollback_floor:$floor,artifacts:$artifacts}' \
    >"$output/release-manifest.json"
  cargo run --locked -p peerward-cli -- update sign-manifest \
    --manifest "$output/release-manifest.json" \
    --private-key "$PEERWARD_UPDATE_SIGNING_KEY_FILE" \
    --output "$output/release-manifest.sig"

  jq -cn \
    --arg commit "$(git rev-parse HEAD)" --arg version "$version" \
    --arg rustc "$(rustc --version)" --arg cargo "$(cargo --version)" \
    --arg java "$(java --version 2>&1 | head -n 1)" \
    --arg gradle "$(apps/peerward-android/gradlew --version | awk '/^Gradle / {print; exit}')" \
    --arg host "$(uname -srmo)" \
    '{schema_version:1,commit_sha:$commit,product_version:$version,environment:{host:$host},tool_versions:{rustc:$rustc,cargo:$cargo,java:$java,gradle:$gradle}}' \
    >"$output/build-metadata.json"
  syft "dir:$output" -o "spdx-json=$output/peerward-release.spdx.json"
  (
    cd "$output"
    find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' \
      ! -name 'release-evidence.json' ! -name 'release-notes-gates.md' \
      ! -name 'evidence-*.json' ! -name 'evidence-*.bundle' \
      -printf '%P\n' | LC_ALL=C sort | xargs sha256sum >SHA256SUMS
  )
  printf 'artifact_set_sha256=%s\n' "$(sha256sum "$output/SHA256SUMS" | cut -d' ' -f1)"
  printf 'Next: create independently reviewed evidence bound to this digest, then run:\n'
  printf '  scripts/release-local.sh finalize %q\n' "$output"
}

finalize_release() {
  require_clean_commit
  require_command cosign
  require_command jq
  [[ -s "$output/SHA256SUMS" ]] || {
    echo "release artifact inventory is missing: $output/SHA256SUMS" >&2
    exit 66
  }
  (cd "$output" && sha256sum --check SHA256SUMS)
  local commit artifact_set
  commit=$(git -C "$root" rev-parse HEAD)
  artifact_set=$(sha256sum "$output/SHA256SUMS" | cut -d' ' -f1)
  jq --arg commit "$commit" --arg artifacts "$artifact_set" \
    '.release.commit_sha=$commit | .release.artifact_set_sha256=$artifacts' \
    "$root/release/release-evidence.preview.json" >"$output/release-evidence.json"
  python3 "$root/scripts/stage-release-evidence.py" \
    "$output/release-evidence.json" "$root/release" "$output"
  python3 "$root/scripts/validate-release-evidence.py" \
    "$output/release-evidence.json" --commit "$commit" \
    --artifact-set-sha256 "$artifact_set" --notes "$output/release-notes-gates.md"
  if [[ -n "${PEERWARD_COSIGN_KEY:-}" ]]; then
    cosign sign-blob --yes --key "$PEERWARD_COSIGN_KEY" \
      --bundle "$output/SHA256SUMS.bundle" "$output/SHA256SUMS"
    cosign public-key --key "$PEERWARD_COSIGN_KEY" \
      --outfile "$output/SHA256SUMS.pub"
  else
    cosign sign-blob --yes --bundle "$output/SHA256SUMS.bundle" \
      "$output/SHA256SUMS"
  fi
  "$root/scripts/validate-release-artifacts.sh" "$output"
  printf 'local release bundle validated at %s\n' "$output"
  printf 'No artifact or image was uploaded. Publishing remains a separate operator action.\n'
}

build_images() {
  require_clean_commit
  require_command docker
  mkdir -p "$output"
  local version epoch role
  version=$(python3 "$root/scripts/release-version.py" "$(release_value product_version)")
  epoch=$(git -C "$root" show -s --format=%ct HEAD)
  cd "$root"
  for role in control relay console; do
    VERSION="$version" SOURCE_DATE_EPOCH="$epoch" docker buildx bake \
      -f packaging/docker/docker-bake.hcl "$role" \
      --set "$role.output=type=oci,dest=$output/peerward-$version-$role.oci.tar"
  done
  printf 'OCI image archives created locally; none were pushed or signed.\n'
}

case "$mode" in
  artifacts) build_artifacts ;;
  finalize) finalize_release ;;
  images) build_images ;;
  help|-h|--help)
    cat <<'EOF'
usage: scripts/release-local.sh STAGE [OUTPUT]
  artifacts  verify and build the normalized Linux/Android release artifact set
  finalize   bind/stage evidence, sign SHA256SUMS, and validate the final bundle
  images     build multi-platform OCI archives locally without publishing

Required signing variables are documented in docs/release-evidence.md.
This command never creates a GitHub release and never pushes an image.
EOF
    ;;
  *) echo "unknown local release stage: $mode" >&2; exit 64 ;;
esac
