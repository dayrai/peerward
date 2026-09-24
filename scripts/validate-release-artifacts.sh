#!/bin/sh
set -eu

mode=${1:-}
directory=${1:-dist}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
repository=ghcr.io/dayrai/peerward

# The release contract deliberately uses one GHCR repository. Role identity is
# carried only by immutable versioned tag suffixes; split repositories and
# mutable tags would make signing and deployment selection ambiguous.
for role in control relay console; do
  grep -Fq "tags = [\"$repository:\${VERSION}-$role\"]" \
    "$root/packaging/docker/docker-bake.hcl"
done
grep -Eq 'image: postgres:18-alpine@sha256:[0-9a-f]{64}' "$root/compose.yaml"
grep -Eq '^# syntax=docker/dockerfile:[^@]+@sha256:[0-9a-f]{64}$' \
  "$root/packaging/docker/peerward.Dockerfile"
grep -Eq '^# syntax=docker/dockerfile:[^@]+@sha256:[0-9a-f]{64}$' \
  "$root/packaging/docker/console.Dockerfile"
grep -Fq "target: control" "$root/compose.yaml"
grep -Fq "target: relay" "$root/compose.yaml"
grep -Fq "target: console" "$root/compose.yaml"
if grep -ER 'ghcr\.io/dayrai/peerward-(control|relay|console)' \
  "$root/packaging" "$root/deploy/cloud-local" \
  "$root/README.md" "$root/docs"; then
  echo "split Peerward GHCR repository found" >&2
  exit 1
fi
if [ "$mode" = --repository-only ]; then
  exit 0
fi

test -s "$directory/SHA256SUMS"
test -s "$directory/SHA256SUMS.bundle"
(cd "$directory" && sha256sum --check SHA256SUMS)
command -v cosign >/dev/null 2>&1
if test -s "$directory/SHA256SUMS.pub"; then
  cosign verify-blob --key "$directory/SHA256SUMS.pub" \
    --bundle "$directory/SHA256SUMS.bundle" "$directory/SHA256SUMS" >/dev/null
else
  : "${PEERWARD_COSIGN_CERTIFICATE_IDENTITY:?keyless checksum verification identity is required}"
  : "${PEERWARD_COSIGN_CERTIFICATE_OIDC_ISSUER:?keyless checksum verification issuer is required}"
  cosign verify-blob --bundle "$directory/SHA256SUMS.bundle" \
    --certificate-identity "$PEERWARD_COSIGN_CERTIFICATE_IDENTITY" \
    --certificate-oidc-issuer "$PEERWARD_COSIGN_CERTIFICATE_OIDC_ISSUER" \
    "$directory/SHA256SUMS" >/dev/null
fi
version=$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["product_version"])' "$root/release.toml")
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  binary="$directory/peerward-$version-$target"
  archive="$binary.tar.gz"
  test -s "$binary"
  test -s "$archive"
  tar -tzf "$archive" | grep -Fq "peerward-$version-$target/bin/peerward"
done
test -s "$directory/peerward-console-web-$version.tar.gz"
tar -tzf "$directory/peerward-console-web-$version.tar.gz" | grep -q '^dist/'
test -s "$directory/peerward-android.apk"
test -s "$directory/peerward-android.aab"
find "$directory" -maxdepth 1 -type f -name '*.deb' -print | grep -q .
find "$directory" -maxdepth 1 -type f -name '*.rpm' -print | grep -q .
find "$directory" -maxdepth 1 -type f -name '*.apk' ! -name 'peerward-android.apk' -print | grep -q .
find "$directory" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.tgz' \) -print |
while IFS= read -r archive; do
  if tar -tzf "$archive" | grep -E '(^/|(^|/)\.\./)' >/dev/null; then
    echo "unsafe archive path in $archive" >&2
    exit 1
  fi
done
test -s "$directory/release-manifest.json"
test -s "$directory/release-manifest.sig"
test -s "$directory/release-evidence.json"
test -s "$directory/release-notes-gates.md"
artifact_set_sha256=$(sha256sum "$directory/SHA256SUMS" | cut -d' ' -f1)
python3 "$root/scripts/validate-release-evidence.py" \
  "$directory/release-evidence.json" \
  --artifact-set-sha256 "$artifact_set_sha256"
python3 - "$directory" "$root/release.toml" <<'PY'
import hashlib
import json
import pathlib
import sys
import tomllib

directory = pathlib.Path(sys.argv[1])
release = tomllib.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
manifest = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8"))
if manifest["version"] != release["product_version"]:
    raise SystemExit("manifest product version drift")
if manifest["rollback_floor"] != release["rollback_floor"]:
    raise SystemExit("manifest rollback floor drift")
if manifest["channel"] != release["channel"]:
    raise SystemExit("manifest release channel drift")
if "-" in release["product_version"] and manifest["channel"] == "stable":
    raise SystemExit("a prerelease cannot produce a stable manifest")
if manifest["schema_version"] != 1:
    raise SystemExit("manifest format version drift")
schema = manifest["schema_compatibility"]
if schema != {"min": release["schema_version"], "max": release["schema_version"]}:
    raise SystemExit("manifest Schema compatibility drift")
wire = manifest["wire_compatibility"]
if wire != {"min": release["wire_major"], "max": release["wire_major"]}:
    raise SystemExit("manifest Wire compatibility drift")
artifacts = manifest.get("artifacts")
if not isinstance(artifacts, list) or len(artifacts) != 2:
    raise SystemExit("manifest must contain exactly two Linux artifacts")
expected_names = {
    f"peerward-{release['product_version']}-x86_64-unknown-linux-gnu",
    f"peerward-{release['product_version']}-aarch64-unknown-linux-gnu",
}
if {artifact.get("name") for artifact in artifacts} != expected_names:
    raise SystemExit("manifest Linux artifact set is incomplete or ambiguous")
for artifact in artifacts:
    path = directory / artifact["name"]
    body = path.read_bytes()
    if artifact["size"] != len(body):
        raise SystemExit(f"manifest size mismatch: {path.name}")
    if artifact["sha256"] != hashlib.sha256(body).hexdigest():
        raise SystemExit(f"manifest digest mismatch: {path.name}")
PY
