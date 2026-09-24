#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target=${1:?target triple required}
version=$(python3 "$root/scripts/release-version.py" "${2:?version required}")
case "$target" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo 'unsupported release target' >&2; exit 64 ;;
esac
output=${3:-$root/dist}
epoch=${SOURCE_DATE_EPOCH:-0}
case "$epoch" in
  ''|*[!0-9]*) echo 'SOURCE_DATE_EPOCH must be a non-negative integer' >&2; exit 64 ;;
esac
mkdir -p -- "$output"
output=$(CDPATH= cd -- "$output" && pwd)
name="peerward-$version-$target"
destination="$output/$name.tar.gz"
if [ -e "$destination" ] || [ -L "$destination" ]; then
  echo 'release archive already exists' >&2
  exit 73
fi
temporary=$(mktemp -d "$output/.archive.XXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage="$temporary/$name"

cd "$root"
mkdir -p "$stage/bin" "$stage/share/doc/peerward"
install -m 0755 "target/$target/release/peerward" "$stage/bin/peerward"
if [ -x "target/$target/release/peerward-console" ]; then
  install -m 0755 "target/$target/release/peerward-console" "$stage/bin/peerward-console"
fi
install -m 0644 LICENSE README.md "$stage/share/doc/peerward/"
cp -R third_party "$stage/share/doc/peerward/third_party"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
  -C "$temporary" -czf "$temporary/archive.tar.gz" "$name"
# Publish only a complete archive, without replacing a concurrent writer's file.
ln -- "$temporary/archive.tar.gz" "$destination"
