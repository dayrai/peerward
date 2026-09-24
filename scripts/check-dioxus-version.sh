#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
expected=0.7.10

versions=$(awk '
  /^name = "dioxus/ { name = $3; gsub(/"/, "", name) }
  name != "" && /^version = / { version = $3; gsub(/"/, "", version); print name " " version; name = "" }
' "$root/Cargo.lock")

test -n "$versions"
unexpected=$(printf '%s\n' "$versions" | awk -v expected="$expected" '$2 != expected')
if [ -n "$unexpected" ]; then
  echo "all Dioxus crates must resolve to exactly $expected:" >&2
  printf '%s\n' "$unexpected" >&2
  exit 1
fi

grep -Eq '^dioxus = \{ package = "peerward-dioxus", path = ' "$root/Cargo.toml"
for dependency in dioxus-core dioxus-core-macro dioxus-config-macros dioxus-hooks dioxus-html dioxus-signals dioxus-stores dioxus-ssr dioxus-fullstack-core dioxus-router dioxus-web; do
  grep -Eq "^$dependency = .*\"=$expected\"" "$root/Cargo.toml"
done
if grep -Eq '^name = "(dioxus-desktop|webkit2gtk|gtk|wry)"$' "$root/Cargo.lock"; then
  echo "Desktop WebView dependency found in Cargo.lock" >&2
  exit 1
fi
