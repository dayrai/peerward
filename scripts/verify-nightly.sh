#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:-all}
duration=${PEERWARD_FUZZ_SECONDS:-600}
output=${PEERWARD_NIGHTLY_OUTPUT:-$root/artifacts/nightly}

case "$duration" in
  ''|*[!0-9]*) echo "PEERWARD_FUZZ_SECONDS must be a positive integer" >&2; exit 64 ;;
esac
(( duration > 0 )) || { echo "PEERWARD_FUZZ_SECONDS must be positive" >&2; exit 64; }
mkdir -p "$output"
cd "$root"

run_fuzz() {
  local target before_manifest after_manifest
  python3 "$root/scripts/seed-fuzz-corpus.py"
  before_manifest="$output/fuzz-corpus-before.sha256"
  after_manifest="$output/fuzz-corpus-after.sha256"
  printf 'fuzz configuration: 7 targets, %s seconds per target, ASan, timeout=5s\n' "$duration"
  cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null
  for target in \
    credential_codecs gateway_mapping_codecs packet_and_directory \
    v2_documents wire_reassembly_update wireguard_and_stun quic_fragments
  do
    [[ -n "$(find "fuzz/corpus/$target" -maxdepth 1 -type f -print -quit)" ]] || {
      echo "fuzz corpus is empty: $target" >&2
      exit 66
    }
  done
  find fuzz/corpus -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum \
    >"$before_manifest"
  printf 'fuzz corpus before: %s files, manifest SHA-256 %s\n' \
    "$(wc -l <"$before_manifest")" "$(sha256sum "$before_manifest" | cut -d' ' -f1)"
  for target in \
    credential_codecs gateway_mapping_codecs packet_and_directory \
    v2_documents wire_reassembly_update wireguard_and_stun quic_fragments
  do
    cargo +nightly fuzz run --sanitizer address "$target" -- \
      -max_total_time="$duration" -timeout=5
  done
  find fuzz/corpus -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum \
    >"$after_manifest"
  printf 'fuzz corpus after: %s files, manifest SHA-256 %s\n' \
    "$(wc -l <"$after_manifest")" "$(sha256sum "$after_manifest" | cut -d' ' -f1)"
}

run_miri() {
  printf 'Miri scope: peerward-types, peerward-policy, peerward-dataplane\n'
  cargo +nightly miri setup
  cargo +nightly miri test --locked \
    -p peerward-types -p peerward-policy -p peerward-dataplane
}

run_coverage() {
  rustup component add llvm-tools-preview
  cargo llvm-cov --locked --workspace --all-targets \
    --lcov --output-path "$output/lcov.info"
  cargo llvm-cov report --summary-only | awk '/^TOTAL/ {print "coverage summary: " $0}'
  printf 'LCOV SHA-256: '
  sha256sum "$output/lcov.info" | cut -d' ' -f1
}

case "$mode" in
  fuzz) run_fuzz ;;
  miri) run_miri ;;
  coverage) run_coverage ;;
  all) run_fuzz; run_miri; run_coverage ;;
  *) echo "usage: scripts/verify-nightly.sh [fuzz|miri|coverage|all]" >&2; exit 64 ;;
esac
