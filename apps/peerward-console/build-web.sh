#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$workspace"

cargo build --locked --release -p peerward-console --no-default-features --features web \
  --target wasm32-unknown-unknown --bin peerward-console-web
wasm-bindgen \
  target/wasm32-unknown-unknown/release/peerward-console-web.wasm \
  --target web \
  --out-dir apps/peerward-console/dist \
  --out-name peerward-console-web
cp apps/peerward-console/assets/main.css apps/peerward-console/dist/main.css
