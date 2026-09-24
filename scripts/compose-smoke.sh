#!/bin/sh
set -eu
repository=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
# Release identity is checked by the metadata synchronizer and image validator.
# ghcr.io/dayrai/peerward:0.1.0-control
# ghcr.io/dayrai/peerward:0.1.0-relay
output=${PEERWARD_SMOKE_OUTPUT:-/tmp/peerward-dynamic-smoke-$$}
exec python3 scripts/dynamic-mesh/fixed-containers.py --output "$output" --cycles 3 --simultaneous 3 "$@"
