#!/bin/sh
set -eu
if [ "${1:-}" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop peerward-control.service peerward-relay.service peerward-peer.service peerward-console.service || true
fi
