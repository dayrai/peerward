#!/bin/sh
set -eu
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/peerward.conf
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/peerward.conf
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
