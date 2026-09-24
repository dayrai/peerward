#!/usr/bin/env python3
"""Synchronize the single Peerward release metadata source into build surfaces."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

from release_metadata import validate_metadata


ROOT = Path(__file__).resolve().parents[1]


def replace(path: str, pattern: str, replacement: str, *, count: int = 0) -> bool:
    target = ROOT / path
    original = target.read_text(encoding="utf-8")
    updated, matches = re.subn(pattern, replacement, original, count=count, flags=re.MULTILINE)
    if matches == 0:
        raise RuntimeError(f"release metadata pattern did not match: {path}: {pattern}")
    if updated == original:
        return False
    if CHECK:
        print(f"release metadata drift: {path}", file=sys.stderr)
    else:
        target.write_text(updated, encoding="utf-8")
    return True


parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true", help="fail without writing when drift exists")
args = parser.parse_args()
CHECK = args.check

metadata = tomllib.loads((ROOT / "release.toml").read_text(encoding="utf-8"))
try:
    validate_metadata(metadata)
except ValueError as error:
    raise SystemExit(str(error)) from error
version = metadata["product_version"]
version_code = metadata["android_version_code"]
schema = metadata["schema_version"]
wire = metadata["wire_major"]
channel = metadata["channel"]

# This file is a template, never a container for evidence from a previous build.
preview = json.loads((ROOT / "release/release-evidence.preview.json").read_text())
if (preview["release"]["commit_sha"] != "0" * 40
        or preview["release"]["artifact_set_sha256"] != "0" * 64
        or any(gate.get("status") != "missing" for gate in preview["gates"].values())):
    raise SystemExit("preview template must contain only unbound missing evidence")

changes = False
changes |= replace(
    "release/release-evidence.preview.json", r'"version": "[^"]+"',
    f'"version": "{version}"', count=1,
)
changes |= replace(
    "release/release-evidence.preview.json", r'"channel": "[^"]+"',
    f'"channel": "{channel}"', count=1,
)
changes |= replace("Cargo.toml", r'^version = "[^"]+"$', f'version = "{version}"', count=1)
changes |= replace(
    "crates/peerward-store/src/lib.rs",
    r"^pub const SCHEMA_VERSION: u32 = [0-9]+;$",
    f"pub const SCHEMA_VERSION: u32 = {schema};",
    count=1,
)
changes |= replace(
    "crates/peerward-wire/src/transport.rs",
    r"^pub const PROTOCOL_MAJOR: u32 = [0-9]+;$",
    f"pub const PROTOCOL_MAJOR: u32 = {wire};",
    count=1,
)
changes |= replace(
    "apps/peerward-android-ui/src/main.rs",
    r'"Wire [0-9]+ · WireGuard"',
    f'"Wire {wire} · WireGuard"',
    count=1,
)
changes |= replace(
    "apps/peerward-android/app/build.gradle.kts",
    r"^\s*versionCode = [0-9]+$",
    f"        versionCode = {version_code}",
    count=1,
)
changes |= replace(
    "apps/peerward-android/app/build.gradle.kts",
    r'^\s*versionName = "[^"]+"$',
    f'        versionName = "{version}"',
    count=1,
)
changes |= replace(
    "compose.yaml", r"peerward-runtime:[^\s]+-control", f"peerward-runtime:{version}-control"
)
changes |= replace(
    "compose.yaml", r"peerward-runtime:[^\s]+-relay", f"peerward-runtime:{version}-relay"
)
changes |= replace(
    "compose.yaml", r"peerward-console:[^\s]+", f"peerward-console:{version}"
)
changes |= replace(
    "packaging/docker/docker-bake.hcl",
    r'^variable "VERSION" \{ default = "[^"]+" \}$',
    f'variable "VERSION" {{ default = "{version}" }}',
    count=1,
)
for dockerfile in ("packaging/docker/peerward.Dockerfile", "packaging/docker/console.Dockerfile"):
    changes |= replace(dockerfile, r"^ARG VERSION=[^\s]+$", f"ARG VERSION={version}")
changes |= replace(
    "README.md",
    r"(Peerward `)[^`]+(` is a clean-install)",
    rf"\g<1>{version}\g<2>",
    count=1,
)
changes |= replace(
    "README.md", r"`[0-9][^`\s]*-(control|relay|console)`",
    lambda match: f"`{version}-{match.group(1)}`",
)
changes |= replace(
    "docs/README.md", r"(当前源码版本为 `)[^`]+(`)",
    rf"\g<1>{version}\g<2>", count=1,
)
changes |= replace(
    "docs/README.md", r"^(\| 发布、数据库兼容、Wire major \| ).*?(：\[release.toml\].*)$",
    rf"\g<1>{version} / {schema} / {wire}\g<2>", count=1,
)
changes |= replace(
    "spec/PRODUCT.md",
    r"(Status: frozen normative input for Peerward `)[^`]+(`\.)",
    rf"\g<1>{version}\g<2>",
    count=1,
)
changes |= replace(
    "spec/ACCEPTANCE.md",
    r"(exact product version `)[^`]+(`\.)",
    rf"\g<1>{version}\g<2>",
    count=1,
)
changes |= replace(
    "docs/deployment.md",
    r"peerward:[^\s`]+-(control|relay|console)",
    lambda match: f"peerward:{version}-{match.group(1)}",
)
changes |= replace(
    "deploy/cloud-local/cloud.compose.yaml",
    r"peerward-runtime:[^\s]+-relay",
    f"peerward-runtime:{version}-relay",
    count=1,
)
changes |= replace(
    "scripts/compose-smoke.sh",
    r"ghcr\.io/dayrai/peerward:[^\s]+-control",
    f"ghcr.io/dayrai/peerward:{version}-control",
    count=1,
)
changes |= replace(
    "deploy/systemd/update.toml",
    r'^channel = "(?:stable|canary)"$',
    f'channel = "{channel}"',
    count=1,
)
changes |= replace(
    "scripts/compose-smoke.sh",
    r"ghcr\.io/dayrai/peerward:[^\s]+-relay",
    f"ghcr.io/dayrai/peerward:{version}-relay",
    count=1,
)
changes |= replace(
    "README.md",
    r"Schema [0-9]+ and Wire major [0-9]+",
    f"Schema {schema} and Wire major {wire}",
    count=1,
)

# Normative release headers describe the authenticated protocol and persistent
# generation. Carrier framing/prologue and device key-record formats are
# independent constants and must not be rewritten just because a release moves.
for path, pattern, replacement in [
    ("spec/PRODUCT.md", r"`protocol_major = [0-9]+`", f"`protocol_major = {wire}`"),
    ("spec/ACCEPTANCE.md", r"Schema [0-9]+, Wire major [0-9]+", f"Schema {schema}, Wire major {wire}"),
    ("spec/PROTOCOL.md", r"^# Peerward Wire v[0-9]+ and WireGuard session specification$", f"# Peerward Wire v{wire} and WireGuard session specification"),
    ("spec/PROTOCOL.md", r"Authenticated Wire major is exactly `[0-9]+`", f"Authenticated Wire major is exactly `{wire}`"),
    ("spec/WIRE_STATE_MACHINE.md", r"exact Wire major [0-9]+", f"exact Wire major {wire}"),
    ("spec/WIREGUARD_CREDENTIALS.md", r"^# Wire [0-9]+ credential and profile contract$", f"# Wire {wire} credential and profile contract"),
    ("spec/WIREGUARD_CREDENTIALS.md", r"Wire major [0-9]+, persistent schema compatibility [0-9]+", f"Wire major {wire}, persistent schema compatibility {schema}"),
]:
    changes |= replace(path, pattern, replacement, count=1)

if CHECK and changes:
    raise SystemExit(1)
