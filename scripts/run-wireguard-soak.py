#!/usr/bin/env python3
"""Start/status an isolated 24h release-build TUN soak owned by the user service manager.

The service survives terminal/agent exit. It never selects an existing deployment.
The product driver copies its binary and fixture sources and records stage failures.
"""
import argparse
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import subprocess
import shutil
import sys
import uuid
from wireguard_fixture import freeze_fixture

ROOT = Path(__file__).resolve().parents[1]


def status(directory):
    manifest = json.loads((directory / "supervisor.json").read_text())
    service = subprocess.run(["systemctl", "--user", "show", manifest["unit"],
        "--property=ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,MainPID,LoadState"],
        capture_output=True, text=True, timeout=10)
    state = dict(line.split("=", 1) for line in service.stdout.splitlines() if "=" in line)
    reports = sorted((directory / "evidence").glob("*/verification.json"))
    report = json.loads(reports[-1].read_text()) if reports else {}
    terminal = report.get("state") in ("passed", "failed")
    manifest.update(service=state, state=report.get("state", "starting"),
                    passed=report.get("passed") is True and terminal,
                    verification=str(reports[-1]) if reports else None)
    if not terminal and state.get("ActiveState") not in ("active", "activating"):
        manifest.update(state="interrupted", passed=False,
                        error="service is no longer active without a final gate verdict")
    if reports:
        samples = reports[-1].parent / "soak-resources.jsonl"
        if samples.exists():
            with samples.open("rb") as stream:
                stream.seek(max(0, samples.stat().st_size - 65536))
                rows = stream.read().splitlines()
            for row in reversed(rows):
                try:
                    manifest["last_online_sample_seconds"] = json.loads(row)["elapsed_seconds"]
                    break
                except (ValueError, KeyError):
                    continue
    print(json.dumps(manifest, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/wireguard/soak-supervised")
    parser.add_argument("--binary", type=Path, help="previously built release executable")
    parser.add_argument("--binary-sha256", help="required digest for --binary")
    args = parser.parse_args()
    if args.status:
        status(args.status.resolve())
        return
    if bool(args.binary) != bool(args.binary_sha256):
        parser.error("--binary and --binary-sha256 must be provided together")
    subprocess.run(["systemctl", "--user", "is-active", "default.target"], check=True,
                   stdout=subprocess.DEVNULL, timeout=10)
    directory = args.output.resolve() / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    directory.mkdir(parents=True, mode=0o700)
    if not args.binary:
        subprocess.run(["cargo", "build", "--locked", "--release", "-p", "peerward-cli"], cwd=ROOT, check=True)
    binary = directory / "peerward"
    shutil.copy2(args.binary or ROOT / "target/release/peerward", binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if args.binary and digest != args.binary_sha256:
        raise ValueError("provided executable differs from the pinned SHA-256")
    fixture_source = directory / "fixture-source"
    fixture_sources = freeze_fixture(ROOT, fixture_source)
    unit = "peerward-wireguard-soak-" + uuid.uuid4().hex[:12] + ".service"
    manifest = {"schema_version": 1, "unit": unit, "requested_seconds": 86400,
                "build_profile": "release", "state": "starting", "passed": False,
                "started_at": datetime.now(timezone.utc).isoformat(), "directory": str(directory)}
    manifest["host_boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    manifest.update(binary_sha256=digest, fixture_sources=fixture_sources)
    (directory / "supervisor.json").write_text(json.dumps(manifest, indent=2) + "\n")
    command = ["systemd-run", "--user", "--collect", "--unit=" + unit,
               "--property=WorkingDirectory=" + str(ROOT), "--property=RuntimeMaxSec=90000",
               "--property=TimeoutStopSec=30", "--property=KillMode=mixed",
               "--property=StandardOutput=append:" + str(directory / "supervisor.log"),
               "--property=StandardError=inherit", "--setenv=PATH=" + os.environ["PATH"],
               sys.executable, str(fixture_source / "scripts/test-wireguard-product.py"),
               "--binary", str(binary), "--binary-sha256", digest,
               "--fixture-source", str(fixture_source),
               "--build-profile", "release", "--relay-carrier", "quic-wss",
               "--soak-seconds", "86400", "--output", str(directory / "evidence")]
    subprocess.run(command, check=True, timeout=15)
    status(directory)


if __name__ == "__main__":
    main()
