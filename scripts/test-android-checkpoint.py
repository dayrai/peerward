#!/usr/bin/env python3
"""Run the shared checkpoint regressions on an explicitly selected Android target.

This tests target-native filesystem/locking semantics under adb shell, without
WebView. It is not an APK, app-sandbox, TUN or complete backend acceptance gate.
Never reads .env. Physical targets require explicit --allow-physical selection.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--allow-physical", action="store_true", help="Explicitly run only isolated core tests under adb shell on a phone")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/wireguard/signed-state")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", args.serial) or (not args.allow_physical and not re.fullmatch(r"emulator-[0-9]+", args.serial)):
        parser.error("physical-device serials require --allow-physical")
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk:
        parser.error("ANDROID_HOME or ANDROID_SDK_ROOT is required")
    adb = [str(Path(sdk) / "platform-tools/adb"), "-s", args.serial]

    def run(command, timeout=90):
        return subprocess.run([str(arg) for arg in command], cwd=ROOT, text=True,
                              capture_output=True, check=True, timeout=timeout).stdout

    physical = run([*adb, "shell", "getprop", "ro.kernel.qemu"]).strip() != "1"
    if physical and not args.allow_physical:
        parser.error("physical target was not explicitly selected")
    api = int(run([*adb, "shell", "getprop", "ro.build.version.sdk"]).strip())
    abi = run([*adb, "shell", "getprop", "ro.product.cpu.abi"]).strip()
    if api < 28 or abi not in {"arm64-v8a", "x86_64"}:
        parser.error("requires API 28+ and a supported 64-bit ABI")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = args.output.resolve() / f"checkpoint-api{api}-{stamp}"
    output.mkdir(parents=True)
    report = {"schema_version": 1, "release_gate_eligible": False, "api": api, "abi": abi, "physical": physical,
              "scope": "shared_core_checkpoint_under_adb_shell", "passed": False, "expected_tests": 10}
    remote = f"/data/local/tmp/peerward-checkpoint-{uuid.uuid4().hex}"
    try:
        build = subprocess.run(["cargo", "ndk", "-t", abi, "--platform", "28", "test", "--locked",
                                "--no-run", "--message-format=json", "-p", "peerward-peer-core", "--lib"],
                               cwd=ROOT, text=True, capture_output=True, timeout=600)
        (output / "build.log").write_text(build.stderr)
        build.check_returncode()
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        binary = Path(next(row["executable"] for row in artifacts
                           if row.get("reason") == "compiler-artifact" and row.get("executable")
                           and row["target"]["name"] == "peerward_peer_core"))
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        run([*adb, "shell", "mkdir", "-m", "700", remote])
        run([*adb, "push", binary, remote + "/tests"])
        run([*adb, "shell", "chmod", "700", remote + "/tests"])
        result = subprocess.run([*adb, "shell", f"TMPDIR={remote}", remote + "/tests",
                                 "checkpoint_tests::", "--test-threads=1"], cwd=ROOT, text=True,
                                capture_output=True, timeout=90)
        (output / "tests.log").write_text(result.stdout + result.stderr)
        report["passed"] = result.returncode == 0 and (
            "test result: ok. 10 passed; 0 failed; 0 ignored" in result.stdout)
    except (OSError, ValueError, StopIteration, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__
    finally:
        try:
            run([*adb, "shell", "rm", "-rf", remote])
        except (OSError, subprocess.SubprocessError):
            report["passed"] = False
            report["error"] = "test directory cleanup failed"
        (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Android checkpoint tests {'passed' if report['passed'] else 'FAILED'}: {output}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
