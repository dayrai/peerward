#!/usr/bin/env python3
"""Wait for an exact functional matrix, then sample its same release binary sequentially."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from wireguard_gate_state import evidence_status, process_identity

ROOT = Path(__file__).resolve().parents[1]
CASES = ["lan", "ipv6", "single-nat", "double-nat", "cgnat", "endpoint-dependent",
         "random-mapping", "udp-blocked", "connect", "mtu-blackhole", "one-way-loss", "nat64"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--after-matrix", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    path = args.output / "verification.json"
    state = {"passed": False, "release_gate_eligible": False, "state": "waiting_for_functional_matrix",
             "process": process_identity(),
             "started_at": datetime.now(timezone.utc).isoformat(), "after_matrix": str(args.after_matrix.resolve())}

    def save():
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n")
        temporary.replace(path)

    save()
    try:
        prerequisite = args.after_matrix / "verification.json"
        deadline = time.monotonic() + 7200
        while True:
            matrix = json.loads(prerequisite.read_text()) if prerequisite.exists() else {}
            if matrix and evidence_status(matrix) not in ("running", "starting"):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("functional matrix did not finish before the two-hour bound")
            time.sleep(15)
        if evidence_status(matrix) != "passed" or matrix.get("passed") is not True or matrix.get("build_profile") != "release":
            raise RuntimeError("functional release matrix did not pass; performance was not started")
        binary = args.after_matrix / "peerward"
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != matrix.get("binary_sha256"):
            raise RuntimeError("functional matrix binary digest differs")
        state.update(state="running", binary_sha256=digest,
                     prerequisite_sha256=hashlib.sha256(prerequisite.read_bytes()).hexdigest())
        save()
        with (args.output / "driver.log").open("w") as log:
            result = subprocess.run([sys.executable, ROOT / "scripts/test-wireguard-matrix.py",
                "--build-profile", "release", "--binary", binary, "--binary-sha256", digest,
                "--attempts", "1", "--jobs", "1", "--performance-rounds", "5", "--performance-seconds", "30",
                "--cases", *CASES, "--output", args.output / "samples"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        reports = sorted((args.output / "samples").glob("*/verification.json"))
        measured = json.loads(reports[-1].read_text()) if reports else {}
        state.update(state="complete", passed=result.returncode == 0 and measured.get("passed") is True,
                     report=str(reports[-1]) if reports else None, exit_code=result.returncode)
    except Exception as error:
        state.update(state="failed", error=str(error))
    finally:
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        save()
    return 0 if state["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
