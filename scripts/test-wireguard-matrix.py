#!/usr/bin/env python3
"""Run isolated product TUN cold-connection matrix, retaining every failed trial.

Does not select an existing installation, read root .env, or change host routes.
Each case owns separate Control/PostgreSQL/Relay and copies its tested binary.
Measures cold first availability and Linux recovery, not NAT hardware.
"""
import argparse
import concurrent.futures
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import signal
import threading
from wireguard_fixture import freeze_fixture
from wireguard_gate_state import process_identity

ROOT = Path(__file__).resolve().parents[1]
CASES = ["lan", "ipv6", "single-nat", "double-nat", "cgnat", "endpoint-dependent",
         "random-mapping", "udp-blocked", "connect", "mtu-blackhole", "one-way-loss", "nat64", "direct-failure", "network-replacement"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--build-profile", choices=["debug", "release"], default="debug")
    parser.add_argument("--binary", type=Path, help="reuse a previously fixed executable")
    parser.add_argument("--binary-sha256", help="required digest for --binary")
    parser.add_argument("--performance-rounds", type=int, choices=[0, 5], default=0)
    parser.add_argument("--performance-seconds", type=int, default=30)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=CASES)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/wireguard/nat-matrix")
    args = parser.parse_args()
    if not 1 <= args.attempts <= 1000 or not 1 <= args.jobs <= 3 or len(set(args.cases)) != len(args.cases):
        parser.error("attempts 1..1000, jobs 1..3, unique cases required")
    if bool(args.binary) != bool(args.binary_sha256):
        parser.error("--binary and --binary-sha256 must be provided together")
    output = args.output.resolve() / ("matrix-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"))
    output.mkdir(parents=True, mode=0o700)
    command = ["cargo", "build", "--locked", "-p", "peerward-cli", *(["--release"] if args.build_profile == "release" else [])]
    if args.binary:
        command = None
    else:
        with (output / "build.log").open("w") as log:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    binary = output / "peerward"
    shutil.copy2(args.binary or ROOT / f"target/{args.build_profile}/peerward", binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if args.binary and digest != args.binary_sha256:
        raise RuntimeError("provided binary digest changed; no fixture was started")
    print(f"Pinned {args.build_profile} executable: {digest}", flush=True)
    fixture_source = output / "fixture-source"
    fixture_sources = freeze_fixture(ROOT, fixture_source)
    stopping = threading.Event()
    active, active_lock = {}, threading.Lock()

    def stop(_signum, _frame):
        stopping.set()
        with active_lock:
            for process in active.values():
                if process.poll() is None:
                    process.terminate()  # child records interruption and owns fixture cleanup

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def run(case):
        if stopping.is_set():
            return {"case": case, "passed": False, "state": "not_started_after_interrupt"}
        with (output / (case + ".log")).open("w") as log:
            command = [sys.executable, fixture_source / "scripts/test-wireguard-product.py",
                                     "--relay-carrier", "quic-wss", "--matrix-case", case, "--build-profile", args.build_profile,
                                     "--binary", binary, "--binary-sha256", digest,
                                     "--fixture-source", fixture_source,
                                     "--attempts", str(args.attempts), "--performance-rounds", str(args.performance_rounds),
                                     "--performance-seconds", str(args.performance_seconds),
                                     "--output", output / case]
            with active_lock:
                if stopping.is_set():
                    return {"case": case, "passed": False, "state": "not_started_after_interrupt"}
                process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                active[case] = process
            code = process.wait()
            with active_lock:
                active.pop(case, None)
        evidence = sorted((output / case).glob("*/verification.json"))
        report = json.loads(evidence[-1].read_text()) if evidence else {}
        return {"case": case, "exit_code": code,
                "evidence": str(evidence[-1]) if evidence else None,
                "binary_sha256": report.get("binary_sha256"),
                "passed": code == 0 and report.get("passed") is True and report.get("binary_sha256") == digest}

    results = []
    report = {"schema_version": 1, "release_gate_eligible": False,
              "scope": "cold_first_availability_and_linux_recovery_kernel_network_models", "jobs": args.jobs,
              "performance_rounds": args.performance_rounds, "build_profile": args.build_profile,
              "performance_seconds": args.performance_seconds, "build_command": command, "binary_sha256": digest,
              "fixture_sources": fixture_sources, "process": process_identity(),
              "attempts_per_case": args.attempts, "requested_cases": args.cases, "cases": results,
              "state": "running", "passed": False}

    def save():
        temporary = output / "verification.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.replace(output / "verification.json")

    save()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(run, case) for case in args.cases]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(f"{result['case']}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
            (output / "progress.json").write_text(json.dumps(results, indent=2) + "\n")
            save()
    report.update(state="interrupted" if stopping.is_set() else "complete",
                  passed=not stopping.is_set() and all(result["passed"] for result in results))
    save()
    print(output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
