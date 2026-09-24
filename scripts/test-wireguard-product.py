#!/usr/bin/env python3
"""Production Linux TUN-to-TUN gate in an isolated container network.

Fresh PostgreSQL, Control, Relay, Root, Mesh and joined peers for every run.
Never reads .env or edits host routes/firewall. Privileges stay in the fixture;
neither container shares the host network. No existing installation is selected.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import signal
from pathlib import Path
import subprocess
import sys
import uuid
from wireguard_gate_state import StageFailure, cleanup_owned_container, finish_report, record_failure
from wireguard_fixture import freeze_fixture

ROOT = Path(__file__).resolve().parents[1]
POSTGRES = "postgres:18-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-seconds", type=int, default=320)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/wireguard/product-tun")
    parser.add_argument("--relay-carrier", choices=["tcp", "quic-wss"], default="tcp")
    parser.add_argument("--soak-seconds", type=int, default=0)
    parser.add_argument("--build-profile", choices=["debug", "release"], default="debug")
    parser.add_argument("--binary", type=Path, help="use a previously built, pinned executable")
    parser.add_argument("--binary-sha256", help="required SHA-256 when --binary is provided")
    parser.add_argument("--fixture-source", type=Path, help="previously frozen fixture with its manifest")
    parser.add_argument("--matrix-case", choices=["lan", "ipv6", "nat64", "single-nat", "double-nat", "cgnat", "endpoint-dependent", "random-mapping", "udp-blocked", "connect", "mtu-blackhole", "one-way-loss", "direct-failure", "network-replacement"])
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--performance-rounds", type=int, default=0)
    parser.add_argument("--performance-seconds", type=int, default=30)
    parser.add_argument("--performance-streams", type=int, choices=range(1, 33), default=1)
    parser.add_argument("--mesh-scale", type=int, choices=[0, 2, 100], default=0)
    parser.add_argument("--scale-seconds", type=int, default=320)
    parser.add_argument("--backbone-flow", action="store_true", help="force real TUN traffic through two distinct QUIC hosts")
    parser.add_argument("--management-network",action="store_true",help="exercise approved LAN resources and selected Internet exit with real Linux peers")
    args = parser.parse_args()
    if bool(args.binary) != bool(args.binary_sha256):
        parser.error("--binary and --binary-sha256 must be supplied together")
    if args.management_network and (args.matrix_case or args.mesh_scale or args.backbone_flow or args.soak_seconds):
        parser.error("management network is an independent isolated scenario")
    if args.backbone_flow and (args.mesh_scale or args.matrix_case or args.soak_seconds or args.relay_carrier != "quic-wss"):
        parser.error("backbone flow requires quic-wss without Mesh scale, matrix or soak")
    if not 5 <= args.performance_seconds <= 300:
        parser.error("performance round duration must be 5..300 seconds")
    if args.mesh_scale and (args.matrix_case or args.soak_seconds or args.relay_carrier != "quic-wss" or not 30 <= args.scale_seconds <= 3600):
        parser.error("Mesh traffic scale requires quic-wss, 30..3600 seconds, no matrix/soak")
    if not 0 <= args.soak_seconds <= 86400:
        parser.error("soak must be between 0 and 86400 seconds")
    if not 1 <= args.attempts <= 1000:
        parser.error("attempts must be 1..1000")
    if args.performance_rounds not in (0, 5) or (args.performance_rounds and not args.matrix_case):
        parser.error("performance requires a matrix case and exactly five rounds")
    if args.matrix_case and (args.soak_seconds or args.relay_carrier != "quic-wss"):
        parser.error("matrix requires quic-wss and no soak")
    if not 320 <= args.offline_seconds <= 3600:
        parser.error("offline flow must cross WireGuard rekeys and the former 300-second ACL expiry: 320..3600 seconds")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = args.output.resolve() / stamp
    output.mkdir(parents=True, mode=0o700)
    suffix = uuid.uuid4().hex[:12]
    fixture_tag = "peerward-wireguard-product-test:gate-" + suffix
    lab, database = "peerward-wg-lab-" + suffix, "peerward-wg-db-" + suffix
    report = {"schema_version": 1, "release_gate_eligible": False, "passed": False,
              "state": "running", "started_at": datetime.now(timezone.utc).isoformat(),
              "host_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
              "build_profile": args.build_profile,
              "scope": "production_linux_tun_to_tun", "offline_seconds": args.offline_seconds, "relay_carrier": args.relay_carrier, "soak_seconds": args.soak_seconds,
              "not_claimed": ["Android TUN", "100-attempt NAT/SLO matrix", "five-round performance",
                              "100-attempt carrier fallback SLO", "CONNECT", "24-hour soak", "independent audit"]}
    if args.matrix_case:
        report.update(scope="production_linux_cold_connection_matrix", matrix_case=args.matrix_case, attempts=args.attempts)
    if args.mesh_scale:
        report.update(scope="production_linux_simultaneous_mesh_traffic", meshes=args.mesh_scale, scale_seconds=args.scale_seconds)
    if args.backbone_flow:
        report.update(scope="production_linux_tun_across_two_quic_hosts", relay_carrier="quic", flow_seconds=args.offline_seconds)
        report.pop("offline_seconds")
    if args.management_network:
        report.update(scope="production_linux_managed_resources_exit_dns_and_recovery")
    def interrupted(number, _frame):
        raise StageFailure(report.get("stage", "interrupted"), -number)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with (output / "driver.log").open("w") as log:
        def save_running():
            temporary = output / "verification.tmp"
            temporary.write_text(json.dumps(report, indent=2) + "\n")
            temporary.replace(output / "verification.json")

        def run(command, label, timeout=600):
            report["stage"] = label
            save_running()
            result = subprocess.run([str(x) for x in command], cwd=ROOT,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
            log.flush()
            if result.returncode:
                raise StageFailure(label, result.returncode)
        try:
            if args.binary:
                report["binary_origin"] = "provided; build provenance belongs to the invoking matrix"
                shutil.copy2(args.binary.resolve(), output / "peerward")
            else:
                run(["cargo", "build", "--locked", "-p", "peerward-cli", *(["--release"] if args.build_profile == "release" else [])], "CLI build", 1200)
                report["binary_origin"] = "built by this driver"
                shutil.copy2(ROOT / f"target/{args.build_profile}/peerward", output / "peerward")
            report["binary_sha256"] = hashlib.sha256((output / "peerward").read_bytes()).hexdigest()
            if args.binary and report["binary_sha256"] != args.binary_sha256:
                raise ValueError("provided executable differs from the pinned SHA-256")
            # Freeze fixture scripts/config templates before launching a long run.
            # Only versioned or explicitly unignored inputs are copied; root .env is never selected.
            fixture_source = output / "fixture-source"
            report["fixture_sources"] = freeze_fixture(ROOT, fixture_source, args.fixture_source)
            for dockerfile, image in [("netns-test", "peerward-netns-test:ubuntu26"),
                                      ("wireguard-product-test", fixture_tag)]:
                run(["docker", "build", "-t", image, "-f", fixture_source / f"packaging/docker/{dockerfile}.Dockerfile", fixture_source], "fixture image")
            image_id = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}",
                                                fixture_tag], text=True).strip()
            report["fixture_image"] = image_id
            run(["docker", "run", "--detach", "--rm", "--name", lab, "--privileged", "--network", "none",
                 *(["--memory", "12g", "--pids-limit", "4096"] if args.mesh_scale else []),
                 "--mount", f"type=bind,source={fixture_source},target=/source,readonly",
                 "--mount", f"type=bind,source={output},target=/evidence",
                 fixture_tag, "sleep", "infinity"], "isolated network")
            run(["docker", "run", "--detach", "--rm", "--name", database, "--network", "container:" + lab,
                 "--env", "POSTGRES_PASSWORD=peerward_test", "--env", "POSTGRES_DB=peerward_test",
                 POSTGRES], "isolated PostgreSQL")
            run(["docker", "exec", database, "sh", "-c",
                 "for attempt in $(seq 1 60); do pg_isready -h 127.0.0.1 -U postgres -d peerward_test && exit 0; sleep 1; done; exit 1"], "PostgreSQL readiness", 70)
            print(f"Production TUN fixture ready: {output}", flush=True)
            scenario = (["/source/scripts/wireguard-product/matrix.py", "--case", args.matrix_case, "--attempts", args.attempts, "--performance-rounds", args.performance_rounds, "--performance-seconds", args.performance_seconds, "--performance-streams", args.performance_streams]
                        if args.matrix_case else ["/source/scripts/wireguard-product/lab.py", "--offline-seconds", args.offline_seconds,
                                                  "--relay-carrier", args.relay_carrier, "--soak-seconds", args.soak_seconds])
            if args.mesh_scale:
                scenario = ["/source/scripts/wireguard-product/mesh-scale.py", "--meshes", args.mesh_scale, "--seconds", args.scale_seconds]
            if args.backbone_flow:
                scenario = ["/source/scripts/wireguard-product/backbone.py", "--seconds", args.offline_seconds]
            if args.management_network:
                scenario = ["/source/scripts/wireguard-product/network-management.py"]
            run(["docker", "exec", "--env", "RUST_LOG=" + os.environ.get("PEERWARD_FIXTURE_LOG", "info"),
                 "--env", "PEERWARD_FIXTURE_LOG=" + os.environ.get("PEERWARD_FIXTURE_LOG", "warn"),
                 "--workdir", "/source", lab, "python3", *scenario],
                "production TUN scenarios", args.mesh_scale * 60 + args.scale_seconds + 300 if args.mesh_scale else args.attempts * 65 + args.performance_rounds * (args.performance_seconds + 15) + 300 if args.matrix_case else args.offline_seconds + args.soak_seconds + 300)
            report["scenarios"] = json.loads((output / "scenarios.json").read_text())
            report["passed"] = report["scenarios"]["passed"]
            if report["passed"]:
                if report["scenarios"].get("performance", {}).get("passed"):
                    report["not_claimed"].remove("five-round performance")
                if report["scenarios"].get("online_relay_soak_seconds", 0) >= 86400:
                    report["not_claimed"].remove("24-hour soak")
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
            record_failure(report, error)
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            if (output / "scenarios.json").exists():
                try:
                    report["scenarios"] = json.loads((output / "scenarios.json").read_text())
                except (OSError, ValueError) as error:
                    report["scenario_report_error"] = str(error)
                    report["passed"] = False
            cleanup = [cleanup_owned_container(name, log) for name in [database, lab]]
            finish_report(report, output / "verification.json", cleanup)
            try:
                subprocess.run(["docker", "image", "rm", fixture_tag], stdout=log,
                               stderr=subprocess.STDOUT, timeout=15)
            except (OSError, subprocess.SubprocessError) as error:
                print(f"fixture image cleanup: {error}", file=log)
    print(f"Production TUN gate {'passed' if report['passed'] else 'FAILED'}: {output}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
