#!/usr/bin/env python3
"""GotaTun adapter <-> Linux WireGuard, real TUN in isolated user/net namespaces.

This is an engine gate, not a deployed Peerward or NAT/Android acceptance result.
No host routes, firewall rules, credentials, or services are modified.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time


def run(*command, **kwargs):
    return subprocess.run(command, text=True, check=True, capture_output=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wg", default="wg")
    parser.add_argument("--binary", default="target/debug/examples/tun_peer")
    parser.add_argument("--output", default="artifacts/wireguard/kernel-interop.json")
    parser.add_argument("--long-seconds", type=int, default=0, help="Optional >=260 second flow across standard rekeys")
    parser.add_argument("--flow", choices=["icmp", "adapter-to-kernel", "kernel-to-adapter"], default="icmp",
                        help="Long-flow workload; UDP choices carry application data in only one direction")
    parser.add_argument("--namespace", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.long_seconds and not 260 <= args.long_seconds <= 3600:
        parser.error("--long-seconds must be zero or 260..3600")
    if not args.namespace:
        # Always enter a new user AND network namespace before creating links.
        result = subprocess.run([
            "unshare", "--user", "--map-root-user", "--net", sys.executable,
            str(Path(__file__).resolve()), *sys.argv[1:], "--namespace",
        ], check=False)
        return result.returncode
    if os.geteuid() != 0 or Path("/proc/self/ns/net").readlink() == Path("/proc/1/ns/net").readlink():
        raise SystemExit("isolated user/network namespace required")

    results = []
    child = None
    peer = None
    receiver = None
    report = {
        "schema_version": 1,
        "scope": "wireguard_engine_kernel_tun_interop",
        "release_gate_eligible": False,
        "gotatun": "0.9.2",
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "kernel": os.uname().release,
        "commit": run("git", "rev-parse", "HEAD").stdout.strip(),
        "worktree_clean": not run("git", "status", "--porcelain").stdout,
        "scenarios": results,
        "limitations": ["No production enrollment, ACL, Relay, NAT matrix or Android exercised."],
    }
    try:
        with tempfile.TemporaryDirectory(prefix="peerward-wg-kernel-") as directory:
            lab = Path(directory)
            os.chmod(lab, 0o700)
            for name in ["adapter", "kernel"]:
                private = run(args.wg, "genkey").stdout
                (lab / f"{name}.key").write_text(private)
                os.chmod(lab / f"{name}.key", 0o600)
                (lab / f"{name}.pub").write_text(run(args.wg, "pubkey", input=private).stdout)
            child = subprocess.Popen(["unshare", "--net", "sleep", str(max(600, args.long_seconds + 120))])
            child_namespace = Path(f"/proc/{child.pid}/ns/net")
            for _ in range(100):
                if child.poll() is not None:
                    raise RuntimeError("kernel namespace exited")
                if child_namespace.readlink() != Path("/proc/self/ns/net").readlink():
                    break
                time.sleep(0.01)
            else:
                raise RuntimeError("kernel namespace was not created")

            def remote(*command):
                return run("nsenter", f"--net={child_namespace}", *command)

            run("ip", "link", "set", "lo", "up")
            remote("ip", "link", "set", "lo", "up")
            run("ip", "link", "add", "lab-a", "type", "veth", "peer", "name", "lab-b")
            run("ip", "link", "set", "lab-b", "netns", str(child.pid))
            run("ip", "address", "add", "172.30.240.1/30", "dev", "lab-a")
            remote("ip", "address", "add", "172.30.240.2/30", "dev", "lab-b")
            run("ip", "link", "set", "lab-a", "up")
            remote("ip", "link", "set", "lab-b", "up")
            remote("ip", "link", "add", "wg0", "type", "wireguard")
            remote(args.wg, "set", "wg0", "private-key", str(lab / "kernel.key"),
                   "listen-port", "51820", "peer", (lab / "adapter.pub").read_text().strip(),
                   "allowed-ips", "10.42.0.1/32,fd42::1/128", "endpoint", "172.30.240.1:51820")
            remote("ip", "address", "add", "10.42.0.2/32", "dev", "wg0")
            remote("ip", "address", "add", "fd42::2/128", "dev", "wg0", "nodad")
            remote("ip", "link", "set", "wg0", "mtu", "1280", "up")
            remote("ip", "route", "add", "10.42.0.1/32", "dev", "wg0")
            remote("ip", "-6", "route", "add", "fd42::1/128", "dev", "wg0")
            with (lab / "adapter.log").open("w+") as log:
                peer = subprocess.Popen([
                    str(Path(args.binary).resolve()), "pwtun", str(lab / "adapter.key"),
                    str(lab / "kernel.pub"), "172.30.240.1:51820", "172.30.240.2:51820",
                ], stdout=log, stderr=log)
                for _ in range(200):
                    if peer.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    if subprocess.run(["ip", "link", "show", "pwtun"], capture_output=True).returncode == 0:
                        break
                    time.sleep(0.01)
                else:
                    raise RuntimeError("adapter TUN did not appear")
                run("ip", "address", "add", "10.42.0.1/32", "dev", "pwtun")
                run("ip", "address", "add", "fd42::1/128", "dev", "pwtun", "nodad")
                run("ip", "link", "set", "pwtun", "mtu", "1280", "up")
                run("ip", "route", "add", "10.42.0.2/32", "dev", "pwtun")
                run("ip", "-6", "route", "add", "fd42::2/128", "dev", "pwtun")
                for direction, family, destination, size in [
                    ("adapter_to_kernel", 4, "10.42.0.2", 33),
                    ("kernel_to_adapter", 4, "10.42.0.1", 1252),
                    ("adapter_to_kernel", 6, "fd42::2", 33),
                    ("kernel_to_adapter", 6, "fd42::1", 1232),
                ]:
                    command = ["ping", f"-{family}", "-n", "-c", "100", "-i", "0.01",
                               "-W", "2", "-s", str(size), destination]
                    if direction == "kernel_to_adapter":
                        command = ["nsenter", f"--net={child_namespace}", *command]
                    started = time.monotonic()
                    ping = subprocess.run(command, text=True, capture_output=True, check=False, timeout=210)
                    match = re.search(r"(\d+) packets transmitted, (\d+) received", ping.stdout)
                    results.append({
                        "direction": direction, "inner_ip_version": family,
                        "payload_bytes": size, "attempts": int(match[1]) if match else 100,
                        "received": int(match[2]) if match else 0,
                        "elapsed_seconds": time.monotonic() - started,
                        "passed": ping.returncode == 0 and match is not None and match[2] == "100",
                        "output": ping.stdout, "stderr": ping.stderr,
                    })
                report["kernel_handshake"] = remote(args.wg, "show", "wg0", "latest-handshakes").stdout.strip()
                if args.long_seconds and args.flow == "icmp":
                    started = time.monotonic()
                    command = ["ping", "-4", "-n", "-w", str(args.long_seconds),
                               "-i", "0.05", "-W", "2", "-s", "1200", "10.42.0.2"]
                    flow = subprocess.run(command, text=True, capture_output=True, check=False,
                                          timeout=args.long_seconds + 5)
                    match = re.search(r"(\d+) packets transmitted, (\d+) received", flow.stdout)
                    report["long_flow"] = {
                        "elapsed_seconds": time.monotonic() - started,
                        "attempts": int(match[1]) if match else 0,
                        "received": int(match[2]) if match else 0,
                        "passed": flow.returncode == 0 and match is not None and match[1] == match[2],
                        "output": flow.stdout, "stderr": flow.stderr,
                        "kernel_handshake_after": remote(args.wg, "show", "wg0", "latest-handshakes").stdout.strip(),
                        "traffic": "bidirectional ICMP echo, 1200-byte payload, standard timers",
                    }
                elif args.long_seconds:
                    destination = "10.42.0.2" if args.flow == "adapter-to-kernel" else "10.42.0.1"
                    token = os.urandom(16).hex()
                    ready = lab / "receiver.ready"
                    worker = str(Path(__file__).with_name("wireguard-flow.py").resolve())
                    receive_command = [sys.executable, worker, "receive", destination,
                                       "--seconds", str(args.long_seconds + 3), "--token", token,
                                       "--ready", str(ready)]
                    send_command = [sys.executable, worker, "send", destination,
                                    "--seconds", str(args.long_seconds), "--token", token]
                    remote_prefix = ["nsenter", f"--net={child_namespace}"]
                    if args.flow == "adapter-to-kernel":
                        receive_command = remote_prefix + receive_command
                    else:
                        send_command = remote_prefix + send_command
                    receiver = subprocess.Popen(receive_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for _ in range(100):
                        if receiver.poll() is not None:
                            raise RuntimeError("one-way UDP receiver exited before ready")
                        if ready.exists():
                            break
                        time.sleep(0.01)
                    else:
                        raise RuntimeError("one-way UDP receiver did not become ready")
                    started = time.monotonic()
                    sender = run(*send_command, timeout=args.long_seconds + 5)
                    receiver_output, receiver_error = receiver.communicate(timeout=5)
                    sent = json.loads(sender.stdout)
                    received = json.loads(receiver_output)
                    report["long_flow"] = {
                        **sent, **received, "elapsed_seconds": time.monotonic() - started,
                        "passed": receiver.returncode == 0 and sent["attempts"] == sent["sent"] == received["received"]
                                  and sent["send_errors"] == received["invalid"] == received["duplicates"] == 0,
                        "stderr": receiver_error + sender.stderr,
                        "traffic": f"one-way UDP {args.flow}, no application responses, 1200-byte payload, standard timers",
                        "kernel_handshake_after": remote(args.wg, "show", "wg0", "latest-handshakes").stdout.strip(),
                    }
                peer.send_signal(signal.SIGINT)
                peer.wait(timeout=5)
                log.seek(0)
                report["adapter_log"] = log.read()
                if args.long_seconds:
                    handshakes = re.search(r"(\d+) handshake messages sent", report["adapter_log"])
                    report["long_flow"]["handshake_messages_sent"] = int(handshakes[1]) if handshakes else 0
                    report["long_flow"]["passed"] &= handshakes is not None and int(handshakes[1]) >= 3
                    sessions = re.search(r"(\d+) data sessions used", report["adapter_log"])
                    report["long_flow"]["data_sessions_used"] = int(sessions[1]) if sessions else 0
                    report["long_flow"]["passed"] &= sessions is not None and int(sessions[1]) >= 3
                    receiving = re.search(r"(\d+) authenticated receiving sessions used", report["adapter_log"])
                    report["long_flow"]["receiving_sessions_used"] = int(receiving[1]) if receiving else 0
                    report["long_flow"]["passed"] &= receiving is not None and int(receiving[1]) >= 3
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        for process in [receiver, peer, child]:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        report["passed"] = "error" not in report and len(results) == 4 and all(s["passed"] for s in results)
        if args.long_seconds:
            report["passed"] &= report.get("long_flow", {}).get("passed", False)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"WireGuard kernel/TUN qualification: {'passed' if report['passed'] else 'FAILED'}; {output}")
        if "error" in report:
            print(report["error"], file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
