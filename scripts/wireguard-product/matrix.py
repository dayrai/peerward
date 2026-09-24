#!/usr/bin/env python3
"""Cold product-process trials. No simulated WireGuard engine or warm ping SLO."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback
from types import SimpleNamespace

import lab
from topology import Topology, NAT64_ENDPOINT


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stop_peers(peers):
    failures = []
    for peer in peers:
        child = peer["child"]
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGINT)
    for peer in peers:
        child = peer["child"]
        if child is not None:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                failures.append("Peer shutdown exceeded ten seconds")
                child.kill()
                child.wait(timeout=3)
        if lab.run("ip", "-n", peer["namespace"], "link", "show", "pwmesh", check=False).returncode == 0:
            failures.append("trial leaked its TUN")
    if failures:
        raise RuntimeError("; ".join(failures))


def trial(peers, topology, index):
    topology.reset()
    result = {"attempt": index, "first_available": False, "direct": False, "relay": False}
    started = time.monotonic()
    try:
        for i, peer in enumerate(peers):
            topology.inside(peer["namespace"], "conntrack", "-F")
            peer["child"] = lab.spawn(["ip", "netns", "exec", peer["namespace"], lab.BINARY, "peer", "run", "--config", peer["profile"] / "peer.toml"], lab.OUT / f"attempt-{index:03d}-peer-{i}.log")
        lab.wait(lambda: all(lab.query(peer, "status").get("tun_up") for peer in peers), "fresh TUN readiness", 10)
        # Timing includes both real process startups and authenticated Relay admission.
        def delivered():
            return lab.run("ip", "netns", "exec", peers[0]["namespace"], "ping", "-n", "-c", "1", "-W", "1", "-s", "1200", peers[1]["address"], check=False).returncode == 0
        lab.wait(delivered, "first full-size TUN reply", 10)
        result["first_available"] = True
        result["first_available_seconds"] = time.monotonic() - started
        # A successful full-size reply with no Relay counter increment proves
        # direct delivery. Discovery has a fixed five-second observation window.
        end = time.monotonic() + 5
        while time.monotonic() < end:
            before = [lab.query(peer, "metrics") for peer in peers]
            if delivered():
                after = [lab.query(peer, "metrics") for peer in peers]
                if all(b.get("peerward_peer_direct_packets_total", 0) > a.get("peerward_peer_direct_packets_total", 0)
                       and b.get("peerward_peer_relay_packets_total", 0) == a.get("peerward_peer_relay_packets_total", 0)
                       for a, b in zip(before, after)):
                    result["direct"] = True
                    result["direct_seconds"] = time.monotonic() - started
                    break
                result["relay"] = True
            time.sleep(.1)
        result["final_path"] = "direct" if result["direct"] else "relay" if result["relay"] else "failed"
        if topology.case in ("direct-failure", "network-replacement"):
            if not result["direct"]:
                raise RuntimeError("recovery prerequisite: full-size direct not established")
            recover(peers[0], peers[1], topology, result)
    except Exception as error:
        result["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        result["elapsed_seconds"] = time.monotonic() - started
        result["peer_diagnostics"] = [{"status": lab.query(peer, "status"), "metrics": lab.query(peer, "metrics")} for peer in peers]
        if index == 1:
            # Synthetic addresses in this isolated fixture only; never a
            # production candidate metric or user network capture.
            for router in topology.routers:
                (lab.OUT / (router + "-conntrack.txt")).write_text(topology.inside(router, "conntrack", "-L", "-p", "udp", check=False).stdout)
        try:
            stop_peers(peers)
        except RuntimeError as error:
            result["cleanup_error"] = str(error)
        if topology.case == "direct-failure":
            for peer in peers:
                topology.inside(peer["namespace"], "nft", "delete", "table", "inet", "fixture_recovery", check=False)
        elif topology.case == "network-replacement":
            for family, replacement, original in [("-4", "10.203.0.4/24", "10.203.0.2/24"), ("-6", "fd42:203::4/64", "fd42:203::2/64")]:
                lab.run("ip", "-n", peers[0]["namespace"], family, "address", "del", replacement, "dev", "underlay", check=False)
                lab.run("ip", "-n", peers[0]["namespace"], family, "address", "replace", original, "dev", "underlay", *(["nodad"] if family == "-6" else []))
    return result


def recover(source, destination, topology, result):
    if topology.case == "direct-failure":
        # INPUT drops silently at the remote side. OUTPUT drop would return
        # EPERM to sendto and only test immediate socket-error fallback.
        for peer in (source, destination):
            topology.inside(peer["namespace"], "nft", "-f", "-", input='table inet fixture_recovery { chain input { type filter hook input priority -200; policy accept; ip saddr 10.203.0.1 udp sport 27777 accept; meta l4proto udp drop; }; }\n')
        result["recovery_fault"] = "silent_direct_ingress_drop_both_peers"
    else:
        result["recovery_fault"] = "replace_ipv4_ipv6_underlay_addresses"
        for family, old, new in [("-4", "10.203.0.2/24", "10.203.0.4/24"), ("-6", "fd42:203::2/64", "fd42:203::4/64")]:
            lab.run("ip", "-n", source["namespace"], family, "address", "del", old, "dev", "underlay")
            lab.run("ip", "-n", source["namespace"], family, "address", "add", new, "dev", "underlay", *(["nodad"] if family == "-6" else []))
    start = time.monotonic()
    result["recovery_passed"] = False
    probe = subprocess.Popen(["ip", "netns", "exec", source["namespace"], "ping", "-n", "-i", ".05", "-w", "8", "-W", "1", "-s", "1200", destination["address"]], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        for line in probe.stdout:
            if "bytes from" in line:
                result["recovery_seconds"] = time.monotonic() - start
                result["recovery_passed"] = True
                break
    finally:
        probe.terminate()
        probe.wait(timeout=2)
    if not result["recovery_passed"]:
        raise RuntimeError("no authenticated full-size reply after failure/network replacement")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True)
    parser.add_argument("--attempts", type=int, required=True)
    parser.add_argument("--performance-rounds", type=int, default=0)
    parser.add_argument("--performance-seconds", type=int, default=30)
    parser.add_argument("--performance-streams", type=int, choices=range(1, 33), default=1)
    args = parser.parse_args()
    if not Path("/.dockerenv").exists() or os.getuid() != 0 or lab.BASE.exists():
        raise SystemExit("fresh dedicated container required")
    if any(link["ifname"] != "lo" for link in json.loads(lab.run("ip", "-j", "link").stdout)):
        raise SystemExit("network-none fixture required")
    lifecycle = load("lifecycle", lab.ROOT / "scripts/dynamic-mesh/lifecycle.py")
    carriers = load("carriers", Path(__file__).with_name("relay-carrier.py"))
    report = {"passed": False, "case": args.case, "requested_attempts": args.attempts, "attempts": [],
              "scope": "Linux kernel NAT models; not operator networks or hardware gateways",
              "uncovered": ["DNS64 discovery on operator networks", "Android 100-attempt handover SLO", "PCP/NAT-PMP/UPnP hardware", "independent audit"]}
    if args.case in ("mtu-blackhole", "one-way-loss"):
        report["fault_model"] = "silent_underlay_ingress_drop_both_address_families"
    if not args.performance_rounds:
        report["uncovered"].append("five-round performance")
    if args.case not in ("direct-failure", "network-replacement"):
        report["uncovered"].append("Linux recovery SLO (separate recovery cases)")
    services = [sys.executable, lab.ROOT / "scripts/dynamic-mesh/native-services.py", lab.BASE, "--binary", lab.BINARY]
    peers, proxy, translator = [], None, None
    try:
        lab.run(sys.executable, lab.ROOT / "deploy/compose/install.py", "--native", "--output", lab.BASE,
                "--public-host", "10.203.0.1", "--database-url", lab.DATABASE,
                "--host-port", "28443", "--control-port", "28880", "--management-port", "28990",
                "--peer-port", "27777", "--backbone-port", "27778", "--relay-health-port", "28991", "--stun-port", "23478")
        lab.run("ip", "link", "add", "brpwd", "type", "bridge")
        lab.run("ip", "address", "add", "10.203.0.1/24", "dev", "brpwd")
        lab.run("ip", "link", "set", "brpwd", "up")
        synthetic = NAT64_ENDPOINT if args.case == "nat64" else None
        options, _ = carriers.configure(lab.BASE, "10.203.0.1", 27777, 27778, lab.OUT, False, use_quic=True, fallback_wss=True, extra_san=synthetic)
        if synthetic:
            # Explicit synthesized endpoint isolates actual IPv6-to-IPv4
            # translation; DNS64 discovery is a separate operator-network gate.
            dynamic = lab.BASE / "control/dynamic.toml"
            dynamic.write_text(dynamic.read_text().replace("quic://10.203.0.1:", f"quic://[{synthetic}]:").replace("wss://10.203.0.1:", f"wss://[{synthetic}]:"))
            lab.run("ip", "-6", "address", "add", "fd42:203::1/64", "dev", "brpwd", "nodad")
            lab.run("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1", "net.ipv4.ip_forward=1")
            folder = lab.BASE / "tayga"
            folder.mkdir()
            config = folder / "tayga.conf"
            config.write_text(f"tun-device nat64\nipv4-addr 10.206.0.1\nipv6-addr fd42:203::64\nprefix fd64:ff9b::/96\ndynamic-pool 10.206.0.0/24\ndata-dir {folder}\n")
            lab.run("tayga", "--config", config, "--mktun")
            lab.run("ip", "link", "set", "nat64", "up")
            lab.run("ip", "address", "add", "10.206.0.1/24", "dev", "nat64")
            lab.run("ip", "-6", "route", "add", "fd64:ff9b::/96", "dev", "nat64")
            translator = lab.spawn(["tayga", "--config", config, "--nodetach"], lab.OUT / "nat64.log")
        if args.case == "connect":
            proxy = carriers.ConnectProxy(("10.203.0.1", 0), ("10.203.0.1", 27777), lab.OUT / "connect-proxy.json")
            options["http_connect_proxy"] = f"tcp://10.203.0.1:{proxy.server_address[1]}"
        topology = Topology(lab.run, args.case, proxy.server_address[1] if proxy else None)
        lab.run(lab.BINARY, "db", "migrate", "--database-url", lab.DATABASE)
        lab.run(*services)
        installation = lifecycle.Installation(SimpleNamespace(environment=lab.BASE / ".env", control="http://127.0.0.1:28880", timeout=90, binary=lab.BINARY))
        mesh = installation.create("nat-matrix-" + args.case)
        lab.policy(installation, mesh, "allow")
        peers = [lab.configure(installation, mesh, index, options, topology.setup, start=False, online=args.case != "nat64") for index in range(2)]
        with (lab.OUT / "attempts.jsonl").open("w") as evidence:
            for index in range(1, args.attempts + 1):
                result = trial(peers, topology, index)
                report["attempts"].append(result)
                evidence.write(json.dumps(result) + "\n")
                evidence.flush()
                print(f"{args.case} attempt {index}/{args.attempts}: {result.get('final_path', 'failed')}", flush=True)
        records = report["attempts"]
        for category in ("direct", "relay", "first_available"):
            report[category + "_rate"] = sum(bool(record[category]) for record in records) / args.attempts
        report["final_failure_rate"] = sum(record.get("final_path", "failed") == "failed" for record in records) / args.attempts
        timings = sorted(record["first_available_seconds"] for record in records if record["first_available"])
        report["successful_first_available_p95_seconds"] = timings[min(len(timings)-1, (len(timings)*95+99)//100-1)] if timings else None
        report["first_available_slo_passed"] = args.attempts >= 100 and len(timings) == args.attempts and report["successful_first_available_p95_seconds"] <= 3
        report["cleanup_failure_count"] = sum("cleanup_error" in record for record in records)
        report["passed"] = report["final_failure_rate"] == 0 and report["cleanup_failure_count"] == 0
        if args.case in ("direct-failure", "network-replacement"):
            recoveries = sorted(record["recovery_seconds"] for record in records if record.get("recovery_passed"))
            report["recovery_success_rate"] = len(recoveries) / args.attempts
            report["successful_recovery_p95_seconds"] = recoveries[min(len(recoveries)-1, (len(recoveries)*95+99)//100-1)] if recoveries else None
            report["recovery_slo_seconds"] = 3 if args.case == "direct-failure" else 5
            report["recovery_slo_passed"] = args.attempts >= 100 and len(recoveries) == args.attempts and report["successful_recovery_p95_seconds"] <= report["recovery_slo_seconds"]
            report["passed"] = report["passed"] and len(recoveries) == args.attempts
        report["functional_passed"] = report["passed"]
        if args.attempts >= 100:
            report["passed"] = report["passed"] and report["first_available_slo_passed"] and report.get("recovery_slo_passed", True)
        if args.performance_rounds:
            import performance
            report["performance"] = performance.run(peers, args.performance_rounds, args.performance_seconds, args.performance_streams)
            stop_peers(peers)
        installation.delete(mesh)
    except Exception as error:
        report["passed"] = False
        report["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        report["locations"] = [Path(frame.filename).name + ":" + str(frame.lineno) for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        try:
            stop_peers(peers)
        except (RuntimeError, subprocess.SubprocessError) as error:
            report["passed"] = False
            report["cleanup_error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        if proxy:
            proxy.stop()
        if translator:
            translator.terminate()
            translator.wait(timeout=5)
        lab.run(*services, "--stop", check=False)
        for role in ("control", "relay"):
            path = lab.BASE / (role + ".log")
            if path.exists():
                (lab.OUT / path.name).write_bytes(path.read_bytes())
        (lab.OUT / "scenarios.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
