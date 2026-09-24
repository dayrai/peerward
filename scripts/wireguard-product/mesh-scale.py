#!/usr/bin/env python3
"""100 real Meshes / 200 TUN peers on one fixed QUIC/WSS host, in a private netns lab."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import lab
from matrix import load
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wireguard_gate_state import listener_endpoints


def resources(peers):
    pids = [peer["child"].pid for peer in peers if peer["child"].poll() is None]
    pids += [int((lab.BASE / (role + ".pid")).read_text()) for role in ("control", "relay")]
    result = []
    for pid in pids:
        proc = Path("/proc") / str(pid)
        stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        result.append({"pid": pid, "rss_pages": int((proc / "statm").read_text().split()[1]),
                       "cpu_ticks": int(stat[11]) + int(stat[12]), "fds": len(list((proc / "fd").iterdir()))})
    return result


def reconnections(peer):
    metrics = lab.query(peer, "metrics")
    return metrics["peerward_peer_relay_reconnects_total"]


def start_flow(peers, index):
    source, destination = peers
    stop = lab.BASE / f"scale-stop-{index}"
    server_ready, client_ready = lab.BASE / f"scale-server-{index}", lab.BASE / f"scale-client-{index}"
    for role, peer, ready in (("server", destination, server_ready), ("client", source, client_ready)):
        child = lab.spawn(["ip", "netns", "exec", peer["namespace"], "python3", lab.TRAFFIC, role,
                           "--address", destination["address"], "--file", lab.OUT / f"flow-{index}-{role}.json",
                           "--ready", ready, "--stop", stop], lab.OUT / f"flow-{index}-{role}.log")
        lab.wait(lambda: ready.exists() or child.poll() is not None, f"scale {role} readiness")
        if child.poll() is not None:
            raise RuntimeError(f"scale {role} {index} exited before readiness")
    return {"child": child, "stop": stop, "file": lab.OUT / f"flow-{index}-client.json"}


def stop_flow(flow):
    flow["stop"].touch()
    if flow["child"].wait(timeout=20) != 0:
        raise RuntimeError("scale TCP flow failed; original report retained")
    return json.loads(flow["file"].read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--meshes", type=int, required=True)
    parser.add_argument("--seconds", type=int, default=320)
    args = parser.parse_args()
    if args.meshes not in (2, 100) or args.seconds < 30:
        raise SystemExit("scale requires 2 (smoke) or 100 Meshes and >=30 seconds")
    if not Path("/.dockerenv").exists() or os.getuid() != 0 or lab.BASE.exists():
        raise SystemExit("fresh dedicated container required")
    if any(link["ifname"] != "lo" for link in json.loads(lab.run("ip", "-j", "link").stdout)):
        raise SystemExit("network-none fixture required")
    # Keep 200 production runtimes bounded on a shared validation workstation.
    os.environ["TOKIO_WORKER_THREADS"] = "2"
    lifecycle = load("lifecycle", lab.ROOT / "scripts/dynamic-mesh/lifecycle.py")
    carriers = load("carriers", Path(__file__).with_name("relay-carrier.py"))
    services = [sys.executable, lab.ROOT / "scripts/dynamic-mesh/native-services.py", lab.BASE, "--binary", lab.BINARY]
    report = {"passed": False, "requested_meshes": args.meshes, "seconds_after_deleting_one": args.seconds,
              "scope": "one fixed shared QUIC/WSS host, real Linux TUNs and persistent full-size TCP echoes",
              "not_claimed": ["hardware NAT", "Android energy", "independent audit"], "stages": []}
    meshes, peers, flows = [], [], []
    try:
        lab.run(sys.executable, lab.ROOT / "deploy/compose/install.py", "--native", "--output", lab.BASE,
                "--public-host", "10.203.0.1", "--database-url", lab.DATABASE,
                "--host-port", "28443", "--control-port", "28880", "--management-port", "28990",
                "--peer-port", "27777", "--backbone-port", "27778", "--relay-health-port", "28991", "--stun-port", "23478")
        lab.run("ip", "link", "add", "brpwd", "type", "bridge")
        lab.run("ip", "address", "add", "10.203.0.1/24", "dev", "brpwd")
        lab.run("ip", "link", "set", "brpwd", "up")
        options, _ = carriers.configure(lab.BASE, "10.203.0.1", 27777, 27778, lab.OUT, False, use_quic=True, fallback_wss=True)
        lab.run(lab.BINARY, "db", "migrate", "--database-url", lab.DATABASE)
        lab.run(*services)
        installation = lifecycle.Installation(SimpleNamespace(environment=lab.BASE / ".env", control="http://127.0.0.1:28880", timeout=180, binary=lab.BINARY))
        report["resources_before"] = resources([])
        report["listeners_before"] = lab.run("ss", "-H", "-lnut").stdout
        for index in range(args.meshes):
            mesh = installation.create(f"traffic-scale-{index}")
            meshes.append(mesh)
            lab.policy(installation, mesh, "allow")
            pair = []
            for side in range(2):
                peer = lab.configure(installation, mesh, index * 2 + side, options)
                peers.append(peer)
                pair.append(peer)
                # Force actual encrypted traffic through the fixed Relay listener.
                lab.run("ip", "netns", "exec", peer["namespace"], "nft", "-f", "-", input=
                    'table inet fixture_scale { chain output { type filter hook output priority -200; policy accept; '
                    'ip daddr 10.203.0.1 udp dport 27777 accept; meta l4proto udp drop; }; }\n')
            flows.append(start_flow(pair, index))
            report["stages"].append({"active_meshes": len(meshes), "live_flows": sum(flow["child"].poll() is None for flow in flows)})
            (lab.OUT / "scale-progress.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"{len(meshes)} real Mesh flows active", flush=True)
        assert all(flow["child"].poll() is None for flow in flows)
        report["resources_peak"] = resources(peers)
        report["listeners_peak"] = lab.run("ss", "-H", "-lnut").stdout
        assert listener_endpoints(report["listeners_peak"]) == listener_endpoints(report["listeners_before"]), "shared listeners changed with Mesh count"
        survivors = peers[2:]
        baseline = [reconnections(peer) for peer in survivors]
        report["deleted_flow"] = stop_flow(flows[0])
        installation.delete(meshes[0])
        lab.wait(lambda: all(peer["child"].poll() is not None for peer in peers[:2]), "deleted Mesh TUN cleanup")
        start = time.monotonic()
        with (lab.OUT / "scale-resources.jsonl").open("w") as samples:
            while time.monotonic() - start < args.seconds:
                assert all(flow["child"].poll() is None for flow in flows[1:]), "unrelated flow stopped"
                assert all(peer["child"].poll() is None for peer in survivors), "unrelated Peer restarted"
                samples.write(json.dumps({"elapsed_seconds": time.monotonic() - start, "processes": resources(survivors)}) + "\n")
                samples.flush()
                time.sleep(max(0, min(5, args.seconds - (time.monotonic() - start))))
        assert [reconnections(peer) for peer in survivors] == baseline, "deletion reconnected another Mesh"
        report["surviving_flows"] = [stop_flow(flow) for flow in flows[1:]]
        assert all(flow["passed"] and flow["connections"] == 1 for flow in report["surviving_flows"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(installation.delete, meshes[1:]))
        lab.wait(lambda: all(peer["child"].poll() is not None for peer in peers), "all Mesh runtimes exit")
        for peer in peers:
            assert lab.run("ip", "-n", peer["namespace"], "link", "show", "pwmesh", check=False).returncode != 0
            assert (peer["profile"] / "resolv.conf").read_text() == "nameserver 9.9.9.9\n"
        report["resources_after"] = resources([])
        assert sum(item["fds"] for item in report["resources_after"]) <= sum(item["fds"] for item in report["resources_before"]) + 32, "host descriptors were not reclaimed"
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error) if isinstance(error, (AssertionError, RuntimeError)) else type(error).__name__
    finally:
        for flow in flows:
            flow["stop"].touch()
        for child in reversed(lab.children):
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
        if lab.BASE.exists():
            lab.run(*services, "--stop", check=False)
            for role in ("control", "relay"):
                path = lab.BASE / (role + ".log")
                if path.exists():
                    (lab.OUT / path.name).write_bytes(path.read_bytes())
        (lab.OUT / "scenarios.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
