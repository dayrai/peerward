#!/usr/bin/env python3
"""Real TUN traffic forced through two distinct shared QUIC hosts in the private lab."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tomllib
from types import SimpleNamespace
import uuid

import lab
from matrix import load


def second_host():
    base = lab.BASE
    folder = base / "second-relay"
    folder.mkdir(mode=0o700)
    host = str(uuid.uuid4())
    lab.run("openssl", "req", "-new", "-newkey", "ed25519", "-nodes", "-keyout", folder / "tls.key",
            "-out", folder / "tls.csr", "-subj", "/CN=" + host)
    (folder / "tls.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
    lab.run("openssl", "x509", "-req", "-in", folder / "tls.csr", "-CA", base / "offline/host-ca.pem",
            "-CAkey", base / "offline/host-ca.key", "-set_serial", str(uuid.uuid4().int),
            "-out", folder / "tls.pem", "-days", "1", "-extfile", folder / "tls.ext")
    for name in ("ca.pem", "wss.pem", "wss.key"):
        (folder / name).write_bytes((base / "relay" / name).read_bytes())
    config = (base / "relay/relay.toml").read_text()
    original = tomllib.loads(config)["host_id"]
    config = config.replace(original, host).replace(str(base / "relay"), str(folder))
    for old, new in [(27777, 27779), (27778, 27780), (28991, 28992), (23478, 23479)]:
        config = config.replace(":" + str(old) + '"', ":" + str(new) + '"')
    (folder / "relay.toml").write_text(config)
    for path in folder.iterdir():
        path.chmod(0o600)
    der = subprocess.check_output(["openssl", "x509", "-in", folder / "tls.pem", "-outform", "DER"])
    with (base / "control/dynamic.toml").open("a") as dynamic:
        dynamic.write(f'\n[[hosts]]\nid = "{host}"\nname = "backbone-tun-second"\ncertificate_sha256 = "{hashlib.sha256(der).hexdigest()}"\n'
                      'peer_endpoints = ["quic://10.203.0.1:27779"]\nbackbone_endpoints = ["quic://10.203.0.1:27779"]\nis_default = false\n')
    return host, folder / "relay.toml"


def pin_and_start(peer, index, port):
    path = peer["profile"] / "peer.toml"
    document, linux = path.read_text().split("[linux]", 1)
    header, *relays = document.split("[[relays]]")
    selected = [part for part in relays if f'quic://10.203.0.1:{port}' in part]
    if len(selected) != 1:
        raise RuntimeError("joined profile lacks exactly one expected QUIC host")
    path.write_text(header + "[[relays]]" + selected[0] + "[linux]" + linux)
    # Only this Peer namespace changes. No raw TCP, alternate Relay or peer UDP is reachable.
    lab.run("ip", "netns", "exec", peer["namespace"], "nft", "-f", "-", input=
        'table inet fixture_backbone { chain output { type filter hook output priority -200; policy accept; '
        f'oifname "underlay" ip daddr 10.203.0.1 udp dport {port} accept; '
        'oifname "underlay" drop; }; }\n')
    peer["child"] = lab.spawn(["ip", "netns", "exec", peer["namespace"], lab.BINARY,
                               "peer", "run", "--config", path], lab.OUT / f"peer-{index}.log")
    lab.wait(lambda: lab.query(peer, "status").get("tun_up") is True or peer["child"].poll() is not None,
             "forced-host TUN creation")
    if peer["child"].poll() is not None:
        raise RuntimeError("forced-host Peer exited before TUN creation")
    return tomllib.loads(path.read_text())["relays"][0]["relay_id"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=320)
    args = parser.parse_args()
    if not 320 <= args.seconds <= 3600:
        raise SystemExit("backbone flow requires 320..3600 seconds")
    if not Path("/.dockerenv").exists() or os.getuid() != 0 or lab.BASE.exists():
        raise SystemExit("fresh dedicated container required")
    if any(link["ifname"] != "lo" for link in json.loads(lab.run("ip", "-j", "link").stdout)):
        raise SystemExit("network-none fixture required")
    os.environ["TOKIO_WORKER_THREADS"] = "2"
    lifecycle = load("lifecycle", lab.ROOT / "scripts/dynamic-mesh/lifecycle.py")
    carrier = load("carriers", Path(__file__).with_name("relay-carrier.py"))
    scale = load("scale", Path(__file__).with_name("mesh-scale.py"))
    services = [sys.executable, lab.ROOT / "scripts/dynamic-mesh/native-services.py", lab.BASE, "--binary", lab.BINARY]
    peers, flows = [], []
    report = {"passed": False, "scope": "TUN to WireGuard to QUIC host A to QUIC backbone to host B to TUN",
              "not_claimed": ["hardware NAT", "five-round throughput baseline", "independent audit"]}
    try:
        lab.run(sys.executable, lab.ROOT / "deploy/compose/install.py", "--native", "--output", lab.BASE,
                "--public-host", "10.203.0.1", "--database-url", lab.DATABASE,
                "--host-port", "28443", "--control-port", "28880", "--management-port", "28990",
                "--peer-port", "27777", "--backbone-port", "27778", "--relay-health-port", "28991", "--stun-port", "23478")
        lab.run("ip", "link", "add", "brpwd", "type", "bridge")
        lab.run("ip", "address", "add", "10.203.0.1/24", "dev", "brpwd")
        lab.run("ip", "link", "set", "brpwd", "up")
        options, _ = carrier.configure(lab.BASE, "10.203.0.1", 27777, 27778, lab.OUT, False, use_quic=True)
        host, config = second_host()
        lab.run(lab.BINARY, "db", "migrate", "--database-url", lab.DATABASE)
        lab.run(*services)
        lab.spawn([lab.BINARY, "relay", "run", "--config", config], lab.OUT / "second-relay.log")
        installation = lifecycle.Installation(SimpleNamespace(environment=lab.BASE / ".env", control="http://127.0.0.1:28880", timeout=90, binary=lab.BINARY))
        mesh = installation.create("backbone-tun")
        def assigned():
            status, body = installation.call("/meshes/" + mesh["id"] + "/relay-hosts", "POST", {"host_id": host})
            if status != 202:
                raise RuntimeError("second host assignment rejected")
            return body["state"] == "ready"
        lab.wait(assigned, "second host assignment", 60)
        lab.policy(installation, mesh, "allow")
        for index in range(2):
            peers.append(lab.configure(installation, mesh, index, options, start=False))
        relay_ids = [pin_and_start(peer, index, port) for index, (peer, port) in enumerate(zip(peers, [27777, 27779]))]
        assert relay_ids[0] != relay_ids[1], "both Peers selected the same Relay"
        report["distinct_relay_ids"] = relay_ids
        lab.wait(lambda: lab.run("ip", "netns", "exec", peers[0]["namespace"], "ping", "-n", "-c", "1", "-W", "1",
                                peers[1]["address"], check=False).returncode == 0, "first real backbone TUN reply")
        lab.ping(peers[0], peers[1])
        lab.ping(peers[1], peers[0])
        before = [lab.query(peer, "metrics") for peer in peers]
        flows.append(scale.start_flow(peers, 0))
        start = time.monotonic()
        with (lab.OUT / "backbone-resources.jsonl").open("w") as log:
            while time.monotonic() - start < args.seconds:
                assert flows[0]["child"].poll() is None, "backbone TCP flow exited"
                assert all(peer["child"].poll() is None for peer in peers), "backbone Peer exited"
                log.write(json.dumps({"elapsed_seconds": time.monotonic() - start, "peers": [lab.query(peer, "metrics") for peer in peers]}) + "\n")
                log.flush()
                time.sleep(min(5, max(0, args.seconds - (time.monotonic() - start))))
        report["observed_seconds"] = time.monotonic() - start
        report["flow"] = scale.stop_flow(flows[0])
        assert report["flow"]["passed"] and report["flow"]["connections"] == 1
        after = [lab.query(peer, "metrics") for peer in peers]
        report["metrics_before"], report["metrics_after"] = before, after
        for initial, final in zip(before, after):
            assert final["peerward_peer_direct_packets_total"] == 0
            assert final["peerward_peer_relay_packets_total"] > initial["peerward_peer_relay_packets_total"]
        revision = lab.policy(installation, mesh, "deny")
        lab.wait(lambda: all(lab.query(peer, "status").get("signed_revisions", {}).get("policy", 0) >= revision for peer in peers), "backbone deny policy")
        lab.ping(peers[0], peers[1], success=False)
        lab.ping(peers[1], peers[0], success=False)
        installation.delete(mesh)
        lab.wait(lambda: all(peer["child"].poll() is not None for peer in peers), "backbone Mesh deletion")
        for peer in peers:
            assert lab.run("ip", "-n", peer["namespace"], "link", "show", "pwmesh", check=False).returncode != 0
            assert (peer["profile"] / "resolv.conf").read_text() == "nameserver 9.9.9.9\n"
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
                    child.wait(timeout=10)
                except Exception:
                    child.kill()
                    child.wait(timeout=5)
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
