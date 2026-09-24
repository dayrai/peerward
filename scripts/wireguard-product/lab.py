#!/usr/bin/env python3
"""Runs only in the dedicated --network none fixture created by the host driver."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import tomllib
from types import SimpleNamespace

ROOT = Path("/source")
BASE = Path("/tmp/peerward-dynamic-product")
OUT = Path("/evidence")
BINARY = OUT / "peerward"
TRAFFIC = Path(__file__).with_name("traffic.py")
DATABASE = "postgres://postgres:peerward_test@127.0.0.1:5432/peerward_test"
children = []


def run(*args, check=True, **kwargs):
    result = subprocess.run([str(x) for x in args], text=True, capture_output=True,
                            timeout=kwargs.pop("timeout", 60), **kwargs)
    if check and result.returncode:
        with (OUT / "command-errors.log").open("a") as errors:
            errors.write(Path(str(args[0])).name + ": " + result.stderr + "\n")
        result.check_returncode()
    return result


def wait(predicate, description, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.2)
    raise RuntimeError(description + " timed out")


def spawn(command, log):
    with log.open("w") as output:
        child = subprocess.Popen([str(x) for x in command], stdout=output, stderr=subprocess.STDOUT)
    children.append(child)
    return child


def query(peer, command):
    result = run(BINARY, command, check=False,
                 env={**os.environ, "PEERWARD_PEER_SOCKET": str(peer["profile"] / "peer.sock")})
    return json.loads(result.stdout) if result.returncode == 0 else {}


def configure(installation, mesh, index, carrier_options=None, network=None, start=True, online=True):
    profile = BASE / f"peer-{index}"
    installation.join(mesh, profile, carrier_options, online=online)
    namespace = "wg-product-" + str(index)
    uplink = "port" + str(index)
    run("ip", "netns", "add", namespace)
    run("ip", "link", "add", uplink, "type", "veth", "peer", "name", "underlay", "netns", namespace)
    run("ip", "link", "set", uplink, "master", "brpwd")
    run("ip", "link", "set", uplink, "up")
    run("ip", "-n", namespace, "link", "set", "lo", "up")
    run("ip", "-n", namespace, "address", "add", f"10.203.0.{index+2}/24", "dev", "underlay")
    run("ip", "-n", namespace, "-6", "address", "add", f"fd42:203::{index+2}/64", "dev", "underlay", "nodad")
    run("ip", "-n", namespace, "link", "set", "underlay", "up")
    if network:
        network(namespace, uplink, index)
    config = profile / "peer.toml"
    joined=tomllib.loads(config.read_text())
    document = config.read_text().split("[linux]")[0]
    address = re.search(r"# Assigned address: ([^\n]+)", document)[1].split("/")[0]
    resolver = profile / "resolv.conf"
    resolver.write_text("nameserver 9.9.9.9\n")
    extra = f'\nmanagement_socket = "{profile}/peer.sock"\nservice_state_file = "{profile}/services.json"\nnat_mapping = "off"\n'
    point = document.index("[[relays]]")
    document = document[:point] + extra + document[point:]
    document += f'''\n[linux]
interface = "pwmesh"
address = "{address}/32"
secondary_address = "{joined['linux']['secondary_address']}"
routes = {json.dumps(joined['linux']['routes'])}
dns_suffix = "{mesh['dns_suffix']}"
dns_server = "{mesh['gateway']}"
dns_upstreams = ["9.9.9.9:53"]
dns_backend = "resolv_conf"
resolv_conf_path = "{resolver}"
platform_state_file = "{profile}/network.json"
mtu = 1280
nft_allow = [{{destination="{mesh['address_cidr']}"}}]
'''
    config.write_text(document)
    peer = {"profile": profile, "namespace": namespace, "address": address, "secondary_address":joined['linux']['secondary_address'].split('/')[0], "peer_id":joined['peer_id'], "child": None}
    if not start:
        return peer
    child = spawn(["ip", "netns", "exec", namespace, BINARY, "peer", "run", "--config", config], OUT / f"peer-{index}.log")
    peer["child"] = child
    wait(lambda: query(peer, "status").get("tun_up") is True or child.poll() is not None, "TUN creation")
    if child.poll() is not None:
        raise RuntimeError("Peer exited before TUN readiness; inspect its runtime log")
    return peer


def ping(source, destination, success=True):
    result = run("ip", "netns", "exec", source["namespace"], "ping", "-n", "-c", "3", "-i", ".2",
                 "-W", "2", "-s", "1200", destination["address"], check=False, timeout=10)
    delivered = result.returncode == 0 and (not success or "3 received" in result.stdout)
    if delivered != success:
        raise RuntimeError("TUN ICMP delivery disagreed with the expected policy")


def full_size_direct(peers):
    before = [query(peer, "metrics") for peer in peers]
    try:
        ping(peers[0], peers[1])
        ping(peers[1], peers[0])
    except RuntimeError:
        return False
    after = [query(peer, "metrics") for peer in peers]
    return all(end.get("peerward_peer_relay_packets_total", 0) == start.get("peerward_peer_relay_packets_total", 0)
               and end.get("peerward_peer_direct_packets_total", 0) > start.get("peerward_peer_direct_packets_total", 0)
               for start, end in zip(before, after))


def policy(installation, mesh, action):
    path = "/meshes/" + mesh["id"] + "/policy"
    status, current = installation.call(path)
    assert status == 200
    status, changed = installation.call(path, "PUT", {"revision": current["revision"] + 1,
        "default_action": action, "rules": []}, {"If-Match": '"' + str(current["revision"]) + '"'})
    assert status == 200
    return changed["revision"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline-seconds", type=int, required=True)
    parser.add_argument("--relay-carrier", choices=["tcp", "quic-wss"], default="tcp")
    parser.add_argument("--soak-seconds", type=int, default=0)
    args = parser.parse_args()
    if not Path("/.dockerenv").exists() or os.getuid() != 0 or BASE.exists():
        raise SystemExit("fresh dedicated container required")
    links = json.loads(run("ip", "-j", "link").stdout)
    if any(link["ifname"] != "lo" for link in links):
        raise SystemExit("fixture must use --network none; host/shared networks are rejected")
    spec = importlib.util.spec_from_file_location("lifecycle", ROOT / "scripts/dynamic-mesh/lifecycle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = {"passed": False, "scenarios": []}
    peers = []
    stop = BASE / "stop-flow"
    observation_stop = BASE / "stop-observer"
    services = [sys.executable, ROOT / "scripts/dynamic-mesh/native-services.py", BASE, "--binary", BINARY]
    try:
        run(sys.executable, ROOT / "deploy/compose/install.py", "--native", "--output", BASE,
            "--public-host", "10.203.0.1", "--database-url", DATABASE,
            "--host-port", "28443", "--control-port", "28880", "--management-port", "28990",
            "--peer-port", "27777", "--backbone-port", "27778", "--relay-health-port", "28991", "--stun-port", "23478")
        run("ip", "link", "add", "brpwd", "type", "bridge")
        run("ip", "address", "add", "10.203.0.1/24", "dev", "brpwd")
        run("ip", "link", "set", "brpwd", "up")
        carrier_options = None
        if args.relay_carrier == "quic-wss":
            carrier_spec = importlib.util.spec_from_file_location("relay_carrier", Path(__file__).with_name("relay-carrier.py"))
            carrier_module = importlib.util.module_from_spec(carrier_spec)
            carrier_spec.loader.exec_module(carrier_module)
            carrier_options, _ = carrier_module.configure(BASE, "10.203.0.1", 27777, 27778, OUT, False,
                                                           use_quic=True, fallback_wss=True)
        report["relay_carrier"] = args.relay_carrier
        run(BINARY, "db", "migrate", "--database-url", DATABASE)
        run(*services)
        installation = module.Installation(SimpleNamespace(environment=BASE / ".env", control="http://127.0.0.1:28880", timeout=90, binary=BINARY))
        mesh = installation.create("wireguard-product")
        policy(installation, mesh, "allow")
        for index in range(2):
            peers.append(configure(installation, mesh, index, carrier_options))
        left, right = peers
        # Per-peer WG/path state is intentionally created on demand by real traffic.
        started = time.monotonic()
        wait(lambda: run("ip", "netns", "exec", left["namespace"], "ping", "-n", "-c", "1", "-W", "1",
                         right["address"], check=False).returncode == 0, "first TUN packet through Relay")
        report["first_ip_round_trip_seconds"] = time.monotonic() - started
        print("First production TUN packet delivered; waiting for authenticated direct probes", flush=True)
        wait(lambda: all(query(peer, "status").get("direct_peers") for peer in peers), "authenticated direct probes")
        wait(lambda: full_size_direct(peers), "full-size authenticated direct MTU proof")
        report["scenarios"].append("bidirectional_1200_byte_icmp_with_no_relay_data")
        capture = OUT / "handshakes.json"
        spawn(["ip", "netns", "exec", left["namespace"], "python3", TRAFFIC, "observe", "--file", capture, "--stop", observation_stop], OUT / "observer.log")
        server_ready, flow_ready = BASE / "server.ready", BASE / "flow.ready"
        spawn(["ip", "netns", "exec", right["namespace"], "python3", TRAFFIC, "server", "--address", right["address"],
               "--ready", server_ready, "--file", OUT / "server.json", "--stop", stop], OUT / "server.log")
        wait(server_ready.exists, "TCP listener")
        flow = spawn(["ip", "netns", "exec", left["namespace"], "python3", TRAFFIC, "client", "--address", right["address"],
                      "--ready", flow_ready, "--file", OUT / "flow.json", "--stop", stop], OUT / "flow.log")
        wait(flow_ready.exists, "one TCP connection through both TUNs")
        before = query(left, "metrics")
        # Keep small probes alive while dropping large UDP datagrams without ICMP feedback.
        run("ip", "netns", "exec", left["namespace"], "nft", "-f", "-", input=
            "table inet fixture_mtu {\n chain output {\n type filter hook output priority -200; policy accept;\n meta l4proto udp udp length > 1252 drop\n }\n}\n")
        wait(lambda: query(left, "metrics").get("peerward_peer_relay_packets_total", 0) > before.get("peerward_peer_relay_packets_total", 0), "MTU blackhole Relay fallback")
        assert query(left, "status").get("direct_peers"), "small direct path incorrectly invalidated by MTU blackhole"
        ping(left, right)
        assert flow.poll() is None, "TCP connection failed during MTU blackhole"
        run("ip", "netns", "exec", left["namespace"], "nft", "delete", "table", "inet", "fixture_mtu")
        wait(lambda: full_size_direct(peers), "MTU proof after bounded retry cooldown", seconds=45)
        report["scenarios"].append("mtu_blackhole_uses_relay_while_small_direct_probes_stay_healthy")
        before = query(left, "metrics")
        fallback_started = time.monotonic()
        run("ip", "netns", "exec", left["namespace"], "nft", "-f", "-", input=
            "table inet fixture_udp {\n chain output {\n type filter hook output priority -200; policy accept;\n meta l4proto udp drop\n }\n}\n")
        wait(lambda: not query(left, "status").get("direct_peers"), "direct failure detection")
        wait(lambda: query(left, "metrics").get("peerward_peer_relay_packets_total", 0) > before.get("peerward_peer_relay_packets_total", 0), "Relay data fallback")
        # A queued DATAGRAM counter is not delivery proof. Wait for a real
        # full-size reply after simultaneous direct + QUIC loss, then check stability.
        wait(lambda: run("ip", "netns", "exec", left["namespace"], "ping", "-n", "-c", "1", "-W", "1", "-s", "1200",
                         right["address"], check=False).returncode == 0, "real WSS fallback packet", seconds=15)
        report["simultaneous_direct_quic_failure_recovery_seconds"] = time.monotonic() - fallback_started
        ping(left, right)
        assert flow.poll() is None, "TCP connection failed during Relay fallback"
        run("ip", "netns", "exec", left["namespace"], "nft", "delete", "table", "inet", "fixture_udp")
        wait(lambda: bool(query(left, "status").get("direct_peers")), "direct restoration")
        wait(lambda: full_size_direct(peers), "restored full-size direct MTU proof", seconds=45)
        report["scenarios"].append("same_tcp_connection_direct_to_relay_to_direct")
        # Force native IPv6 without changing the WireGuard owner or the live TCP socket.
        run("ip", "netns", "exec", left["namespace"], "nft", "-f", "-", input=
            "table ip fixture_ipv4 {\n chain output {\n type filter hook output priority -200; policy accept;\n ip protocol udp drop\n }\n}\n")
        wait(lambda: full_size_direct(peers), "IPv6 full-size direct path", seconds=45)
        wait(capture.exists, "WireGuard wire observation")
        assert json.loads(capture.read_text())["ipv6_transport_packets"] > 0
        report["scenarios"].append("native_ipv6_direct_without_relay_data")
        initial = json.loads(capture.read_text())
        run(*services, "--stop")
        before = query(left, "metrics")
        print("Control/Relay stopped; observing standard WireGuard rekeys on the live direct TCP flow", flush=True)
        until = time.monotonic() + args.offline_seconds
        while time.monotonic() < until:
            if flow.poll() is not None or any(peer["child"].poll() is not None for peer in peers):
                raise RuntimeError("offline direct TCP flow or Peer exited")
            time.sleep(.5)
        final = json.loads(capture.read_text())
        assert final["unique_initiations"] > initial["unique_initiations"], "no new WireGuard initiation observed offline"
        assert final["unique_responses"] > initial["unique_responses"], "no new WireGuard response observed offline"
        assert query(left, "metrics")["peerward_peer_direct_packets_total"] > before["peerward_peer_direct_packets_total"]
        assert final["outer_fragments"] == 0 and final["ipv4_without_df"] == 0
        if args.soak_seconds:
            run("ip", "netns", "exec", left["namespace"], "nft", "delete", "table", "ip", "fixture_ipv4")
            run(*services)
            # Sustain real ciphertext through the Relay, not an idle process.
            for peer in peers:
                run("ip", "netns", "exec", peer["namespace"], "nft", "-f", "-", input=
                    'table inet fixture_soak { chain output { type filter hook output priority -200; policy accept; '
                    'ip daddr 10.203.0.1 udp dport 27777 accept; meta l4proto udp drop; }; }\n')
            print(f"Starting {args.soak_seconds}-second online Relay TCP soak", flush=True)
            soak_start = time.monotonic()
            last_sample = 0
            with (OUT / "soak-resources.jsonl").open("w") as samples:
                while time.monotonic() - soak_start < args.soak_seconds:
                    if flow.poll() is not None or any(peer["child"].poll() is not None for peer in peers):
                        raise RuntimeError("online soak flow or Peer exited")
                    elapsed = time.monotonic() - soak_start
                    if elapsed >= last_sample:
                        last_sample = elapsed + 30
                        observations = []
                        for peer in peers:
                            proc = Path("/proc") / str(peer["child"].pid)
                            stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
                            observations.append({"rss_pages": int((proc / "statm").read_text().split()[1]),
                                                 "cpu_ticks": int(stat[11]) + int(stat[12]),
                                                 "fds": len(list((proc / "fd").iterdir())), "metrics": query(peer, "metrics")})
                        samples.write(json.dumps({"elapsed_seconds": elapsed, "peers": observations}) + "\n")
                        samples.flush()
                    time.sleep(.5)
            report["online_relay_soak_seconds"] = time.monotonic() - soak_start
            for peer in peers:
                run("ip", "netns", "exec", peer["namespace"], "nft", "delete", "table", "inet", "fixture_soak")
        stop.touch()
        assert flow.wait(timeout=20) == 0, "TCP echo did not complete"
        report["flow"] = json.loads((OUT / "flow.json").read_text())
        report["offline_wireguard"] = {"seconds": args.offline_seconds, "before": initial, "after": final}
        report["scenarios"].append("offline_direct_tcp_across_standard_wireguard_rekeys")
        if not args.soak_seconds:
            run("ip", "netns", "exec", left["namespace"], "nft", "delete", "table", "ip", "fixture_ipv4")
            run(*services)
        revision = policy(installation, mesh, "deny")
        wait(lambda: all(query(peer, "status").get("signed_revisions", {}).get("policy", 0) >= revision for peer in peers), "signed deny policy")
        ping(left, right, success=False)
        ping(right, left, success=False)
        report["scenarios"].append("signed_acl_denies_both_tun_directions")
        policy(installation, mesh, "allow")
        installation.delete(mesh)
        wait(lambda: all(peer["child"].poll() is not None for peer in peers), "trusted Mesh deletion")
        for peer in peers:
            assert peer["profile"].joinpath("peer.mesh-terminated").exists()
            assert peer["profile"].joinpath("resolv.conf").read_text() == "nameserver 9.9.9.9\n"
            assert run("ip", "-n", peer["namespace"], "link", "show", "pwmesh", check=False).returncode != 0
            assert not run("ip", "netns", "exec", peer["namespace"], "nft", "list", "tables").stdout.strip()
        report["scenarios"].append("trusted_deletion_releases_tun_dns_and_firewall")
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error) if isinstance(error, (AssertionError, RuntimeError)) else type(error).__name__
    finally:
        if BASE.exists():
            stop.touch()
            observation_stop.touch()
        for index, peer in enumerate(peers):
            try:
                (OUT / f"peer-{index}-diagnostics.json").write_text(json.dumps({
                    "status": query(peer, "status"), "metrics": query(peer, "metrics")}, indent=2) + "\n")
            except (OSError, subprocess.SubprocessError, ValueError):
                pass
        for child in reversed(children):
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        if BASE.exists():
            run(*services, "--stop", check=False)
            for role in ("control", "relay"):
                log = BASE / (role + ".log")
                if log.exists():
                    (OUT / (role + ".log")).write_text(log.read_text())
        (OUT / "scenarios.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Product TUN scenarios " + ("passed" if report["passed"] else "FAILED"), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
