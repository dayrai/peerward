"""Disposable Linux TUN peer for the explicitly selected physical Android gate."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
from wireguard_fixture import freeze_fixture
from wireguard_gate_state import cleanup_owned_container

ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def linux_peer(installation, mesh, installation_path, output, carrier_options=None):
    profile = installation_path / "linux-peer"
    installation.join(mesh, profile, carrier_options)
    config = profile / "peer.toml"
    document = config.read_text().split("[linux]")[0]
    address = re.search(r"# Assigned address: ([^\n]+)", document)[1].split("/")[0]
    resolver = profile / "resolv.conf"
    resolver.write_text("nameserver 9.9.9.9\n")
    extra = f'\nmanagement_socket = "{profile}/peer.sock"\nservice_state_file = "{profile}/services.json"\nnat_mapping = "off"\n'
    point = document.index("[[relays]]")
    document = document[:point] + extra + document[point:]
    document += f'''
[linux]
interface = "pwandroid"
address = "{address}/32"
routes = ["{mesh['address_cidr']}"]
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
    name = "peerward-android-tun-" + uuid.uuid4().hex[:12]
    image = "peerward-wireguard-product-test:" + name
    fixture_source = output / "fixture-source"
    manifest = freeze_fixture(ROOT, fixture_source)
    (output / "fixture-sources.json").write_text(json.dumps(manifest, indent=2) + "\n")
    processes = []
    import shutil
    shutil.copy2(installation.args.binary, output / "peerward")
    with (output / "linux-driver.log").open("w") as log:
        def run(command, timeout=60, check=True):
            return subprocess.run([str(x) for x in command], stdout=log, stderr=subprocess.STDOUT,
                                  timeout=timeout, check=check)
        try:
            for dockerfile, tag in [("netns-test", "peerward-netns-test:ubuntu26"),
                                   ("wireguard-product-test", image)]:
                run(["docker", "build", "-t", tag, "-f", fixture_source / f"packaging/docker/{dockerfile}.Dockerfile", fixture_source], 600)
            run(["docker", "run", "--detach", "--rm", "--name", name,
                 "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                 "--mount", f"type=bind,source={fixture_source},target=/source,readonly",
                 "--mount", f"type=bind,source={profile},target={profile}",
                 "--mount", f"type=bind,source={output},target=/evidence",
                 image, "sleep", "infinity"])
            if carrier_options:
                # Keep inner overlay UDP, forbid every underlay UDP packet in
                # this disposable namespace: WG traffic must use the selected Relay.
                run(["docker", "exec", name, "nft", "add", "table", "inet", "carrier_fixture"])
                run(["docker", "exec", name, "nft", "add", "chain", "inet", "carrier_fixture", "output", "{ type filter hook output priority -10; policy accept; }"])
                # Permit only advertised QUIC Relay UDP; direct WireGuard/STUN
                # remains blocked so this test proves the selected relay carrier.
                import tomllib
                from urllib.parse import urlsplit
                relay_config = tomllib.loads(config.read_text())
                for relay in relay_config.get("relays", []):
                    for endpoint in relay.get("endpoints", []):
                        target = urlsplit(endpoint)
                        if target.scheme == "quic":
                            family = "ip6" if ":" in target.hostname else "ip"
                            run(["docker", "exec", name, "nft", "add", "rule", "inet", "carrier_fixture", "output", family, "daddr", target.hostname, "udp", "dport", str(target.port), "counter", "accept"])
                run(["docker", "exec", name, "nft", "add", "rule", "inet", "carrier_fixture", "output", "oifname", "!=", "pwandroid", "meta", "l4proto", "udp", "counter", "drop"])
            with (output / "linux-peer.log").open("w") as peer_log:
                processes.append(subprocess.Popen(["docker", "exec", "--env", "RUST_LOG=" + os.environ.get("PEERWARD_FIXTURE_LOG", "info"), name, "/evidence/peerward",
                    "peer", "run", "--config", str(config)], stdout=peer_log, stderr=subprocess.STDOUT))
            for _ in range(100):
                if processes[0].poll() is not None:
                    raise RuntimeError("Linux TUN peer exited")
                result = subprocess.run(["docker", "exec", "--env", "PEERWARD_PEER_SOCKET=" + str(profile / "peer.sock"), name, "/evidence/peerward", "status"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and json.loads(result.stdout).get("tun_up"):
                    break
                time.sleep(.2)
            else:
                raise RuntimeError("Linux TUN peer readiness timed out")
            with (output / "linux-echo.log").open("w") as echo_log:
                processes.append(subprocess.Popen(["docker", "exec", name, "python3",
                    "/source/scripts/wireguard-product/udp-echo.py", address], stdout=echo_log, stderr=subprocess.STDOUT))
            for _ in range(100):
                if (output / "linux-echo.json").exists():
                    break
                if processes[-1].poll() is not None:
                    raise RuntimeError("Linux TUN UDP echo exited")
                time.sleep(.1)
            else:
                raise RuntimeError("Linux TUN UDP echo readiness timed out")
            yield address
        finally:
            for command in ["status", "metrics"]:
                result = subprocess.run(["docker", "exec", "--env", "PEERWARD_PEER_SOCKET=" + str(profile / "peer.sock"), name, "/evidence/peerward", command], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    (output / f"linux-{command}.json").write_text(result.stdout)
            # Stop the sole test Peer before returning ownership of its private state.
            run(["docker", "exec", name, "pkill", "-INT", "-x", "peerward"], check=False)
            if processes:
                try:
                    processes[0].wait(timeout=15)
                except subprocess.TimeoutExpired:
                    run(["docker", "exec", name, "pkill", "-KILL", "-x", "peerward"], check=False)
            # Private runtime checkpoints are root-owned inside this disposable profile.
            # Return ownership before TemporaryDirectory cleanup on the unprivileged host.
            run(["docker", "exec", name, "chown", "-R", f"{os.getuid()}:{os.getgid()}", profile], check=False)
            cleanup = cleanup_owned_container(name, log)
            (output / "linux-cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")
            run(["docker", "image", "rm", image], check=False)
            for process in processes:
                process.wait(timeout=15)
            if not cleanup["removed"]:
                raise RuntimeError("Linux Android fixture cleanup could not be verified")
