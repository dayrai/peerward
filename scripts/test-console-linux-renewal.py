#!/usr/bin/env python3
"""Verify administrative renewal with a real Linux TUN peer in a disposable container."""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts/wireguard-product"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--relay-host", help="Host IPv4 reachable from the disposable Docker peer; defaults to the Docker bridge gateway")
    parser.add_argument("--package", type=Path, help="Exercise peer install and the real packaged systemd service from this deb")
    parser.add_argument("--isolated-database", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.isolated_database:
        return subprocess.call([ROOT / "scripts/with-postgres.sh", sys.executable, __file__, *sys.argv[1:], "--isolated-database"])
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    database = os.environ["PEERWARD_TEST_DATABASE_URL"]
    relay_host = args.relay_host or subprocess.run(["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"], capture_output=True, text=True, check=True).stdout.strip()
    relay_host = str(ipaddress.IPv4Address(relay_host))
    lifecycle = load("console_linux_lifecycle", ROOT / "scripts/dynamic-mesh/lifecycle.py")
    fixture = load("console_linux_fixture", ROOT / "scripts/wireguard-product/android-peer.py")
    report = {"passed": False, "scope": "Linux TUN / Control / Relay / local key rotation / authenticated completion"}
    with (args.output / "driver.log").open("w") as log:
        def run(command):
            subprocess.run([str(x) for x in command], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        run(["cargo", "build", "--locked", "-p", "peerward-cli"])
        with tempfile.TemporaryDirectory(prefix="peerward-dynamic-console-linux-") as temporary:
            base = Path(temporary)
            binary = base / "peerward"
            shutil.copy2(ROOT / "target/debug/peerward", binary)
            installation_path = base / "installation"
            ports = []
            sockets = [socket.socket() for _ in range(6)] + [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
            try:
                for sock in sockets:
                    sock.bind(("127.0.0.1", 0))
                    ports.append(sock.getsockname()[1])
                command = [sys.executable, ROOT / "deploy/compose/install.py", "--native", "--output", installation_path,
                           "--public-host", relay_host, "--database-url", database]
                for name, port in zip(["host-port", "control-port", "management-port", "peer-port", "backbone-port", "relay-health-port", "stun-port"], ports):
                    command += ["--" + name, str(port)]
                run(command)
                for role, file in [("control", "control.toml"), ("control", "dynamic.toml"), ("relay", "relay.toml")]:
                    path = installation_path / role / file
                    contents = path.read_text().replace("0.0.0.0:", "127.0.0.1:")
                    if role == "relay":
                        for port in [ports[3], ports[6]]:
                            contents = contents.replace(f"127.0.0.1:{port}", f"{relay_host}:{port}")
                    path.write_text(contents)
            finally:
                for sock in sockets:
                    sock.close()
            services = [sys.executable, ROOT / "scripts/dynamic-mesh/native-services.py", installation_path, "--binary", binary]
            try:
                run([binary, "db", "migrate", "--database-url", database])
                run(services)
                installation = lifecycle.Installation(SimpleNamespace(environment=installation_path / ".env", control=f"http://127.0.0.1:{ports[1]}", timeout=90, binary=binary))
                mesh = installation.create("console-linux-renewal")
                if args.package:
                    native = load("console_native_peer", ROOT / "scripts/wireguard-product/native-peer.py")
                    peer_fixture = native.installed_peer(installation, mesh, installation_path, args.output, args.package)
                else:
                    peer_fixture = fixture.linux_peer(installation, mesh, installation_path, args.output)
                with peer_fixture:
                    base_path = f"/meshes/{mesh['id']}"
                    deadline = time.monotonic() + 60
                    while True:
                        status, peers = installation.call(base_path + "/peers")
                        if status == 200 and len(peers["items"]) == 1 and peers["items"][0]["online"]:
                            peer = peers["items"][0]
                            break
                        if time.monotonic() > deadline:
                            raise RuntimeError("Linux peer did not become authenticated online")
                        time.sleep(.2)
                    request_id = str(uuid.uuid4())
                    path = base_path + f"/console/devices/{peer['id']}/renewals"
                    body = {"request_id": request_id, "current_serial": peer["credentials"]["active"]["serial"], "reason": "Isolated Linux acceptance", "valid_for_seconds": 300}
                    headers = {"If-Match": '"' + str(peer["version"]) + '"'}
                    status, result = installation.call(path, "POST", body, headers)
                    if status != 200:
                        raise RuntimeError("Linux renewal request rejected")
                    status, retry = installation.call(path, "POST", body, headers)
                    if status != 200 or retry["id"] != request_id:
                        raise RuntimeError("Linux renewal request retry did not preserve identity")
                    report.update(peer_id=peer["id"], request_id=request_id)
                    deadline = time.monotonic() + 120
                    while time.monotonic() < deadline:
                        status, page = installation.call(path)
                        if status != 200:
                            raise RuntimeError("Linux renewal status unavailable")
                        current = next(item for item in page["items"] if item["id"] == request_id)
                        report["state"] = current["state"]
                        if current["state"] == "completed":
                            status, updated = installation.call(base_path + f"/peers/{peer['id']}")
                            if status != 200 or not updated["online"] or updated["credentials"]["active"]["serial"] == body["current_serial"]:
                                raise RuntimeError("Linux completion did not preserve online presence with a new credential")
                            report["passed"] = True
                            break
                        time.sleep(.5)
                    if not report["passed"]:
                        raise RuntimeError("Linux credential renewal did not complete")
            except Exception as error:
                report["error"] = type(error).__name__
                report["passed"] = False
                raise
            finally:
                try:
                    run([*services, "--stop"])
                finally:
                    (args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Linux console renewal passed:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
