#!/usr/bin/env python3
"""Disposable two-host QUIC admission/backbone/deletion gate. Never reads root .env."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-database", action="store_true")
    parser.add_argument("--lifecycle-scale", action="store_true", help="also exercise 100 create/delete cycles and 100 simultaneous Mesh contexts")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/wireguard/quic-host")
    parser.add_argument("--binary", type=Path, help="previously built executable")
    parser.add_argument("--binary-sha256", help="required SHA-256 for --binary")
    args = parser.parse_args()
    if bool(args.binary) != bool(args.binary_sha256):
        parser.error("--binary and --binary-sha256 must be provided together")
    if not args.isolated_database:
        return subprocess.call([ROOT / "scripts/with-postgres.sh", sys.executable,
                                __file__, *sys.argv[1:], "--isolated-database"])
    database = os.environ["PEERWARD_TEST_DATABASE_URL"]
    output = args.output.resolve() / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True)
    report = {"passed": False, "release_gate_eligible": False,
              "scope": "two_production_dual_stack_shared_hosts_quic_peer_and_backbone",
              "not_claimed": ["TUN data", "100 Meshes with simultaneous traffic", "independent audit"]}
    with (output / "driver.log").open("w") as log, tempfile.TemporaryDirectory(prefix="peerward-dynamic-quic-") as temporary:
        base = Path(temporary) / "installation"
        second = None
        binary = output / "peerward"
        services = [sys.executable, ROOT / "scripts/dynamic-mesh/native-services.py", base, "--binary", binary]

        def run(command, timeout=180, env=None):
            subprocess.run([str(item) for item in command], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=timeout, env=env)
            log.flush()

        try:
            if not args.binary:
                run(["cargo", "build", "--locked", "-p", "peerward-cli"], 600)
            shutil.copy2(args.binary or ROOT / "target/debug/peerward", binary)
            report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            if args.binary and report["binary_sha256"] != args.binary_sha256:
                raise ValueError("provided executable differs from the pinned SHA-256")
            reserved = [socket.socket() for _ in range(9)] + [socket.socket(type=socket.SOCK_DGRAM) for _ in range(4)]
            for item in reserved:
                item.bind(("127.0.0.1", 0))
            ports = [item.getsockname()[1] for item in reserved]
            cert, key = Path(temporary) / "quic.pem", Path(temporary) / "quic.key"
            run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1",
                 "-subj", "/CN=Peerward QUIC host validation", "-addext", "subjectAltName=IP:127.0.0.1,IP:::1",
                 "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", key, "-out", cert])
            key.chmod(0o600)
            command = [sys.executable, ROOT / "deploy/compose/install.py", "--native", "--output", base,
                       "--public-host", "127.0.0.1", "--database-url", database,
                       "--stun-port", ports[11],
                       "--quic-port", ports[9], "--quic-certificate-file", cert,
                       "--quic-private-key-file", key, "--quic-ca-file", cert]
            for name, port in zip(["host", "control", "management", "peer", "backbone", "relay-health"], ports):
                command += ["--" + name + "-port", port]
            run(command)
            first_config = base / "relay/relay.toml"
            first_config.write_text(first_config.read_text().replace("[quic]\n", f'[quic]\nadditional_address = "[::1]:{ports[9]}"\n'))
            folder = base / "second-relay"
            folder.mkdir(mode=0o700)
            host = str(uuid.uuid4())
            run(["openssl", "req", "-new", "-newkey", "ed25519", "-nodes", "-keyout", folder / "tls.key",
                 "-out", folder / "tls.csr", "-subj", "/CN=" + host])
            (folder / "tls.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
            run(["openssl", "x509", "-req", "-in", folder / "tls.csr", "-CA", base / "offline/host-ca.pem",
                 "-CAkey", base / "offline/host-ca.key", "-set_serial", str(uuid.uuid4().int),
                 "-out", folder / "tls.pem", "-days", "1", "-extfile", folder / "tls.ext"])
            for name in ("ca.pem", "quic.pem", "quic.key"):
                (folder / name).write_bytes((base / "relay" / name).read_bytes())
            config = (base / "relay/relay.toml").read_text()
            original = json.loads((base / "installation.json").read_text())["host_id"]
            config = config.replace(original, host).replace(str(base / "relay"), str(folder))
            for old, new in [(ports[3], ports[6]), (ports[4], ports[7]), (ports[5], ports[8]), (ports[9], ports[10]), (ports[11], ports[12])]:
                config = config.replace(":" + str(old) + '"', ":" + str(new) + '"')
            (folder / "relay.toml").write_text(config)
            for path in folder.iterdir():
                path.chmod(0o600)
            der = subprocess.check_output(["openssl", "x509", "-in", folder / "tls.pem", "-outform", "DER"])
            with (base / "control/dynamic.toml").open("a") as dynamic:
                dynamic.write(f'\n[[hosts]]\nid = "{host}"\nname = "second-quic-host"\ncertificate_sha256 = "{hashlib.sha256(der).hexdigest()}"\n'
                              f'peer_endpoints = ["quic://[::1]:{ports[10]}"]\nbackbone_endpoints = ["quic://[::1]:{ports[10]}"]\nis_default = false\n')
            for item in reserved:
                item.close()
            run([binary, "db", "migrate", "--database-url", database])
            run(services)
            with (output / "second-relay.log").open("w") as relay_log:
                second = subprocess.Popen([binary, "relay", "run", "--config", folder / "relay.toml"],
                                          stdout=relay_log, stderr=subprocess.STDOUT, cwd=ROOT,
                                          env={**os.environ, "RUST_LOG": os.environ.get("PEERWARD_FIXTURE_LOG", "info")})
            env = {**os.environ, "PEERWARD_TEST_BINARY": str(binary), "PEERWARD_DYNAMIC_TEST_DIR": str(base), "PEERWARD_DYNAMIC_RELAY_CA": str(cert),
                   "PEERWARD_DYNAMIC_SECOND_HOST": host, "PEERWARD_DYNAMIC_CONTROL": f"http://127.0.0.1:{ports[1]}"}
            run(["cargo", "test", "--locked", "-p", "peerward-relay", "--test", "dynamic_host", "--", "--ignored", "--nocapture"], 300, env)
            if args.lifecycle_scale:
                run([sys.executable, ROOT / "scripts/dynamic-mesh/lifecycle.py", "--environment", base / ".env",
                     "--control", f"http://127.0.0.1:{ports[1]}", "--output", output / "lifecycle",
                     "--cycles", "100", "--simultaneous", "100", "--binary", binary], 1800)
                report["lifecycle"] = json.loads((output / "lifecycle/result.json").read_text())
            report["passed"] = True
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            report["error"] = type(error).__name__
        finally:
            if second is not None:
                second.send_signal(signal.SIGINT)
                try:
                    second.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    second.kill()
                    second.wait(timeout=5)
                    report["passed"] = False
                    report["error"] = "second host shutdown timed out"
            if base.exists():
                try:
                    run([*services, "--stop"], 30)
                except subprocess.SubprocessError:
                    report["passed"] = False
                for role in ("control", "relay"):
                    path = base / (role + ".log")
                    if path.exists():
                        (output / path.name).write_bytes(path.read_bytes())
            (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"QUIC host gate {'passed' if report['passed'] else 'FAILED'}: {output}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
