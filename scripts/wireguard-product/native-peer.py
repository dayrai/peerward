"""Exercise the real packaged Peer and unchanged service sandbox in disposable systemd."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def installed_peer(installation, mesh, installation_path, output, package):
    package = package.resolve()
    profile = installation_path / "linux-peer"
    installation.join(mesh, profile)
    name = "peerward-install-test-" + uuid.uuid4().hex[:12]
    image = "peerward-install-systemd-test:local"
    report = {"passed": False, "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
              "scope": "real deb, installed profile, packaged systemd sandbox, systemd-resolved, identity renewal and crash recovery"}
    with (output / "native-install-driver.log").open("w") as log:
        def run(*command, check=True):
            result = subprocess.run([str(value) for value in command], capture_output=True, text=True, timeout=600)
            log.write(result.stdout + result.stderr)
            log.flush()
            if check and result.returncode:
                raise RuntimeError("native service fixture command failed; see native-install-driver.log")
            return result

        def command(*args, check=True):
            return run("docker", "exec", name, *args, check=check)

        def status():
            result = command("runuser", "-u", "peerward", "--", "peerward", "status", check=False)
            return json.loads(result.stdout) if result.returncode == 0 else {}

        def online():
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                current = status()
                if (current.get("tun_up") and current.get("dns_host_ready") is True
                        and any(relay["healthy"] for relay in current.get("relay_attachments", []))):
                    return current
                time.sleep(.3)
            raise RuntimeError("packaged Peer failed to become ready")

        try:
            run("docker", "build", "-t", image, "-f", ROOT / "deploy/tests/peer-install-systemd.Dockerfile", ROOT)
            run("docker", "run", "-d", "--name", name, "--cgroupns", "private", "--privileged",
                "--sysctl", "net.ipv4.ip_unprivileged_port_start=1024", "--tmpfs", "/run", "--tmpfs", "/run/lock",
                "--tmpfs", "/tmp", "--env", "container=docker", image)
            report["image_id"] = run("docker", "inspect", "--format", "{{.Image}}", name).stdout.strip()
            for _ in range(100):
                if command("systemctl", "is-system-running", check=False).stdout.strip() in ("running", "degraded"):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("isolated systemd failed to start")
            assert command("cat", "/proc/1/cgroup").stdout.strip() == "0::/init.scope"
            run("docker", "cp", package, name + ":/peerward.deb")
            command("dpkg", "-i", "/peerward.deb")
            run("docker", "cp", profile, name + ":/joined")
            command("systemctl", "start", "systemd-resolved")
            command("peerward", "peer", "install", "--profile", "/joined")
            command("peerward", "peer", "install", "--profile", "/joined")
            command("systemctl", "enable", "--now", "peerward-peer")
            report["initial_status"] = online()
            report["service_user"] = command("systemctl", "show", "peerward-peer", "-p", "User", "--value").stdout.strip()
            assert report["service_user"] == "peerward"
            report["config_permissions"] = command("stat", "-c", "%U:%G %a", "/etc/peerward/peer.toml").stdout.strip()
            assert report["config_permissions"] == "root:peerward 640"
            assert command("runuser", "-u", "peerward", "--", "resolvectl", "dns", "pwd0", "9.9.9.9", check=False).returncode != 0
            report["dns_mutation_outside_service_denied"] = True
            report["resolved_dns"] = command("resolvectl", "dns", "pwd0").stdout.strip()
            assert str(mesh["gateway"]) in report["resolved_dns"]
            assert command("peerward", "peer", "install", "--profile", "/joined", check=False).returncode != 0
            report["running_install_rejected"] = True
            yield
            # A real process crash must recover journals using the same packaged unit.
            command("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", "peerward-peer")
            time.sleep(4)
            report["recovered_status"] = online()
            command("systemctl", "stop", "peerward-peer")
            credential = command("sha256sum", "/var/lib/peerward/peer/peer.credential").stdout.split()[0]
            command("peerward", "peer", "install", "--profile", "/joined")
            assert command("sha256sum", "/var/lib/peerward/peer/peer.credential").stdout.split()[0] == credential
            report["renewed_identity_retained"] = True
            assert command("ip", "link", "show", "pwd0", check=False).returncode != 0
            assert "peerward" not in command("nft", "list", "tables").stdout
            report["stopped_network_restored"] = True
            report["passed"] = True
        except Exception as error:
            report["error"] = type(error).__name__
            raise
        finally:
            result = command("journalctl", "--no-pager", "-u", "peerward-peer", check=False)
            (output / "native-peer-journal.log").write_text(result.stdout + result.stderr)
            run("docker", "rm", "-f", name, check=False)
            (output / "native-install.json").write_text(json.dumps(report, indent=2) + "\n")
