#!/usr/bin/env python3
"""Actual CLI/signatures/systemd/process recovery; fixture roles are not a network acceptance test."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(*args, check=True, **kwargs):
    kwargs.setdefault("text", True)
    result = subprocess.run(args, capture_output=True, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"{args[:3]} failed: {result.stderr[-3000:]}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="peerward-update-systemd-test:local")
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/peerward")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runner-api",action="store_true",help="also run the real Control API and restricted native runner")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    # Debug symbols are not release input. Preserve the original and stage a bounded
    # copy of the same executable so this fixture uses the production input limits.
    tool = output / "peerward-tool"
    run("strip", "--strip-debug", "-o", str(tool), str(args.binary.resolve()))
    identifier = uuid.uuid4().hex[:12]
    name = "peerward-updater-test-" + identifier
    postgres = name + "-postgres"
    evidence = {"started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "passed": False,
                "boundary": "real signed CLI, production systemd units and Linux process/filesystem behavior; synthetic role service, not full application upgrade",
                "binary_sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
                "build_binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in [ROOT / "scripts/test-linux-updater.py", ROOT / "scripts/updater-test-role.c"]},
                "scenarios": []}

    def command(*argv, check=True, env=None):
        prefix = ["docker", "exec"]
        for key, value in (env or {}).items():
            prefix += ["--env", key + "=" + value]
        return run(*prefix, name, *argv, check=check)

    def note(label, **fields):
        evidence["scenarios"].append({"name": label, **fields})
        print(label, flush=True)

    def source(number):
        return ["--manifest", f"/fixture/release-{number}.json", "--signature", f"/fixture/release-{number}.sig", "--public-key", "/fixture/update.pub"]

    def update(role, number):
        health = "unix:///run/peerward/peer.sock" if role == "peer" else f"http://127.0.0.1:{19092 if role == 'control' else 19091}/readyz"
        return ["/fixture/peerward", "update", "apply", *source(number), "--installation-root", "/opt/" + role,
                "--role", role, "--health-url", health, "--artifact-file", f"/fixture/role-{number}"]

    def status(role):
        return json.loads(command("/fixture/peerward", "update", "status", "--installation-root", "/opt/" + role, "--role", role).stdout)["transaction"]

    def pid(role):
        return command("systemctl", "show", f"peerward-{role}.service", "--property=MainPID", "--value").stdout.strip()

    def wait_ready(role):
        for _ in range(50):
            result = command("systemctl", "is-active", f"peerward-{role}.service", check=False)
            if result.stdout.strip() == "active" and pid(role) != "0":
                time.sleep(0.15)
                return
            time.sleep(0.1)
        raise RuntimeError(f"{role} did not start")

    try:
        run("docker", "run", "-d", "--name", name, "--network", "none", "--cgroupns", "private", "--privileged",
            "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", "--env", "container=docker", args.image)
        evidence["image_id"] = run("docker", "inspect", "--format", "{{.Image}}", name).stdout.strip()
        for _ in range(80):
            if command("systemctl", "is-system-running", check=False).stdout.strip() in ("running", "degraded"):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("isolated systemd did not start")
        evidence["systemd"] = command("systemctl", "--version").stdout.splitlines()[0]
        evidence["cgroup"] = command("cat", "/proc/1/cgroup").stdout.strip()
        assert evidence["cgroup"] == "0::/init.scope", "requires the container's own cgroup namespace"
        command("mkdir", "-p", "/fixture", "/etc/peerward")
        command("useradd", "--system", "--no-create-home", "peerward")
        run("docker", "cp", str(tool), name + ":/fixture/peerward")
        run("docker", "cp", str(ROOT / "scripts/updater-test-role.c"), name + ":/fixture/role.c")
        now = int(time.time())
        for number in range(1, 7):
            command("gcc", "-O2", "-DBUILD=" + str(number), "/fixture/role.c", "-o", f"/fixture/role-{number}")
            run("docker", "cp", name + f":/fixture/role-{number}", str(output / f"role-{number}"))
            data = (output / f"role-{number}").read_bytes()
            release = {"schema_version": 1, "sequence": number, "version": f"1.0.{number-1}", "channel": "stable",
                       "published_at": now - 60, "expires_at": now + 3600, "schema_compatibility": {"min": 4, "max": 4},
                       "wire_compatibility": {"min": 5, "max": 5}, "rollback_floor": "1.0.0",
                       "artifacts": [{"platform": "linux", "architecture": "x86_64", "kind": "binary", "name": "peerward",
                                      "url": "https://release.example/peerward", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}]}
            path = output / f"release-{number}.json"
            path.write_text(json.dumps(release, separators=(",", ":")))
            run("docker", "cp", str(path), name + f":/fixture/{path.name}")
        seed = secrets.token_bytes(32)
        key = output / "fixture-key.der"
        key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
        key.chmod(0o600)
        public = run("openssl", "pkey", "-inform", "DER", "-in", str(key), "-pubout", "-outform", "DER", text=False).stdout
        private = output / "fixture-key.hex"
        private.write_text(seed.hex())
        private.chmod(0o600)
        (output / "update.pub").write_text(public[-32:].hex())
        for path in (private, output / "update.pub"):
            run("docker", "cp", str(path), name + ":/fixture/" + path.name)
        for number in range(1, 7):
            command("/fixture/peerward", "update", "sign-manifest", "--manifest", f"/fixture/release-{number}.json",
                    "--private-key", "/fixture/fixture-key.hex", "--output", f"/fixture/release-{number}.sig")
        for role in ("relay", "peer", "control"):
            result = command("/fixture/peerward", "update", "register", *source(1), "--installation-root", "/opt/" + role,
                             "--role", role, "--binary", "/fixture/role-1")
            assert json.loads(result.stdout)["systemd"] == "not_changed"
            run("docker", "cp", str(ROOT / f"deploy/systemd/peerward-{role}.service"), name + f":/etc/systemd/system/peerward-{role}.service")
            command("mkdir", "-p", f"/etc/systemd/system/peerward-{role}.service.d")
            command("cp", f"/opt/{role}/roles/{role}/systemd.conf", f"/etc/systemd/system/peerward-{role}.service.d/10-versioned.conf")
            # Production sandbox retained; avoid auto-restart masking the failed fixture binary.
            command("sh", "-c", 'printf "[Service]\\nRestart=no\\n" > "$1"', "sh", f"/etc/systemd/system/peerward-{role}.service.d/20-test.conf")
        command("systemctl", "daemon-reload")
        for role in ("relay", "peer", "control"):
            command("systemctl", "start", f"peerward-{role}.service")
            wait_ready(role)
        note("signed-registration-and-production-unit-dropins")
        old_pid = pid("relay")
        preview_command=update("relay",2)
        preview_command[2]="preview"
        accepted=command("cat","/opt/relay/accepted-update.json").stdout
        preview=json.loads(command(*preview_command).stdout)
        assert accepted==command("cat","/opt/relay/accepted-update.json").stdout
        command("systemctl","restart","peerward-relay.service")
        wait_ready("relay")
        result=command(*update("relay",2),"--preview-digest",preview["digest"],check=False)
        assert result.returncode != 0 and accepted==command("cat","/opt/relay/accepted-update.json").stdout
        preview=json.loads(command(*preview_command).stdout)
        assert command(*update("relay", 2),"--preview-digest",preview["digest"]).returncode == 0
        new_pid = pid("relay")
        assert new_pid != old_pid and status("relay")["stage"] == "succeeded"
        command(*update("relay", 2),"--preview-digest",preview["digest"])
        assert pid("relay") == new_pid, "repeated success must not restart"
        note("relay-switch-and-idempotent-success", old_pid=old_pid, new_pid=new_pid)
        note("readonly-preview-stale-process-rejected-and-original-digest-retry")
        rollback = ["/fixture/peerward", "update", "rollback", "--installation-root", "/opt/relay", "--role", "relay"]
        command(*rollback)
        rollback_pid = pid("relay")
        command(*rollback)
        assert pid("relay") == rollback_pid and status("relay")["stage"] == "rolled_back"
        note("rollback-retry-does-not-toggle")
        result = command(*update("relay", 3), check=False)
        assert result.returncode != 0 and status("relay")["stage"] == "rolled_back"
        wait_ready("relay")
        note("failed-binary-restores-and-checks-previous")
        command("sh", "-c", 'printf "[Service]\\nExecStartPre=/bin/sleep 8\\n" > /etc/systemd/system/peerward-relay.service.d/30-delay.conf')
        command("systemctl", "daemon-reload")
        process = subprocess.Popen(["docker", "exec", name, "sh", "-c", 'echo $$ > /fixture/updater.pid; exec "$@"', "sh", *update("relay", 4)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(100):
            record = status("relay")
            if record["manifest"]["sequence"] == 4 and record["stage"] == "restart_pending":
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("updater did not reach restart boundary")
        updater_pid = command("cat", "/fixture/updater.pid").stdout.strip()
        command("kill", "-KILL", updater_pid)
        process.communicate(timeout=10)
        command("rm", "/etc/systemd/system/peerward-relay.service.d/30-delay.conf")
        command("systemctl", "daemon-reload")
        command("/fixture/peerward", "update", "recover", "--installation-root", "/opt/relay", "--role", "relay")
        assert status("relay")["stage"] == "succeeded"
        note("actual-updater-sigkill-after-link-switch-and-recovery")
        command(*update("peer", 2))
        assert status("peer")["stage"] == "succeeded"
        note("peer-protected-unix-health-with-daemon-uid-and-pid")
        # Database is new and accessible only in the fixture network namespace.
        password = secrets.token_hex(24)
        run("docker", "run", "-d", "--name", postgres, "--network", "container:" + name,
            "--tmpfs", "/var/lib/postgresql", "--env", "POSTGRES_PASSWORD=" + password, "postgres:18-alpine")
        for _ in range(80):
            if run("docker", "exec", postgres, "pg_isready", "-U", "postgres", check=False).returncode == 0:
                break
            time.sleep(0.1)
        database = {"PEERWARD_DATABASE_URL": "postgres://postgres:" + password + "@127.0.0.1:5432/postgres"}
        command("touch", "/fixture/fail-control")
        result = command(*update("control", 2), check=False, env=database)
        assert result.returncode != 0 and status("control")["stage"] == "recovery_required"
        assert command("readlink", "/opt/control/roles/control/current").stdout.strip() == "../../versions/1.0.1/peerward"
        command("rm", "/fixture/fail-control")
        command("/fixture/peerward", "update", "recover", "--installation-root", "/opt/control", "--role", "control", env=database)
        assert status("control")["stage"] == "succeeded"
        result = command("/fixture/peerward", "update", "rollback", "--installation-root", "/opt/control", "--role", "control", check=False)
        assert result.returncode != 0
        note("control-failure-retains-target-and-recovers-forward")
        result = command(*update("control", 3), check=False, env=database)
        assert result.returncode != 0 and status("control")["stage"] == "recovery_required"
        command(*update("control", 4), "--repair", env=database)
        assert status("control")["stage"] == "succeeded"
        old = json.loads(command("cat", "/opt/control/roles/control/previous-update-transaction.json").stdout)
        assert old["manifest"]["sequence"] == 3 and old["stage"] == "recovery_required"
        note("explicit-newer-signed-repair-retains-failed-control-record")
        if args.runner_api:
            run("docker","exec",postgres,"createdb","-U","postgres","peerward_test")
            run("docker","cp",str(ROOT/"target/debug/examples/console_review_fixture"),name+":/fixture/api-fixture")
            run("docker","cp",str(ROOT/"scripts"),name+":/fixture/scripts")
            run("docker","exec","-d","--env","PEERWARD_TEST_DATABASE_URL=postgres://postgres:"+password+"@127.0.0.1:5432/peerward_test",
                "--env","PEERWARD_CONSOLE_FIXTURE_LISTEN=127.0.0.1:29080",name,"/fixture/api-fixture")
            for _ in range(80):
                if command("python3","-c","import urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:29080/api/v1/meshes',headers={'authorization':'Bearer console-review-test'}),timeout=1).read()",check=False).returncode==0:
                    break
                time.sleep(.1)
            else:raise RuntimeError("real API fixture did not start")
            command("mkdir","-m","700","/fixture/operator")
            command("python3","-c","import os; from pathlib import Path; p=Path('/fixture/operator/database-url'); p.write_text(os.environ['PEERWARD_DATABASE_URL']); p.chmod(0o600)",env=database)
            command("python3","/fixture/scripts/peerward-maintain.py","register-upgrade","--installation-root","/opt/relay","--role","relay",
                "--health-url","http://127.0.0.1:19091/readyz","--program","/fixture/peerward","--manifest","/fixture/release-5.json",
                "--signature","/fixture/release-5.sig","--public-key","/fixture/update.pub","--artifact","/fixture/role-5","--output","/fixture/operator/native-profile.json")
            command("python3","/fixture/scripts/updater-task-fixture.py")
            run("docker","cp",name+":/fixture/native-task-result.json",str(output/"native-task-result.json"))
            note("real-api-restricted-runner-systemd-upgrade-and-lost-assignment-response")
        for role in ("relay", "peer", "control"):
            (output / f"{role}-transaction.json").write_text(json.dumps(status(role), indent=2))
        evidence["passed"] = True
    finally:
        evidence["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / "verification.json").write_text(json.dumps(evidence, indent=2) + "\n")
        result = command("journalctl", "--no-pager", "-u", "peerward-relay", "-u", "peerward-peer", "-u", "peerward-control", check=False)
        (output / "systemd.log").write_text(result.stdout + result.stderr)
        run("docker", "rm", "-f", postgres, check=False)
        run("docker", "rm", "-f", name, check=False)
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
