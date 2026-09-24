#!/usr/bin/env python3
"""Real disposable Compose backup/restore gate. Never select an existing project."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import select
import socket
import shutil
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from archive import ArchiveError
import backup
from common import digest, read_json, run, write_json
import profile
import restore
import runner
import fixture_relay

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/peerward")
    parser.add_argument("--age", default="age")
    parser.add_argument("--keygen", default="age-keygen")
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    project = "peerward-backup-test-" + uuid.uuid4().hex[:12]
    state = output / "installation"
    compose = output / "compose.json"
    source_files = [*Path(__file__).resolve().parent.glob("*.py"), ROOT / "scripts/peerward-maintain.py"]
    source_hashes = {str(file.relative_to(ROOT)): hashlib.sha256(file.read_bytes()).hexdigest() for file in source_files}
    report = {"passed": False, "project": project, "scenarios": [], "sources": source_hashes,
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "platform": platform.platform()}
    def compose_run(*arguments):
        return run(["docker", "compose", "--env-file", state / ".env", "--project-name", project, "--file", compose, *arguments], timeout=150)
    def wait(predicate, label, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(1)
        raise AssertionError(label)
    try:
        run([sys.executable, ROOT / "deploy/compose/install.py", "--output", state, "--public-host", "relay"])
        second_relay, second_host = fixture_relay.prepare(state)
        binary = output / "peerward"
        shutil.copyfile(args.binary, binary)
        binary.chmod(0o700)
        with binary.open("rb") as stream:
            report["binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        report["version"] = run([binary, "--version"]).decode().strip()
        identifier = output / "age.key"
        run([args.keygen, "--output", identifier])
        recipient = run([args.keygen, "-y", identifier]).decode().strip()
        image = "peerward-netns-test:ubuntu26"
        services = {"postgres": {"image": restore.POSTGRES, "environment": {"POSTGRES_USER": "${POSTGRES_USER}", "POSTGRES_DB": "${POSTGRES_DB}", "POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}"},
                                 "tmpfs": ["/var/lib/postgresql"], "ports": ["127.0.0.1::5432"],
                                 "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U $POSTGRES_USER -d $POSTGRES_DB"], "interval": "1s", "timeout": "2s", "retries": 60}}}
        for role in ("control", "relay"):
            services[role] = {"image": image, "user": f"{os.getuid()}:{os.getgid()}", "cap_drop": ["ALL"], "read_only": True,
                              "security_opt": ["no-new-privileges:true"], "tmpfs": ["/tmp"],
                              "entrypoint": ["/opt/peerward"], "command": [role, "run", "--config", f"/etc/peerward/{role}.toml"],
                              "environment": {"PEERWARD_DATABASE_URL": "${PEERWARD_DATABASE_URL}", "PEERWARD_DEV_BEARER": "${PEERWARD_DEV_BEARER}"},
                              "volumes": [f"{binary}:/opt/peerward:ro", f"{state / role}:/etc/peerward:ro", f"{state / role}/meshes:/var/lib/peerward/meshes"],
                              "healthcheck": {"test": ["CMD", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/9090; printf 'GET /readyz HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3; IFS= read -r status <&3; [[ \"$$status\" == *' 200 '* ]]"], "interval": "1s", "timeout": "2s", "retries": 60}}
        services["control"]["environment"]["PEERWARD_DYNAMIC_CONFIG"] = "/etc/peerward/dynamic.toml"
        services["relay-two"] = json.loads(json.dumps(services["relay"]))
        services["relay-two"]["volumes"] = [f"{binary}:/opt/peerward:ro", f"{second_relay}:/etc/peerward:ro", f"{second_relay}/meshes:/var/lib/peerward/meshes"]
        services["control"]["volumes"].append(f"{state}/control/recovery:/var/lib/peerward/recovery")
        with socket.socket() as port_reservation:
            port_reservation.bind(("127.0.0.1", 0))
            control_binding = port_reservation.getsockname()[1]
        services["control"]["ports"] = [f"127.0.0.1:{control_binding}:8080"]
        write_json(compose, {"services": services})
        compose_run("up", "-d", "--wait", "postgres")
        port = compose_run("port", "postgres", "5432").decode().strip().rsplit(":", 1)[1]
        environment = dict(line.split("=", 1) for line in (state / ".env").read_text().splitlines() if "=" in line)
        migration_env = os.environ.copy()
        migration_env["PEERWARD_DATABASE_URL"] = f"postgres://{environment['POSTGRES_USER']}:{environment['POSTGRES_PASSWORD']}@127.0.0.1:{port}/{environment['POSTGRES_DB']}"
        with (output / "migrations.log").open("wb") as log:
            subprocess.run([binary, "db", "migrate"], env=migration_env, stdout=log, stderr=log, check=True)
        compose_run("up", "-d", "--wait", "control", "relay", "relay-two")
        control_port = compose_run("port", "control", "8080").decode().strip().rsplit(":", 1)[1]
        spec = importlib.util.spec_from_file_location("lifecycle", ROOT / "scripts/dynamic-mesh/lifecycle.py")
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        installation = lifecycle.Installation(SimpleNamespace(environment=state / ".env", control="http://127.0.0.1:" + control_port, timeout=90, binary=binary))
        mesh = installation.create("backup")
        other_mesh = installation.create("backup-secondary")
        for value in (mesh, other_mesh):
            status, _ = installation.call("/meshes/" + value["id"] + "/relay-hosts", "POST", {"host_id": second_host})
            assert status in (200, 201, 202)
        profile_path = output / "profile.json"
        profile.register(state, project, [state / "relay", second_relay], [compose], [recipient], profile_path)
        config = profile.load(profile_path)
        def ready():
            try:
                backup.preview(config)
                return True
            except ArchiveError as error:
                # A binary/source migration mismatch cannot converge by waiting.
                if "migration chain" in str(error):
                    raise
                return False
        wait(ready, "snapshot material matches the actual Control and Relay")
        first = backup.preview(config)
        assert first["material"]["meshes"] == 2 and first["material"]["relay_hosts"] == 2
        tls_key = state / "control/tls.key"
        correct_key = tls_key.read_bytes()
        tls_key.write_bytes((second_relay / "tls.key").read_bytes())
        try:
            try:
                backup.preview(config)
                raise AssertionError("mismatched Control TLS key accepted")
            except ArchiveError:
                pass
        finally:
            tls_key.write_bytes(correct_key)
        dynamic = state / "control/dynamic.toml"
        original_dynamic = dynamic.read_bytes()
        dynamic.write_bytes(original_dynamic.replace(b'/var/lib/peerward/recovery', b'/unarchived/recovery'))
        try:
            try:
                backup.preview(config)
                raise AssertionError("unarchived key path accepted")
            except ArchiveError:
                pass
        finally:
            dynamic.write_bytes(original_dynamic)
        report["scenarios"].append("mismatched Control TLS keys and online key paths outside the inventory are rejected")
        with patch.dict(config, {"relays": []}):
            try:
                backup.preview(config)
                raise AssertionError("missing Relay inventory accepted")
            except ArchiveError:
                pass
        report["scenarios"].append("complete Relay inventory required")
        changed = state / "control/preview-test"
        changed.write_bytes(b"preview fence changed")
        try:
            backup.execute(config, str(uuid.uuid4()), first["digest"], age=args.age)
            raise AssertionError("stale preview accepted")
        except ArchiveError:
            pass
        changed.unlink()
        report["scenarios"].append("stale preview rejected before service changes")
        task = str(uuid.uuid4())
        record = backup.execute(config, task, backup.preview(config)["digest"], age=args.age)
        assert record["status"] == "succeeded", record
        assert backup.execute(config, task, record["request"]["preview_digest"], age=args.age) == record
        profile.validate_running(config)
        report["scenarios"].append("consistent snapshot, encryption, service recovery and task replay")
        verified = restore.execute(config, str(uuid.uuid4()), task, identifier, age=args.age)
        assert verified["status"] == "succeeded", verified
        report["scenarios"].append("network-none PostgreSQL restore, all table counts and actual keys match")
        archive = backup.paths(config)[2] / (task + ".age")
        with archive.open("r+b") as stream:
            stream.seek(-1, 2); original = stream.read(1)
            stream.seek(-1, 2); stream.write(bytes([original[0] ^ 1]))
        refused = restore.execute(config, str(uuid.uuid4()), task, identifier, age=args.age)
        assert refused["status"] == "failed" and "isolated_container" not in refused
        with archive.open("r+b") as stream:
            stream.seek(-1, 2); stream.write(original)
        report["scenarios"].append("tampered ciphertext rejected before creating a restore database")
        # Fault injection is at the external encryption boundary; actual stop/start operations remain real.
        with patch.object(backup, "encrypt_archive", side_effect=ArchiveError("injected failure")):
            failed = backup.execute(config, str(uuid.uuid4()), backup.preview(config)["digest"], age=args.age)
        assert failed["status"] == "failed" and failed["artifact"] is None
        profile.validate_running(config)
        report["scenarios"].append("encryption failure restores original healthy services")
        # Kill an actual backup worker after its durable journal and snapshot, before encryption completes.
        crash_id = str(uuid.uuid4())
        code = """import sys,time
sys.path.insert(0,sys.argv[1])
import backup,profile
def paused(*args,**kwargs):
 print('snapshot-journal-durable',flush=True)
 time.sleep(600)
backup.encrypt_archive=paused
backup.execute(profile.load(sys.argv[2]),sys.argv[3],sys.argv[4])
"""
        child = subprocess.Popen([sys.executable, "-c", code, str(ROOT / "scripts/maintenance"), str(profile_path), crash_id, backup.preview(config)["digest"]],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            assert select.select([child.stdout], [], [], 90)[0], "backup worker never reached its durable boundary"
            assert child.stdout.readline().strip() == b"snapshot-journal-durable"
        finally:
            child.kill()
            child.wait(timeout=5)
            child.stdout.close()
        recovered = backup.recover(config, crash_id)
        assert recovered["status"] == "failed" and recovered["stage"] == "recovered"
        profile.validate_running(config)
        report["scenarios"].append("SIGKILL of the backup worker preserves a recoverable journal; exact original services restart and plaintext stage is removed")
        runner_id = str(uuid.uuid4())
        status, enrolled = installation.call("/deployment-runners", "POST", {"id": runner_id, "name": "backup-fixture-runner", "profile_digest": digest(config), "ttl_seconds": 3600})
        assert status == 201
        connection_file = output / "runner-connection.json"
        write_json(connection_file, {"runner_id": runner_id, "token": enrolled["token"], "control_url": installation.args.control, "profile_digest": digest(config)})
        runner.serve(config, connection_file, age=args.age, once=True)
        status, current = installation.call("/deployment-runners")
        registered = next(row for row in current["items"] if row["id"] == runner_id)
        remote_id = str(uuid.uuid4())
        status, remote = installation.call("/deployment-tasks", "POST", {"id": remote_id, "runner_id": runner_id, "preview_digest": registered["preview"]["digest"]})
        assert status == 202
        actual_request = runner.request
        def lost_response(*arguments):
            actual_request(*arguments)
            raise ArchiveError("injected loss after server assigned the operation")
        with patch.object(runner, "request", side_effect=lost_response):
            try:
                runner.serve(config, connection_file, age=args.age, once=True)
                raise AssertionError("assignment response loss was hidden")
            except ArchiveError:
                pass
        runner.serve(config, connection_file, age=args.age, once=True)
        status, remote = installation.call("/deployment-tasks/" + remote_id)
        assert status == 200 and remote["status"] == "succeeded", remote
        local = read_json(backup.paths(config)[1] / (remote_id + ".json"))
        assert remote["report"]["artifact"]["sha256"] == local["artifact"]["sha256"]
        assert remote["reported_at"] is not None
        remote_verified = restore.execute(config, str(uuid.uuid4()), remote_id, identifier, age=args.age)
        assert remote_verified["status"] == "succeeded", remote_verified
        report["scenarios"].append("restricted API runner recovers a lost assignment response, executes one real backup, reports its digest and verifies the restored database")
        # Remove the entire owned source deployment before portable verification.
        workspace = output / "independent-verification"
        portable = profile.load(profile_path, workspace)
        assert digest(portable) == digest(config)
        _, portable_tasks, portable_archives = backup.paths(portable)
        shutil.copyfile(backup.paths(config)[1] / (remote_id + ".json"), portable_tasks / (remote_id + ".json"))
        shutil.copyfile(backup.paths(config)[2] / (remote_id + ".age"), portable_archives / (remote_id + ".age"))
        compose_run("down", "--volumes", "--remove-orphans")
        independent = restore.execute(portable, str(uuid.uuid4()), remote_id, identifier, age=args.age)
        assert independent["status"] == "succeeded", independent
        try:
            backup.recover(portable, remote_id)
            raise AssertionError("verification workspace attempted source recovery")
        except ArchiveError:
            pass
        report["scenarios"].append("portable verification succeeds after source containers and database are removed; verification workspace cannot operate source services")
        assert not list((state / "maintenance").glob(".backup-*")) and not list((state / "maintenance").glob(".verify-*"))
        report.update(passed=True, backup={k: record["artifact"][k] for k in ("sha256", "bytes", "files")}, verification=verified["result"], mesh_id=mesh["id"])
    finally:
        if compose.exists():
            try:
                compose_run("down", "--volumes", "--remove-orphans")
            except ArchiveError:
                report["cleanup_failed"] = True
                report["passed"] = False
        if source_hashes != {str(file.relative_to(ROOT)): hashlib.sha256(file.read_bytes()).hexdigest() for file in source_files}:
            report.update(passed=False, sources_changed_during_run=True)
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(output / "verification.json", report)
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
