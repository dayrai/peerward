"""Verify a pinned backup in a disposable PostgreSQL with no network or host mounts."""
import shutil
import time
from archive import ArchiveError, decrypt_archive, private_directory
from common import LABEL, POSTGRES, digest, exclusive, inspect, read_json, run, task_id
from database import Snapshot, inventory, verify_material
from backup import begin, paths, save


def remove_owned(identifier, container):
    row = inspect(container)
    if (row["Config"].get("Labels") or {}).get(LABEL) != identifier:
        raise ArchiveError("restore container ownership changed")
    if row["HostConfig"]["NetworkMode"] != "none" or any(m["Type"] != "tmpfs" for m in row["Mounts"]):
        raise ArchiveError("restore container isolation changed")
    run(["docker", "rm", "--force", container])


def execute(profile, identifier, backup_id, identity, *, age="age", storage_gib=2):
    if not 1 <= storage_gib <= 64:
        raise ArchiveError("isolated restore storage must be 1 to 64 GiB")
    base, tasks, archives = paths(profile)
    with exclusive(base / "operation.lock"):
        receipt = read_json(tasks / (task_id(backup_id) + ".json"))
        if receipt["operation"] != "installation_backup" or receipt["status"] != "succeeded" or receipt["profile_digest"] != digest(profile):
            raise ArchiveError("select a completed backup receipt for this exact registered profile")
        artifact = receipt["artifact"]
        if artifact["name"] != backup_id + ".age":
            raise ArchiveError("invalid backup artifact reference")
        request = {"operation": "isolated_restore_verify", "backup_id": backup_id,
                   "ciphertext_sha256": artifact["sha256"], "storage_gib": storage_gib}
        path, record, fresh = begin(profile, identifier, request)
        if not fresh:
            return record
        stage = base / (".verify-" + identifier)
        try:
            private_directory(stage)
            save(path, record, stage="decrypting")
            manifest = decrypt_archive(archives / artifact["name"], artifact["sha256"], identity, stage / "inputs", age=age)
            metadata = manifest["metadata"]
            if metadata.get("type") != "peerward-installation" or metadata.get("task_id") != backup_id or metadata.get("profile_digest") != digest(profile) or metadata.get("requires_security_reconciliation") is not True:
                raise ArchiveError("backup provenance differs from its task receipt")
            inputs = stage / "inputs"
            expected = read_json(inputs / "database/inventory.json")
            database = metadata["database"]
            if database != profile["database"]:
                raise ArchiveError("backup database identity differs from the registered profile")
            name = "peerward-restore-" + identifier
            # Write deterministic ownership before Docker create, including the narrow create/receipt crash window.
            save(path, record, stage="creating_isolation", isolated_name=name)
            container = run(["docker", "create", "--name", name, "--label", LABEL + "=" + identifier,
                             "--network", "none", "--user", "70:70", "--read-only", "--cap-drop", "ALL",
                             "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "2g", "--cpus", "2",
                             "--tmpfs", f"/var/lib/postgresql:rw,nosuid,nodev,noexec,size={storage_gib}g,uid=70,gid=70,mode=0700",
                             "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,noexec,size=16m,uid=70,gid=70,mode=0700",
                             "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m,uid=70,gid=70,mode=0700",
                             "--env", "POSTGRES_USER=" + database["user"], "--env", "POSTGRES_DB=" + database["name"],
                             "--env", "POSTGRES_HOST_AUTH_METHOD=reject", "--env", "POSTGRES_PASSWORD=unused-isolated-no-network",
                             POSTGRES]).decode().strip()
            save(path, record, isolated_container=container, stage="restoring")
            run(["docker", "start", container])
            deadline = time.monotonic() + 60
            while True:
                try:
                    run(["docker", "exec", container, "pg_isready", "-U", database["user"], "-d", database["name"]], timeout=5)
                    break
                except ArchiveError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(1)
            with open(inputs / "database/postgres.dump", "rb") as source:
                # Keep the original owner/ACLs inside the archive; this verification DB uses only its isolated owner.
                run(["docker", "exec", "-i", container, "pg_restore", "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl",
                     "--no-password", "-U", database["user"], "-d", database["name"]], stdin=source, timeout=1800)
            with Snapshot(container, database) as snapshot:
                actual = inventory(snapshot)
            if actual != expected:
                raise ArchiveError("restored database counts, revisions or key inventory differ from the snapshot")
            material = verify_material(actual, inputs / "control", {r["host_id"]: inputs / "relays" / r["host_id"] for r in profile["relays"]})
            row = inspect(container)
            if row["HostConfig"]["NetworkMode"] != "none" or row["HostConfig"].get("PortBindings") or row["HostConfig"].get("Binds"):
                raise ArchiveError("restore isolation could not be confirmed")
            save(path, record, result={"ciphertext_sha256": artifact["sha256"], "tables_verified": len(actual["counts"]),
                                      "material": material, "network": "none", "application_started": False,
                                      "authorization_activation": "forbidden", "storage": "temporary_memory",
                                      "postgres_image": row["Image"]}, stage="cleanup")
        except (Exception, KeyboardInterrupt) as error:
            save(path, record, error_code="isolated_restore_failed", stage="cleanup",
                 error_message=str(error) if isinstance(error, ArchiveError) else "Verification failed; the archive was not activated. Inspect the trusted receipt and available resources.")
        finally:
            try:
                cleanup(profile, path, record)
            except ArchiveError:
                save(path, record, status="recovery_required", error_code="isolation_cleanup_required")
        if record["status"] != "recovery_required":
            save(path, record, status="succeeded" if record["error_code"] is None else "failed", stage="complete")
        return record


def cleanup(profile, path, record):
    name = record.get("isolated_name")
    if name is not None:
        if name != "peerward-restore-" + task_id(record["id"]):
            raise ArchiveError("invalid isolated restore identity")
        ids = run(["docker", "ps", "-aq", "--no-trunc", "--filter", "label=" + LABEL + "=" + record["id"]]).decode().split()
        for container in ids:
            row = inspect(container)
            if row["Name"] != "/" + name:
                raise ArchiveError("isolated restore label is ambiguous")
            remove_owned(record["id"], container)
    stage = paths(profile)[0] / (".verify-" + task_id(record["id"]))
    if stage.exists():
        shutil.rmtree(stage)


def recover(profile, identifier):
    base, tasks, _ = paths(profile)
    with exclusive(base / "operation.lock"):
        path = tasks / (task_id(identifier) + ".json")
        record = read_json(path)
        if record["profile_digest"] != digest(profile):
            raise ArchiveError("restore cleanup requires its original registered profile")
        if record["operation"] != "isolated_restore_verify" or record["status"] not in ("running", "recovery_required"):
            return record
        cleanup(profile, path, record)
        save(path, record, status="failed", stage="recovered", error_code="interrupted_verification_not_retried")
        return record
