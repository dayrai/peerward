"""Quiesced Compose backup with a durable, recoverable local task journal."""
import hashlib
import os
from pathlib import Path
import shutil
import time
from archive import ArchiveError, encrypt_archive, private_directory, regular_input
from common import checked_container, digest, exclusive, read_json, run, task_id, wait_healthy, write_json
from database import Snapshot, inventory, verify_material
from profile import validate_running, writers


def online_files(profile):
    root = Path(profile["installation"])
    result = {"deployment/installation.json": root / "installation.json", "deployment/installation.env": root / ".env"}
    for index, path in enumerate(profile["deployment_files"]):
        result[f"deployment/inputs/{index}"] = Path(path)
    roots = [("control", root / "control"), *(("relays/" + r["host_id"], Path(r["root"])) for r in profile["relays"])]
    for prefix, directory in roots:
        private_directory(directory)
        for parent, directories, files in os.walk(directory, followlinks=False):
            for child in directories:
                if child == "offline" or (Path(parent) / child).is_symlink():
                    raise ArchiveError("online inventory contains an offline or symlink directory")
            for name in files:
                path = Path(parent) / name
                with regular_input(path) as (_, info):
                    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                        raise ArchiveError("online material must be private and owned")
                result[prefix + "/" + str(path.relative_to(directory))] = path
    return result


def preview(profile):
    validate_running(profile)
    files = online_files(profile)
    with Snapshot(profile["postgres"]["id"], profile["database"]) as snapshot:
        state = inventory(snapshot)
    material = verify_material(state, Path(profile["installation"]) / "control", {r["host_id"]: Path(r["root"]) for r in profile["relays"]})
    content = {}
    for name, path in sorted(files.items()):
        with regular_input(path) as (stream, _):
            content[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    fence = {"profile": digest(profile), "files": content, "meshes": state["meshes"], "authorities": state["authorities"],
             "hosts": state["hosts"], "assignments": state["assignments"], "migrations": state["migrations"]}
    return {"digest": digest(fence), "operation": "installation_backup", "material": material,
            "services_to_pause": [r["name"] for r in writers(profile)], "online_files": len(files),
            "database_bytes": None, "impact": "Control, console and all registered Relays pause for a consistent snapshot; peer authorization leases continue to expire. Original services are restarted and health checked."}


def paths(profile):
    base = private_directory(getattr(profile, "workspace", None) or Path(profile["installation"]) / "maintenance")
    return base, private_directory(base / "tasks"), private_directory(base / "archives")


def save(path, record, **changes):
    record.update(changes, updated_at=int(time.time()))
    record["version"] += 1
    write_json(path, record, replace=True)


def recover_services(profile, task_path, record):
    """Only start exact containers recorded before stopping; never recreate them."""
    errors = []
    selected = {item["id"] for item in record["stop_intents"]}
    order = [profile["control"], *(r["container"] for r in profile["relays"]), *profile["console"]]
    for container in order:
        if container["id"] not in selected:
            continue
        try:
            row = checked_container(container)
            if not row["State"]["Running"]:
                run(["docker", "start", container["id"]])
            wait_healthy(container)
        except ArchiveError:
            errors.append(container["name"])
    save(task_path, record, recovery_pending=errors)
    if errors:
        raise ArchiveError("original services require recovery; use the recover task operation")


def begin(profile, identifier, request, *, supersede=None):
    _, tasks, _ = paths(profile)
    task_path = tasks / (task_id(identifier) + ".json")
    if task_path.exists():
        old = read_json(task_path)
        if old["request"] != request or old["profile_digest"] != digest(profile):
            raise ArchiveError("task ID is already bound to another request or profile")
        return task_path, old, False
    for path in tasks.glob("*.json"):
        if supersede is not None and path.stem == supersede:
            continue  # Native repair has validated the exact failed predecessor under operation.lock.
        if read_json(path)["status"] in ("running", "recovery_required"):
            raise ArchiveError("resolve the unfinished maintenance task first")
    record = {"id": identifier, "operation": request["operation"], "request": request,
              "profile_digest": digest(profile), "version": 1, "status": "running", "stage": "preflight",
              "created_at": int(time.time()), "updated_at": int(time.time()), "stop_intents": [], "recovery_pending": [],
              "error_code": None, "artifact": None}
    write_json(task_path, record)
    return task_path, record, True


def execute(profile, identifier, expected_preview, *, age="age"):
    if getattr(profile, "workspace", None) is not None:
        raise ArchiveError("a verification workspace cannot operate source services")
    base, _, archives = paths(profile)
    with exclusive(base / "operation.lock"):
        request = {"operation": "installation_backup", "preview_digest": expected_preview}
        task_path = base / "tasks" / (task_id(identifier) + ".json")
        if task_path.exists():
            return begin(profile, identifier, request)[1]
        current = preview(profile)
        if current["digest"] != expected_preview:
            raise ArchiveError("backup preview is stale; review the current installation again")
        task_path, record, _ = begin(profile, identifier, request)
        stage = base / (".backup-" + identifier)
        archive = archives / (identifier + ".age")
        try:
            private_directory(stage)
            # Record intent before each side effect, so SIGKILL/host reboot can be recovered.
            for container in writers(profile):
                checked_container(container, running=True)
                save(task_path, record, stage="quiescing", stop_intents=[*record["stop_intents"], container])
                # Current Control/Relay runtimes install the SIGINT shutdown handler.
                run(["docker", "stop", "--signal", "SIGINT", "--timeout", "30", container["id"]], timeout=45)
                checked_container(container, running=False)
            save(task_path, record, stage="snapshot")
            with Snapshot(profile["postgres"]["id"], profile["database"]) as snapshot:
                others = snapshot.query("SELECT to_json(count(*)) FROM pg_stat_activity WHERE datname=current_database() AND backend_type='client backend' AND pid<>pg_backend_pid()")
                if others:
                    raise ArchiveError("unaccounted database clients remain; a complete backup cannot be confirmed")
                state = inventory(snapshot)
                material = verify_material(state, Path(profile["installation"]) / "control", {r["host_id"]: Path(r["root"]) for r in profile["relays"]})
                snapshot.dump(stage / "postgres.dump")
            (stage / "postgres.dump").chmod(0o600)
            write_json(stage / "inventory.json", state)
            files = online_files(profile)
            files.update({"database/postgres.dump": stage / "postgres.dump", "database/inventory.json": stage / "inventory.json"})
            metadata = {"type": "peerward-installation", "task_id": identifier, "release": profile["metadata"],
                        "profile_digest": digest(profile), "database": profile["database"], "material": material,
                        "images": [r["image"] for r in [profile["postgres"], *writers(profile)]],
                        "snapshot_at": int(time.time()), "requires_security_reconciliation": True}
            save(task_path, record, stage="encrypting")
            artifact = encrypt_archive(files, metadata, archive, profile["recipients"], age=age)
            save(task_path, record, artifact={**artifact, "name": archive.name}, stage="recovering")
        except (Exception, KeyboardInterrupt) as error:
            save(task_path, record, error_code="backup_interrupted", stage="recovering",
                 error_message=str(error) if isinstance(error, ArchiveError) else "Backup interrupted; inspect local service health and retry with a new task after recovery.")
        finally:
            # Verification plaintext never becomes an installation. Only this task's private stage is removed.
            try:
                if stage.exists():
                    shutil.rmtree(stage)
            except OSError:
                save(task_path, record, cleanup_pending=True, error_code="backup_cleanup_required", status="recovery_required")
            try:
                recover_services(profile, task_path, record)
            except ArchiveError:
                save(task_path, record, status="recovery_required", stage="recovering", error_code="service_recovery_required")
        if not record["recovery_pending"] and not record.get("cleanup_pending"):
            succeeded = record["artifact"] is not None and record["error_code"] is None
            save(task_path, record, status="succeeded" if succeeded else "failed", stage="complete")
        return record


def recover(profile, identifier):
    if getattr(profile, "workspace", None) is not None:
        raise ArchiveError("a verification workspace cannot recover source services")
    base, tasks, _ = paths(profile)
    with exclusive(base / "operation.lock"):
        path = tasks / (task_id(identifier) + ".json")
        record = read_json(path)
        if record["profile_digest"] != digest(profile):
            raise ArchiveError("task recovery requires its original registered profile")
        if record["operation"] != "installation_backup" or record["status"] not in ("running", "recovery_required"):
            return record
        # A crashed stage is not a verified backup, even if a partial ciphertext exists.
        stage = base / (".backup-" + identifier)
        try:
            if stage.exists():
                shutil.rmtree(stage)
            save(path, record, cleanup_pending=False)
        finally:
            recover_services(profile, path, record)
        save(path, record, status="failed", stage="recovered", error_code="interrupted_backup_not_retried")
        return record
