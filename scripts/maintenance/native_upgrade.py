"""Fixed native upgrade task execution and reconciliation of its owned CLI journal."""
import fcntl
import hashlib
import json
from pathlib import Path
from archive import ArchiveError, regular_input
import backup
import native_repair
from common import digest, exclusive, read_json, read_private, task_id
import upgrade_profile


def preview(profile):
    result = upgrade_profile.invoke(profile, "preview")
    if result.returncode:
        raise ArchiveError("native role has no current executable upgrade preview")
    value = upgrade_profile.parse_output(result)
    expected = profile["release"]
    if any(value.get(key) != item for key, item in expected.items()) or value.get("role") != profile["role"] or value["current_version"] == value["version"]:
        raise ArchiveError("staged release differs or is already installed")
    return {"digest": value["digest"], "services_to_pause": [profile["role"]], "online_files": 1, "meshes": 0, "relay_hosts": 0,
            "upgrade": {key: value[key] for key in ("role", "current_version", "version", "manifest_sha256", "artifact_sha256", "artifact_bytes", "rollback_floor", "repair")}}


def cli_transaction(profile):
    result = upgrade_profile.invoke(profile, "status")
    if result.returncode:
        raise ArchiveError("cannot read native role transaction")
    return upgrade_profile.parse_output(result)["transaction"]


def updater_running(profile):
    # Test the existing lock without creating, unlinking or changing it.
    with (Path(profile["installation"]) / "update.lock").open("rb") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(stream, fcntl.LOCK_UN)
        return False


def owns_transaction(profile, record, transaction):
    release = json.loads(read_private(Path(profile["assets"]) / "manifest"))
    return transaction is not None and transaction.get("manifest") == release and transaction.get("role") == profile["role"] and transaction.get("approved_preview") == record["request"]["preview_digest"]


def save_observation(path, record, **values):
    if any(record.get(key) != value for key, value in values.items()):
        backup.save(path, record, **values)
    return record


def observe(profile, path, record):
    if updater_running(profile):
        return save_observation(path, record, status="running", stage="native_running", error_code=None, upgrade=None)
    transaction = cli_transaction(profile)
    if not owns_transaction(profile, record, transaction):
        # No side effect can precede the native journal. A different journal must
        # never be adopted as this task's successful result or resumed by its ID.
        if digest(transaction)==record.get("before_journal_digest"):
            return save_observation(path, record, status="failed", stage="preflight", error_code="native_preflight_failed", artifact=None, upgrade=None)
        return save_observation(path, record, status="recovery_required", stage="native_recovery_required", error_code="native_result_unknown", artifact=None, upgrade=None)
    phase = transaction["stage"]
    native_repair.reconcile(profile, record)
    version = transaction["previous_version"] if transaction["direction"] == "rollback" else transaction["manifest"]["version"]
    binary = Path(profile["installation"]) / "versions" / version / "peerward"
    with regular_input(binary) as (stream, info):
        current_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        size = info.st_size
    outcome = {"role": profile["role"], "version": version, "manifest_sha256": profile["release"]["manifest_sha256"],
               "current_sha256": current_hash, "state": "recovery_required", "runtime_checked": False}
    if phase == "succeeded" and current_hash == profile["release"]["artifact_sha256"] and size == profile["release"]["artifact_bytes"]:
        outcome.update(state="succeeded", runtime_checked=True)
        return save_observation(path, record, status="succeeded", stage="succeeded", error_code=None,
                                artifact={"sha256": current_hash, "bytes": size, "files": 1}, upgrade=outcome)
    if phase == "rolled_back":
        outcome.update(state="rolled_back", runtime_checked=True)
        return save_observation(path, record, status="failed", stage="rolled_back", error_code="native_upgrade_rolled_back",
                                artifact={"sha256": current_hash, "bytes": size, "files": 1}, upgrade=outcome)
    return save_observation(path, record, status="recovery_required", stage="native_recovery_required",
                            error_code="native_recovery_required", artifact=None, upgrade=outcome)


def execute(profile, identifier, expected_preview, *, age=None):
    del age
    base = backup.paths(profile)[0]
    with exclusive(base / "operation.lock"):
        request = {"operation": "native_upgrade", "preview_digest": expected_preview}
        path = backup.paths(profile)[1] / (task_id(identifier) + ".json")
        if path.exists():
            return backup.begin(profile, identifier, request)[1]
        if preview(profile)["digest"] != expected_preview:
            raise ArchiveError("upgrade preview changed; review the current role again")
        before = cli_transaction(profile)
        supersedes = native_repair.predecessor(profile, before)
        path, record, _ = backup.begin(profile, identifier, request, supersede=supersedes["id"] if supersedes else None)
        backup.save(path, record, stage="native_starting", before_journal_digest=digest(before),
                    native_role=profile["role"], supersedes=supersedes)
        try:
            upgrade_profile.invoke(profile, "apply", expected_preview)
            return observe(profile, path, record)
        except (ArchiveError, OSError):
            return save_observation(path, record, status="recovery_required", stage="native_recovery_required",
                                    error_code="native_result_unknown")


def recover(profile, identifier, *, execute=False, generation=None):
    base = backup.paths(profile)[0]
    with exclusive(base / "operation.lock"):
        path = backup.paths(profile)[1] / (task_id(identifier) + ".json")
        record = read_json(path)
        if record["profile_digest"] != digest(profile) or record["operation"] != "native_upgrade":
            raise ArchiveError("task belongs to another upgrade profile")
        if record["status"] in ("succeeded", "failed"):
            return record
        if generation is not None and generation>record.get("requested_recovery",0):
            backup.save(path,record,requested_recovery=generation,status="running",stage="native_recovery_requested",upgrade=None,error_code=None)
        requested=record.get("requested_recovery",0)
        execute=execute or requested>record.get("completed_recovery",0)
        if execute:
            if updater_running(profile):
                return save_observation(path,record,status="running",stage="native_running",upgrade=None,error_code=None)
            transaction = cli_transaction(profile)
            if not owns_transaction(profile, record, transaction):
                raise ArchiveError("native transaction does not match this task; inspect it locally")
            # A local command or a new durable control intent can request restart.
            # Re-delivery of the same generation only reconciles its recorded result.
            try:
                upgrade_profile.invoke(profile, "recover")
            except ArchiveError:
                pass  # Record the actual remaining phase below.
            backup.save(path,record,completed_recovery=requested)
        return observe(profile, path, record)
