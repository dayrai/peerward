"""Explicit forward repair can supersede only the failed native transaction it reviewed."""
from pathlib import Path
from archive import ArchiveError
import backup
from common import digest, read_json, task_id


def predecessor(profile, transaction):
    records = (read_json(path) for path in backup.paths(profile)[1].glob("*.json"))
    active = [record for record in records if record["status"] in ("running", "recovery_required")]
    if not active:
        return None
    if len(active) != 1 or not profile["repair"] or transaction is None:
        raise ArchiveError("resolve the unfinished maintenance task first")
    old = active[0]
    if (old["status"] != "recovery_required" or old["operation"] != "native_upgrade"
            or old.get("native_role") != profile["role"]
            or transaction["role"] != profile["role"] or transaction["stage"] != "recovery_required"
            or transaction.get("approved_preview") != old["request"]["preview_digest"]):
        raise ArchiveError("repair cannot replace an unrelated or running maintenance operation")
    return {"id": old["id"], "profile_digest": old["profile_digest"], "request_digest": digest(old["request"]),
            "journal_digest": digest(transaction)}


def reconcile(profile, record):
    """Called only after the new CLI journal has been proven to belong to this task.

    The old task remains unfinished until its native intent was actually superseded.
    A crash before this bookkeeping is reconciled from both durable CLI journals.
    """
    old = record.get("supersedes")
    if old is None:
        return
    retained = read_json(Path(profile["installation"]) / "roles" / profile["role"] / "previous-update-transaction.json")
    if digest(retained) != old["journal_digest"]:
        raise ArchiveError("retained failed transaction differs from the approved repair")
    path = backup.paths(profile)[1] / (task_id(old["id"]) + ".json")
    previous = read_json(path)
    if previous.get("superseded_by") == record["id"] and previous["status"] == "failed":
        return
    if (previous["profile_digest"] != old["profile_digest"] or digest(previous["request"]) != old["request_digest"]
            or previous["status"] not in ("running", "recovery_required")):
        raise ArchiveError("failed maintenance task changed before repair reconciliation")
    backup.save(path, previous, status="failed", stage="superseded", error_code="native_superseded",
                upgrade=None, artifact=None, superseded_by=record["id"])
