"""Forward repair must preserve unrelated work and bind the archived failed intent."""
from pathlib import Path
import tempfile
import unittest
import uuid

from archive import ArchiveError
import backup
from common import digest, read_json, write_json
import native_repair


class NativeRepairTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.profile = {"installation": self.directory.name, "repair": True, "role": "control"}
        self.identifier = str(uuid.uuid4())
        self.path, self.old, _ = backup.begin(self.profile, self.identifier,
            {"operation": "native_upgrade", "preview_digest": "a" * 64})
        backup.save(self.path, self.old, status="recovery_required", native_role="control")
        self.transaction = {"role": "control", "stage": "recovery_required", "approved_preview": "a" * 64}

    def test_running_unrelated_and_unapproved_work_cannot_be_superseded(self):
        for change in ({"role": "relay"}, {"repair": False}):
            with self.subTest(change=change), self.assertRaises(ArchiveError):
                native_repair.predecessor({**self.profile, **change}, self.transaction)
        for change in ({"stage": "restart_pending"}, {"approved_preview": "b" * 64}):
            with self.subTest(change=change), self.assertRaises(ArchiveError):
                native_repair.predecessor(self.profile, {**self.transaction, **change})
        backup.save(self.path, self.old, status="running")
        with self.assertRaises(ArchiveError):
            native_repair.predecessor(self.profile, self.transaction)
        backup.save(self.path, self.old, status="recovery_required", operation="installation_backup")
        with self.assertRaises(ArchiveError):
            native_repair.predecessor(self.profile, self.transaction)

    def test_retained_intent_is_required_and_reconciliation_is_idempotent(self):
        prior = native_repair.predecessor(self.profile, self.transaction)
        replacement = {"id": str(uuid.uuid4()), "supersedes": prior}
        # Recording a new local intent alone cannot erase the unfinished predecessor.
        self.assertEqual(read_json(self.path)["status"], "recovery_required")
        archive = Path(self.directory.name) / "roles/control/previous-update-transaction.json"
        archive.parent.mkdir(mode=0o700, parents=True)
        write_json(archive, {**self.transaction, "approved_preview": "b" * 64})
        with self.assertRaises(ArchiveError):
            native_repair.reconcile(self.profile, replacement)
        self.assertEqual(read_json(self.path)["status"], "recovery_required")
        write_json(archive, self.transaction, replace=True)
        native_repair.reconcile(self.profile, replacement)
        terminal = read_json(self.path)
        self.assertEqual(terminal["superseded_by"], replacement["id"])
        self.assertEqual(terminal["stage"], "superseded")
        self.assertEqual(digest(read_json(archive)), prior["journal_digest"])
        native_repair.reconcile(self.profile, replacement)
        self.assertEqual(read_json(self.path), terminal)


if __name__ == "__main__":
    unittest.main()
