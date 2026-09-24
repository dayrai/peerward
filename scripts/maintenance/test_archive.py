"""Real age round trips and hostile-archive checks, without any deployment access."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from archive import ArchiveError, decrypt_archive, encrypt_archive, relative_name

AGE = os.environ.get("PEERWARD_TEST_AGE", "age")
KEYGEN = os.environ.get("PEERWARD_TEST_AGE_KEYGEN", "age-keygen")


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="peerward-backup-unit-")
        self.root = Path(self.work.name)
        self.identity = self.root / "identity"
        subprocess.run([KEYGEN, "--output", self.identity], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.identity.chmod(0o600)
        self.recipient = subprocess.check_output([KEYGEN, "-y", self.identity], text=True).strip()
        self.original = self.root / "issuer.json"
        self.original.write_bytes(b"private test signing material")
        self.original.chmod(0o600)
        self.addCleanup(self.work.cleanup)

    def backup(self):
        path = self.root / "backup.age"
        receipt = encrypt_archive({"control/meshes/example/issuer.json": self.original},
                                  {"schema": 4, "wire": 5}, path, [self.recipient], age=AGE)
        return path, receipt

    def test_encrypted_roundtrip_preserves_bytes_and_refuses_overwrite(self):
        path, receipt = self.backup()
        self.assertNotIn(self.original.read_bytes(), path.read_bytes())
        result = self.root / "verified"
        manifest = decrypt_archive(path, receipt["sha256"], self.identity, result, age=AGE)
        self.assertEqual(manifest["metadata"], {"schema": 4, "wire": 5})
        self.assertEqual((result / "control/meshes/example/issuer.json").read_bytes(), self.original.read_bytes())
        self.assertEqual(result.stat().st_mode & 0o777, 0o700)
        self.assertEqual((result / "control/meshes/example/issuer.json").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ArchiveError):
            self.backup()
        with self.assertRaises(ArchiveError):
            decrypt_archive(path, receipt["sha256"], self.identity, result, age=AGE)

    def test_tamper_or_wrong_identity_never_publishes_plaintext(self):
        path, receipt = self.backup()
        wrong = self.root / "wrong-identity"
        subprocess.run([KEYGEN, "--output", wrong], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wrong.chmod(0o600)
        with self.assertRaises(ArchiveError):
            decrypt_archive(path, receipt["sha256"], wrong, self.root / "verified", age=AGE)
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        target = self.root / "verified"
        with self.assertRaises(ArchiveError):
            decrypt_archive(path, receipt["sha256"], self.identity, target, age=AGE)
        # Even with a substituted external digest, the age authentication fails.
        with self.assertRaises(ArchiveError):
            decrypt_archive(path, hashlib.sha256(data).hexdigest(), self.identity, target, age=AGE)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".restore-*")))

    def test_inventory_limits_and_offline_keys_are_not_archived(self):
        for name in ("../offline/key", "/control/key", "control/../offline/key", "deployment/offline/key", "offline/key", "control//key"):
            with self.subTest(name=name), self.assertRaises(ArchiveError):
                relative_name(name)
        link = self.root / "linked"
        link.symlink_to(self.original)
        with self.assertRaises(ArchiveError):
            encrypt_archive({"control/issuer.json": link}, {}, self.root / "link.age", [self.recipient], age=AGE)
        with self.assertRaises(ArchiveError):
            encrypt_archive({"control/issuer.json": self.original}, {}, self.root / "large.age", [self.recipient], age=AGE, maximum=1)
        offline = self.root / "offline"
        offline.mkdir(mode=0o700)
        key = offline / "root.key"
        key.write_bytes(b"never enter routine online backups")
        with self.assertRaises(ArchiveError):
            encrypt_archive({"control/renamed.key": key}, {}, self.root / "offline.age", [self.recipient], age=AGE)
        self.assertFalse(list(self.root.glob(".partial-*")))

    def hostile(self, kind):
        content = b"data"
        entry = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        name = "control/issuer.json"
        manifest = {"format": 1, "metadata": {}, "files": {name: entry}}
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            data = json.dumps(manifest).encode()
            item = tarfile.TarInfo("manifest.json"); item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
            item = tarfile.TarInfo(name); item.size = len(content)
            if kind == "traversal": item.name = "../escape"
            if kind == "symlink": item.type = tarfile.SYMTYPE; item.linkname = "/tmp/escape"; item.size = 0
            if kind == "corrupt": content = b"evil"
            tar.addfile(item, io.BytesIO(content))
            if kind == "duplicate": tar.addfile(item, io.BytesIO(content))
        encrypted = subprocess.check_output([AGE, "--encrypt", "--recipient", self.recipient], input=archive.getvalue())
        path = self.root / (kind + ".age"); path.write_bytes(encrypted)
        with self.assertRaises(ArchiveError):
            decrypt_archive(path, hashlib.sha256(encrypted).hexdigest(), self.identity, self.root / "verified", age=AGE)
        self.assertFalse((self.root / "verified").exists())

    def test_authenticated_archive_still_rejects_traversal_links_duplicates_and_corruption(self):
        for kind in ("traversal", "symlink", "duplicate", "corrupt"):
            with self.subTest(kind=kind): self.hostile(kind)


if __name__ == "__main__":
    unittest.main()
