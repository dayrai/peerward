#!/usr/bin/env python3
"""Exercise archive contents, repeatability and publication boundaries in isolation."""
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "source with spaces"
        self.root.mkdir()
        (self.root / "scripts").mkdir()
        for name in ("release-archive.sh", "release-version.py", "release_metadata.py"):
            shutil.copy2(ROOT / "scripts" / name, self.root / "scripts" / name)
        for name in ("release.toml", "README.md", "LICENSE"):
            shutil.copy2(ROOT / name, self.root / name)
        shutil.copytree(ROOT / "third_party", self.root / "third_party")
        self.version = tomllib.loads((self.root / "release.toml").read_text())["product_version"]
        binary = self.root / "target" / TARGET / "release" / "peerward"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"fixture executable\n")
        binary.chmod(0o755)
        self.output = self.root.parent / "output with spaces"

    def run_archive(self, *, version=None, target=TARGET, epoch="1234567890", output=None):
        return subprocess.run(
            ["sh", str(self.root / "scripts/release-archive.sh"), target,
             self.version if version is None else version, str(output or self.output)],
            cwd=self.root.parent, env={**os.environ, "SOURCE_DATE_EPOCH": epoch},
            capture_output=True, text=True,
        )

    def test_archive_is_repeatable_and_contains_licenses_with_executable_mode(self):
        self.assertEqual(self.run_archive().returncode, 0)
        archive = next(self.output.glob("*.tar.gz"))
        with tarfile.open(archive) as contents:
            prefix = f"peerward-{self.version}-{TARGET}"
            binary = contents.getmember(prefix + "/bin/peerward")
            self.assertEqual(binary.mode, 0o755)
            self.assertEqual(contents.extractfile(binary).read(), b"fixture executable\n")
            contents.getmember(prefix + "/share/doc/peerward/LICENSE")
            contents.getmember(prefix + "/share/doc/peerward/third_party/gotatun/LICENSE")
            self.assertTrue(all(item.uid == 0 and item.gid == 0 and item.mtime == 1234567890
                                for item in contents.getmembers()))
        second = self.root.parent / "second"
        self.assertEqual(self.run_archive(output=second).returncode, 0)
        self.assertEqual(archive.read_bytes(), next(second.glob("*.tar.gz")).read_bytes())
        self.assertFalse(list(self.output.glob(".archive.*")))

    def test_existing_output_and_symlinks_are_never_replaced(self):
        self.assertEqual(self.run_archive().returncode, 0)
        archive = next(self.output.glob("*.tar.gz"))
        before = archive.read_bytes()
        self.assertNotEqual(self.run_archive().returncode, 0)
        self.assertEqual(archive.read_bytes(), before)
        archive.unlink()
        archive.symlink_to(self.output / "missing")
        self.assertNotEqual(self.run_archive().returncode, 0)
        self.assertTrue(archive.is_symlink())

    def test_invalid_inputs_and_failed_builds_do_not_publish_or_delete_source(self):
        for change in ({"target": "../../escape"}, {"version": "../../escape"},
                       {"epoch": "yesterday"}, {"version": self.version + "-other"}):
            with self.subTest(change=change):
                self.assertNotEqual(self.run_archive(**change).returncode, 0)
                self.assertFalse(self.output.exists())
        shutil.rmtree(self.root / "target")
        self.assertNotEqual(self.run_archive().returncode, 0)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertTrue((self.root / "README.md").is_file())


if __name__ == "__main__":
    unittest.main()
