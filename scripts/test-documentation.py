#!/usr/bin/env python3
"""Regression checks for documentation validation in checkouts and source archives."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "documentation", Path(__file__).with_name("check-documentation.py")
)
documentation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(documentation)


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_archive_checks_relative_paths_and_reports_missing_targets(self):
        self.write("docs/README.md", "[源码](../source%20file.rs#item)\n[missing](gone.md)\n")
        self.write("source file.rs", "")
        self.assertEqual(documentation.check(self.root), (
            2, 0, ["docs/README.md:2: missing local path: gone.md"]
        ))

    def test_generated_documents_are_excluded_but_fuzz_seeds_are_checked(self):
        for directory in [
            "target", "apps/console/node_modules", "apps/console/test-results",
            "artifacts", "deploy/compose/state-local", "fuzz/corpus", "examples/webhooks/.venv",
        ]:
            self.write(f"{directory}/README.md", "[missing](gone.md)")
        self.write("fuzz/seeds/README.md", "[missing](gone.md)")
        self.assertEqual(documentation.check(self.root), (
            1, 0, ["fuzz/seeds/README.md:1: missing local path: gone.md"]
        ))

    def test_only_local_artifact_links_are_exempt(self):
        self.write("README.md", "\n".join([
            "[external](https://example.test/docs)", "[section](#section)",
            "[archive](artifacts/run/report.json)", "[other](artifacts-old/report.json)",
        ]))
        self.assertEqual(documentation.check(self.root), (
            1, 1, ["README.md:4: missing local path: artifacts-old/report.json"]
        ))

    def test_checkout_uses_git_ignores_and_includes_untracked_documents(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write(".gitignore", "local/\n")
        self.write("local/README.md", "[missing](gone.md)")
        self.write("README.md", "[missing](gone.md)")
        self.assertEqual(documentation.check(self.root), (
            1, 0, ["README.md:1: missing local path: gone.md"]
        ))


if __name__ == "__main__":
    unittest.main()
