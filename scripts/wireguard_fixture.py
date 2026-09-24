"""Freeze the non-secret fixture inputs once for all trials of a gate."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

INPUTS = ("scripts", "deploy/compose", "release", "spec", "packaging")
INPUT_FILES = ("release.toml",)


def freeze_fixture(root, destination, provided=None):
    source = Path(provided or root).resolve()
    expected = None
    if provided:
        expected = json.loads((source / "fixture-manifest.json").read_text())
        inputs = list(expected)
    else:
        inputs = subprocess.check_output(["git", "ls-files", "--cached", "--others",
            "--exclude-standard", "--", *INPUTS, *INPUT_FILES], cwd=source, text=True).splitlines()
    manifest = {}
    for relative in inputs:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not (
                relative in INPUT_FILES or any(relative.startswith(prefix + "/") for prefix in INPUTS)):
            raise ValueError("fixture manifest contains a path outside the allowed inputs")
        original = source / path
        if not original.is_file() or original.is_symlink():
            if expected is not None:
                raise ValueError("pinned fixture input missing or replaced: " + relative)
            continue
        if not original.resolve().is_relative_to(source):
            raise ValueError("fixture input escapes its source directory")
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if expected is not None and expected[relative] != digest:
            raise ValueError("pinned fixture input changed: " + relative)
        manifest[relative] = digest
    (destination / "fixture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
