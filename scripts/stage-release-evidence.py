#!/usr/bin/env python3
"""Copy only evidence artifacts named by passed gates into a release directory."""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil


def contained(
    root: pathlib.Path, value: object, context: str, suffix: str
) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be a non-empty relative path")
    if pathlib.PurePath(value).name != value:
        raise ValueError(f"{context} must be a direct child of its evidence directory")
    if not value.startswith("evidence-") or not value.endswith(suffix):
        raise ValueError(f"{context} must use an evidence-*{suffix} filename")
    path = (root / value).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{context} escapes its evidence directory") from error
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    arguments = parser.parse_args()
    source_root = arguments.source.resolve()
    destination_root = arguments.destination.resolve()
    document = json.loads(arguments.evidence.read_text(encoding="utf-8"))
    for name, gate in document["gates"].items():
        if gate.get("status") != "passed":
            continue
        for field, suffix in (("report", ".json"), ("cosign_bundle", ".bundle")):
            source = contained(
                source_root, gate.get(field), f"gates.{name}.{field}", suffix
            )
            destination = contained(
                destination_root, gate.get(field), f"gates.{name}.{field}", suffix
            )
            if not source.is_file():
                raise ValueError(f"gates.{name}.{field} is missing")
            if destination.exists():
                raise ValueError(f"gates.{name}.{field} collides with a release artifact")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
