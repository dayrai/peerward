#!/usr/bin/env python3
"""Return the canonical release version only when it matches release.toml."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from release_metadata import validate_metadata, version_precedence


if len(sys.argv) != 2:
    raise SystemExit("usage: release-version.py VERSION")

candidate = sys.argv[1]
root = Path(__file__).resolve().parents[1]
metadata = tomllib.loads((root / "release.toml").read_text(encoding="utf-8"))
try:
    validate_metadata(metadata)
    version_precedence(candidate)
except ValueError as error:
    raise SystemExit(str(error)) from error
expected = metadata["product_version"]
if candidate != expected:
    raise SystemExit(
        f"requested release {candidate!r} does not match release.toml version {expected!r}"
    )
print(candidate)
