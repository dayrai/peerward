#!/usr/bin/env python3
"""Version bumps must preserve compatible update paths and reject invalid floors."""

from pathlib import Path
import subprocess
import sys
import tomllib
import unittest

from release_metadata import validate_metadata, validate_version_range, version_precedence


ROOT = Path(__file__).resolve().parents[1]


class ReleaseMetadataTests(unittest.TestCase):
    def test_metadata_requires_exact_fields_and_canonical_types(self):
        metadata = tomllib.loads((ROOT / "release.toml").read_text())
        validate_metadata(metadata)
        for field in metadata:
            for invalid in (None, True, [], {}, 1.5):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    validate_metadata({**metadata, field: invalid})
        for invalid in ({**metadata, "typo": 1}, {k: v for k, v in metadata.items() if k != "wire_major"}):
            with self.assertRaises(ValueError):
                validate_metadata(invalid)

    def test_metadata_checks_build_numeric_bounds_and_channel(self):
        metadata = tomllib.loads((ROOT / "release.toml").read_text())
        for field, limit in (("android_version_code", 2_100_000_000),
                             ("schema_version", 2**32 - 1), ("wire_major", 2**32 - 1)):
            validate_metadata({**metadata, field: limit})
            for invalid in (0, -1, limit + 1, "4"):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    validate_metadata({**metadata, field: invalid})
        with self.assertRaises(ValueError):
            validate_metadata({**metadata, "channel": "unknown"})
        with self.assertRaises(ValueError):
            validate_metadata({**metadata, "product_version": "1.0.0-rc.1", "channel": "stable"})
        with self.assertRaises(ValueError):
            version_precedence(f"{2**64}.0.0")

    def test_semver_order_includes_numeric_identifiers_and_final_releases(self):
        ordered = [
            "0.1.0-alpha", "0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-alpha.10",
            "0.1.0-alpha.beta", "0.1.0-beta", "0.1.0-beta.2", "0.1.0-beta.11",
            "0.1.0-rc.1", "0.1.0", "0.1.1", "0.2.0", "0.10.0", "1.0.0",
        ]
        for lower, higher in zip(ordered, ordered[1:]):
            with self.subTest(lower=lower, higher=higher):
                self.assertLess(version_precedence(lower), version_precedence(higher))

    def test_release_versions_reject_noncanonical_and_build_labels(self):
        for version in ["0.1", "v0.1.0", "00.1.0", "0.1.0-01", "0.1.0-",
                        "0.1.0-alpha..1", "0.1.0+build.1", "0.1.0\n"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                version_precedence(version)

    def test_compatible_patch_release_retains_floor(self):
        validate_version_range("0.1.0", "0.1.0")
        validate_version_range("0.1.1", "0.1.0")
        validate_version_range("0.1.0", "0.1.0-rc.1")

    def test_future_or_invalid_floor_is_rejected(self):
        for version, floor in [("0.1.0", "0.1.1"), ("0.1.0-rc.1", "0.1.0"),
                               ("0.1.0", "0.1"), ("0.1", "0.1.0")]:
            with self.subTest(version=version, floor=floor), self.assertRaises(ValueError):
                validate_version_range(version, floor)

    def test_release_cli_accepts_only_the_current_canonical_version(self):
        current = tomllib.loads((ROOT / "release.toml").read_text())["product_version"]
        for candidate, expected in [(current, 0), (current + "-unexpected", 1), ("0.1", 1)]:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/release-version.py"), candidate],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected == 0:
                self.assertEqual(result.stdout.strip(), current)


if __name__ == "__main__":
    unittest.main()
