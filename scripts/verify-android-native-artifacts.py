#!/usr/bin/env python3
"""Verify that an Android package contains only its variant's native libraries."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
ABIS = ("arm64-v8a", "x86_64")
LIBRARY = "libpeerward_android_core.so"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("variant", choices=("debug", "release"))
    parser.add_argument("package", type=pathlib.Path)
    arguments = parser.parse_args()
    package = arguments.package.resolve()
    native_root = (
        ROOT
        / "apps/peerward-android/app/build/generated/peerwardJni"
        / arguments.variant
    )
    if not package.is_file():
        raise SystemExit(f"Android package does not exist: {package}")

    package_prefix = "base/lib" if package.suffix == ".aab" else "lib"
    expected_entries = {f"{package_prefix}/{abi}/{LIBRARY}" for abi in ABIS}
    with zipfile.ZipFile(package) as archive:
        native_entries = {
            name
            for name in archive.namelist()
            if name.startswith(f"{package_prefix}/") and name.endswith(".so")
        }
        packaged_abis = {name.split("/")[-2] for name in native_entries}
        if packaged_abis != set(ABIS):
            raise SystemExit(
                f"unexpected package ABI inventory: {sorted(packaged_abis)!r}"
            )
        actual_entries = {
            name
            for name in native_entries
            if name.endswith(f"/{LIBRARY}")
        }
        if actual_entries != expected_entries:
            raise SystemExit(
                f"unexpected native library inventory: {sorted(actual_entries)!r}"
            )
        for abi in ABIS:
            source = native_root / abi / LIBRARY
            if not source.is_file():
                raise SystemExit(f"variant native library is missing: {source}")
            entry = f"{package_prefix}/{abi}/{LIBRARY}"
            if digest(source.read_bytes()) != digest(archive.read(entry)):
                raise SystemExit(f"{entry} was not packaged from {native_root}")

    print(
        f"Android {arguments.variant} {package.suffix.removeprefix('.').upper()} "
        "native package valid: "
        + ", ".join(sorted(expected_entries))
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, zipfile.BadZipFile) as error:
        print(f"Android native package rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
