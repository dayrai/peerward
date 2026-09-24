"""Canonical release versions and SemVer precedence, without external dependencies."""

import re


VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
)


def version_precedence(value: str) -> tuple:
    """Return an ordering key; release metadata intentionally excludes build labels."""
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError(f"release version must be canonical SemVer: {value!r}")
    major, minor, patch, prerelease = match.groups()
    if any(int(part) > 2**64 - 1 for part in (major, minor, patch)):
        raise ValueError("release version components must fit Rust SemVer u64 values")
    identifiers = tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in prerelease.split(".")
    ) if prerelease is not None else ()
    return int(major), int(minor), int(patch), prerelease is None, identifiers


def validate_version_range(version: str, floor: str) -> None:
    """A compatible update may retain an earlier floor, but never a future one."""
    if version_precedence(floor) > version_precedence(version):
        raise ValueError("rollback_floor must not exceed product_version")


def validate_metadata(metadata: dict) -> None:
    """Validate TOML types before synchronizing any generated release surfaces."""
    expected = {"product_version", "android_version_code", "schema_version",
                "wire_major", "rollback_floor", "channel"}
    if set(metadata) != expected:
        raise ValueError("release metadata must contain exactly: " + ", ".join(sorted(expected)))
    validate_version_range(metadata["product_version"], metadata["rollback_floor"])
    for field, maximum in (("android_version_code", 2_100_000_000),
                           ("schema_version", 2**32 - 1), ("wire_major", 2**32 - 1)):
        value = metadata[field]
        # bool is an int subclass; int(value) also silently truncates TOML floats.
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{field} must be an integer in 1..{maximum}")
    channel = metadata["channel"]
    if channel not in ("canary", "stable"):
        raise ValueError("release channel must be canary or stable")
    if "-" in metadata["product_version"] and channel == "stable":
        raise ValueError("a prerelease version cannot use the stable channel")
