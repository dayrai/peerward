#!/usr/bin/env python3
"""Enforce Peerward's single, reviewed Android JNI unsafe boundary."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/peerward-android-core/src"
EXPORT_COUNTS = {
    "android_jni_audit.rs": 4,
    "android_jni_enrollment.rs": 4,
    "android_jni_exports.rs": 10,
    "android_jni_identity.rs": 2,
    "android_jni_link.rs": 3,
    "android_jni_mapping.rs": 7,
    "android_jni_management.rs": 2,
    "android_jni_profile.rs": 9,
    "android_jni_relay_pool.rs": 8,
    "android_jni_relay_socket.rs": 6,
    "android_jni_quic.rs": 3,
    "android_jni_rotation.rs": 4,
    "android_jni_runtime.rs": 7,
    "android_jni_status.rs": 1,
    "android_jni_stun.rs": 4,
    "android_jni_tun_dns.rs": 4,
    "android_jni_tun_pump.rs": 5,
    "android_jni_wireguard.rs": 3,
    "android_jni_wireguard_udp.rs": 3,
}
UNSAFE_BLOCK_COUNTS = {
    "android_jni_relay_socket.rs": 1,
    "android_jni_tun_pump.rs": 2,
    "android_jni_wireguard_udp.rs": 1,
}
ALLOW_LOCATION = ("lib.rs", "#[allow(unsafe_code)]\nmod android_jni;")


def fail(message: str) -> None:
    print(f"unsafe boundary rejected: {message}", file=sys.stderr)
    raise SystemExit(1)


def matches(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text))


def main() -> None:
    rust_files = sorted(ROOT.glob("**/*.rs"))
    rust_files = [path for path in rust_files if "target" not in path.parts]
    allowances = []
    unsafe_blocks: dict[str, int] = {}
    exports: dict[str, int] = {}

    for path in rust_files:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        if "#[allow(unsafe_code)]" in text:
            allowances.append(relative)
        count = matches(r"\bunsafe\s*\{", text)
        if count:
            unsafe_blocks[relative] = count
        count = matches(r"#\[unsafe\(no_mangle\)\]", text)
        if count:
            exports[relative] = count

    allow_path, allow_text = ALLOW_LOCATION
    library = (SOURCE / allow_path).read_text(encoding="utf-8")
    expected_allowance = (SOURCE / allow_path).relative_to(ROOT).as_posix()
    if allowances != [expected_allowance] or allow_text not in library:
        fail("#[allow(unsafe_code)] must apply only to the android_jni module")

    expected_blocks = {
        (SOURCE / name).relative_to(ROOT).as_posix(): count
        for name, count in UNSAFE_BLOCK_COUNTS.items()
    }
    if unsafe_blocks != expected_blocks:
        fail(f"unsafe block inventory changed: {unsafe_blocks!r}")

    expected_exports = {
        (SOURCE / name).relative_to(ROOT).as_posix(): count
        for name, count in EXPORT_COUNTS.items()
    }
    if exports != expected_exports:
        fail(f"JNI export inventory changed: {exports!r}")

    print(
        "unsafe boundary valid: "
        f"{sum(unsafe_blocks.values())} blocks, {sum(exports.values())} JNI exports"
    )


if __name__ == "__main__":
    main()
