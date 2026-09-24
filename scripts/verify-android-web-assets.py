#!/usr/bin/env python3
"""Verify that the packaged Android WebView entry point closes over its assets."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from zipfile import ZipFile


ASSET_PREFIX = "/assets/dioxus/"
APK_PREFIX = "assets/dioxus/"


class AssetReferences(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in {"href", "src"} and value:
                self.references.add(value)


def packaged_name(reference: str) -> str:
    parsed = urlsplit(reference)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith(ASSET_PREFIX):
        raise ValueError(
            f"WebView asset reference must start with {ASSET_PREFIX!r}: {reference!r}"
        )
    relative = PurePosixPath(parsed.path.removeprefix(ASSET_PREFIX))
    if not relative.parts or ".." in relative.parts:
        raise ValueError(f"invalid WebView asset reference: {reference!r}")
    return APK_PREFIX + relative.as_posix()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    args = parser.parse_args()

    if not args.apk.is_file():
        parser.error(f"APK not found: {args.apk}")

    entry = APK_PREFIX + "index.html"
    with ZipFile(args.apk) as archive:
        names = set(archive.namelist())
        if entry not in names:
            raise SystemExit(f"missing WebView entry point: {entry}")
        document = archive.read(entry).decode("utf-8")

    references = AssetReferences()
    references.feed(document)
    packaged = {packaged_name(reference) for reference in references.references}
    missing = sorted(packaged - names)
    if missing:
        raise SystemExit("missing referenced WebView assets:\n" + "\n".join(missing))
    if not any(name.endswith(".js") for name in packaged):
        raise SystemExit("WebView entry point does not reference a JavaScript bundle")
    if not any(
        name.startswith(APK_PREFIX) and name.endswith(".wasm") for name in names
    ):
        raise SystemExit("APK does not contain a WebAssembly bundle under the WebView asset root")

    print(f"android WebView assets: {len(packaged)} entry-point references present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
