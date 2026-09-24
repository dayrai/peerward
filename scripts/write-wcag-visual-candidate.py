#!/usr/bin/env python3
"""Write an unverified WCAG/visual candidate from completed browser checks."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import platform
import re
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"[0-9a-f]{64}")
EXPECTED_SCREENSHOTS = {
    "desktop-en-light.png",
    "desktop-zh-dark.png",
    "mobile-en-dark.png",
    "mobile-zh-light.png",
    "android-empty-en-light-mobile.png",
    "android-permission-zh-dark-desktop.png",
    "android-degraded-en-dark-mobile.png",
    "android-failed-zh-light-desktop.png",
    "android-healthy-diagnostics-en-light-mobile.png",
}


def command(*arguments: str, cwd: pathlib.Path | None = None) -> str:
    return subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshots", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--artifact-set-sha256", default="0" * 64)
    arguments = parser.parse_args()
    if not SHA256.fullmatch(arguments.artifact_set_sha256):
        raise SystemExit("artifact set must be lowercase SHA-256")
    if arguments.output.exists():
        raise SystemExit("candidate output already exists")
    screenshots = {
        path.name: path
        for path in arguments.screenshots.iterdir()
        if path.is_file() and path.suffix == ".png"
    }
    if set(screenshots) != EXPECTED_SCREENSHOTS:
        missing = sorted(EXPECTED_SCREENSHOTS - set(screenshots))
        extra = sorted(set(screenshots) - EXPECTED_SCREENSHOTS)
        raise SystemExit(f"screenshot set differs: missing={missing} extra={extra}")
    started = datetime.datetime.fromisoformat(arguments.started_at.replace("Z", "+00:00"))
    if started.tzinfo != datetime.timezone.utc:
        raise SystemExit("started-at must be UTC RFC3339")
    finished = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    if finished <= started:
        raise SystemExit("finished time must be after started time")
    e2e = ROOT / "apps/peerward-console/e2e"
    package_lock = json.loads((e2e / "package-lock.json").read_text(encoding="utf-8"))
    axe_version = package_lock["packages"]["node_modules/@axe-core/playwright"]["version"]
    browser = command(
        "node",
        "--input-type=module",
        "--eval",
        "import {chromium} from 'playwright'; const b=await chromium.launch(); "
        "console.log(b.version()); await b.close();",
        cwd=e2e,
    )
    report = {
        "schema_version": 1,
        "gate": "wcag_visual",
        "status": "unverified",
        "evidence_binding": {
            "commit_sha": command("git", "-C", str(ROOT), "rev-parse", "HEAD"),
            "artifact_set_sha256": arguments.artifact_set_sha256,
        },
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": finished.isoformat().replace("+00:00", "Z"),
        "environment": {
            "runner": platform.node() or "unnamed-runner",
            "kernel": platform.release(),
            "browser": f"Chromium {browser}",
        },
        "tool_versions": {
            "node": command("node", "--version"),
            "playwright": command("npx", "playwright", "--version", cwd=e2e),
            "axe_core_playwright": axe_version,
        },
        "artifacts": [
            {"name": name, "sha256": digest(screenshots[name])}
            for name in sorted(screenshots)
        ],
        "result": {
            "routes": ["/", "android:#/", "android:#/diagnostics"],
            "locales": ["en-US", "zh-CN"],
            "themes": ["light", "dark"],
            "viewports": ["1440x1000", "1024x800", "390x844"],
            "automated_violations": 0,
            "keyboard": "missing",
            "focus": "missing",
            "manual_review": "missing",
            "gate_eligible": False,
            "reason": "automated axe and screenshot comparisons passed; independent keyboard, focus, and manual review remain missing",
        },
    }
    arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote unverified WCAG/visual candidate to {arguments.output}")


if __name__ == "__main__":
    main()
