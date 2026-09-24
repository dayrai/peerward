#!/usr/bin/env python3
"""Check repository Markdown file links; local artifact archives are not shipped."""

from pathlib import Path
import os
import re
import subprocess
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'\]\(([^\s)]+)(?:\s+"[^"]*")?\)')
# Source archives have no Git index. Prune generated and local-state directories
# before walking so dependencies and build reports are not treated as project docs.
GENERATED = {
    ".git", ".gradle", ".kotlin", ".idea", ".venv", "__pycache__", "artifacts",
    "build", "captures", "corpus", "dist", "node_modules", "peerward-device",
    "peerward-device.peerward-join", "playwright-report", "target", "test-results",
}


def markdown_files(root: Path):
    if (root / ".git").exists():
        names = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.md"],
            cwd=root,
        ).decode().split("\0")
        yield from (root / name for name in sorted(set(names) - {""}))
        return
    for directory, children, files in os.walk(root):
        children[:] = sorted(
            name for name in children
            if name not in GENERATED
            and not (Path(directory) == root / "deploy/compose"
                     and (name == "state" or name.startswith("state-")))
        )
        yield from (Path(directory) / name for name in sorted(files) if name.endswith(".md"))


def check(root: Path) -> tuple[int, int, list[str]]:
    checked = 0
    archives = 0
    missing = []
    for document in markdown_files(root):
        if not document.is_file():
            continue  # Deletions in the current worktree.
        for number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            for match in LINK.finditer(line):
                link = urlsplit(match[1])
                if link.scheme or link.netloc or not link.path:
                    continue
                target = (document.parent / unquote(link.path)).resolve()
                if target.is_relative_to(root / "artifacts"):
                    archives += 1
                    continue
                checked += 1
                if not target.exists():
                    missing.append(f"{document.relative_to(root)}:{number}: missing local path: {link.path}")
    return checked, archives, missing


def main() -> None:
    checked, archives, missing = check(ROOT)
    if missing:
        raise SystemExit("\n".join(missing))
    print(f"documentation: {checked} local paths checked; {archives} local archive links excluded")


if __name__ == "__main__":
    main()
