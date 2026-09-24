#!/usr/bin/env python3
"""Copy reviewed fuzz seeds without replacing existing or minimized corpora."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for seed in sorted((root / "fuzz/seeds").glob("*/*")):
    if not seed.is_file():
        continue
    target = root / "fuzz/corpus" / seed.parent.name / seed.name
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as output:
            output.write(seed.read_bytes())
    except FileExistsError:
        pass
