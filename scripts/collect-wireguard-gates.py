#!/usr/bin/env python3
"""Refresh an internal migration evidence index; never grants release approval."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

from wireguard_gate_state import evidence_status
from android_gate_evidence import apply_diagnostic_intervention

ROOT = Path(__file__).resolve().parents[1]


def collect(item):
    paths = sorted(ROOT.glob(item["pattern"]))
    result = {**item, "status": "missing"}
    if paths:
        path = paths[-1]
        snapshot = path.read_bytes()
        report = json.loads(snapshot)
        apply_diagnostic_intervention(report, path.parent)
        result.update(path=str(path.relative_to(ROOT)), status=evidence_status(report),
                      sha256=hashlib.sha256(snapshot).hexdigest(),
                      binary_sha256=report.get("binary_sha256"), apk_sha256=report.get("apk_sha256"),
                      error=report.get("error"))
        for name in ("superseded.json", "interruption-observation.json"):
            observation = path.parent / name
            if observation.exists():
                result.update(status=json.loads(observation.read_text())["state"],
                              observation=str(observation.relative_to(ROOT)))
    if item.get("unit"):
        service = subprocess.run(["systemctl", "--user", "show", item["unit"],
            "--property=ActiveState,SubState,Result,ExecMainStatus,LoadState"],
            text=True, capture_output=True, timeout=10)
        state = dict(line.split("=", 1) for line in service.stdout.splitlines() if "=" in line)
        result["service"] = state
        if result["status"] in ("running", "starting", "waiting_for_functional_matrix"):
            if state.get("ActiveState") not in ("active", "activating"):
                result["status"] = "interrupted"
        elif result["status"] == "missing" and state.get("ActiveState") in ("active", "activating"):
            result["status"] = "starting"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    report = {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
              "scope": "internal verification; distinct builds and failed attempts are retained",
              "migration_complete": False, "release_gate_eligible": False,
              "context": manifest["context"], "open_gaps": manifest["open_gaps"],
              "evidence": [collect(item) for item in manifest["evidence"]]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(args.output)
    print(json.dumps([(item["name"], item["status"]) for item in report["evidence"]]))


if __name__ == "__main__":
    main()
