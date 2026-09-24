"""Durable failure records and bounded cleanup for owned WireGuard fixtures."""
import json
import os
from pathlib import Path
import subprocess
import time
from datetime import datetime, timezone


def listener_endpoints(observation):
    """Compare ss -H -lnut endpoints, preserving duplicates but ignoring queue sizes."""
    endpoints = []
    for line in observation.splitlines():
        columns = line.split()
        if len(columns) != 6 or columns[0] not in ("tcp", "udp"):
            raise ValueError("unexpected listener observation")
        endpoints.append((columns[0], columns[1], columns[4], columns[5]))
    if not endpoints:
        raise ValueError("missing listener observation")
    return sorted(endpoints)


def process_identity():
    return {"pid": os.getpid(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "start_ticks": Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]}


def process_still_running(owner):
    try:
        return (owner["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                and owner["start_ticks"] == Path(f"/proc/{int(owner['pid'])}/stat").read_text().rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, KeyError, IndexError):
        return False


def evidence_status(report):
    """Completion is not success; active runs with passed=false are still pending."""
    state = report.get("state", report.get("status", "pending"))
    if state in ("failed", "interrupted"):
        return state
    if state in ("running", "starting", "waiting_for_functional_matrix") and report.get("process"):
        if not process_still_running(report["process"]):
            return "interrupted"
    if report.get("passed") is False:
        return state if state in ("running", "starting", "waiting_for_functional_matrix") else "failed"
    if report.get("passed") is True or state == "passed":
        return "passed"
    return state


class StageFailure(RuntimeError):
    def __init__(self, stage, exit_code):
        super().__init__(f"{stage} failed (exit {exit_code}); see driver.log")
        self.stage = stage
        self.exit_code = exit_code


def record_failure(report, error):
    report["passed"] = False
    report["error"] = str(error)
    report["failure"] = {"type": type(error).__name__, "message": str(error)}
    if isinstance(error, StageFailure):
        report["failure"].update(stage=error.stage, exit_code=error.exit_code)
    elif isinstance(error, subprocess.TimeoutExpired):
        report["failure"].update(timeout_seconds=error.timeout)


def cleanup_owned_container(name, log, *, run=subprocess.run, clock=time.monotonic, sleep=time.sleep):
    """Never assume an unavailable Docker daemon means that a container is gone."""
    deadline = clock() + 5
    detail = {"container": name, "removed": False}
    try:
        removed = run(["docker", "rm", "--force", name], stdout=log,
                      stderr=subprocess.STDOUT, timeout=10)
        detail["remove_exit_code"] = removed.returncode
        while True:
            state = run(["docker", "inspect", "--format", "{{json .State}}", name],
                        capture_output=True, text=True, timeout=5)
            if state.returncode:
                error = state.stderr or ""
                if any(f"no such {kind}: {name}" in error.casefold() for kind in ("object", "container")):
                    detail["removed"] = True
                else:
                    detail["error"] = "cannot verify container removal: " + error.strip()[:512]
                return detail
            try:
                detail["last_state"] = json.loads(state.stdout)
            except (ValueError, TypeError):
                detail["error"] = "malformed container state"
                return detail
            if clock() >= deadline:
                detail["error"] = "container still present after cleanup deadline"
                return detail
            sleep(0.1)
    except (OSError, subprocess.SubprocessError) as error:
        detail["error"] = str(error)
        return detail


def finish_report(report, path, cleanup):
    report["cleanup"] = cleanup
    if any(not item["removed"] for item in cleanup):
        report["passed"] = False
        report.setdefault("error", "fixture cleanup failed")
    report["state"] = "passed" if report["passed"] else "failed"
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)
