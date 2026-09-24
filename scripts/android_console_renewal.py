"""Exercise a console renewal against the running disposable Android installation.

Only public peer/request identifiers and result states enter the evidence report.
Administrative credentials stay on the host in the existing Installation client.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import threading
import time
import uuid


@contextmanager
def console_renewal(installation, mesh, adb, package, output, console_url=None):
    stop = threading.Event()
    report = {"passed": False, "state": "waiting_for_device"}

    def exercise():
        try:
            deadline = time.monotonic() + 180
            peer = None
            while not stop.is_set() and time.monotonic() < deadline:
                marker = subprocess.run(
                    [*adb, "exec-out", "run-as", package, "cat", "files/console-renewal-ready.json"],
                    capture_output=True, text=True, timeout=5,
                )
                if marker.returncode == 0:
                    try:
                        identity = json.loads(marker.stdout)
                    except json.JSONDecodeError:
                        stop.wait(.5)
                        continue
                    if identity["mesh_id"] != mesh["id"]:
                        raise ValueError("unexpected test mesh")
                    peer = str(uuid.UUID(identity["peer_id"]))
                    break
                stop.wait(.5)
            if peer is None:
                raise TimeoutError("device did not reach renewal scenario")
            base = f"/meshes/{mesh['id']}"

            def observed_evidence():
                deadline = time.monotonic() + 60
                while not stop.is_set() and time.monotonic() < deadline:
                    status, current = installation.call(f"{base}/peers/{peer}")
                    evidence_status, condition = installation.call(f"{base}/peers/{peer}/device-condition")
                    evidence = condition.get("evidence") or {}
                    statement = evidence.get("statement") or {}
                    if (status == 200 and evidence_status == 200
                            and evidence.get("credential_serial") == current["credentials"]["active"]["serial"]
                            and statement.get("platform") == "android"
                            and evidence.get("source") == "device_signed_self_report"):
                        return {"observed_at": evidence["observed_at"], "valid_until": evidence["valid_until"],
                                "credential_serial": evidence["credential_serial"], "statement": statement}
                    stop.wait(.5)
                raise TimeoutError("current Android signed device evidence was not observed")

            report["evidence_before_renewal"] = observed_evidence()
            if console_url:
                script = Path(__file__).resolve().parents[1] / "apps/peerward-console/e2e/physical-renewal.mjs"
                with (output / "console-browser.log").open("w") as log:
                    process = subprocess.Popen(["node", script, console_url, mesh["id"], peer, str(output)],
                                               stdout=log, stderr=subprocess.STDOUT)
                    try:
                        deadline = time.monotonic() + 150
                        while process.poll() is None:
                            if stop.wait(.2) or time.monotonic() >= deadline:
                                raise TimeoutError("browser renewal cancelled or timed out")
                        if process.returncode:
                            raise RuntimeError("browser renewal failed")
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=5)
                report.update(json.loads((output / "console-browser-renewal.json").read_text()))
                report["evidence_after_renewal"] = observed_evidence()
                return
            status, current = installation.call(f"{base}/peers/{peer}")
            if status != 200 or not current["online"]:
                raise ValueError("device is not authenticated online")
            request_id = str(uuid.uuid4())
            body = {
                "request_id": request_id,
                "current_serial": current["credentials"]["active"]["serial"],
                "valid_for_seconds": 300,
                "reason": "Disposable Android console renewal acceptance",
            }
            path = f"{base}/console/devices/{peer}/renewals"
            headers = {"If-Match": '"' + str(current["version"]) + '"'}
            status, renewal = installation.call(path, "POST", body, headers)
            if status != 200:
                raise ValueError("console renewal request rejected")
            # A retry must resolve to the same durable request.
            status, retry = installation.call(path, "POST", body, headers)
            if status != 200 or retry["id"] != renewal["id"]:
                raise ValueError("renewal retry was not idempotent")
            report.update(request_id=request_id, state=renewal["state"], peer_id=peer)
            deadline = time.monotonic() + 120
            while not stop.is_set() and time.monotonic() < deadline:
                status, page = installation.call(path)
                if status != 200:
                    raise ValueError("renewal status unavailable")
                renewal = next(item for item in page["items"] if item["id"] == request_id)
                report["state"] = renewal["state"]
                if renewal["state"] == "completed":
                    report["evidence_after_renewal"] = observed_evidence()
                    report["passed"] = True
                    break
                stop.wait(.5)
        except Exception as error:
            # Do not serialize exception text: clients may include credentials in URLs.
            report["error"] = type(error).__name__
            report["passed"] = False
        finally:
            (output / "console-renewal.json").write_text(json.dumps(report, indent=2) + "\n")

    worker = threading.Thread(target=exercise, daemon=True)
    worker.start()
    try:
        yield report
        worker.join(timeout=10)
        if not report["passed"]:
            raise RuntimeError("Android console renewal did not reach authenticated completion; see console-renewal.json")
    finally:
        stop.set()
        worker.join(timeout=10)
