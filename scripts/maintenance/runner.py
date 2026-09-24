"""Restricted deployment exchange; all effects remain in the pinned local profile."""
import ipaddress
import datetime
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from archive import ArchiveError
import backup
import native_upgrade
from common import OperationBusy, digest, exclusive, read_json, task_id, write_json


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise ArchiveError("deployment exchange redirects are forbidden")


def connection(path, profile):
    value = read_json(path)
    if set(value) - {"runner_id", "token", "control_url", "profile_digest", "ca_file"}:
        raise ArchiveError("unknown runner connection field")
    task_id(value["runner_id"])
    if re.fullmatch(r"pw_runner_[a-zA-Z0-9_-]{44}", value["token"]) is None or value["profile_digest"] != digest(profile):
        raise ArchiveError("runner credential or profile binding is invalid")
    url = urllib.parse.urlsplit(value["control_url"])
    if not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ArchiveError("use a Control origin without credentials, query or path")
    if url.scheme != "https":
        try:
            loopback = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            loopback = False
        if url.scheme != "http" or not loopback:
            raise ArchiveError("runner exchange requires HTTPS or a literal loopback HTTP address")
    return value


def request(connection, body):
    url = connection["control_url"].rstrip("/") + "/api/v1/deployment-runners/" + connection["runner_id"] + "/exchange"
    context = ssl.create_default_context(cafile=connection.get("ca_file"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    req = urllib.request.Request(url, data=json.dumps(body, separators=(",", ":")).encode(), method="POST",
                                 headers={"authorization": "Bearer " + connection["token"], "content-type": "application/json"})
    try:
        with opener.open(req, timeout=20) as response:
            payload = response.read(2 * 1024**2 + 1)
        if len(payload) > 2 * 1024**2:
            raise ArchiveError("deployment response exceeds its size limit")
        return json.loads(payload)
    except urllib.error.HTTPError as error:
        raise ArchiveError(f"deployment exchange rejected with HTTP {error.code}; keep the original pending exchange") from error
    except (OSError, ValueError) as error:
        raise ArchiveError("deployment exchange unavailable; original pending exchange is retained") from error


def operation(profile):
    return "native_upgrade" if profile.get("kind")=="native_upgrade" else "installation_backup"


def backend(profile):
    return native_upgrade if operation(profile)=="native_upgrade" else backup


def public_report(record):
    artifact = record.get("artifact")
    result = {"task_id": record["id"], "local_version": record["version"], "status": record["status"],
            "stage": record["stage"], "error_code": record["error_code"],
            "artifact": {k: artifact[k] for k in ("sha256", "bytes", "files")} if artifact else None}
    if record.get("upgrade") is not None:
        result["upgrade"] = record["upgrade"]
    return result


def next_body(profile, state):
    reports = []
    tasks = backup.paths(profile)[1]
    for identifier, known in state["known"].items():
        path = tasks / (task_id(identifier) + ".json")
        if path.exists():
            record = read_json(path)
            if record["version"] > known["reported"]:
                reports.append(public_report(record))
        if len(reports) == 16:
            break
    preview = None
    try:
        local = backend(profile).preview(profile)
        if operation(profile)=="native_upgrade":
            preview=local
        else:
            preview = {k: local[k] for k in ("digest", "services_to_pause", "online_files")}
            preview.update({k: local["material"][k] for k in ("meshes", "relay_hosts")})
    except (ArchiveError, OSError):
        pass  # Missing observation never becomes a ready preview.
    return {"sequence": state["sequence"] + 1, "profile_digest": digest(profile), "preview": preview, "reports": reports}


def accept_response(profile, connection, state, response):
    pending = state["pending"]
    if set(response) != {"sequence", "task"} or response["sequence"] != pending["sequence"]:
        raise ArchiveError("deployment response does not match the durable pending exchange")
    task = response["task"]
    if task is not None:
        identifier = task_id(task["id"])
        if task["runner_id"] != connection["runner_id"] or task["profile_digest"] != digest(profile) or task["operation"] != operation(profile) or task["status"] not in ("running", "recovery_required"):
            raise ArchiveError("deployment task is outside this runner's fixed operation and profile")
        intent = task["request"]
        expected={"id","runner_id","preview_digest"} | ({"operation"} if operation(profile)=="native_upgrade" else set())
        if intent.get("operation","installation_backup") != operation(profile) or set(intent) != expected or intent["id"] != identifier or intent["runner_id"] != connection["runner_id"] or re.fullmatch(r"[0-9a-f]{64}", intent["preview_digest"]) is None:
            raise ArchiveError("invalid deployment task intent")
        state["known"].setdefault(identifier, {"reported": 0, "started": False})
    for report in pending["reports"]:
        state["known"][report["task_id"]]["reported"] = report["local_version"]
    state.update(sequence=pending["sequence"], pending=None, assigned=task)


def execute_assigned(profile, state, state_path, *, age):
    task = state["assigned"]
    if task is None:
        return
    identifier = task["id"]
    local_path = backup.paths(profile)[1] / (identifier + ".json")
    known = state["known"][identifier]
    if local_path.exists():
        record = read_json(local_path)
        if record["profile_digest"] != digest(profile) or record["request"] != {"operation": operation(profile), "preview_digest": task["request"]["preview_digest"]}:
            raise ArchiveError("local task ID is bound to another operation")
        if record["status"] in ("running", "recovery_required"):
            if operation(profile)=="native_upgrade":
                native_upgrade.recover(profile,identifier,generation=task.get("recovery_generation",0))
            else:
                backup.recover(profile, identifier)
        state["assigned"] = None
        write_json(state_path, state, replace=True)
        return
    if known["started"]:
        raise ArchiveError("local task journal is missing; inspect original service states before any retry")
    known["started"] = True
    write_json(state_path, state, replace=True)
    try:
        try:
            created = datetime.datetime.fromisoformat(task["created_at"].replace("Z", "+00:00")).timestamp()
        except (KeyError, ValueError, TypeError) as error:
            raise ArchiveError("deployment task start deadline is invalid") from error
        if not created - 60 <= time.time() <= created + 900:
            raise ArchiveError("deployment task start window expired; review a fresh backup task")
        backend(profile).execute(profile, identifier, task["request"]["preview_digest"], age=age)
    except OperationBusy:
        # The lock was refused before entering the operation. Keep the assignment
        # pending, without turning a competing runner into a missing-journal failure.
        known["started"] = False
        write_json(state_path, state, replace=True)
        return
    except ArchiveError:
        # A refused preflight must also reach the console. No side effect precedes
        # backup's own durable journal; keep any existing interrupted record intact.
        base = backup.paths(profile)[0]
        with exclusive(base / "operation.lock"):
            path, record, fresh = backup.begin(profile, identifier, {"operation": operation(profile), "preview_digest": task["request"]["preview_digest"]})
            if fresh:
                backup.save(path, record, status="failed", stage="preflight", error_code="local_preflight_failed")
    state["assigned"] = None
    write_json(state_path, state, replace=True)


def serve(profile, connection_file, *, age="age", once=False):
    configured = connection(connection_file, profile)
    base = backup.paths(profile)[0]
    state_path = base / ("runner-" + configured["runner_id"] + ".json")
    with exclusive(base / ("runner-" + configured["runner_id"] + ".lock")):
        if not state_path.exists():
            write_json(state_path, {"format": 1, "runner_id": configured["runner_id"], "profile_digest": digest(profile),
                                    "sequence": 0, "pending": None, "assigned": None, "known": {}})
        state = read_json(state_path)
        if state.get("format") != 1 or state["runner_id"] != configured["runner_id"] or state["profile_digest"] != digest(profile):
            raise ArchiveError("durable runner state belongs to another registered profile")
        executed = False
        while True:
            try:
                executed = executed or state["assigned"] is not None
                execute_assigned(profile, state, state_path, age=age)
                if state["pending"] is None:
                    state["pending"] = next_body(profile, state)
                    write_json(state_path, state, replace=True)
                response = request(configured, state["pending"])
                accept_response(profile, configured, state, response)
                write_json(state_path, state, replace=True)
                if state["assigned"] is not None:
                    if not executed:
                        continue  # Execute the new assignment and deliver its observation.
                    if once:
                        return {"runner_id": configured["runner_id"], "sequence": state["sequence"], "status": "task_pending"}
                    time.sleep(5)  # Unfinished work is observed without a busy loop.
                    continue
                if once:
                    return {"runner_id": configured["runner_id"], "sequence": state["sequence"], "status": "exchange_complete"}
            except ArchiveError as error:
                if once:
                    raise
                print(json.dumps({"runner_id": configured["runner_id"], "error": str(error)}), flush=True)
            time.sleep(5)
