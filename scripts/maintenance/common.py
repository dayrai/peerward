"""Private durable records and fixed Docker operations for the local operator."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from archive import ArchiveError, fsync_directory, private_directory, regular_input

POSTGRES = "postgres:18-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
LABEL = "io.peerward.maintenance.task"


class OperationBusy(ArchiveError):
    """The installation lock was refused before any protected operation began."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read_private(path, maximum=4 * 1024**2):
    with regular_input(path) as (stream, info):
        if info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > maximum:
            raise ArchiveError("maintenance input must be private, owned and bounded")
        return stream.read(maximum + 1)


def read_json(path):
    try:
        return json.loads(read_private(path))
    except (ValueError, TypeError) as error:
        raise ArchiveError("invalid maintenance record") from error


def write_json(path, value, *, replace=False):
    path = Path(path)
    private_directory(path.parent)
    temporary = path.with_name(".record-" + str(uuid.uuid4()))
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(canonical(value) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def task_id(value):
    try:
        identifier = uuid.UUID(value)
        if identifier.version != 4 or str(identifier) != value:
            raise ValueError()
        return value
    except (ValueError, AttributeError) as error:
        raise ArchiveError("task ID must be a canonical UUID v4") from error


@contextmanager
def exclusive(path):
    private_directory(Path(path).parent)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise OperationBusy("another local maintenance operation is running") from error
        yield
    finally:
        os.close(fd)


def run(arguments, *, input=None, stdin=None, stdout=subprocess.PIPE, timeout=120):
    try:
        result = subprocess.run(list(map(str, arguments)), input=input, stdin=stdin, stdout=stdout,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=True)
        return result.stdout
    except (OSError, subprocess.SubprocessError) as error:
        # Subprocess diagnostics may include database URLs, file contents or SQL.
        raise ArchiveError("fixed maintenance operation failed; inspect local service health") from error


def inspect(identifier):
    if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
        raise ArchiveError("container identity must be pinned")
    return json.loads(run(["docker", "inspect", identifier]))[0]


def public_container(row):
    labels = row["Config"].get("Labels") or {}
    return {"id": row["Id"], "image": row["Image"], "name": row["Name"].lstrip("/"),
            "project": labels.get("com.docker.compose.project"),
            "service": labels.get("com.docker.compose.service")}


def checked_container(expected, *, running=None):
    row = inspect(expected["id"])
    if public_container(row) != expected:
        raise ArchiveError("container identity changed; register and preview the installation again")
    if running is not None and row["State"]["Running"] != running:
        raise ArchiveError("container running state changed")
    return row


def wait_healthy(expected, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        row = checked_container(expected)
        if row["State"]["Running"] and row["State"].get("Health", {}).get("Status") == "healthy":
            return
        time.sleep(1)
    raise ArchiveError("service recovery requires attention: health confirmation timed out")
