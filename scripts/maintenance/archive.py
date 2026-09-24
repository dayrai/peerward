"""Immutable age-encrypted maintenance archives; no plaintext publication.

The caller must quiesce signing-material writers and obtain a consistent pg_dump.
The restore caller pins the ciphertext digest from a trusted task receipt: an age
recipient public key alone does not authenticate the sender of a backup.
"""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import uuid

MAX_FILES = 100_000
MAX_MANIFEST = 4 * 1024 * 1024
CHUNK = 1024 * 1024
ROOTS = {"control", "relays", "deployment", "database"}


class ArchiveError(Exception):
    """A stable, secret-free archive error."""


def relative_name(value):
    if not isinstance(value, str):
        raise ArchiveError("invalid archive path")
    path = PurePosixPath(value)
    if (not isinstance(value, str) or not value or len(value) > 1024
            or path.is_absolute() or str(path) != value or ".." in path.parts
            or path.parts[0] not in ROOTS or "offline" in path.parts
            or any(ord(character) < 32 for character in value)):
        raise ArchiveError("archive path is outside the online backup inventory")
    return value


def private_directory(path):
    path = Path(path)
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ArchiveError("maintenance directory cannot contain symlinks")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ArchiveError("maintenance directory must be owned and mode 0700")
    return path


@contextmanager
def regular_input(path):
    path = Path(path)
    # Parent symlinks are rejected as well as a substituted leaf. Local operators
    # must protect the containing installation directory from untrusted writers.
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ArchiveError("backup input cannot contain symlinks")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ArchiveError("backup input must be a regular file with one link")
        yield stream, info


def digest_stream(stream, maximum):
    digest = hashlib.sha256()
    count = 0
    while chunk := stream.read(CHUNK):
        count += len(chunk)
        if count > maximum:
            raise ArchiveError("archive size limit exceeded")
        digest.update(chunk)
    return digest.hexdigest(), count


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class VerifiedReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size=-1):
        chunk = self.stream.read(size)
        self.digest.update(chunk)
        self.count += len(chunk)
        return chunk


def encrypt_archive(files, metadata, destination, recipients, *, age="age", maximum=64 * 1024**3):
    """Publish a complete archive once, refusing changed files and existing outputs.

    `files` maps allowlisted archive paths to local paths; metadata is public
    provenance supplied by the trusted deployment runner, never remote commands.
    """
    if not files or len(files) > MAX_FILES or not 1 <= len(recipients) <= 10:
        raise ArchiveError("invalid backup inventory")
    if any(not re.fullmatch(r"age1[a-z0-9]{58}", value) for value in recipients):
        raise ArchiveError("use native age recipient public keys")
    destination = Path(destination)
    private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise ArchiveError("backup destination already exists")
    inventory = {}
    total = 0
    for name, path in sorted(files.items()):
        relative_name(name)
        if "offline" in Path(path).parts:
            raise ArchiveError("offline recovery material is outside online backups")
        with regular_input(path) as (stream, info):
            digest, size = digest_stream(stream, maximum - total)
            if size != info.st_size:
                raise ArchiveError("backup input changed during inspection")
        inventory[name] = {"sha256": digest, "size": size}
        total += size
    manifest = json.dumps({"format": 1, "metadata": metadata, "files": inventory},
                          sort_keys=True, separators=(",", ":")).encode()
    if len(manifest) > MAX_MANIFEST:
        raise ArchiveError("backup manifest is too large")
    temporary = destination.with_name(".partial-" + str(uuid.uuid4()))
    process = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            command = [str(age), "--encrypt"]
            for recipient in recipients:
                command.extend(["--recipient", recipient])
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL)
            with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
                item = tarfile.TarInfo("manifest.json")
                item.size = len(manifest)
                item.mode = 0o600
                archive.addfile(item, io.BytesIO(manifest))
                for name, path in sorted(files.items()):
                    with regular_input(path) as (stream, info):
                        if info.st_size != inventory[name]["size"]:
                            raise ArchiveError("backup input changed before encryption")
                        item = tarfile.TarInfo(name)
                        item.size, item.mode = info.st_size, 0o600
                        reader = VerifiedReader(stream)
                        archive.addfile(item, reader)
                        if reader.count != info.st_size or reader.digest.hexdigest() != inventory[name]["sha256"]:
                            raise ArchiveError("backup input changed during encryption")
            process.stdin.close()
            if process.wait(timeout=120) != 0:
                raise ArchiveError("backup encryption failed")
            output.flush()
            os.fsync(output.fileno())
        with regular_input(temporary) as (stream, _):
            digest, size = digest_stream(stream, maximum + MAX_MANIFEST + MAX_FILES * 2048 + 1024**2)
        # No overwrite, including a destination created after preflight.
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
        fsync_directory(destination.parent)
        return {"sha256": digest, "bytes": size, "files": len(inventory), "format": 1}
    except (OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise ArchiveError("backup archive could not be completed") from error
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        temporary.unlink(missing_ok=True)


def decrypt_archive(source, expected_digest, identity, destination, *, age="age", maximum=64 * 1024**3):
    """Authenticate fully before manual extraction into a new private directory.

    This extracts verification inputs. It never starts Control/Relay, overwrites
    an installation, or treats restored authorizations as current.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise ArchiveError("pin the ciphertext digest from a trusted task receipt")
    destination = Path(destination)
    private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise ArchiveError("restore destination already exists")
    with regular_input(identity) as (key_file, info):
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ArchiveError("decryption identity must be owned and mode 0600")
        key_bytes = key_file.read(4097)
        keys = [line.strip() for line in key_bytes.splitlines() if line.strip() and not line.startswith(b"#")]
        if len(key_bytes) > 4096 or len(keys) != 1 or re.fullmatch(rb"AGE-SECRET-KEY-1[A-Z0-9]{58}", keys[0]) is None:
            raise ArchiveError("use one native age identity; plugins and interactive keys are not supported")
    with tempfile.TemporaryDirectory(prefix=".restore-", dir=destination.parent) as stage_name:
        stage = Path(stage_name)
        payload = stage / "payload.tar"
        with regular_input(source) as (stream, _):
            digest, _ = digest_stream(stream, maximum + MAX_MANIFEST + MAX_FILES * 2048 + 1024**2)
            if digest != expected_digest:
                raise ArchiveError("backup ciphertext digest differs from the trusted receipt")
            stream.seek(0)
            # Private temporary storage is never published before authentication.
            fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                result = subprocess.run([str(age), "--decrypt", "--identity", str(identity)],
                                        stdin=stream, stdout=output, stderr=subprocess.DEVNULL, timeout=3600)
            if result.returncode != 0:
                raise ArchiveError("backup decryption or authentication failed")
        if payload.stat().st_size > maximum + MAX_MANIFEST + MAX_FILES * 2048:
            raise ArchiveError("decrypted archive size limit exceeded")
        extracted = stage / "verified"
        extracted.mkdir(mode=0o700)
        with tarfile.open(payload, "r:") as archive:
            first = archive.next()
            if first is None or first.name != "manifest.json" or first.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or first.size > MAX_MANIFEST:
                raise ArchiveError("backup manifest missing or invalid")
            manifest = json.loads(archive.extractfile(first).read())
            if set(manifest) != {"format", "metadata", "files"} or manifest["format"] != 1:
                raise ArchiveError("unsupported backup manifest")
            inventory = manifest["files"]
            if not isinstance(inventory, dict) or not 1 <= len(inventory) <= MAX_FILES:
                raise ArchiveError("invalid archive inventory")
            for name, entry in inventory.items():
                relative_name(name)
                if (not isinstance(entry, dict) or set(entry) != {"sha256", "size"}
                        or not isinstance(entry["size"], int) or isinstance(entry["size"], bool)
                        or entry["size"] < 0 or not re.fullmatch(r"[0-9a-f]{64}", str(entry["sha256"]))):
                    raise ArchiveError("invalid archive file declaration")
            if sum(value["size"] for value in inventory.values()) > maximum:
                raise ArchiveError("archive extraction limit exceeded")
            seen = set()
            for item in archive:
                # tar iteration includes the cached first manifest entry.
                if item is first:
                    continue
                relative_name(item.name)
                if item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or item.sparse is not None or item.name in seen or item.name not in inventory:
                    raise ArchiveError("archive contains unexpected files or links")
                entry = inventory[item.name]
                if item.size != entry["size"]:
                    raise ArchiveError("archive file size does not match manifest")
                target = extracted / item.name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                digest = hashlib.sha256()
                with os.fdopen(descriptor, "wb") as output, archive.extractfile(item) as content:
                    while chunk := content.read(CHUNK):
                        output.write(chunk)
                        digest.update(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                if digest.hexdigest() != entry["sha256"]:
                    raise ArchiveError("restored file digest mismatch")
                seen.add(item.name)
            if seen != set(inventory):
                raise ArchiveError("archive is incomplete")
        # mkdir is the no-overwrite boundary. A crash while publishing leaves
        # an explicit incomplete directory, never an activation-ready restore.
        destination.mkdir(mode=0o700)
        marker = destination / ".incomplete"
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        fsync_directory(destination)
        fsync_directory(destination.parent)
        directories = {destination}
        for name in sorted(inventory):
            target = destination / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.link(extracted / name, target, follow_symlinks=False)
            for parent in target.parents:
                if parent == destination:
                    break
                directories.add(parent)
        for directory in sorted(directories, key=lambda value: len(value.parts), reverse=True):
            fsync_directory(directory)
        marker.unlink()
        fsync_directory(destination)
        fsync_directory(destination.parent)
        return manifest
