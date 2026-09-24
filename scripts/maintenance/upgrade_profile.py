"""An operator-staged native upgrade: immutable local inputs, no remote command parameters."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import uuid
from archive import ArchiveError, private_directory, regular_input
from common import digest, read_json, read_private, write_json

FIELDS = {"format", "kind", "installation", "role", "health_url", "repair", "assets", "hashes", "release"}
INPUTS = {"program", "manifest", "signature", "public_key", "artifact"}


def copy_input(source, destination, executable=False):
    # Inputs are operator-selected; their immutable copies are private and have no links.
    path = Path(source).resolve(strict=True)
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,"rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024**2:
            raise ArchiveError("upgrade input must be a bounded regular file")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500 if executable else 0o600)
        with os.fdopen(fd, "wb") as output:
            remaining = 256 * 1024**2
            while chunk := stream.read(min(1024**2, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    raise ArchiveError("upgrade input exceeds its size bound")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())


def register(args):
    output = args.output.absolute()
    private_directory(output.parent)
    if output.exists():
        raise ArchiveError("upgrade profile already exists; use a new profile for a new release")
    assets = private_directory(output.parent / ("upgrade-" + uuid.uuid4().hex))
    try:
        selected = {name: getattr(args, name) for name in INPUTS}
        if args.database_url_file is not None:
            read_private(args.database_url_file, 4096)  # Do not stage an unprotected database secret.
            selected["database_url_file"] = args.database_url_file
        if (args.role == "control") != ("database_url_file" in selected):
            raise ArchiveError("only Control profiles require a private database URL file")
        for name, path in selected.items():
            copy_input(path, assets / name, executable=name == "program")
        profile = {"format": 1, "kind": "native_upgrade", "installation": str(args.installation_root.absolute()),
                   "role": args.role, "health_url": args.health_url, "repair": args.repair,
                   "assets": str(assets), "hashes": {}, "release": {}}
        for name in selected:
            with regular_input(assets / name) as (stream, _):
                profile["hashes"][name] = hashlib.file_digest(stream, "sha256").hexdigest()
        local = invoke(profile, "preview")
        if local.returncode:
            raise ArchiveError("native upgrade preview failed; check the signed inputs and local role before registration")
        value = parse_output(local)
        if value["current_version"] == value["version"]:
            raise ArchiveError("the selected version is already installed")
        profile["release"] = {key: value[key] for key in ("version", "sequence", "manifest_sha256", "artifact_sha256", "artifact_bytes", "rollback_floor")}
        write_json(output, profile)
        return {"profile": str(output), "profile_digest": digest(profile), "operation": "native_upgrade",
                "role": profile["role"], "version": value["version"], "status": "registered", "services_changed": False}
    except BaseException:
        if not output.exists():
            shutil.rmtree(assets)
        raise


def load(path):
    value = read_json(path)
    if set(value) != FIELDS or value["format"] != 1 or value["kind"] != "native_upgrade" or value["role"] not in ("control", "relay", "peer") or type(value["repair"]) is not bool:
        raise ArchiveError("unsupported native upgrade profile")
    if not Path(value["installation"]).is_absolute() or not Path(value["assets"]).is_absolute():
        raise ArchiveError("native upgrade requires absolute local paths")
    verify_inputs(value)
    return value


def verify_inputs(profile):
    expected = INPUTS | ({"database_url_file"} if profile["role"] == "control" else set())
    if set(profile["hashes"]) != expected:
        raise ArchiveError("upgrade profile input inventory differs")
    assets = private_directory(profile["assets"])
    for name, expected in profile["hashes"].items():
        with regular_input(assets / name) as (stream, info):
            if info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 256 * 1024**2 or hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                raise ArchiveError("registered upgrade input changed; keep the existing task record")


def invoke(profile, operation, preview_digest=None):
    verify_inputs(profile)
    assets = Path(profile["assets"])
    arguments = [str(assets / "program"), "update", operation, "--installation-root", profile["installation"], "--role", profile["role"]]
    if operation in ("preview", "apply"):
        for flag, name in (("manifest", "manifest"), ("signature", "signature"), ("public-key", "public_key"), ("artifact-file", "artifact")):
            arguments += ["--" + flag, str(assets / name)]
        release = json.loads(read_private(assets / "manifest"))
        arguments += ["--channel", release["channel"], "--health-url", profile["health_url"]]
        if profile["repair"]:
            arguments += ["--repair"]
        if preview_digest is not None:
            arguments += ["--preview-digest", preview_digest]
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    if profile["role"] == "control":
        environment["PEERWARD_DATABASE_URL"] = read_private(assets / "database_url_file", 4096).decode().strip()
    try:
        result = subprocess.run(arguments, env=environment, cwd="/", capture_output=True, timeout=210)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ArchiveError("native updater interrupted; inspect its durable transaction before retrying") from error
    if len(result.stdout) > 4 * 1024**2 or len(result.stderr) > 4 * 1024**2:
        raise ArchiveError("native updater response exceeds its bound")
    return result


def parse_output(result):
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError) as error:
        raise ArchiveError("native updater did not return its structured result") from error
