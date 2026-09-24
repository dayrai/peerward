"""Register explicitly selected, co-located Compose services; never read other Env values."""
import json
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit, unquote
from archive import ArchiveError, private_directory
from common import checked_container, digest, public_container, read_json, read_private, run, write_json


def mount_matches(row, source, target, writable):
    return any(item["Type"] == "bind" and item["Source"] == str(source)
               and item["Destination"] == target and item["RW"] == writable for item in row["Mounts"])


def register(installation, project, relay_roots, deployment_files, recipients, destination):
    root = Path(installation).absolute()
    private_directory(root)
    metadata = read_json(root / "installation.json")
    if metadata.get("version") != 2 or metadata.get("schema_version") != 4 or metadata.get("wire_major") != 5:
        raise ArchiveError("only fresh Schema 4 / Wire 5 installations are supported")
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project) is None:
        raise ArchiveError("invalid Compose project")
    if not 1 <= len(recipients) <= 10 or any(re.fullmatch(r"age1[a-z0-9]{58}", r) is None for r in recipients):
        raise ArchiveError("supply native age recipient public keys")
    ids = run(["docker", "ps", "-aq", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project]).decode().split()
    if not ids:
        raise ArchiveError("selected Compose project has no containers")
    rows = json.loads(run(["docker", "inspect", *ids]))
    selected = []
    for row in rows:
        service = (row["Config"].get("Labels") or {}).get("com.docker.compose.service")
        if not row["State"]["Running"]:
            if service == "migrate":
                continue
            raise ArchiveError("bring the selected services to a known running state before registration")
        selected.append(row)
    controls = [r for r in selected if mount_matches(r, root / "control", "/etc/peerward", False)]
    databases = [r for r in selected if public_container(r)["service"] == "postgres"]
    consoles = [r for r in selected if public_container(r)["service"] == "console"]
    if len(controls) != 1 or len(databases) != 1 or len(consoles) > 1:
        raise ArchiveError("select exactly one Control and PostgreSQL and at most one console")
    control, database = controls[0], databases[0]
    for row in [control, *consoles]:
        if any(binding.get("HostPort") in ("", "0") for bindings in (row["HostConfig"].get("PortBindings") or {}).values() for binding in bindings or []):
            raise ArchiveError("Control and console require fixed published ports so restart preserves the management address")
    if not mount_matches(control, root / "control/meshes", "/var/lib/peerward/meshes", True) or not mount_matches(control, root / "control/recovery", "/var/lib/peerward/recovery", True):
        raise ArchiveError("Control signing and recovery paths differ from the installation inventory")
    relays = []
    for directory in relay_roots or [root / "relay"]:
        directory = Path(directory).absolute()
        private_directory(directory)
        config = tomllib.loads(read_private(directory / "relay.toml").decode())
        matches = [r for r in selected if mount_matches(r, directory, "/etc/peerward", False)
                   and mount_matches(r, directory / "meshes", "/var/lib/peerward/meshes", True)]
        if len(matches) != 1:
            raise ArchiveError("each Relay requires its own pinned container and local signing paths")
        relays.append({"host_id": config["host_id"], "root": str(directory), "container": public_container(matches[0])})
    members = [control, database, *consoles, *(next(r for r in selected if r["Id"] == h["container"]["id"]) for h in relays)]
    if len({r["Id"] for r in members}) != len(members) or {r["Id"] for r in selected} != {r["Id"] for r in members}:
        raise ArchiveError("all project services must be explicitly accounted for; overlapping roles are forbidden")
    config = tomllib.loads(read_private(root / "control/control.toml").decode())
    parsed = urlsplit(config["database_url"])
    # In-container PG tools use the existing local authentication; passwords never enter argv.
    user, name = unquote(parsed.username or ""), unquote(parsed.path.removeprefix("/"))
    if any(re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,62}", x) is None for x in (user, name)) or parsed.hostname != "postgres" or parsed.port not in (None, 5432):
        raise ArchiveError("this runner requires the selected local Compose PostgreSQL")
    env = dict(value.split("=", 1) for value in database["Config"].get("Env", []) if "=" in value)
    if env.get("POSTGRES_USER") != user or env.get("POSTGRES_DB") != name:
        raise ArchiveError("Control database and selected PostgreSQL identity differ")
    for row in [control, *(r for r in members if r["Id"] in {h["container"]["id"] for h in relays})]:
        runtime_env = dict(value.split("=", 1) for value in row["Config"].get("Env", []) if "=" in value)
        if runtime_env.get("PEERWARD_DATABASE_URL", config["database_url"]) != config["database_url"]:
            raise ArchiveError("runtime database override differs from the registered database")
    files = []
    for value in deployment_files:
        path = Path(value).absolute()
        read_private(path)
        if "offline" in path.parts:
            raise ArchiveError("offline recovery keys are not an online backup input")
        files.append(str(path))
    profile = {"format": 1, "installation": str(root), "metadata": metadata,
               "control": public_container(control), "postgres": public_container(database),
               "console": [public_container(r) for r in consoles], "relays": relays,
               "database": {"user": user, "name": name}, "deployment_files": files,
               "recipients": recipients}
    for row in members:
        if row["State"].get("Health", {}).get("Status") != "healthy":
            raise ArchiveError("all registered services need current Docker health confirmation")
    write_json(destination, profile)
    return {"profile_digest": digest(profile), "services": len(members), "relay_hosts": len(relays)}


class RegisteredProfile(dict):
    """Optional local verification workspace is not part of the immutable profile digest."""
    workspace = None


def load(path, workspace=None):
    profile = read_json(path)
    if profile.get("format") != 1 or set(profile) != {"format", "installation", "metadata", "control", "postgres", "console", "relays", "database", "deployment_files", "recipients"}:
        raise ArchiveError("unsupported maintenance profile")
    if profile["metadata"].get("schema_version") != 4 or profile["metadata"].get("wire_major") != 5:
        raise ArchiveError("maintenance profile is incompatible")
    profile = RegisteredProfile(profile)
    if workspace is None:
        private_directory(profile["installation"])
    else:
        profile.workspace = private_directory(Path(workspace).absolute())
    return profile


def writers(profile):
    return [*profile["console"], profile["control"], *(r["container"] for r in profile["relays"])]


def validate_running(profile):
    containers = [profile["postgres"], *writers(profile)]
    expected = {row["id"] for row in containers}
    actual = set(run(["docker", "ps", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project=" + profile["control"]["project"]]).decode().split())
    if actual != expected:
        raise ArchiveError("the running project inventory changed; review and register every service")
    for container in containers:
        row = checked_container(container, running=True)
        if row["State"].get("Health", {}).get("Status") != "healthy":
            raise ArchiveError("service health is not confirmed")
        if container["id"] == profile["control"]["id"]:
            environment = dict(value.split("=", 1) for value in row["Config"].get("Env", []) if "=" in value)
            if environment.get("PEERWARD_DYNAMIC_CONFIG") != "/etc/peerward/dynamic.toml":
                raise ArchiveError("Control runtime configuration is outside the registered inventory")
    validate_paths(profile)


def validate_paths(profile):
    control = Path(profile["installation"]) / "control"
    dynamic = tomllib.loads(read_private(control / "dynamic.toml").decode())
    expected = {"state_directory": "/var/lib/peerward/meshes", "recovery_directory": "/var/lib/peerward/recovery",
                "ca_file": "/etc/peerward/ca.pem", "certificate_file": "/etc/peerward/tls.pem", "private_key_file": "/etc/peerward/tls.key"}
    if any(dynamic.get(key) != value for key, value in expected.items()):
        raise ArchiveError("Control key paths are outside the supported online inventory")
    config = tomllib.loads(read_private(control / "control.toml").decode())
    database = urlsplit(config["database_url"])
    if database.hostname != "postgres" or database.port not in (None, 5432) or unquote(database.username or "") != profile["database"]["user"] or unquote(database.path.removeprefix("/")) != profile["database"]["name"] or config.get("authority_key_directory"):
        raise ArchiveError("Control database or signing inventory changed; register the installation again")
    relay_expected = {key: value for key, value in expected.items() if key != "recovery_directory"}
    for relay in profile["relays"]:
        config = tomllib.loads(read_private(Path(relay["root"]) / "relay.toml").decode())
        if config.get("host_id") != relay["host_id"] or any(config.get(key) != value for key, value in relay_expected.items()):
            raise ArchiveError("Relay identity or key paths are outside the registered inventory")
        for carrier in ("wss", "quic"):
            if carrier in config:
                value = config[carrier]
                if value.get("certificate_file") != f"/etc/peerward/{carrier}.pem" or value.get("private_key_file") != f"/etc/peerward/{carrier}.key":
                    raise ArchiveError("Relay transport TLS keys are outside the supported inventory")
