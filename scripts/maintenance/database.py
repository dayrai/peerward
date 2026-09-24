"""One exported PostgreSQL snapshot shared by the manifest and pg_dump."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time
from archive import ArchiveError
from common import read_private, run

ROOT = Path(__file__).resolve().parents[2]


class Snapshot:
    def __init__(self, container, database):
        self.container, self.database = container, database
        self.process = None

    def command(self, program):
        return ["docker", "exec", "-i", self.container, program, "--no-password", "-U", self.database["user"], "-d", self.database["name"]]

    def __enter__(self):
        self.process = subprocess.Popen(self.command("psql") + ["-XAtq", "-v", "ON_ERROR_STOP=1"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        try:
            self.snapshot = self.query("SET statement_timeout='120s'; SET idle_in_transaction_session_timeout='10min'; BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT to_json(pg_export_snapshot())")
            if re.fullmatch(r"[0-9A-Fa-f-]{1,64}", self.snapshot) is None:
                raise ArchiveError("invalid PostgreSQL snapshot identifier")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def query(self, sql):
        self.process.stdin.write((sql + ";\n").encode())
        self.process.stdin.flush()
        response = bytearray()
        deadline = time.monotonic() + 130
        while time.monotonic() < deadline and len(response) <= 32 * 1024**2:
            if not select.select([self.process.stdout], [], [], min(1, max(0, deadline - time.monotonic())))[0]:
                continue
            chunk = self.process.stdout.read(65536)
            if not chunk:
                break
            response.extend(chunk)
            if response.endswith(b"\n"):
                try:
                    return json.loads(response)
                except ValueError as error:
                    raise ArchiveError("database verification returned invalid data") from error
        raise ArchiveError("database verification exceeded its time or size limit")

    def dump(self, path):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            run(self.command("pg_dump") + ["--format=custom", "--snapshot=" + self.snapshot, "--lock-wait-timeout=10s"],
                stdout=output, timeout=540)

    def __exit__(self, *_):
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    self.process.stdin.write(b"ROLLBACK;\n\\q\n")
                    self.process.stdin.close()
                    self.process.wait(timeout=5)
                except (OSError, subprocess.SubprocessError):
                    self.process.kill()
                    self.process.wait()
            self.process.stdout.close()
            if not self.process.stdin.closed:
                self.process.stdin.close()


def inventory(snapshot):
    value = {}
    queries = {
        "installation": "SELECT product_major,wire_major FROM peerward_installation",
        "migrations": "SELECT version,encode(checksum,'hex') AS checksum FROM peerward_schema_migrations ORDER BY version",
        "meshes": "SELECT id,lifecycle FROM meshes ORDER BY id",
        "authorities": "SELECT id,mesh_id,lifecycle,encode(public_key,'hex') AS public_key,encode(certificate,'hex') AS certificate FROM mesh_authorities ORDER BY id",
        "hosts": "SELECT id,encode(certificate_sha256,'hex') AS certificate_sha256 FROM relay_hosts ORDER BY id",
        "assignments": "SELECT host_id,mesh_id,desired,state,revision,applied_revision,encode(public_key,'hex') AS public_key FROM relay_host_assignments ORDER BY host_id,mesh_id",
        "sequences": "SELECT sequencename,last_value FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename",
    }
    for name, sql in queries.items():
        value[name] = snapshot.query("SELECT COALESCE(json_agg(row_to_json(r)), '[]') FROM (" + sql + ") r")
    tables = snapshot.query("SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public'")
    if len(tables) > 512:
        raise ArchiveError("database table inventory exceeds supported bounds")
    value["counts"] = {}
    for table in tables:
        if re.fullmatch(r"[a-z][a-z0-9_]{0,62}", table) is None:
            raise ArchiveError("unexpected database table name")
        value["counts"][table] = snapshot.query('SELECT to_json(count(*)) FROM public."' + table + '"')
    return value


def compatible(value):
    if value["installation"] != [{"product_major": 1, "wire_major": 5}]:
        raise ArchiveError("database is not a fresh Wire 5 installation")
    expected = [{"version": int(file.name[:4]), "checksum": hashlib.sha256(file.read_bytes()).hexdigest()}
                for file in sorted((ROOT / "crates/peerward-store/migrations").glob("[0-9][0-9][0-9][0-9]_*.sql"))]
    if value["migrations"] != expected:
        raise ArchiveError("database migration chain differs from this maintenance release")


def public_key(seed, algorithm):
    if len(seed) != 32:
        raise ArchiveError("invalid online private key length")
    oid = "70" if algorithm == "ed25519" else "6e"
    der = bytes.fromhex("302e020100300506032b65" + oid + "04220420") + seed
    result = run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=der)
    if len(result) != 44:
        raise ArchiveError("invalid online public key")
    return result[-32:].hex()


def verify_material(value, control, relays):
    """Compare actual online keys/certificates to the very same database snapshot."""
    compatible(value)
    certificate_public = run(["openssl", "x509", "-pubkey", "-noout"], input=read_private(control / "tls.pem"))
    key_public = run(["openssl", "pkey", "-pubout"], input=read_private(control / "tls.key"))
    if certificate_public != key_public:
        raise ArchiveError("Control certificate and private key differ")
    if any(m["lifecycle"] in ("creating", "deleting") for m in value["meshes"]):
        raise ArchiveError("finish Mesh creation or deletion before a complete installation backup")
    hosts = {row["id"]: row for row in value["hosts"]}
    if set(hosts) != set(relays):
        raise ArchiveError("complete backup requires every registered Relay host's local online inventory")
    for host_id, path in relays.items():
        certificate = run(["openssl", "x509", "-inform", "PEM", "-outform", "DER"], input=read_private(path / "tls.pem"))
        if hashlib.sha256(certificate).hexdigest() != hosts[host_id]["certificate_sha256"]:
            raise ArchiveError("Relay host certificate differs from the database")
        public = run(["openssl", "x509", "-pubkey", "-noout"], input=read_private(path / "tls.pem"))
        private_public = run(["openssl", "pkey", "-pubout"], input=read_private(path / "tls.key"))
        if public != private_public:
            raise ArchiveError("Relay host certificate and private key differ")
    authorities = {row["id"]: row for row in value["authorities"]}
    roots, covered = {}, set()
    for mesh in value["meshes"]:
        if mesh["lifecycle"] != "active":
            continue
        bundle = json.loads(read_private(control / "meshes" / mesh["id"] / "issuer.json", 65536))
        if bytes(bundle["recovery"]) != read_private(control / "recovery" / (mesh["id"] + ".recovery")):
            raise ArchiveError("online issuer and encrypted Root recovery package differ")
        root = bundle["issuer"]["root_public_key"]
        if re.fullmatch(r"[0-9a-f]{64}", root) is None:
            raise ArchiveError("invalid Root public key")
        roots[mesh["id"]] = root
        for issuer in [bundle["issuer"], *bundle.get("additional_issuers", [])]:
            authority = authorities.get(issuer["authority_id"])
            if authority is None or issuer["mesh_id"] != mesh["id"] or authority["mesh_id"] != mesh["id"] or issuer["root_public_key"] != root:
                raise ArchiveError("online issuer has no matching database authority")
            if public_key(bytes.fromhex(issuer["authority_private_key"]), "ed25519") != authority["public_key"]:
                raise ArchiveError("online Authority key differs from the database")
            if base64.urlsafe_b64decode(issuer["authority_certificate"] + "==").hex() != authority["certificate"]:
                raise ArchiveError("online Authority certificate differs from the database")
            for key, algorithm in [("directory_private_key", "ed25519"), ("service_private_key", "ed25519"), ("audit_private_key", "x25519")]:
                public_key(bytes.fromhex(issuer[key]), algorithm)
            covered.add(authority["id"])
    if any(row["mesh_id"] in roots and row["lifecycle"] in ("active", "staged", "overlap") and row["id"] not in covered for row in authorities.values()):
        raise ArchiveError("a current Authority signing key is missing from the backup inventory")
    for assignment in value["assignments"]:
        if assignment["desired"] == "removed":
            if assignment["state"] != "removed":
                raise ArchiveError("finish Relay key removal before backup")
            continue
        path = relays[assignment["host_id"]] / "meshes" / assignment["mesh_id"]
        if assignment["applied_revision"] != assignment["revision"] or assignment["state"] not in ("ready", "draining", "suspended"):
            raise ArchiveError("Relay assignment has not reached a stable applied revision")
        if public_key(read_private(path / "noise.key", 32), "x25519") != assignment["public_key"]:
            raise ArchiveError("Relay Noise key differs from the database")
        if read_private(path / "root.pub", 32).hex() != roots.get(assignment["mesh_id"]):
            raise ArchiveError("Relay Root trust differs from the Control issuer")
        if (path / "terminated.bin").exists():
            raise ArchiveError("live assignment contains a terminal Mesh record")
    return {"meshes": len(roots), "relay_hosts": len(hosts), "authorities": len(covered)}
