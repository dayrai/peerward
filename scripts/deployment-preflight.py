#!/usr/bin/env python3
"""Fail-closed production preflight for the documented single-node topology."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import shutil
import socket
import stat
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request

MAX_RESPONSE_BYTES = 1024 * 1024


def check(condition: bool, message: str, failures: list[str]) -> None:
    print(("PASS " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"user-agent": "peerward-preflight/1"})
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise RuntimeError("response is too large")
        document = json.loads(body)
        if not isinstance(document, dict):
            raise ValueError("expected a JSON object")
        return document


def private_listener(listener: str) -> bool:
    """Check every resolved address, including bracketed IPv6 listeners."""
    try:
        endpoint = urllib.parse.urlsplit("//" + listener)
        if (not endpoint.hostname or endpoint.port is None
                or not 1 <= endpoint.port <= 65535
                or endpoint.username is not None or endpoint.password is not None
                or endpoint.path or endpoint.query or endpoint.fragment):
            return False
        addresses = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(
                endpoint.hostname, endpoint.port, type=socket.SOCK_STREAM
            )
        }
        return bool(addresses) and all(
            (address.is_loopback or address.is_private)
            and not address.is_unspecified and not address.is_multicast
            for address in addresses
        )
    except (ValueError, OSError):
        return False


def relay_identity_file(config_path: pathlib.Path, config: dict) -> str:
    # RelayHostConfig resolves relative paths against the configuration file.
    key = pathlib.Path(config["private_key_file"])
    return str((config_path.parent / key).resolve())


def secure_file(path: pathlib.Path) -> bool:
    try:
        metadata = path.stat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o077 == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--oidc-issuer", required=True)
    parser.add_argument("--tls-url", required=True)
    parser.add_argument("--relay-config", action="append", type=pathlib.Path, required=True)
    parser.add_argument("--secret", action="append", type=pathlib.Path, required=True)
    parser.add_argument("--offline-root", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--relay-port", action="append", type=int, default=[])
    parser.add_argument("--management-listener", action="append", required=True)
    parser.add_argument("--backup-evidence", type=pathlib.Path, required=True)
    parser.add_argument("--firewall-evidence", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    failures: list[str] = []

    ntp = shutil.which("timedatectl")
    synchronized = False
    if ntp:
        result = subprocess.run(
            [ntp, "show", "--property=NTPSynchronized", "--value"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        synchronized = result.returncode == 0 and result.stdout.strip().lower() == "yes"
    check(synchronized, "system clock is NTP synchronized", failures)

    try:
        issuer = arguments.oidc_issuer.rstrip("/")
        discovery = fetch_json(issuer + "/.well-known/openid-configuration")
        check(discovery.get("issuer", "").rstrip("/") == issuer, "OIDC discovery issuer is exact", failures)
    except Exception as error:
        check(False, f"OIDC discovery is reachable and valid ({error})", failures)
    try:
        parsed_tls = urllib.parse.urlparse(arguments.tls_url)
        check(parsed_tls.scheme == "https", "public ingress uses HTTPS", failures)
        with urllib.request.urlopen(arguments.tls_url, timeout=10) as response:
            check(200 <= response.status < 500, "TLS ingress certificate and route are reachable", failures)
    except Exception as error:
        check(False, f"TLS ingress certificate and route are reachable ({error})", failures)

    psql = shutil.which("psql")
    check(psql is not None, "psql is installed for database preflight", failures)
    if psql:
        result = subprocess.run(
            [psql, arguments.database_url, "-Atqc", "SHOW server_version_num"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        version = result.stdout.strip()
        check(result.returncode == 0, "PostgreSQL is reachable", failures)
        check(version.isdigit() and int(version) >= 180000, "PostgreSQL major version is at least 18", failures)

    for secret in arguments.secret:
        check(secure_file(secret), f"secret is a regular 0600-or-stricter file: {secret}", failures)

    mountpoints = set()
    try:
        for line in pathlib.Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
            fields = line.split()
            mountpoints.add(os.path.realpath(fields[4]))
    except OSError:
        failures.append("cannot inspect mounted filesystems")
    for root in arguments.offline_root:
        resolved = os.path.realpath(root)
        check(resolved not in mountpoints, f"offline Root is not mounted: {root}", failures)

    relay_ids: list[str] = []
    identity_files: list[str] = []
    for config_path in arguments.relay_config:
        try:
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
            check(config.get("config_version") == 2, "Relay uses shared-host configuration version 2", failures)
            relay_ids.append(config["host_id"])
            check(config.get("control_url", "").startswith("https://"), "Relay management uses HTTPS", failures)
            identity_files.append(relay_identity_file(config_path, config))
        except (OSError, KeyError, TypeError, ValueError) as error:
            failures.append(f"cannot parse relay config {config_path}: {error}")
    check(len(relay_ids) == len(set(relay_ids)), "every Relay host ID is unique", failures)
    check(len(identity_files) == len(set(identity_files)), "every Relay uses a distinct private-key file", failures)

    for listener in arguments.management_listener:
        check(private_listener(listener), f"management listener is loopback/private: {listener}", failures)
    for port in arguments.relay_port:
        check(1 <= port <= 65535, f"Relay port is valid: {port}", failures)
    check(secure_file(arguments.backup_evidence), "backup/PITR evidence is protected and present", failures)
    check(secure_file(arguments.firewall_evidence), "firewall review evidence is protected and present", failures)

    if failures:
        print(f"preflight rejected with {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print(f"preflight passed at Unix time {int(time.time())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
