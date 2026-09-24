#!/usr/bin/env python3
"""Run an external two-Relay lab driver and write an unverified evidence candidate."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tempfile
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"[0-9a-f]{64}")
SCENARIOS = {
    "connection_establishment",
    "steady_forwarding",
    "reconnect_storm",
    "relay_failure",
    "postgresql_failure_recovery",
    "resource_bounds",
    "no_plaintext",
}
METRICS = {
    "latency_ms",
    "throughput_packets_per_second",
    "failed_operations",
    "cpu_percent",
    "ram_bytes",
    "relay_ingress_bytes_per_second",
    "relay_egress_bytes_per_second",
    "postgresql_tps",
    "postgresql_wal_bytes",
    "recovery_seconds",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact(value: object, keys: set[str], context: str) -> dict:
    require(isinstance(value, dict), f"{context} must be an object")
    require(set(value) == keys, f"{context} fields differ")
    return value


def number(value: object, context: str) -> float:
    require(not isinstance(value, bool) and isinstance(value, (int, float)), f"{context} must be numeric")
    result = float(value)
    require(0 <= result < float("inf"), f"{context} must be non-negative and finite")
    return result


def timestamp(value: object, context: str) -> datetime.datetime:
    require(isinstance(value, str) and value.endswith("Z"), f"{context} must be UTC RFC3339")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{context} must be UTC RFC3339") from error
    require(parsed.tzinfo == datetime.timezone.utc, f"{context} must be UTC RFC3339")
    return parsed


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def validate_raw(
    raw: object,
    version: str,
    mode: str,
    duration: int,
    tier: int,
    commit: str,
    artifact_set: str,
) -> dict:
    document = exact(
        raw,
        {
            "schema_version", "mode", "scope", "tier", "evidence_binding",
            "started_at", "finished_at", "environment", "tool_versions",
            "relay_identities", "traffic", "scenarios", "metrics", "artifacts",
        },
        "driver result",
    )
    require(document["schema_version"] == 1, "driver schema_version must be 1")
    require(document["mode"] == mode, "driver result mode differs from the requested mode")
    require(document["scope"] == "end_to_end", "driver result must declare end_to_end scope")
    require(document["tier"] == tier, "driver result tier differs from the requested tier")
    binding = exact(document["evidence_binding"], {"commit_sha", "artifact_set_sha256"}, "evidence_binding")
    require(binding["commit_sha"] == commit, "driver tested a different commit")
    require(binding["artifact_set_sha256"] == artifact_set, "driver tested a different artifact set")
    started = timestamp(document["started_at"], "started_at")
    finished = timestamp(document["finished_at"], "finished_at")
    require(finished > started, "finished_at must be after started_at")
    environment = exact(
        document["environment"],
        {"hardware", "kernel", "peerward_version", "postgresql_version"},
        "environment",
    )
    require(environment["peerward_version"] == version, "driver tested a different Peerward version")
    require(all(isinstance(value, str) and value.strip() for value in environment.values()), "environment values must be non-empty")
    tools = document["tool_versions"]
    require(isinstance(tools, dict) and tools, "tool_versions must be non-empty")
    require(all(isinstance(value, str) and value.strip() for value in tools.values()), "tool versions must be non-empty")
    identities = document["relay_identities"]
    require(isinstance(identities, list) and len(identities) >= 2, "at least two Relay identities are required")
    require(all(isinstance(value, str) and value.strip() for value in identities), "Relay identities must be non-empty strings")
    require(len(set(identities)) == len(identities), "Relay identities must be distinct")
    traffic = exact(
        document["traffic"],
        {"duration_seconds", "model", "concurrent_rate", "relay_packet_ratio"},
        "traffic",
    )
    require(
        not isinstance(traffic["duration_seconds"], bool)
        and isinstance(traffic["duration_seconds"], int),
        "driver duration must be an integer",
    )
    require(traffic["duration_seconds"] >= duration, "driver duration is shorter than requested")
    require(
        (finished - started).total_seconds() >= traffic["duration_seconds"],
        "driver timestamps are shorter than the declared duration",
    )
    require(isinstance(traffic["model"], str) and traffic["model"].strip(), "traffic model is required")
    number(traffic["concurrent_rate"], "concurrent rate")
    require(number(traffic["relay_packet_ratio"], "Relay packet ratio") <= 1, "Relay packet ratio exceeds one")
    scenarios = exact(document["scenarios"], SCENARIOS, "scenarios")
    require(all(value == "passed" for value in scenarios.values()), "all lab scenarios must pass")
    metrics = exact(document["metrics"], METRICS, "metrics")
    latency = exact(metrics["latency_ms"], {"p50", "p95", "p99"}, "latency")
    percentiles = [number(latency[name], f"latency {name}") for name in ("p50", "p95", "p99")]
    require(percentiles == sorted(percentiles), "latency percentiles are not monotonic")
    for name, value in metrics.items():
        if name != "latency_ms":
            number(value, name)
    artifacts = document["artifacts"]
    require(isinstance(artifacts, list) and artifacts, "driver artifacts are required")
    names = set()
    for artifact in artifacts:
        item = exact(artifact, {"name", "sha256"}, "artifact")
        require(isinstance(item["name"], str), "artifact name must be a string")
        require(pathlib.PurePath(item["name"]).name == item["name"], "artifact name must be a basename")
        require(item["name"] not in names, "artifact names must be unique")
        names.add(item["name"])
        require(isinstance(item["sha256"], str) and SHA256.fullmatch(item["sha256"]), "artifact digest is invalid")
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("capacity", "soak"))
    parser.add_argument("--driver", type=pathlib.Path, required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--tier", type=int, choices=(100, 1000, 10000), default=100)
    parser.add_argument("--artifact-set-sha256", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    require(arguments.driver.is_file(), "external lab driver is missing")
    require(arguments.duration_seconds > 0, "duration must be positive")
    if arguments.mode == "soak":
        require(arguments.duration_seconds >= 86_400, "soak duration must be at least 24 hours")
    require(SHA256.fullmatch(arguments.artifact_set_sha256) is not None, "artifact set digest is invalid")
    require(not arguments.output.exists(), "candidate output already exists")
    version = tomllib.loads((ROOT / "release.toml").read_text(encoding="utf-8"))[
        "product_version"
    ]
    commit = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="peerward-stability-") as temporary:
        raw_path = pathlib.Path(temporary) / "driver-result.json"
        subprocess.run(
            [
                str(arguments.driver),
                "--mode", arguments.mode,
                "--duration-seconds", str(arguments.duration_seconds),
                "--tier", str(arguments.tier),
                "--commit-sha", commit,
                "--artifact-set-sha256", arguments.artifact_set_sha256,
                "--output", str(raw_path),
            ],
            check=True,
        )
        after = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        require(after == commit, "repository commit changed while the lab was running")
        raw = validate_raw(
            json.loads(raw_path.read_text(encoding="utf-8")),
            version,
            arguments.mode,
            arguments.duration_seconds,
            arguments.tier,
            commit,
            arguments.artifact_set_sha256,
        )
        copies = []
        for artifact in raw["artifacts"]:
            source = raw_path.parent / artifact["name"]
            require(source.is_file() and not source.is_symlink(), f"driver artifact is missing or unsafe: {artifact['name']}")
            require(digest(source) == artifact["sha256"], f"driver artifact digest mismatch: {artifact['name']}")
            destination = arguments.output.parent / artifact["name"]
            require(destination.resolve() != arguments.output.resolve(), "driver artifact collides with candidate report")
            require(not destination.exists(), f"driver artifact destination already exists: {artifact['name']}")
            copies.append((source, destination))
        for source, destination in copies:
            shutil.copy2(source, destination)
    common = {
        "schema_version": 1,
        "gate": "capacity" if arguments.mode == "capacity" else "dual_relay_soak_24h",
        "status": "unverified",
        "evidence_binding": {"commit_sha": commit, "artifact_set_sha256": arguments.artifact_set_sha256},
        "started_at": raw["started_at"],
        "finished_at": raw["finished_at"],
        "environment": raw["environment"] | {"relay_nodes": len(raw["relay_identities"])},
        "tool_versions": raw["tool_versions"],
        "artifacts": raw["artifacts"],
    }
    if arguments.mode == "capacity":
        report = common | {
            "scope": "end_to_end",
            "tier": arguments.tier,
            "traffic": raw["traffic"],
            "scenarios": {name: raw["scenarios"][name] for name in (
                "connection_establishment", "steady_forwarding", "reconnect_storm",
                "relay_failure", "postgresql_failure_recovery",
            )},
            "metrics": raw["metrics"],
            "result": {"status": "unverified"},
        }
    else:
        metrics = raw["metrics"]
        report = common | {
            "result": {
                "relay_identities": raw["relay_identities"],
                "duration_seconds": raw["traffic"]["duration_seconds"],
                "scenarios": {
                    "steady_forwarding": raw["scenarios"]["steady_forwarding"],
                    "relay_failure": raw["scenarios"]["relay_failure"],
                    "postgresql_blackhole_recovery": raw["scenarios"]["postgresql_failure_recovery"],
                    "resource_bounds": raw["scenarios"]["resource_bounds"],
                    "no_plaintext": raw["scenarios"]["no_plaintext"],
                },
                "metrics": {
                    "failed_operations": metrics["failed_operations"],
                    "peak_cpu_percent": metrics["cpu_percent"],
                    "peak_ram_bytes": metrics["ram_bytes"],
                    "relay_bytes": (metrics["relay_ingress_bytes_per_second"] + metrics["relay_egress_bytes_per_second"]) * raw["traffic"]["duration_seconds"],
                    "recovery_seconds": metrics["recovery_seconds"],
                },
            }
        }
    arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote unverified {arguments.mode} candidate; independent review and signing remain required")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"stability lab failed: {error}") from error
