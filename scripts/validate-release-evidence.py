#!/usr/bin/env python3
"""Validate release evidence and enforce the stable-channel evidence gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tomllib
from datetime import datetime, timezone


GATE_NAMES = (
    "reproducible_build_1",
    "reproducible_build_2",
    "android_physical_matrix",
    "dual_relay_soak_24h",
    "clean_room",
    "wcag_visual",
    "capacity",
    "external_security_audit",
)
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA256 = re.compile(r"[0-9a-f]{64}")
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
COMMON_REPORT_KEYS = {
    "schema_version",
    "gate",
    "status",
    "evidence_binding",
    "started_at",
    "finished_at",
    "environment",
    "tool_versions",
    "artifacts",
    "result",
}


def fail(message: str) -> None:
    raise ValueError(message)


def exact_keys(value: object, expected: set[str], context: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    actual = set(value)
    if actual != expected:
        fail(f"{context} fields differ: missing={sorted(expected-actual)} extra={sorted(actual-expected)}")
    return value


def digest_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_artifact(
    root: pathlib.Path, value: object, context: str, suffix: str
) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        fail(f"{context} must be a non-empty relative path")
    if pathlib.PurePath(value).name != value:
        fail(f"{context} must be a direct child of the evidence directory")
    if not value.startswith("evidence-") or not value.endswith(suffix):
        fail(f"{context} must use an evidence-*{suffix} filename")
    path = (root / value).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"{context} escapes the evidence directory")
    return path


def validate_report_binding(report: pathlib.Path, release: dict, context: str) -> dict:
    try:
        document = json.loads(report.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{context} must be a UTF-8 JSON report: {error}")
    if not isinstance(document, dict):
        fail(f"{context} must be a JSON object")
    binding = exact_keys(
        document.get("evidence_binding"),
        {"commit_sha", "artifact_set_sha256"},
        f"{context}.evidence_binding",
    )
    if binding["commit_sha"] != release["commit_sha"]:
        fail(f"{context} is bound to a different commit")
    if binding["artifact_set_sha256"] != release["artifact_set_sha256"]:
        fail(f"{context} is bound to a different artifact set")
    return document


def finite_number(value: object, context: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{context} must be a number")
    number = float(value)
    if not (number >= 0 and number < float("inf")) or (positive and number <= 0):
        fail(f"{context} must be {'positive' if positive else 'non-negative'} and finite")
    return number


def non_empty_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{context} must be a non-empty string")
    return value


def sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"{context} must be lowercase SHA-256")
    return value


def passed(value: object, context: str) -> None:
    if value != "passed":
        fail(f"{context} must be passed")


def non_empty_string_list(value: object, context: str, *, minimum: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        fail(f"{context} must contain at least {minimum} values")
    for index, item in enumerate(value):
        non_empty_string(item, f"{context}[{index}]")
    if len(set(value)) != len(value):
        fail(f"{context} must not contain duplicates")
    return value


def validate_common_report(
    document: dict,
    release: dict,
    gate: str,
    context: str,
    *,
    status: str = "passed",
    keys: set[str] = COMMON_REPORT_KEYS,
) -> dict:
    report = exact_keys(document, keys, context)
    if report["schema_version"] != 1 or report["gate"] != gate or report["status"] != status:
        fail(f"{context} must be a schema 1 {status} report for {gate}")
    validate_report_binding_document(report, release, context)
    timestamps = []
    for field in ("started_at", "finished_at"):
        value = report[field]
        if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
            fail(f"{context}.{field} must be a UTC timestamp ending in Z")
        timestamps.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
    if timestamps[0].astimezone(timezone.utc) >= timestamps[1].astimezone(timezone.utc):
        fail(f"{context}.finished_at must be after started_at")
    environment = report["environment"]
    if not isinstance(environment, dict) or not environment:
        fail(f"{context}.environment must be a non-empty object")
    for name, value in environment.items():
        non_empty_string(name, f"{context}.environment key")
        if isinstance(value, str):
            non_empty_string(value, f"{context}.environment.{name}")
        elif isinstance(value, bool) or not isinstance(value, (int, float)):
            fail(f"{context}.environment.{name} must be a string or number")
    tools = report["tool_versions"]
    if not isinstance(tools, dict) or not tools:
        fail(f"{context}.tool_versions must be a non-empty object")
    for name, value in tools.items():
        non_empty_string(name, f"{context}.tool_versions key")
        non_empty_string(value, f"{context}.tool_versions.{name}")
    artifacts = report["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        fail(f"{context}.artifacts must be a non-empty array")
    names = set()
    for index, artifact in enumerate(artifacts):
        item = exact_keys(artifact, {"name", "sha256"}, f"{context}.artifacts[{index}]")
        name = non_empty_string(item["name"], f"{context}.artifacts[{index}].name")
        if pathlib.PurePath(name).name != name or name in names:
            fail(f"{context}.artifacts names must be unique basenames")
        names.add(name)
        sha256(item["sha256"], f"{context}.artifacts[{index}].sha256")
    if not isinstance(report["result"], dict):
        fail(f"{context}.result must be an object")
    return report


def validate_report_binding_document(document: dict, release: dict, context: str) -> None:
    binding = exact_keys(
        document.get("evidence_binding"),
        {"commit_sha", "artifact_set_sha256"},
        f"{context}.evidence_binding",
    )
    if binding["commit_sha"] != release["commit_sha"]:
        fail(f"{context} is bound to a different commit")
    if binding["artifact_set_sha256"] != release["artifact_set_sha256"]:
        fail(f"{context} is bound to a different artifact set")


def validate_reproducible_report(document: dict, release: dict, gate: str, context: str) -> None:
    report = validate_common_report(document, release, gate, context)
    result = exact_keys(
        report["result"], {"builder_id", "run_id", "target_artifacts"}, f"{context}.result"
    )
    non_empty_string(result["builder_id"], f"{context}.result.builder_id")
    non_empty_string(result["run_id"], f"{context}.result.run_id")
    targets = result["target_artifacts"]
    if not isinstance(targets, list) or not targets:
        fail(f"{context}.result.target_artifacts must be a non-empty array")
    identities = set()
    for index, target in enumerate(targets):
        item = exact_keys(
            target, {"name", "target", "sha256"}, f"{context}.result.target_artifacts[{index}]"
        )
        identity = (
            non_empty_string(item["name"], f"{context}.result.target_artifacts[{index}].name"),
            non_empty_string(item["target"], f"{context}.result.target_artifacts[{index}].target"),
        )
        if identity in identities:
            fail(f"{context}.result.target_artifacts contains a duplicate")
        identities.add(identity)
        sha256(item["sha256"], f"{context}.result.target_artifacts[{index}].sha256")


def validate_android_report(document: dict, release: dict, context: str) -> None:
    report = validate_common_report(document, release, "android_physical_matrix", context)
    result = exact_keys(report["result"], {"devices", "scenarios"}, f"{context}.result")
    devices = result["devices"]
    if not isinstance(devices, list) or not devices:
        fail(f"{context}.result.devices must be a non-empty array")
    for index, device in enumerate(devices):
        item = exact_keys(
            device,
            {"device_id_hash", "model", "api_level", "security_patch", "network_profiles"},
            f"{context}.result.devices[{index}]",
        )
        sha256(item["device_id_hash"], f"{context}.result.devices[{index}].device_id_hash")
        non_empty_string(item["model"], f"{context}.result.devices[{index}].model")
        if type(item["api_level"]) is not int or not 28 <= item["api_level"] <= 100:
            fail(f"{context}.result.devices[{index}].api_level must be at least 28")
        if not isinstance(item["security_patch"], str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}", item["security_patch"]
        ):
            fail(f"{context}.result.devices[{index}].security_patch must be YYYY-MM-DD")
        non_empty_string_list(
            item["network_profiles"], f"{context}.result.devices[{index}].network_profiles", minimum=2
        )
    scenarios = exact_keys(
        result["scenarios"],
        {
            "real_network", "nat", "doze", "underlay_switch", "force_stop_restart",
            "dns", "direct_relay_fallback", "profile_key_cleanup",
        },
        f"{context}.result.scenarios",
    )
    for name, value in scenarios.items():
        passed(value, f"{context}.result.scenarios.{name}")
    if not any(item["name"].endswith(".apk") for item in report["artifacts"]):
        fail(f"{context}.artifacts must include the tested APK")


def validate_soak_report(document: dict, release: dict, context: str) -> None:
    report = validate_common_report(document, release, "dual_relay_soak_24h", context)
    result = exact_keys(
        report["result"], {"relay_identities", "duration_seconds", "scenarios", "metrics"},
        f"{context}.result",
    )
    non_empty_string_list(result["relay_identities"], f"{context}.result.relay_identities", minimum=2)
    if type(result["duration_seconds"]) is not int or result["duration_seconds"] < 86_400:
        fail(f"{context}.result.duration_seconds must be at least 86400")
    scenarios = exact_keys(
        result["scenarios"],
        {"steady_forwarding", "relay_failure", "postgresql_blackhole_recovery", "resource_bounds", "no_plaintext"},
        f"{context}.result.scenarios",
    )
    for name, value in scenarios.items():
        passed(value, f"{context}.result.scenarios.{name}")
    metrics = exact_keys(
        result["metrics"],
        {"failed_operations", "peak_cpu_percent", "peak_ram_bytes", "relay_bytes", "recovery_seconds"},
        f"{context}.result.metrics",
    )
    for name, value in metrics.items():
        finite_number(value, f"{context}.result.metrics.{name}")


def validate_clean_room_report(document: dict, release: dict, context: str) -> None:
    report = validate_common_report(document, release, "clean_room", context)
    result = exact_keys(
        report["result"],
        {"verifier", "independent", "isolation", "spec_sha256", "toolchain", "build", "tests", "attestation"},
        f"{context}.result",
    )
    non_empty_string(result["verifier"], f"{context}.result.verifier")
    if result["independent"] is not True:
        fail(f"{context}.result.independent must be true")
    for field in ("isolation", "toolchain", "attestation"):
        non_empty_string(result[field], f"{context}.result.{field}")
    sha256(result["spec_sha256"], f"{context}.result.spec_sha256")
    passed(result["build"], f"{context}.result.build")
    passed(result["tests"], f"{context}.result.tests")


def validate_wcag_report(document: dict, release: dict, context: str) -> None:
    report = validate_common_report(document, release, "wcag_visual", context)
    result = exact_keys(
        report["result"],
        {"routes", "locales", "themes", "viewports", "automated_violations", "keyboard", "focus", "manual_review"},
        f"{context}.result",
    )
    for field in ("routes", "locales", "themes", "viewports"):
        non_empty_string_list(result[field], f"{context}.result.{field}")
    if type(result["automated_violations"]) is not int or result["automated_violations"] != 0:
        fail(f"{context}.result.automated_violations must be zero")
    for field in ("keyboard", "focus", "manual_review"):
        passed(result[field], f"{context}.result.{field}")
    if not any(item["name"].endswith((".png", ".webp")) for item in report["artifacts"]):
        fail(f"{context}.artifacts must include visual evidence")


def validate_external_audit_report(document: dict, release: dict, context: str) -> None:
    report = validate_common_report(document, release, "external_security_audit", context)
    result = exact_keys(
        report["result"],
        {"auditor", "scope", "findings", "open_blocking_findings", "audit_report_sha256"},
        f"{context}.result",
    )
    non_empty_string(result["auditor"], f"{context}.result.auditor")
    non_empty_string_list(result["scope"], f"{context}.result.scope")
    findings = exact_keys(
        result["findings"], {"critical", "high", "medium", "low", "informational"},
        f"{context}.result.findings",
    )
    for name, value in findings.items():
        if type(value) is not int or value < 0:
            fail(f"{context}.result.findings.{name} must be a non-negative integer")
    if result["open_blocking_findings"] != 0:
        fail(f"{context}.result.open_blocking_findings must be zero")
    sha256(result["audit_report_sha256"], f"{context}.result.audit_report_sha256")


def validate_capacity_report(document: dict, release: dict, context: str) -> None:
    report = validate_common_report(
        document,
        release,
        "capacity",
        context,
        status="verified",
        keys=COMMON_REPORT_KEYS | {"scope", "tier", "traffic", "scenarios", "metrics"},
    )
    if report["scope"] != "end_to_end" or report["tier"] not in {100, 1000, 10000}:
        fail(f"{context} must declare an end_to_end 100, 1000, or 10000 Peer tier")
    result = exact_keys(report["result"], {"status"}, f"{context}.result")
    passed(result["status"], f"{context}.result.status")
    environment = exact_keys(
        report["environment"],
        {"hardware", "kernel", "peerward_version", "relay_nodes", "postgresql_version"},
        f"{context}.environment",
    )
    for name, value in environment.items():
        if name == "relay_nodes":
            if type(value) is not int or value < 2:
                fail(f"{context}.environment.relay_nodes must be an integer of at least two")
        elif not isinstance(value, str) or not value.strip():
            fail(f"{context}.environment.{name} must be non-empty")
    if environment["peerward_version"] != release["version"]:
        fail(f"{context}.environment.peerward_version must match the release")
    traffic = exact_keys(
        report["traffic"],
        {"duration_seconds", "model", "concurrent_rate", "relay_packet_ratio"},
        f"{context}.traffic",
    )
    if type(traffic["duration_seconds"]) is not int or traffic["duration_seconds"] <= 0:
        fail(f"{context}.traffic.duration_seconds must be a positive integer")
    if not isinstance(traffic["model"], str) or not traffic["model"].strip():
        fail(f"{context}.traffic.model must be non-empty")
    finite_number(traffic["concurrent_rate"], f"{context}.traffic.concurrent_rate")
    ratio = finite_number(traffic["relay_packet_ratio"], f"{context}.traffic.relay_packet_ratio")
    if ratio > 1:
        fail(f"{context}.traffic.relay_packet_ratio must be within 0..=1")
    scenarios = exact_keys(
        report["scenarios"],
        {
            "connection_establishment", "steady_forwarding", "reconnect_storm",
            "relay_failure", "postgresql_failure_recovery",
        },
        f"{context}.scenarios",
    )
    if any(value != "passed" for value in scenarios.values()):
        fail(f"{context}.scenarios must all be passed")
    metrics = exact_keys(
        report["metrics"],
        {
            "latency_ms", "throughput_packets_per_second", "failed_operations",
            "cpu_percent", "ram_bytes", "relay_ingress_bytes_per_second",
            "relay_egress_bytes_per_second", "postgresql_tps", "postgresql_wal_bytes",
            "recovery_seconds",
        },
        f"{context}.metrics",
    )
    latency = exact_keys(
        metrics["latency_ms"], {"p50", "p95", "p99"}, f"{context}.metrics.latency_ms"
    )
    percentiles = [finite_number(latency[name], f"{context}.metrics.latency_ms.{name}") for name in ("p50", "p95", "p99")]
    if percentiles != sorted(percentiles):
        fail(f"{context}.metrics latency percentiles must be monotonic")
    for name, value in metrics.items():
        if name != "latency_ms":
            finite_number(value, f"{context}.metrics.{name}")


def validate(
    evidence_path: pathlib.Path,
    release_path: pathlib.Path,
    expected_commit: str | None,
    expected_artifact_set: str | None,
    verify_bundles: bool,
) -> list[str]:
    document = exact_keys(
        json.loads(evidence_path.read_text(encoding="utf-8")),
        {"schema_version", "release", "gates"},
        "evidence",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        fail("schema_version must be integer 1")

    release = exact_keys(
        document["release"],
        {"version", "channel", "commit_sha", "artifact_set_sha256"},
        "release",
    )
    if not isinstance(release["version"], str) or not SEMVER.fullmatch(release["version"]):
        fail("release.version is not canonical SemVer")
    if release["channel"] not in {"canary", "stable"}:
        fail("release.channel must be canary or stable")
    if not isinstance(release["commit_sha"], str) or not re.fullmatch(r"[0-9a-f]{40}", release["commit_sha"]):
        fail("release.commit_sha must be a lowercase full Git SHA")
    if not isinstance(release["artifact_set_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", release["artifact_set_sha256"]
    ):
        fail("release.artifact_set_sha256 must be lowercase SHA-256")

    configured = tomllib.loads(release_path.read_text(encoding="utf-8"))
    if release["version"] != configured["product_version"]:
        fail("evidence version does not match release.toml")
    if release["channel"] != configured["channel"]:
        fail("evidence channel does not match release.toml")
    if expected_commit and release["commit_sha"] != expected_commit:
        fail("evidence commit does not match the release commit")
    if expected_artifact_set and release["artifact_set_sha256"] != expected_artifact_set:
        fail("evidence artifact set does not match SHA256SUMS")

    gates = exact_keys(document["gates"], set(GATE_NAMES), "gates")
    missing: list[str] = []
    reports: dict[str, dict] = {}
    must_verify_bundles = verify_bundles or release["channel"] == "stable"
    cosign = shutil.which("cosign") if must_verify_bundles else None
    for name in GATE_NAMES:
        gate = gates[name]
        if not isinstance(gate, dict):
            fail(f"gates.{name} must be an object")
        status = gate.get("status")
        if status == "missing":
            exact_keys(gate, {"status", "reason"}, f"gates.{name}")
            if not isinstance(gate["reason"], str) or not 1 <= len(gate["reason"]) <= 512:
                fail(f"gates.{name}.reason must contain 1..512 characters")
            missing.append(name)
            continue
        if status != "passed":
            fail(f"gates.{name}.status must be passed or missing")
        exact_keys(
            gate,
            {
                "status",
                "report",
                "sha256",
                "cosign_bundle",
                "certificate_identity",
                "certificate_oidc_issuer",
            },
            f"gates.{name}",
        )
        if not isinstance(gate["certificate_identity"], str) or not gate["certificate_identity"]:
            fail(f"gates.{name}.certificate_identity must be non-empty")
        if not isinstance(gate["certificate_oidc_issuer"], str) or not re.fullmatch(
            r"https://[^\s]+", gate["certificate_oidc_issuer"]
        ):
            fail(f"gates.{name}.certificate_oidc_issuer must be an HTTPS URL")
        evidence_root = evidence_path.parent.resolve()
        report = local_artifact(
            evidence_root, gate["report"], f"gates.{name}.report", ".json"
        )
        bundle = local_artifact(
            evidence_root,
            gate["cosign_bundle"],
            f"gates.{name}.cosign_bundle",
            ".bundle",
        )
        if not report.is_file() or not bundle.is_file():
            fail(f"gates.{name} report or cosign bundle is missing")
        if not isinstance(gate["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", gate["sha256"]):
            fail(f"gates.{name}.sha256 must be lowercase SHA-256")
        if digest_file(report) != gate["sha256"]:
            fail(f"gates.{name} report digest mismatch")
        report_document = validate_report_binding(report, release, f"gates.{name}.report")
        context = f"gates.{name}.report"
        if name.startswith("reproducible_build_"):
            validate_reproducible_report(report_document, release, name, context)
        elif name == "android_physical_matrix":
            validate_android_report(report_document, release, context)
        elif name == "dual_relay_soak_24h":
            validate_soak_report(report_document, release, context)
        elif name == "clean_room":
            validate_clean_room_report(report_document, release, context)
        elif name == "wcag_visual":
            validate_wcag_report(report_document, release, context)
        elif name == "capacity":
            validate_capacity_report(report_document, release, f"gates.{name}.report")
        elif name == "external_security_audit":
            validate_external_audit_report(report_document, release, context)
        reports[name] = report_document
        if must_verify_bundles:
            if cosign is None:
                fail("cosign is required to verify evidence bundles")
            completed = subprocess.run(
                [
                    cosign,
                    "verify-blob",
                    "--bundle",
                    str(bundle),
                    "--certificate-identity",
                    gate["certificate_identity"],
                    "--certificate-oidc-issuer",
                    gate["certificate_oidc_issuer"],
                    str(report),
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if completed.returncode:
                fail(f"gates.{name} cosign verification failed: {completed.stdout.strip()}")

    first = reports.get("reproducible_build_1")
    second = reports.get("reproducible_build_2")
    if first is not None and second is not None:
        first_result = first["result"]
        second_result = second["result"]
        if first_result["builder_id"] == second_result["builder_id"]:
            fail("reproducible builds must use distinct builder identities")
        if first_result["run_id"] == second_result["run_id"]:
            fail("reproducible builds must use distinct run identities")
        if first_result["target_artifacts"] != second_result["target_artifacts"]:
            fail("reproducible builds must produce identical target artifact digests")

    if release["channel"] == "stable" and missing:
        fail("stable release is missing evidence: " + ", ".join(missing))
    if release["channel"] == "stable" and "-" in release["version"]:
        fail("stable channel cannot publish a prerelease version")
    return missing


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument("--release", type=pathlib.Path, default=pathlib.Path("release.toml"))
    parser.add_argument("--commit")
    parser.add_argument("--artifact-set-sha256")
    parser.add_argument("--verify-bundles", action="store_true")
    parser.add_argument("--notes", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        missing = validate(
            arguments.evidence,
            arguments.release,
            arguments.commit,
            arguments.artifact_set_sha256,
            arguments.verify_bundles,
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"release evidence rejected: {error}", file=sys.stderr)
        return 1
    if arguments.notes:
        lines = ["## Release evidence"]
        if missing:
            lines.extend(("", "This technical preview does not satisfy these stable-release gates:", ""))
            lines.extend(f"- `{name}`" for name in missing)
        else:
            lines.extend(("", "All required stable-release evidence is present and verified."))
        arguments.notes.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("release evidence valid" + (f"; missing preview gates: {', '.join(missing)}" if missing else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
