#!/usr/bin/env python3
import copy
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_evidence", ROOT / "scripts/validate-release-evidence.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(
            (ROOT / "release/release-evidence.preview.json").read_text(encoding="utf-8")
        )

    def write(self, directory: pathlib.Path, document: dict) -> pathlib.Path:
        path = directory / "evidence.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def report(self, gate: str, *, status: str = "passed") -> dict:
        return {
            "schema_version": 1,
            "gate": gate,
            "status": status,
            "evidence_binding": {
                "commit_sha": self.document["release"]["commit_sha"],
                "artifact_set_sha256": self.document["release"]["artifact_set_sha256"],
            },
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:01:00Z",
            "environment": {"runner": "isolated-test-runner"},
            "tool_versions": {"python": "3.13"},
            "artifacts": [{"name": "artifact.bin", "sha256": "a" * 64}],
            "result": {},
        }

    def attach(self, directory: pathlib.Path, document: dict, gate: str) -> None:
        report = directory / f"evidence-{gate}.json"
        report.write_text(json.dumps(document), encoding="utf-8")
        bundle = directory / f"evidence-{gate}.bundle"
        bundle.write_text("test-only", encoding="utf-8")
        self.document["gates"][gate] = {
            "status": "passed",
            "report": report.name,
            "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            "cosign_bundle": bundle.name,
            "certificate_identity": "test@example.com",
            "certificate_oidc_issuer": "https://issuer.example",
        }

    def test_checked_in_schemas_are_valid_json(self):
        for name in (
            "release-evidence.schema.json",
            "evidence-report.schema.json",
            "capacity-report.schema.json",
            "stability-driver.schema.json",
        ):
            document = json.loads((ROOT / "release" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_preview_reports_missing_gates(self):
        missing = MODULE.validate(
            ROOT / "release/release-evidence.preview.json",
            ROOT / "release.toml",
            None,
            None,
            False,
        )
        self.assertEqual(set(missing), set(MODULE.GATE_NAMES))

    def test_stable_rejects_any_missing_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            release = directory / "release.toml"
            release.write_text('product_version = "1.0.0"\nchannel = "stable"\n', encoding="utf-8")
            document = copy.deepcopy(self.document)
            document["release"]["version"] = "1.0.0"
            document["release"]["channel"] = "stable"
            with self.assertRaisesRegex(ValueError, "stable release is missing evidence"):
                MODULE.validate(self.write(directory, document), release, None, None, False)

    def test_unknown_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            document = copy.deepcopy(self.document)
            document["surprise"] = True
            with self.assertRaisesRegex(ValueError, "fields differ"):
                MODULE.validate(
                    self.write(pathlib.Path(temporary), document),
                    ROOT / "release.toml",
                    None,
                    None,
                    False,
                )

    def test_commit_binding_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "release commit"):
            MODULE.validate(
                ROOT / "release/release-evidence.preview.json",
                ROOT / "release.toml",
                "1" * 40,
                None,
                False,
            )

    def test_signed_report_must_bind_the_same_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            report = directory / "evidence-clean-room.json"
            report.write_text(json.dumps({
                "evidence_binding": {
                    "commit_sha": "1" * 40,
                    "artifact_set_sha256": self.document["release"]["artifact_set_sha256"],
                },
                "result": {"status": "passed"},
            }), encoding="utf-8")
            (directory / "evidence-clean-room.bundle").write_text("test-only", encoding="utf-8")
            document = copy.deepcopy(self.document)
            document["gates"]["clean_room"] = {
                "status": "passed",
                "report": "evidence-clean-room.json",
                "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                "cosign_bundle": "evidence-clean-room.bundle",
                "certificate_identity": "https://evidence.peerward.invalid/builders/clean-room",
                "certificate_oidc_issuer": "https://issuer.example",
            }
            with self.assertRaisesRegex(ValueError, "different commit"):
                MODULE.validate(self.write(directory, document), ROOT / "release.toml", None, None, False)

    def test_signed_report_must_bind_the_same_artifact_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            report = directory / "evidence-clean-room.json"
            report.write_text(json.dumps({
                "evidence_binding": {
                    "commit_sha": self.document["release"]["commit_sha"],
                    "artifact_set_sha256": "f" * 64,
                },
                "result": {"status": "passed"},
            }), encoding="utf-8")
            (directory / "evidence-clean-room.bundle").write_text("test-only", encoding="utf-8")
            document = copy.deepcopy(self.document)
            document["gates"]["clean_room"] = {
                "status": "passed",
                "report": "evidence-clean-room.json",
                "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                "cosign_bundle": "evidence-clean-room.bundle",
                "certificate_identity": "https://evidence.peerward.invalid/builders/clean-room",
                "certificate_oidc_issuer": "https://issuer.example",
            }
            with self.assertRaisesRegex(ValueError, "different artifact set"):
                MODULE.validate(self.write(directory, document), ROOT / "release.toml", None, None, False)

    def test_evidence_artifact_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            document = copy.deepcopy(self.document)
            document["gates"]["clean_room"] = {
                "status": "passed",
                "report": "../report.json",
                "sha256": "0" * 64,
                "cosign_bundle": "report.bundle",
                "certificate_identity": "test@example.com",
                "certificate_oidc_issuer": "https://issuer.example",
            }
            with self.assertRaisesRegex(ValueError, "direct child of the evidence directory"):
                MODULE.validate(self.write(directory, document), ROOT / "release.toml", None, None, False)

    def test_component_noise_benchmark_cannot_pass_capacity_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            report = directory / "evidence-capacity.json"
            document = self.report("capacity", status="unverified")
            document.update({
                "schema_version": 1,
                "status": "unverified",
                "scope": "noise_component",
                "tier": 10000,
                "environment": {},
                "traffic": {},
                "scenarios": {},
                "metrics": {},
            })
            report.write_text(json.dumps(document), encoding="utf-8")
            (directory / "evidence-capacity.bundle").write_text("test-only", encoding="utf-8")
            document = copy.deepcopy(self.document)
            document["gates"]["capacity"] = {
                "status": "passed",
                "report": report.name,
                "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                "cosign_bundle": "evidence-capacity.bundle",
                "certificate_identity": "test@example.com",
                "certificate_oidc_issuer": "https://issuer.example",
            }
            with self.assertRaisesRegex(ValueError, "schema 1 verified report"):
                MODULE.validate(
                    self.write(directory, document), ROOT / "release.toml", None, None, False
                )

    def test_complete_end_to_end_capacity_report_is_accepted_for_preview_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            report = directory / "evidence-capacity.json"
            document = self.report("capacity", status="verified")
            document.update({
                "scope": "end_to_end",
                "tier": 100,
                "environment": {
                    "hardware": "fixed test hosts",
                    "kernel": "test kernel",
                    "peerward_version": self.document["release"]["version"],
                    "relay_nodes": 2,
                    "postgresql_version": "18",
                },
                "traffic": {
                    "duration_seconds": 60,
                    "model": "test",
                    "concurrent_rate": 1,
                    "relay_packet_ratio": 0.5,
                },
                "scenarios": {
                    "connection_establishment": "passed",
                    "steady_forwarding": "passed",
                    "reconnect_storm": "passed",
                    "relay_failure": "passed",
                    "postgresql_failure_recovery": "passed",
                },
                "metrics": {
                    "latency_ms": {"p50": 1, "p95": 2, "p99": 3},
                    "throughput_packets_per_second": 4,
                    "failed_operations": 0,
                    "cpu_percent": 5,
                    "ram_bytes": 6,
                    "relay_ingress_bytes_per_second": 7,
                    "relay_egress_bytes_per_second": 8,
                    "postgresql_tps": 9,
                    "postgresql_wal_bytes": 10,
                    "recovery_seconds": 11,
                },
                "result": {"status": "passed"},
            })
            report.write_text(json.dumps(document), encoding="utf-8")
            (directory / "evidence-capacity.bundle").write_text("test-only", encoding="utf-8")
            document = copy.deepcopy(self.document)
            document["gates"]["capacity"] = {
                "status": "passed",
                "report": report.name,
                "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                "cosign_bundle": "evidence-capacity.bundle",
                "certificate_identity": "test@example.com",
                "certificate_oidc_issuer": "https://issuer.example",
            }
            missing = MODULE.validate(
                self.write(directory, document), ROOT / "release.toml", None, None, False
            )
            self.assertNotIn("capacity", missing)

    def test_empty_passed_report_cannot_close_a_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            report = self.report("clean_room")
            report["result"] = {"status": "passed"}
            self.attach(directory, report, "clean_room")
            with self.assertRaisesRegex(ValueError, "result.*fields differ"):
                MODULE.validate(
                    self.write(directory, self.document), ROOT / "release.toml", None, None, False
                )

    def test_reproducible_builds_require_distinct_builders_and_identical_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            outputs = [{"name": "peerward.tar.gz", "target": "x86_64-unknown-linux-gnu", "sha256": "b" * 64}]
            first = self.report("reproducible_build_1")
            first["result"] = {
                "builder_id": "builder-a",
                "run_id": "run-a",
                "target_artifacts": outputs,
            }
            second = self.report("reproducible_build_2")
            second["result"] = {
                "builder_id": "builder-a",
                "run_id": "run-b",
                "target_artifacts": copy.deepcopy(outputs),
            }
            self.attach(directory, first, "reproducible_build_1")
            self.attach(directory, second, "reproducible_build_2")
            with self.assertRaisesRegex(ValueError, "distinct builder identities"):
                MODULE.validate(
                    self.write(directory, self.document), ROOT / "release.toml", None, None, False
                )

            second["result"]["builder_id"] = "builder-b"
            second["result"]["target_artifacts"][0]["sha256"] = "c" * 64
            self.attach(directory, second, "reproducible_build_2")
            with self.assertRaisesRegex(ValueError, "identical target artifact digests"):
                MODULE.validate(
                    self.write(directory, self.document), ROOT / "release.toml", None, None, False
                )

    def test_android_physical_report_requires_real_matrix_scenarios(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            report = self.report("android_physical_matrix")
            report["artifacts"] = [{"name": "peerward.apk", "sha256": "d" * 64}]
            report["result"] = {"devices": [], "scenarios": {}}
            self.attach(directory, report, "android_physical_matrix")
            with self.assertRaisesRegex(ValueError, "devices must be a non-empty array"):
                MODULE.validate(
                    self.write(directory, self.document), ROOT / "release.toml", None, None, False
                )


if __name__ == "__main__":
    unittest.main()
