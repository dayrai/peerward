#!/usr/bin/env python3
import json
import pathlib
import subprocess
import tempfile
import unittest
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]


class StabilityLabTests(unittest.TestCase):
    def run_candidate(
        self,
        relay_identities: list[str],
        duration: int = 60,
        *,
        scope: str = "end_to_end",
        reported_tier: int = 100,
        reported_artifact_set: str = "b" * 64,
        finished_at: str = "2026-01-01T00:01:00Z",
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            driver = directory / "driver.py"
            commit = subprocess.run(
                ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            result = {
                "schema_version": 1,
                "mode": "capacity",
                "scope": scope,
                "tier": reported_tier,
                "evidence_binding": {
                    "commit_sha": commit,
                    "artifact_set_sha256": reported_artifact_set,
                },
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": finished_at,
                "environment": {
                    "hardware": "fixed lab",
                    "kernel": "test kernel",
                    "peerward_version": tomllib.loads((ROOT / "release.toml").read_text())["product_version"],
                    "postgresql_version": "18",
                },
                "tool_versions": {"driver": "1"},
                "relay_identities": relay_identities,
                "traffic": {
                    "duration_seconds": duration,
                    "model": "test traffic",
                    "concurrent_rate": 1,
                    "relay_packet_ratio": 0.5,
                },
                "scenarios": {
                    "connection_establishment": "passed",
                    "steady_forwarding": "passed",
                    "reconnect_storm": "passed",
                    "relay_failure": "passed",
                    "postgresql_failure_recovery": "passed",
                    "resource_bounds": "passed",
                    "no_plaintext": "passed",
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
                "artifacts": [{"name": "raw-metrics.json", "sha256": "0" * 64}],
            }
            driver.write_text(
                "#!/usr/bin/env python3\n"
                "import hashlib, json, pathlib, sys\n"
                f"document = {result!r}\n"
                "output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])\n"
                "body = b'test raw metrics\\n'\n"
                "attachment = output.parent / 'raw-metrics.json'\n"
                "attachment.write_bytes(body)\n"
                "document['artifacts'][0]['sha256'] = hashlib.sha256(body).hexdigest()\n"
                "output.write_text(json.dumps(document))\n",
                encoding="utf-8",
            )
            driver.chmod(0o700)
            output = directory / "candidate.json"
            completed = subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts/run-linux-stability-lab.py"),
                    "capacity",
                    "--driver",
                    str(driver),
                    "--duration-seconds",
                    str(duration),
                    "--tier",
                    "100",
                    "--artifact-set-sha256",
                    "b" * 64,
                    "--output",
                    str(output),
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            document = json.loads(output.read_text()) if output.exists() else None
            attachment_copied = (directory / "raw-metrics.json").is_file()
            return completed, document, attachment_copied

    def test_complete_driver_result_stays_unverified_until_review_and_signature(self):
        completed, document, attachment_copied = self.run_candidate(["relay-a", "relay-b"])
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertEqual(document["status"], "unverified")
        self.assertEqual(document["scope"], "end_to_end")
        self.assertEqual(document["environment"]["relay_nodes"], 2)
        self.assertTrue(attachment_copied)

    def test_duplicate_relay_identity_is_rejected(self):
        completed, document, attachment_copied = self.run_candidate(["relay-a", "relay-a"])
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(document)
        self.assertFalse(attachment_copied)
        self.assertIn("Relay identities must be distinct", completed.stdout)

    def test_component_scope_cannot_be_promoted_to_end_to_end(self):
        completed, document, attachment_copied = self.run_candidate(
            ["relay-a", "relay-b"], scope="noise_component"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(document)
        self.assertFalse(attachment_copied)
        self.assertIn("must declare end_to_end scope", completed.stdout)

    def test_driver_cannot_substitute_tier(self):
        completed, document, attachment_copied = self.run_candidate(
            ["relay-a", "relay-b"],
            reported_tier=1000,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(document)
        self.assertFalse(attachment_copied)
        self.assertIn("tier differs", completed.stdout)

    def test_driver_cannot_substitute_artifact_set(self):
        completed, document, attachment_copied = self.run_candidate(
            ["relay-a", "relay-b"], reported_artifact_set="c" * 64
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(document)
        self.assertFalse(attachment_copied)
        self.assertIn("different artifact set", completed.stdout)

    def test_declared_duration_must_fit_observed_timestamps(self):
        completed, document, attachment_copied = self.run_candidate(
            ["relay-a", "relay-b"], duration=61
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(document)
        self.assertFalse(attachment_copied)
        self.assertIn("timestamps are shorter", completed.stdout)


if __name__ == "__main__":
    unittest.main()
