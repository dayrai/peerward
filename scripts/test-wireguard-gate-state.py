#!/usr/bin/env python3
"""Regressions for interrupted tests and concurrent Docker auto-removal."""
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from wireguard_gate_state import StageFailure, cleanup_owned_container, evidence_status, finish_report, listener_endpoints, process_identity, record_failure
from wireguard_fixture import freeze_fixture
from android_gate_evidence import apply_diagnostic_intervention
import hashlib


class GateStateTests(unittest.TestCase):
    def test_manual_android_rescue_cannot_be_counted_as_unattended_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {"passed": True}
            apply_diagnostic_intervention(report, root)
            self.assertTrue(report["passed"])
            (root / "diagnostic-intervention.json").write_text(json.dumps({"reason": "foreground rescue"}))
            apply_diagnostic_intervention(report, root)
            self.assertFalse(report["passed"])
            self.assertEqual(report["diagnostic_intervention"]["reason"], "foreground rescue")
            report["error"] = "original timeout"
            apply_diagnostic_intervention(report, root)
            self.assertEqual(report["error"], "original timeout")

    def test_listener_queue_load_and_output_order_do_not_count_as_new_ports(self):
        before = "udp UNCONN 0 0 10.203.0.1:27777 0.0.0.0:*\ntcp LISTEN 0 128 [::]:443 [::]:*\n"
        busy = "tcp LISTEN 3 128 [::]:443 [::]:*\nudp UNCONN 960 0 10.203.0.1:27777 0.0.0.0:*\n"
        self.assertEqual(listener_endpoints(before), listener_endpoints(busy))
        self.assertNotEqual(listener_endpoints(before), listener_endpoints(busy.replace(':27777', ':27778')))
        self.assertNotEqual(listener_endpoints(before), listener_endpoints(before + before.splitlines()[0] + "\n"))
        for malformed in ("", "udp UNCONN 0 0"):
            with self.assertRaises(ValueError):
                listener_endpoints(malformed)

    def test_completed_failed_gate_is_never_reported_as_passed_or_pending(self):
        self.assertEqual(evidence_status({"state": "complete", "passed": False}), "failed")
        self.assertEqual(evidence_status({"state": "running", "passed": False}), "running")
        self.assertEqual(evidence_status({"state": "failed", "passed": True}), "failed")
        self.assertEqual(evidence_status({"state": "complete", "passed": True}), "passed")

    def test_reboot_or_reused_pid_cannot_leave_a_stale_running_verdict(self):
        owner = process_identity()
        report = {"state": "running", "passed": False, "process": owner}
        self.assertEqual(evidence_status(report), "running")
        owner["start_ticks"] = "different-process"
        self.assertEqual(evidence_status(report), "interrupted")
        owner.update(process_identity())
        owner["boot_id"] = "previous-boot"
        self.assertEqual(evidence_status(report), "interrupted")

    def test_pinned_fixture_drift_is_rejected_before_a_trial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pinned = root / "pinned"
            (pinned / "scripts").mkdir(parents=True)
            source = pinned / "scripts/scenario.py"
            source.write_text("original")
            (pinned / "fixture-manifest.json").write_text(json.dumps({
                "scripts/scenario.py": hashlib.sha256(source.read_bytes()).hexdigest()}))
            first = root / "first"
            freeze_fixture(root, first, pinned)
            source.write_text("changed")
            self.assertEqual((first / "scripts/scenario.py").read_text(), "original")
            with self.assertRaisesRegex(ValueError, "pinned fixture input changed"):
                freeze_fixture(root, root / "second", pinned)

    def test_fixture_manifest_cannot_select_root_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture-manifest.json").write_text(json.dumps({".env": "not-read"}))
            with self.assertRaisesRegex(ValueError, "outside the allowed inputs"):
                freeze_fixture(root, root / "copy", root)

    def test_cleanup_never_overwrites_the_scenario_exit(self):
        report = {"passed": False}
        record_failure(report, StageFailure("production TUN scenarios", 137))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verification.json"
            finish_report(report, path, [{"container": "owned", "removed": False}])
            saved = json.loads(path.read_text())
        self.assertEqual(saved["failure"]["exit_code"], 137)
        self.assertIn("production TUN scenarios", saved["error"])
        self.assertEqual(saved["state"], "failed")

    def test_auto_removal_race_waits_for_confirmed_absence(self):
        responses = iter([
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0, '{"Status":"removing"}', ''),
            subprocess.CompletedProcess([], 1, '', 'Error: No such object: owned'),
        ])
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            return next(responses)
        result = cleanup_owned_container("owned", io.StringIO(), run=run, sleep=lambda _: None)
        self.assertTrue(result["removed"])
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(command[-1] == "owned" for command in calls))

    def test_docker_cli_lowercase_absence_is_supported(self):
        responses = iter([
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1, '', 'error: no such object: owned'),
        ])
        result = cleanup_owned_container("owned", io.StringIO(), run=lambda *a, **k: next(responses))
        self.assertTrue(result["removed"])

    def test_unavailable_daemon_is_not_successful_cleanup(self):
        responses = iter([
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 1, '', 'Cannot connect to the Docker daemon'),
        ])
        result = cleanup_owned_container("owned", io.StringIO(), run=lambda *a, **k: next(responses))
        self.assertFalse(result["removed"])
        self.assertIn("cannot verify", result["error"])

    def test_cleanup_has_a_deadline_and_a_failed_verdict(self):
        times = iter([0, 6])
        responses = iter([
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0, '{"Status":"running"}', ''),
        ])
        result = cleanup_owned_container("owned", io.StringIO(), run=lambda *a, **k: next(responses),
                                         clock=lambda: next(times))
        self.assertFalse(result["removed"])
        self.assertIn("deadline", result["error"])


if __name__ == "__main__":
    unittest.main()
