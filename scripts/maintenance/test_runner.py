"""Credential delivery, private temporary output and clock-bound task checks."""
import http.server
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid
import datetime

from archive import ArchiveError
from common import digest, exclusive, read_json, write_json
import backup
from database import Snapshot
import runner


class RunnerBoundaryTests(unittest.TestCase):
    def test_competing_installation_operation_retains_an_unstarted_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = {"installation": directory}
            identifier = str(uuid.uuid4())
            state = {"assigned": {"id": identifier, "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                  "request": {"preview_digest": "a" * 64}},
                     "known": {identifier: {"reported": 0, "started": False}}}
            state_path = Path(directory) / "runner-state.json"
            write_json(state_path, state)
            with exclusive(backup.paths(profile)[0] / "operation.lock"):
                runner.execute_assigned(profile, state, state_path, age="unused")
            persisted = read_json(state_path)
            self.assertFalse(persisted["known"][identifier]["started"])
            self.assertEqual(persisted["assigned"]["id"], identifier)
            self.assertFalse((backup.paths(profile)[1] / (identifier + ".json")).exists())

    def test_plaintext_dump_is_private_even_if_caller_umask_is_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Snapshot("a" * 64, {"user": "peerward", "name": "peerward"})
            snapshot.snapshot = "00000001-1"
            def dump_command(_, *, stdout, **__):
                self.assertEqual(os.fstat(stdout.fileno()).st_mode & 0o777, 0o600)
                stdout.write(b"private database content")
            previous = os.umask(0)
            try:
                with patch("database.run", side_effect=dump_command):
                    snapshot.dump(Path(directory) / "database.dump")
            finally:
                os.umask(previous)

    def test_runner_connection_never_sends_credentials_to_insecure_or_ambiguous_origins(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = {"installation": "private-test"}
            value = {"runner_id": str(uuid.uuid4()), "token": "pw_runner_" + "a" * 44,
                     "profile_digest": digest(profile), "control_url": "http://127.0.0.1:1234"}
            path = Path(directory) / "connection.json"
            write_json(path, value)
            self.assertEqual(runner.connection(path, profile), value)
            for url in ("http://control.example", "http://localhost:1234", "https://user:pass@control.example",
                        "https://control.example/path", "https://control.example/?token=secret", "file:///tmp/control"):
                with self.subTest(url=url):
                    write_json(path, {**value, "control_url": url}, replace=True)
                    with self.assertRaises(ArchiveError):
                        runner.connection(path, profile)

    def test_actual_http_redirect_is_not_followed_with_runner_credential(self):
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append(self.path)
                self.send_response(307)
                self.send_header("Location", "/credential-sink")
                self.end_headers()
            def log_message(self, *_):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(ArchiveError):
                runner.request({"control_url": f"http://127.0.0.1:{server.server_port}",
                                "runner_id": str(uuid.uuid4()), "token": "unit-test-credential"}, {"sequence": 1})
            self.assertEqual(len(seen), 1)
            self.assertNotIn("/credential-sink", seen)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
