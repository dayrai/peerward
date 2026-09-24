#!/usr/bin/env python3
"""Exercise bounded discovery reads and deployment address/path checks offline."""

import importlib.util
import io
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "preflight", Path(__file__).with_name("deployment-preflight.py")
)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class Response(io.BytesIO):
    status = 200

    def __init__(self, body, headers):
        super().__init__(body)
        self.headers = headers


class PreflightTests(unittest.TestCase):
    def fetch(self, body, headers=None):
        with patch.object(preflight.urllib.request, "urlopen",
                          return_value=Response(body, headers or {})):
            return preflight.fetch_json("https://issuer.example/discovery")

    def test_discovery_object_and_exact_size_boundary(self):
        body = b'{"issuer":"https://issuer.example"}'
        self.assertEqual(self.fetch(body)["issuer"], "https://issuer.example")
        self.assertEqual(self.fetch(b"{}" + b" " * (preflight.MAX_RESPONSE_BYTES - 2)), {})

    def test_oversized_body_with_missing_or_misleading_length(self):
        for headers in [{}, {"content-length": "2"}, {"content-length": "1048577"}]:
            with self.subTest(headers=headers), self.assertRaisesRegex(RuntimeError, "too large"):
                self.fetch(b"{}" + b" " * preflight.MAX_RESPONSE_BYTES, headers)

    def test_non_object_discovery_is_rejected(self):
        for body in [b"null", b"[]", b'"issuer"']:
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "JSON object"):
                self.fetch(body)

    def listener(self, listener, addresses):
        answers = [
            (socket.AF_INET6 if ":" in address else socket.AF_INET,
             socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))
            for address in addresses
        ]
        with patch.object(preflight.socket, "getaddrinfo", return_value=answers):
            return preflight.private_listener(listener)

    def test_ipv4_ipv6_and_private_dns(self):
        for listener, addresses in [
            ("127.0.0.1:8080", ["127.0.0.1"]), ("[::1]:8080", ["::1"]),
            ("control.internal:443", ["10.0.0.1", "fd00::1"]),
        ]:
            with self.subTest(listener=listener):
                self.assertTrue(self.listener(listener, addresses))

    def test_wildcard_public_multicast_or_mixed_dns_is_rejected(self):
        for addresses in [[], ["0.0.0.0"], ["::"], ["224.0.0.1"], ["ff02::1"],
                          ["8.8.8.8"], ["10.0.0.1", "8.8.8.8"]]:
            with self.subTest(addresses=addresses):
                self.assertFalse(self.listener("control.internal:443", addresses))

    def test_malformed_listener_is_rejected(self):
        for listener in ["localhost", "localhost:0", "localhost:65536", "localhost:x",
                         "[::1", "::1:8080", "user@localhost:443", "localhost:443/path"]:
            with self.subTest(listener=listener):
                self.assertFalse(self.listener(listener, ["127.0.0.1"]))
        with patch.object(preflight.socket, "getaddrinfo", side_effect=socket.gaierror()):
            self.assertFalse(preflight.private_listener("missing.internal:443"))

    def test_relative_identity_paths_follow_each_config_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = {"private_key_file": "tls.key"}
            first = preflight.relay_identity_file(root / "a/relay.toml", config)
            second = preflight.relay_identity_file(root / "b/relay.toml", config)
            self.assertEqual(first, str(root / "a/tls.key"))
            self.assertNotEqual(first, second)
            shared = {"private_key_file": "../a/tls.key"}
            self.assertEqual(first, preflight.relay_identity_file(root / "b/relay.toml", shared))
            absolute = {"private_key_file": first}
            self.assertEqual(first, preflight.relay_identity_file(root / "b/relay.toml", absolute))

    def test_shared_runtime_directory_survives_individual_role_restarts(self):
        root = Path(__file__).resolve().parents[1]
        for role in ("console", "control", "peer", "relay"):
            with self.subTest(role=role):
                unit = (root / "deploy/systemd" / f"peerward-{role}.service").read_text()
                self.assertIn("RuntimeDirectory=peerward\n", unit)
                self.assertIn("RuntimeDirectoryPreserve=yes\n", unit)


if __name__ == "__main__":
    unittest.main()
