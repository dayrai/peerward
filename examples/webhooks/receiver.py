#!/usr/bin/env python3
"""Verify Peerward notifications and atomically enqueue each event once in SQLite.

Bind loopback behind an operator-managed HTTPS reverse proxy. The receiver does
not execute scripts or apply network configuration. A separate local consumer
can process the durable inbox in its own transaction.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from uuid import UUID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"peerward/webhook-notification/v1\0"
LIMIT = 16 * 1024


def unique_object(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = entry
    return value


def uuid4(value):
    identifier = UUID(value)
    if identifier.version != 4 or str(identifier) != value:
        raise ValueError("invalid identity")
    return value


def verify(body, signature, key, mesh, webhook, now):
    if not 1 <= len(body) <= LIMIT or not signature.startswith("ed25519="):
        raise ValueError("invalid envelope")
    encoded = signature.removeprefix("ed25519=")
    if len(encoded) != 86 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in encoded):
        raise ValueError("invalid signature")
    key.verify(base64.urlsafe_b64decode(encoded + "=="), DOMAIN + body)
    notice = json.loads(body, object_pairs_hook=unique_object)
    if set(notice) != {"version", "mesh_id", "webhook_id", "delivery_id", "attempt", "sent_at", "event"}:
        raise ValueError("unexpected fields")
    if type(notice["version"]) is not int or notice["version"] != 1 or notice["mesh_id"] != mesh or notice["webhook_id"] != webhook:
        raise ValueError("unexpected authority")
    if type(notice["sent_at"]) is not int or abs(now - notice["sent_at"]) > 300:
        raise ValueError("expired notification")
    if type(notice["attempt"]) is not int or not 1 <= notice["attempt"] <= 10:
        raise ValueError("invalid attempt")
    uuid4(notice["delivery_id"])
    event = notice["event"]
    if set(event) != {"id", "sequence", "occurred_at", "kind", "resource_kind", "resource_id"}:
        raise ValueError("unexpected event")
    uuid4(event["id"])
    if event["resource_id"] is not None:
        uuid4(event["resource_id"])
    if type(event["sequence"]) is not int or event["sequence"] < 1 or type(event["occurred_at"]) is not int or not 0 <= event["occurred_at"] <= notice["sent_at"]:
        raise ValueError("invalid event time or sequence")
    for name in (event["kind"], event["resource_kind"]):
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in name):
            raise ValueError("invalid event name")
    return notice


class Inbox:
    def __init__(self, database):
        self.connection = sqlite3.connect(database, timeout=5)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("CREATE TABLE IF NOT EXISTS inbox (delivery_id TEXT PRIMARY KEY, event_digest TEXT NOT NULL, event_json TEXT NOT NULL, received_at INTEGER NOT NULL, processed INTEGER NOT NULL DEFAULT 0)")
        self.connection.commit()

    def accept(self, notice):
        # Attempt/time change across retries; the authenticated original event does not.
        event = json.dumps({"mesh_id": notice["mesh_id"], "webhook_id": notice["webhook_id"], "event": notice["event"]}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(event.encode()).hexdigest()
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            prior = self.connection.execute("SELECT event_digest FROM inbox WHERE delivery_id=?", (notice["delivery_id"],)).fetchone()
            if prior and prior[0] != digest:
                raise ValueError("delivery identity reused")
            self.connection.execute("INSERT OR IGNORE INTO inbox(delivery_id,event_digest,event_json,received_at) VALUES(?,?,?,?)", (notice["delivery_id"], digest, event, int(time.time())))
        # Returning before the commit would acknowledge an event that could be lost.


def handler_type(inbox, key, mesh, webhook):
    class Receiver(BaseHTTPRequestHandler):
        timeout = 5
        def log_message(self, *_):
            pass

        def do_POST(self):
            status = 400
            try:
                lengths = self.headers.get_all("content-length") or []
                signatures = self.headers.get_all("peerward-signature") or []
                if self.path != "/peerward" or len(lengths) != 1 or len(signatures) != 1 or self.headers.get("transfer-encoding"):
                    raise ValueError("invalid request")
                size = int(lengths[0])
                if not 1 <= size <= LIMIT:
                    raise ValueError("invalid body size")
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError("incomplete body")
                notice = verify(body, signatures[0], key, mesh, webhook, int(time.time()))
                inbox.accept(notice)
                status = 204
            except (ValueError, TypeError, KeyError, InvalidSignature, UnicodeDecodeError):
                status = 400
            except (sqlite3.Error, OSError):
                status = 503
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
    return Receiver


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mesh", required=True, type=uuid4)
    parser.add_argument("--webhook", required=True, type=uuid4)
    parser.add_argument("--public-key", required=True, help="pinned 32-byte Ed25519 public key in hex")
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()
    os.umask(0o077)
    if args.database.is_symlink() or args.database.parent.resolve() != args.database.parent.absolute():
        parser.error("use an app-owned database path without symlinks")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(args.public_key))
    inbox = Inbox(args.database)
    server = HTTPServer(("127.0.0.1", args.port), handler_type(inbox, key, args.mesh, args.webhook))
    try:
        server.serve_forever()
    finally:
        server.server_close()
        inbox.connection.close()


if __name__ == "__main__":
    main()
