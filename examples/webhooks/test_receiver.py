import base64
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from receiver import Inbox, verify, DOMAIN


class ReceiverTest(unittest.TestCase):
    def test_shared_rust_python_wire_vector(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        vector = json.loads(Path(__file__).with_name("signature-vector.json").read_text())
        notice = json.loads(vector["body"])
        signature = "ed25519=" + base64.urlsafe_b64encode(bytes(vector["signature"])).rstrip(b"=").decode()
        self.assertEqual(verify(vector["body"].encode(), signature, Ed25519PublicKey.from_public_bytes(bytes(vector["public_key"])),
                                notice["mesh_id"], notice["webhook_id"], vector["now"]), notice)

    def test_authentication_freshness_and_durable_deduplication(self):
        key = Ed25519PrivateKey.generate()
        mesh, webhook, delivery = (str(uuid4()) for _ in range(3))
        notice = dict(version=1, mesh_id=mesh, webhook_id=webhook, delivery_id=delivery, attempt=1, sent_at=1000,
                      event=dict(id=str(uuid4()), sequence=1, occurred_at=900, kind="peer.disabled", resource_kind="peer", resource_id=None))
        def signed(value):
            body = json.dumps(value, separators=(",", ":")).encode()
            signature = "ed25519=" + base64.urlsafe_b64encode(key.sign(DOMAIN + body)).rstrip(b"=").decode()
            return body, signature
        body, signature = signed(notice)
        valid = verify(body, signature, key.public_key(), mesh, webhook, 1100)
        with self.assertRaises(InvalidSignature):
            verify(body + b" ", signature, key.public_key(), mesh, webhook, 1100)
        with self.assertRaises(ValueError):
            verify(body, signature, key.public_key(), str(uuid4()), webhook, 1100)
        for now in (699, 1301):
            with self.assertRaises(ValueError):
                verify(body, signature, key.public_key(), mesh, webhook, now)
        with tempfile.TemporaryDirectory(prefix="peerward-webhook-receiver-") as directory:
            path = Path(directory) / "inbox.sqlite"
            first = Inbox(path)
            first.accept(valid)
            first.connection.close()
            notice.update(attempt=2, sent_at=1100)
            body, signature = signed(notice)
            second = Inbox(path)
            second.accept(verify(body, signature, key.public_key(), mesh, webhook, 1100))
            self.assertEqual(second.connection.execute("SELECT count(*) FROM inbox").fetchone()[0], 1)
            notice["event"]["sequence"] = 2
            with self.assertRaises(ValueError):
                second.accept(notice)
            self.assertEqual(second.connection.execute("SELECT processed FROM inbox").fetchone()[0], 0)
            second.connection.close()


if __name__ == "__main__":
    unittest.main()
