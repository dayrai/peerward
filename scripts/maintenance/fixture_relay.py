"""A second real host certificate for the disposable installation backup gate."""
import hashlib
import json
from pathlib import Path
import uuid
from common import run


def prepare(state):
    directory = Path(state) / "relay-two"
    directory.mkdir(mode=0o700)
    host_id = str(uuid.uuid4())
    original = json.loads((state / "installation.json").read_text())["host_id"]
    run(["openssl", "req", "-new", "-newkey", "ed25519", "-nodes", "-keyout", directory / "tls.key",
         "-out", directory / "tls.csr", "-subj", "/CN=" + host_id])
    extension = directory / "tls.ext"
    extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
    run(["openssl", "x509", "-req", "-in", directory / "tls.csr", "-CA", state / "offline/host-ca.pem",
         "-CAkey", state / "offline/host-ca.key", "-set_serial", str(uuid.uuid4().int), "-out", directory / "tls.pem",
         "-days", "1", "-extfile", extension])
    (directory / "ca.pem").write_bytes((state / "relay/ca.pem").read_bytes())
    (directory / "relay.toml").write_text((state / "relay/relay.toml").read_text().replace(original, host_id))
    (directory / "meshes").mkdir(mode=0o700)
    (directory / "tls.csr").unlink()
    extension.unlink()
    certificate = run(["openssl", "x509", "-in", directory / "tls.pem", "-outform", "DER"])
    fingerprint = hashlib.sha256(certificate).hexdigest()
    with (state / "control/dynamic.toml").open("a") as stream:
        stream.write(f'\n[[hosts]]\nid = "{host_id}"\nname = "second-backup-relay"\ncertificate_sha256 = "{fingerprint}"\n'
                     'peer_endpoints = ["tcp://relay-two:7777"]\nbackbone_endpoints = ["tcp://relay-two:7778"]\nis_default = false\n')
    return directory, host_id
