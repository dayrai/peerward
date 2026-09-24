"""Private-CA WSS and fixed-target CONNECT for disposable validation backends."""
import json
import selectors
import socket
import socketserver
import subprocess
import threading


def configure(installation, public_host, peer_port, backbone_port, output, use_proxy, use_quic=False, fallback_wss=False, extra_san=None):
    relay = installation / "relay"
    certificate = relay / "wss.pem"
    key = relay / "wss.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "3",
                    "-subj", "/CN=Peerward WSS validation", "-addext", "subjectAltName=IP:" + public_host + (",IP:" + extra_san if extra_san else ""),
                    "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", str(key), "-out", str(certificate)],
                   check=True, capture_output=True)
    key.chmod(0o600)
    ca_pem = certificate.read_text()
    endpoint = f"quic://{public_host}:{peer_port}" if use_quic else f"wss://{public_host}:{peer_port}/peerward"
    dynamic = installation / "control/dynamic.toml"
    text = dynamic.read_text().replace(f"tcp://{public_host}:{peer_port}", endpoint)
    text = text.replace(f"tcp://{public_host}:{backbone_port}", endpoint)
    if fallback_wss:
        if not use_quic or use_proxy:
            raise ValueError("fallback fixture requires QUIC without proxy")
        text = text.replace(json.dumps(endpoint), json.dumps(endpoint) + ', ' + json.dumps(f"wss://{public_host}:{peer_port}/peerward"))
    dynamic.write_text(text)
    config = relay / "relay.toml"
    text = config.read_text().replace(f'peer_address = "{public_host}:{peer_port}"', 'peer_address = "127.0.0.1:0"')
    text = text.replace(f'peer_address = "0.0.0.0:{peer_port}"', 'peer_address = "127.0.0.1:0"')
    # Native TCP binds an unadvertised ephemeral loopback port. WSS is the only
    # signed peer/backbone endpoint; a successful test cannot use a TCP fallback.
    text = text.replace(f'peer_address = "127.0.0.1:{peer_port}"', 'peer_address = "127.0.0.1:0"')
    text += f'\n[relay_transport]\nca_pem = {json.dumps(ca_pem)}\n'
    carrier = 'quic' if use_quic else 'wss'
    text += f'\n[{carrier}]\naddress = "{public_host}:{peer_port}"\ncertificate_file = {json.dumps(str(certificate))}\nprivate_key_file = {json.dumps(str(key))}\n'
    if fallback_wss:
        text += f'\n[wss]\naddress = "{public_host}:{peer_port}"\ncertificate_file = {json.dumps(str(certificate))}\nprivate_key_file = {json.dumps(str(key))}\n'
    config.write_text(text)
    options = {"ca_pem": ca_pem}
    proxy = None
    if use_proxy:
        proxy = ConnectProxy((public_host, 0), (public_host, peer_port), output / "connect-proxy.json")
        options["http_connect_proxy"] = f"tcp://{public_host}:{proxy.server_address[1]}"
    return options, proxy


class ConnectProxy(socketserver.ThreadingTCPServer):
    """At most 16 sockets, one permitted CONNECT target; no open proxy behavior."""
    daemon_threads = True

    def __init__(self, address, target, evidence):
        self.target = target
        self.evidence = evidence
        self.budget = threading.BoundedSemaphore(16)
        self.lock = threading.Lock()
        self.connections = 0
        self.forwarded = 0
        super().__init__(address, ConnectHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def verify_request(self, request, client_address):
        return self.budget.acquire(blocking=False)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.budget.release()

    def stop(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)
        self.evidence.write_text(json.dumps({"connections": self.connections, "forwarded_bytes": self.forwarded}, indent=2))


class ConnectHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            request = bytearray()
            while not request.endswith(b"\r\n\r\n") and len(request) < 8192:
                part = self.request.recv(1)
                if not part:
                    return
                request += part
            authority = "%s:%d" % self.server.target
            expected = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
            if request != expected:
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return
            with socket.create_connection(self.server.target, timeout=5) as upstream, selectors.DefaultSelector() as ready:
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                with self.server.lock:
                    self.server.connections += 1
                ready.register(self.request, selectors.EVENT_READ, upstream)
                ready.register(upstream, selectors.EVENT_READ, self.request)
                while True:
                    for key, _ in ready.select(timeout=5):
                        data = key.fileobj.recv(16384)
                        if not data:
                            return
                        key.data.sendall(data)
                        with self.server.lock:
                            self.server.forwarded += len(data)
        except (OSError, ConnectionError):
            return
