"""Bounded echo of actual overlay UDP payloads; runs inside the isolated Linux peer."""
import json
from pathlib import Path
import socket
import sys

output = Path("/evidence/linux-echo.json")
counts = {"datagrams": 0, "bytes": 0, "full_size_datagrams": 0}
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
    stream.bind((sys.argv[1], 24445))
    output.write_text(json.dumps(counts))
    while counts["datagrams"] < 10000:
        data, source = stream.recvfrom(2048)
        if len(data) != 1200 or not data.startswith(b"peerward-tun-probe:"):
            continue
        stream.sendto(data, source)
        counts["datagrams"] += 1
        counts["full_size_datagrams"] += 1
        counts["bytes"] += len(data)
        temporary = output.with_suffix(".tmp")
        temporary.write_text(json.dumps(counts))
        temporary.replace(output)
