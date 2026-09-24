#!/usr/bin/env python3
"""Bounded TCP echo and public WireGuard message counting inside the test netns."""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import socket
import struct
import time


def exact(stream, count):
    chunks = bytearray()
    while len(chunks) < count:
        part = stream.recv(count - len(chunks))
        if not part:
            raise EOFError("TCP connection closed before the complete record")
        chunks.extend(part)
    return bytes(chunks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["server", "client", "observe"])
    parser.add_argument("--address")
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--stop", type=Path, required=True)
    args = parser.parse_args()
    if args.role == "observe":
        observed = {1: set(), 2: set()}
        counts = {"unique_initiations": 0, "unique_responses": 0, "transport_packets": 0,
                  "ipv6_transport_packets": 0, "outer_fragments": 0, "ipv4_without_df": 0}
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as wire:
            wire.bind(("underlay", 0))
            wire.settimeout(0.2)
            while not args.stop.exists():
                try:
                    packet = wire.recv(65535)
                except socket.timeout:
                    continue
                if len(packet) < 48:
                    continue
                version = packet[0] >> 4
                if (version == 4 and int.from_bytes(packet[6:8], "big") & 0x3fff) or (version == 6 and packet[6] == 44):
                    counts["outer_fragments"] += 1
                if version == 4 and packet[9] == 17:
                    header = (packet[0] & 15) * 4
                elif version == 6 and packet[6] == 17:
                    header = 40
                else:
                    continue
                payload = packet[header + 8:]
                if len(payload) < 4:
                    continue
                kind = int.from_bytes(payload[:4], "little")
                if kind in observed and len(payload) == {1: 148, 2: 92}[kind]:
                    if len(observed[kind]) < 4096:
                        observed[kind].add(hashlib.sha256(payload).hexdigest())
                elif kind == 4:
                    counts["transport_packets"] += 1
                    if version == 6:
                        counts["ipv6_transport_packets"] += 1
                else:
                    continue
                if version == 4 and not int.from_bytes(packet[6:8], "big") & 0x4000:
                    counts["ipv4_without_df"] += 1
                counts["unique_initiations"] = len(observed[1])
                counts["unique_responses"] = len(observed[2])
                temporary = args.file.with_suffix(".tmp")
                temporary.write_text(json.dumps(counts))
                temporary.replace(args.file)
        return
    if args.role == "server":
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((args.address, 24444))
            listener.listen(1)
            args.ready.write_text("ready")
            stream, _ = listener.accept()
            with stream:
                while True:
                    part = stream.recv(4096)
                    if not part:
                        return
                    stream.sendall(part)
    else:
        result = {"passed": False, "records": 0, "connections": 1}
        latencies = deque(maxlen=100_000)
        maximum_latency = 0
        next_snapshot = 0
        started = time.monotonic()
        try:
            with socket.create_connection((args.address, 24444), 10) as stream:
                stream.settimeout(15)
                while not args.stop.exists():
                    record = struct.pack("!Q", result["records"]) + bytes(1192)
                    before = time.monotonic()
                    stream.sendall(record)
                    if exact(stream, len(record)) != record:
                        raise ValueError("echo payload mismatch")
                    latency = (time.monotonic() - before) * 1000
                    latencies.append(latency)
                    maximum_latency = max(maximum_latency, latency)
                    if time.monotonic() >= next_snapshot:
                        next_snapshot = time.monotonic() + 30
                        status = {**result, "state": "running", "elapsed_seconds": time.monotonic() - started}
                        args.file.with_suffix(".progress.json").write_text(json.dumps(status))
                    result["records"] += 1
                    if result["records"] == 5:
                        args.ready.write_text("ready")
                    time.sleep(0.05)
                result["passed"] = args.stop.exists()
        except (OSError, EOFError, ValueError) as error:
            result["error"] = type(error).__name__
        finally:
            result["seconds"] = time.monotonic() - started
            if latencies:
                ordered = sorted(latencies)
                result["echo_rtt_ms"] = {"p50": ordered[len(ordered) // 2],
                                         "p95": ordered[int(len(ordered) * .95)], "max": maximum_latency, "quantile_window_records": len(ordered)}
            args.file.write_text(json.dumps(result, indent=2) + "\n")
        if not result["passed"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
