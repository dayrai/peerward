#!/usr/bin/env python3
"""One-way UDP workload for the isolated kernel/TUN qualification harness.

The receiver never replies. Results cross the local filesystem, not the tunnel.
Sequence accounting retains loss, duplicates, malformed packets and send errors.
"""

import argparse
import json
from pathlib import Path
import socket
import struct
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["send", "receive"])
    parser.add_argument("address")
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--ready", type=Path)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3605:
        parser.error("duration must be 1..3605 seconds")
    token = bytes.fromhex(args.token)
    if len(token) != 16:
        parser.error("token must be 16 bytes")
    if args.role == "receive" and args.ready is None:
        parser.error("receiver requires --ready")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        if args.role == "send":
            udp.settimeout(0.1)
            attempts = sent = errors = 0
            started = time.monotonic()
            deadline = started + args.seconds
            while time.monotonic() < deadline:
                # Constant 1200-byte inner payload, no response or application ACK.
                packet = token + struct.pack("!I", attempts) + bytes(1180)
                attempts += 1
                try:
                    sent += int(udp.sendto(packet, (args.address, 51822)) == len(packet))
                except OSError:
                    errors += 1
                delay = started + attempts * 0.02 - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            result = {"attempts": attempts, "sent": sent, "send_errors": errors}
        else:
            udp.bind((args.address, 51822))
            udp.settimeout(0.2)
            deadline = time.monotonic() + args.seconds
            args.ready.write_text("ready\n")
            seen = set()
            duplicates = invalid = 0
            while time.monotonic() < deadline:
                try:
                    packet, _ = udp.recvfrom(1201)
                except socket.timeout:
                    continue
                if len(packet) != 1200 or packet[:16] != token or any(packet[20:]):
                    invalid += 1
                    continue
                sequence = struct.unpack("!I", packet[16:20])[0]
                if sequence >= 180_250:
                    invalid += 1
                elif sequence in seen:
                    duplicates += 1
                else:
                    seen.add(sequence)
            result = {"received": len(seen), "duplicates": duplicates, "invalid": invalid}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
