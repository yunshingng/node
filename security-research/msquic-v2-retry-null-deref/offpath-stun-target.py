#!/usr/bin/env python3
"""Controlled single-datagram off-path delivery test using one STUN-mapped UDP socket."""
import json, os, secrets, socket, struct, sys, time, pathlib

LOCAL_PORT = int(os.environ.get("LOCAL_PORT", "45679"))
STUN_HOST = "stun.l.google.com"
STUN_PORT = 19302
MAGIC = b"OFFPATH-DELIVERY-PROOF"
COOKIE = 0x2112A442

def parse_stun(data, txid):
    if len(data) < 20:
        raise ValueError("short STUN response")
    typ, length, cookie, got_txid = struct.unpack("!HHI12s", data[:20])
    if typ != 0x0101 or cookie != COOKIE or got_txid != txid:
        raise ValueError("response is not the matching STUN Binding Success")
    off, end = 20, min(len(data), 20 + length)
    while off + 4 <= end:
        attr, n = struct.unpack("!HH", data[off:off+4])
        off += 4
        value = data[off:off+n]
        off += (n + 3) & ~3
        if attr == 0x0020 and n >= 8 and value[1] == 1:
            port = struct.unpack("!H", value[2:4])[0] ^ 0x2112
            mask = struct.pack("!I", COOKIE)
            ip = bytes(value[4+i] ^ mask[i] for i in range(4))
            return socket.inet_ntoa(ip), port
        if attr == 0x0001 and n >= 8 and value[1] == 1:
            return socket.inet_ntoa(value[4:8]), struct.unpack("!H", value[2:4])[0]
    raise ValueError("STUN response has no IPv4 mapped address")

answers = socket.getaddrinfo(STUN_HOST, STUN_PORT, socket.AF_INET, socket.SOCK_DGRAM)
stun_ip = answers[0][4][0]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", LOCAL_PORT))
sock.settimeout(10)

txid = secrets.token_bytes(12)
request = struct.pack("!HHI12s", 0x0001, 0, COOKIE, txid)
sock.sendto(request, (stun_ip, STUN_PORT))
data, peer = sock.recvfrom(2048)
if peer[0] != stun_ip or peer[1] != STUN_PORT:
    raise SystemExit(f"FAIL: STUN reply source differs from queried endpoint: {peer}, expected {(stun_ip, STUN_PORT)}")
mapped_ip, mapped_port = parse_stun(data, txid)

mapping = {
    "stun_host": STUN_HOST,
    "peer_ip": stun_ip,
    "peer_port": STUN_PORT,
    "client_public_ip": mapped_ip,
    "client_public_port": mapped_port,
    "client_local_port": LOCAL_PORT,
    "run_id": os.environ.get("GITHUB_RUN_ID", ""),
    "claim": "Exact endpoint-dependent mapping learned from a reply to this same still-open UDP socket."
}
pathlib.Path("offpath-stun-results").mkdir(exist_ok=True)
pathlib.Path("offpath-stun-results/mapping.json").write_text(json.dumps(mapping, indent=2) + "\n")
print("STUN_REPLY_RECEIVED_FROM=%s:%d" % peer, flush=True)
print("EXACT_PUBLIC_MAPPING=%s:%d" % (mapped_ip, mapped_port), flush=True)

# Publish only after the same socket received the STUN reply; keep this socket open.
os.system("python3 security-research/msquic-v2-retry-null-deref/nettest-coord.py publish exact-stun-mapping offpath-stun-results/mapping.json")
sock.settimeout(55)
deadline = time.time() + 55
while time.time() < deadline:
    try:
        packet, source = sock.recvfrom(2048)
    except socket.timeout:
        break
    record = {
        "source_ip": source[0],
        "source_port": source[1],
        "payload_hex": packet.hex(),
        "payload_ascii": packet.decode("ascii", "replace"),
        "expected_source_ip": stun_ip,
        "expected_source_port": STUN_PORT,
        "payload_matches": packet == MAGIC,
        "source_matches": source == (stun_ip, STUN_PORT),
        "received_unix": time.time()
    }
    pathlib.Path("offpath-stun-results/received.json").write_text(json.dumps(record, indent=2) + "\n")
    print("UDP_DATAGRAM_RECEIVED=" + json.dumps(record, sort_keys=True), flush=True)
    if record["payload_matches"] and record["source_matches"]:
        print("PASS: forged-source packet arrived from the exact previously contacted STUN endpoint", flush=True)
        sock.close()
        raise SystemExit(0)
print("FAIL: no matching spoofed datagram received before timeout", flush=True)
sock.close()
raise SystemExit(2)
