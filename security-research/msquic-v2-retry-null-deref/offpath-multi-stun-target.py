#!/usr/bin/env python3
"""Bind one UDP socket, learn exact NAT mappings for known public STUN peers, then wait for markers."""
import json, os, secrets, socket, struct, pathlib, time

LOCAL_PORT = int(os.environ.get("LOCAL_PORT", "45679"))
SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.nextcloud.com", 443),
    ("stun.sonetel.net", 3478),
    ("stun.sipnet.ru", 3478),
    ("stun.voipbuster.com", 3478),
    ("stun.ekiga.net", 3478),
    ("stun.callwithus.com", 3478),
    ("stun.voip.eutelia.it", 3478),
    ("stun.linuxtrent.it", 3478),
    ("stun.framasoft.org", 3478),
]
COOKIE = 0x2112A442

def parse_stun(data, txid):
    if len(data) < 20:
        raise ValueError("short STUN response")
    typ, n, cookie, got_txid = struct.unpack("!HHI12s", data[:20])
    if typ != 0x0101 or cookie != COOKIE or got_txid != txid:
        raise ValueError("not matching STUN Binding Success")
    off, end = 20, min(len(data), 20 + n)
    while off + 4 <= end:
        attr, alen = struct.unpack("!HH", data[off:off+4])
        off += 4
        value = data[off:off+alen]
        off += (alen + 3) & ~3
        if attr == 0x0020 and alen >= 8 and value[1] == 1:
            port = struct.unpack("!H", value[2:4])[0] ^ 0x2112
            mask = struct.pack("!I", COOKIE)
            ip = bytes(value[4+i] ^ mask[i] for i in range(4))
            return socket.inet_ntoa(ip), port
        if attr == 0x0001 and alen >= 8 and value[1] == 1:
            return socket.inet_ntoa(value[4:8]), struct.unpack("!H", value[2:4])[0]
    raise ValueError("no IPv4 mapped address")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", LOCAL_PORT))
sock.settimeout(0.25)

seen_destinations = set()
mappings = []
failures = []
for host, port in SERVERS:
    try:
        answers = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except Exception as e:
        failures.append({"host": host, "port": port, "error": f"resolve: {e}"})
        continue
    for answer in answers:
        ip = answer[4][0]
        dest = (ip, port)
        if dest in seen_destinations:
            continue
        seen_destinations.add(dest)
        txid = secrets.token_bytes(12)
        request = struct.pack("!HHI12s", 0x0001, 0, COOKIE, txid)
        try:
            sock.sendto(request, dest)
            deadline = time.time() + 2.5
            got = False
            while time.time() < deadline:
                try:
                    data, peer = sock.recvfrom(2048)
                except socket.timeout:
                    break
                try:
                    mapped = parse_stun(data, txid)
                except ValueError:
                    continue
                entry = {
                    "configured_host": host,
                    "configured_destination": f"{ip}:{port}",
                    "actual_reply_peer": f"{peer[0]}:{peer[1]}",
                    "peer_ip": peer[0],
                    "peer_port": peer[1],
                    "mapped_ip": mapped[0],
                    "mapped_port": mapped[1],
                    "local_port": LOCAL_PORT,
                    "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                }
                mappings.append(entry)
                print("STUN_MAPPING=" + json.dumps(entry, sort_keys=True), flush=True)
                got = True
                break
            if not got:
                failures.append({"host": host, "destination": f"{ip}:{port}", "error": "no matching Binding Success"})
        except Exception as e:
            failures.append({"host": host, "destination": f"{ip}:{port}", "error": str(e)})

if not mappings:
    pathlib.Path("offpath-multi-results").mkdir(parents=True, exist_ok=True)
    pathlib.Path("offpath-multi-results/mappings.json").write_text(json.dumps({"mappings": [], "failures": failures}, indent=2)+"\n")
    raise SystemExit("FAIL: no public STUN peers returned a matching response")

result = {
    "local_port": LOCAL_PORT,
    "run_id": os.environ.get("GITHUB_RUN_ID", ""),
    "mappings": mappings,
    "failures": failures,
    "note": "Each peer tuple is the exact source IP:port from a Binding Success received on the same still-open socket; each mapped address/port is learned from that reply."
}
pathlib.Path("offpath-multi-results").mkdir(parents=True, exist_ok=True)
pathlib.Path("offpath-multi-results/mappings.json").write_text(json.dumps(result, indent=2)+"\n")
print("STUN_PEERS_CONFIRMED=" + str(len(mappings)), flush=True)
os.system("python3 security-research/msquic-v2-retry-null-deref/nettest-coord.py publish exact-stun-mappings offpath-multi-results/mappings.json")

sock.settimeout(1)
deadline = time.time() + 180
received = []
while time.time() < deadline:
    try:
        packet, source = sock.recvfrom(4096)
    except socket.timeout:
        continue
    record = {
        "source_ip": source[0],
        "source_port": source[1],
        "payload_hex": packet.hex(),
        "payload_ascii": packet.decode("ascii", "replace"),
        "received_unix": time.time(),
    }
    received.append(record)
    print("UDP_DATAGRAM_RECEIVED=" + json.dumps(record, sort_keys=True), flush=True)
    for idx, item in enumerate(mappings):
        if source == (item["peer_ip"], item["peer_port"]) and packet == f"OFFPATH-MULTI-{idx}".encode():
            pathlib.Path("offpath-multi-results/received.json").write_text(json.dumps(record, indent=2)+"\n")
            pathlib.Path("offpath-multi-results/received-index.txt").write_text(str(idx)+"\n")
            print(f"PASS: received exact marker from confirmed STUN peer index {idx}", flush=True)
            sock.close()
            raise SystemExit(0)

pathlib.Path("offpath-multi-results/received-all.json").write_text(json.dumps(received, indent=2)+"\n")
print(f"FAIL: no spoofed marker received; total unrelated datagrams={len(received)}", flush=True)
sock.close()
raise SystemExit(2)
