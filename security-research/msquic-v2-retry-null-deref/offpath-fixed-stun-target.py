#!/usr/bin/env python3
"""Fast, fixed-IP STUN peer mapping test; no hostname resolution delays."""
import json, os, secrets, socket, struct, pathlib, time

LOCAL_PORT = int(os.environ.get("LOCAL_PORT", "45679"))
SERVERS = [
    ("google-stun", "74.125.250.129", 19302),
    ("cloudflare-turn", "141.101.90.1", 443),
    ("sonetel", "195.201.132.113", 3478),
    ("aws-stun", "52.26.251.34", 3478),
    ("oracle-stun", "129.153.212.128", 3478),
    ("eutelia-stun", "83.211.9.232", 3478),
    ("hetzner-stun", "136.243.59.79", 3478),
    ("1und1-stun", "212.227.67.33", 3478),
    ("ippi-stun", "194.169.214.30", 3478),
    ("logic-ky-stun", "216.144.89.2", 3478),
    ("aws-east-stun", "34.197.205.39", 3478),
    ("zadarma-stun", "185.45.152.22", 3478),
    ("hetzner-stun-alt", "5.161.57.75", 3478),
    ("goldfish-stun", "185.112.247.26", 3478),
    ("gcp-stun", "34.74.124.204", 3478),
]
COOKIE = 0x2112A442

def parse_stun(data, txid):
    if len(data) < 20:
        raise ValueError("short STUN")
    typ, n, cookie, got = struct.unpack("!HHI12s", data[:20])
    if typ != 0x0101 or cookie != COOKIE or got != txid:
        raise ValueError("not matching STUN success")
    off, end = 20, min(len(data), 20+n)
    while off+4 <= end:
        attr, alen = struct.unpack("!HH", data[off:off+4]); off += 4
        value = data[off:off+alen]; off += (alen+3)&~3
        if attr == 0x0020 and alen >= 8 and value[1] == 1:
            port = struct.unpack("!H", value[2:4])[0] ^ 0x2112
            mask = struct.pack("!I", COOKIE)
            ip = bytes(value[4+i]^mask[i] for i in range(4))
            return socket.inet_ntoa(ip), port
        if attr == 0x0001 and alen >= 8 and value[1] == 1:
            return socket.inet_ntoa(value[4:8]), struct.unpack("!H", value[2:4])[0]
    raise ValueError("no IPv4 mapped address")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", LOCAL_PORT))
sock.settimeout(0.2)
mappings, failures = [], []
for name, ip, port in SERVERS:
    txid = secrets.token_bytes(12)
    req = struct.pack("!HHI12s", 0x0001, 0, COOKIE, txid)
    dest = (ip, port)
    try:
        sock.sendto(req, dest)
    except Exception as e:
        failures.append({"name":name,"dest":f"{ip}:{port}","error":f"send:{e}"})
        continue
    deadline = time.time() + 1.5
    found = False
    while time.time() < deadline:
        try:
            data, peer = sock.recvfrom(2048)
        except socket.timeout:
            continue
        try:
            mapped = parse_stun(data, txid)
        except ValueError:
            continue
        row = {
            "name": name,
            "peer_ip": peer[0], "peer_port": peer[1],
            "mapped_ip": mapped[0], "mapped_port": mapped[1],
            "local_port": LOCAL_PORT
        }
        mappings.append(row)
        print("STUN_MAPPING=" + json.dumps(row, sort_keys=True), flush=True)
        found = True
        break
    if not found:
        failures.append({"name":name,"dest":f"{ip}:{port}","error":"timeout/no-matching-success"})

if not mappings:
    raise SystemExit("FAIL: no STUN server returned a matching response")
result = {"run_id":os.environ.get("GITHUB_RUN_ID",""),"local_port":LOCAL_PORT,"mappings":mappings,"failures":failures}
pathlib.Path("offpath-fixed-results").mkdir(parents=True,exist_ok=True)
pathlib.Path("offpath-fixed-results/mappings.json").write_text(json.dumps(result,indent=2)+"\n")
print(f"STUN_PEERS_CONFIRMED={len(mappings)} FAILURES={len(failures)}",flush=True)
os.system("python3 security-research/msquic-v2-retry-null-deref/nettest-coord.py publish exact-fixed-stun-mappings offpath-fixed-results/mappings.json")

sock.settimeout(1)
end = time.time()+180
while time.time()<end:
    try:
        data, source = sock.recvfrom(4096)
    except socket.timeout:
        continue
    rec={"source_ip":source[0],"source_port":source[1],"payload_hex":data.hex(),"payload_ascii":data.decode("ascii","replace")}
    print("UDP_DATAGRAM_RECEIVED="+json.dumps(rec,sort_keys=True),flush=True)
    for idx,row in enumerate(mappings):
        if source==(row["peer_ip"],row["peer_port"]) and data==f"OFFPATH-FIXED-{idx}".encode():
            pathlib.Path("offpath-fixed-results/received.json").write_text(json.dumps(rec,indent=2)+"\n")
            pathlib.Path("offpath-fixed-results/received-index.txt").write_text(str(idx)+"\n")
            print(f"PASS: marker received from peer index {idx}",flush=True)
            sock.close()
            raise SystemExit(0)
print("FAIL: no off-path marker received",flush=True)
sock.close()
raise SystemExit(2)
