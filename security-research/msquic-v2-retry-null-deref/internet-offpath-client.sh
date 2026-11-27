#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-internet-results/client"
APP="$ROOT/bin/Release/net10.0/MsQuicRetryE2E.dll"
mkdir -p "$RESULTS"
export DOTNET_ROLL_FORWARD=LatestPatch
export LD_LIBRARY_PATH="$MSQUIC_LIB_DIR"

python3 "$ROOT/nettest-coord.py" wait "server.json" "$RESULTS/server.json" 
python3 "$ROOT/nettest-coord.py" wait "ca.crt" "$RESULTS/ca.crt"
SERVER_IP="$(jq -r .server_ip "$RESULTS/server.json")"
sudo install -m 0644 "$RESULTS/ca.crt" /usr/local/share/ca-certificates/msquic-internet-test-ca.crt
sudo update-ca-certificates >/dev/null
sudo sysctl -w kernel.core_pattern="$RESULTS/core.%e.%p" >/dev/null
ulimit -c unlimited

# This raw UDP receiver independently records a datagram arriving at the
# client host with the forged QUIC-server source tuple and exact trigger bytes.
sudo python3 "$ROOT/internet-offpath-sniffer.py" "$SERVER_IP" 4568 "$RESULTS/spoof-received.txt" \
  >"$RESULTS/sniffer.log" 2>&1 &
SNIFFER_PID=$!
cleanup(){ set +e; kill "$SNIFFER_PID" 2>/dev/null; wait "$SNIFFER_PID" 2>/dev/null; }
trap cleanup EXIT
sleep 1

QUIC_REMOTE_IP="$SERVER_IP" QUIC_REMOTE_PORT=4568 dotnet "$APP" client "$RESULTS/client-connected" \
  >"$RESULTS/client.log" 2>&1 &
CLIENT_PID=$!
echo "CLIENT_PID=$CLIENT_PID"
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
  echo "PASS: external spoofed datagram reached client host and client SIGSEGV"
else
  echo "FAIL: cross-Internet off-path proof incomplete (need received packet + exit 139)"
  exit 1
fi
