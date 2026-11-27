#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-internet-results/server"
APP="$ROOT/bin/Release/net10.0/MsQuicRetryE2E.dll"
mkdir -p "$RESULTS/cert"
export DOTNET_ROLL_FORWARD=LatestPatch
export LD_LIBRARY_PATH="$MSQUIC_LIB_DIR"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -keyout "$RESULTS/cert/ca.key" -out "$RESULTS/cert/ca.crt" \
  -subj "/CN=MsQuic Internet test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$RESULTS/cert/server.key" -out "$RESULTS/cert/server.csr" \
  -subj "/CN=localhost"
cat > "$RESULTS/cert/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF
openssl x509 -req -in "$RESULTS/cert/server.csr" \
  -CA "$RESULTS/cert/ca.crt" -CAkey "$RESULTS/cert/ca.key" -CAcreateserial \
  -out "$RESULTS/cert/server.crt" -days 2 -sha256 -extfile "$RESULTS/cert/server.ext"

SERVER_IP="$(curl -4 -fsS https://api.ipify.org)"
printf '{"server_ip":"%s","server_port":4568,"public_ip_source":"ipify"}\n' "$SERVER_IP" > "$RESULTS/server.json"
python3 "$ROOT/nettest-coord.py" publish "server.json" "$RESULTS/server.json"
python3 "$ROOT/nettest-coord.py" publish "ca.crt" "$RESULTS/cert/ca.crt"

sudo sysctl -w net.ipv4.ip_forward=0 >/dev/null
QUIC_LISTEN_IP=0.0.0.0 QUIC_LISTEN_PORT=4568 dotnet "$APP" server \
  "$RESULTS/cert/server.crt" "$RESULTS/cert/server.key" >"$RESULTS/server.log" 2>&1 &
SERVER_PID=$!
cleanup(){ set +e; kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; }
trap cleanup EXIT

for _ in $(seq 1 240); do
  if grep -q '^SERVER_CLIENT_REMOTE=' "$RESULTS/server.log"; then break; fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then cat "$RESULTS/server.log"; exit 1; fi
  sleep 1
done
REMOTE="$(sed -n 's/^SERVER_CLIENT_REMOTE=//p' "$RESULTS/server.log" | head -n1)"
test -n "$REMOTE" || { echo "FAIL: no external QUIC client connected"; cat "$RESULTS/server.log"; exit 1; }
python3 - "$SERVER_IP" "$REMOTE" > "$RESULTS/mapping.json" <<'PY'
import json,re,sys
server_ip,remote=sys.argv[1:]
m=re.fullmatch(r'([0-9.]+):(\d+)',remote)
if not m: raise SystemExit("unparsed client public endpoint: "+remote)
print(json.dumps({"server_ip":server_ip,"server_port":4568,
                  "client_public_ip":m.group(1),"client_public_port":int(m.group(2)),
                  "server_observed_remote":remote}))
PY
cat "$RESULTS/mapping.json"
python3 "$ROOT/nettest-coord.py" publish "mapping.json" "$RESULTS/mapping.json"

set +e
wait "$SERVER_PID"
RC=$?
set -e
echo "SERVER_EXIT=$RC"
cat "$RESULTS/server.log"
