#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="security-research/msquic-v2-retry-null-deref"
RESULTS="$GITHUB_WORKSPACE/msquic-e2e-results"
APP="$ROOT/bin/Release/net10.0/MsQuicRetryE2E.dll"
LIB_DIR="${MSQUIC_LIB_DIR:?MSQUIC_LIB_DIR must point to the Release MsQuic build}"
mkdir -p "$RESULTS"

# Preserve native crash dumps for a symbolized backtrace after a Release crash.
ulimit -c unlimited
sudo sysctl -w kernel.core_pattern="$RESULTS/core.%e.%p"
echo "CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern)"
echo "CORE_LIMIT=$(ulimit -c)"

export DOTNET_ROLL_FORWARD=LatestPatch
export LD_LIBRARY_PATH="$LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

echo "=== Runtime ==="
dotnet --list-runtimes
dotnet "$APP" --check-runtime

echo "=== Native MsQuic ==="
ls -l "$LIB_DIR"/libmsquic.so*
test -e "$LIB_DIR/libmsquic.so.2"

# Create a local CA and a localhost certificate. The client uses ordinary TLS
# certificate validation; no insecure mode or validation bypass is enabled.
CERT_DIR="$RESULTS/cert"
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
  -subj "/CN=MsQuic isolated E2E test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -subj "/CN=localhost"

cat > "$CERT_DIR/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF

openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" -days 2 -sha256 -extfile "$CERT_DIR/server.ext"

sudo install -m 0644 "$CERT_DIR/ca.crt" \
  /usr/local/share/ca-certificates/msquic-isolated-e2e-ca.crt
sudo update-ca-certificates

run_case() {
  local name="$1"
  local mode="$2"
  local expected="$3"
  local case_dir="$RESULTS/$name"
  local marker="$case_dir/client-connected"
  local injection_marker="$case_dir/injected"
  local server_pid=""
  local relay_pid=""
  local client_pid=""
  local watchdog_pid=""
  local rc=0

  mkdir -p "$case_dir"
  rm -f "$marker" "$injection_marker"

  echo
  echo "=== CASE $name mode=$mode expected=$expected ==="

  dotnet "$APP" server "$CERT_DIR/server.crt" "$CERT_DIR/server.key" \
    >"$case_dir/server.log" 2>&1 &
  server_pid=$!

  for _ in $(seq 1 100); do
    if grep -q "SERVER_LISTENING=" "$case_dir/server.log"; then
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$case_dir/server.log"
      echo "FAIL: server exited before listening"
      return 1
    fi
    sleep 0.1
  done
  if ! grep -q "SERVER_LISTENING=" "$case_dir/server.log"; then
    cat "$case_dir/server.log"
    echo "FAIL: server did not start"
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    return 1
  fi

  python3 "$ROOT/relay.py" \
    --listen 4567 --upstream 4568 --mode "$mode" \
    --marker "$marker" --injection-marker "$injection_marker" \
    --delay-ms 10 >"$case_dir/relay.log" 2>&1 &
  relay_pid=$!

  sleep 0.2
  dotnet "$APP" client "$marker" >"$case_dir/client.log" 2>&1 &
  client_pid=$!

  # This marker is written only after ConnectAsync completes, i.e. after TLS
  # handshake completion and Initial-key discard.
  for _ in $(seq 1 300); do
    if [ -f "$marker" ]; then
      break
    fi
    if ! kill -0 "$client_pid" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done

  if [ ! -f "$marker" ]; then
    echo "FAIL: client did not complete the QUIC handshake"
    cat "$case_dir/client.log" "$case_dir/server.log" "$case_dir/relay.log"
    kill "$client_pid" "$relay_pid" "$server_pid" 2>/dev/null || true
    wait "$client_pid" "$relay_pid" "$server_pid" 2>/dev/null || true
    return 1
  fi

  # Prove the .NET client mapped the selected official MsQuic Release shared object.
  for _ in $(seq 1 50); do
    if [ -r "/proc/$client_pid/maps" ] && grep -q "libmsquic" "/proc/$client_pid/maps"; then
      grep "libmsquic" "/proc/$client_pid/maps" >"$case_dir/client-msquic-maps.txt"
      break
    fi
    sleep 0.01
  done

  if [ ! -s "$case_dir/client-msquic-maps.txt" ]; then
    echo "FAIL: could not prove which libmsquic the .NET client loaded"
    cat "$case_dir/client.log"
    kill "$client_pid" "$relay_pid" "$server_pid" 2>/dev/null || true
    wait "$client_pid" "$relay_pid" "$server_pid" 2>/dev/null || true
    return 1
  fi
  cat "$case_dir/client-msquic-maps.txt"

  for _ in $(seq 1 200); do
    if [ -f "$injection_marker" ]; then
      break
    fi
    if ! kill -0 "$client_pid" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done

  if [ ! -f "$injection_marker" ]; then
    echo "FAIL: relay did not inject after the completed handshake"
    cat "$case_dir/client.log" "$case_dir/relay.log"
    kill "$client_pid" "$relay_pid" "$server_pid" 2>/dev/null || true
    wait "$client_pid" "$relay_pid" "$server_pid" 2>/dev/null || true
    return 1
  fi

  # A watchdog prevents a hung client from stalling the workflow.
  ( sleep 25; kill -TERM "$client_pid" 2>/dev/null || true ) &
  watchdog_pid=$!

  set +e
  wait "$client_pid"
  rc=$?
  set -e

  kill "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  kill "$relay_pid" "$server_pid" 2>/dev/null || true
  wait "$relay_pid" "$server_pid" 2>/dev/null || true

  # If the expected crash occurred, extract a native backtrace from its core.
  if [ "$expected" = "crash" ]; then
    core_file="$(find "$RESULTS" -maxdepth 1 -type f -name 'core.dotnet.*' -print -quit || true)"
    if [ -n "$core_file" ]; then
      gdb --batch --quiet \
        -ex "set pagination off" \
        -ex "set debuginfod enabled off" \
        -ex "thread apply all bt 24" \
        -ex "thread 1" \
        -ex "info args" \
        -ex "info registers rax rbx rcx rdx rsi rdi rbp rsp rip" \
        -ex 'x/16i $pc-32' \
        -ex 'x/8gx $rdi' \
        -ex 'x/8gx $rsi' \
        -ex 'info symbol $pc' \
        -ex "info sharedlibrary" \
        /usr/share/dotnet/dotnet "$core_file" >"$case_dir/core-backtrace.txt" 2>&1 || true
      echo "CORE_BACKTRACE_CAPTURED=$case_dir/core-backtrace.txt"
      # Retain the original core dump as reproducible crash evidence.
      cp "$core_file" "$case_dir/$(basename "$core_file").dump"
      sha256sum "$case_dir/$(basename "$core_file").dump" >"$case_dir/core.sha256"
      rm -f "$core_file"
    else
      {
        echo "No core file was found."
        echo "CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern)"
      } >"$case_dir/core-backtrace.txt"
      echo "WARNING: no core dump found for $name"
    fi
  fi

  {
    echo "case=$name"
    echo "mode=$mode"
    echo "expected=$expected"
    echo "client_exit=$rc"
    echo "injected_packet=$(cat "$injection_marker")"
    echo "runtime=$(grep '^RUNTIME=' "$case_dir/client.log" | head -n1)"
    echo "native_library=$(head -n1 "$case_dir/client-msquic-maps.txt")"
    if [ -s "$case_dir/core-backtrace.txt" ]; then
      echo "core_backtrace=$case_dir/core-backtrace.txt"
    fi
  } | tee "$case_dir/result.txt"

  cat "$case_dir/client.log"
  cat "$case_dir/relay.log"

  if [ "$expected" = "crash" ]; then
    if [ "$rc" -eq 139 ]; then
      echo "PASS: Release client terminated with SIGSEGV (exit 139)"
    else
      echo "FAIL: expected Release SIGSEGV (139), got exit $rc"
      cat "$case_dir/server.log"
      return 1
    fi
  else
    if [ "$rc" -eq 0 ]; then
      echo "PASS: control client survived and exited 0"
    else
      echo "FAIL: control expected exit 0, got $rc"
      cat "$case_dir/server.log"
      return 1
    fi
  fi
}

run_case "attack-original-7-byte" "attack-original" "crash"
run_case "attack-fixedbit" "attack-fixedbit" "crash"
run_case "control-alt-ip-port" "attack-alt-source" "survive"
run_case "control-alt-port" "control-alt-port" "survive"
run_case "control-alt-ip" "control-alt-ip" "survive"
run_case "control-original-v1" "control-original" "survive"
run_case "control-v1-retry" "control-retry" "survive"

echo
echo "ALL CASES PASSED"
