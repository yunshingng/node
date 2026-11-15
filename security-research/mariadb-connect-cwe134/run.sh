#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"
command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

image_tag="mariadb-connect-cwe134:local"
docker build --build-arg "MARIADB_IMAGE=${MARIADB_IMAGE:-mariadb:11.4}" -t "$image_tag" .

failures=0

run_case() {
  local name="$1"
  local filename="$2"
  local container="connect-cwe134-${name}-$$"
  local log_file="result-${name}.log"
  local sql_file
  sql_file="$(mktemp)"
  cat >"$sql_file" <<SQL
CREATE DATABASE cwe134;
USE cwe134;
SELECT VERSION() AS mariadb_version;
SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS
 WHERE PLUGIN_NAME = 'CONNECT';
CREATE TABLE t_cwe134 (
  id INT,
  v VARCHAR(32)
) ENGINE=CONNECT TABLE_TYPE=CSV FILE_NAME='${filename}'
PARTITION BY RANGE(id) (
  PARTITION p0 VALUES LESS THAN (10),
  PARTITION p1 VALUES LESS THAN MAXVALUE
);
INSERT INTO t_cwe134 VALUES (1, 'probe');
SELECT * FROM t_cwe134;
SQL

  echo "===== case: $name ====="
  docker run -d --name "$container" \
    -e MARIADB_ROOT_PASSWORD=test-only-password \
    "$image_tag" >/dev/null

  local ready=0
  # The official image briefly starts a socket-only temporary server while
  # initializing users. Require TCP readiness to avoid racing that phase.
  for _ in $(seq 1 90); do
    if docker exec "$container" mariadb-admin --protocol=tcp -h127.0.0.1 \
      -uroot -ptest-only-password ping --silent >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
      break
    fi
    sleep 2
  done

  if [[ "$ready" -ne 1 ]]; then
    echo "FAIL: MariaDB did not become TCP-ready" | tee "$log_file"
    docker logs "$container" >>"$log_file" 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -f "$sql_file"
    failures=$((failures + 1))
    return
  fi

  set +e
  docker exec -i "$container" mariadb --protocol=tcp -h127.0.0.1 \
    -uroot -ptest-only-password --show-warnings <"$sql_file" >"$log_file" 2>&1
  local sql_rc=$?
  set -e
  echo "sql_exit_code=$sql_rc" | tee -a "$log_file"

  sleep 2
  local running
  running="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || echo missing)"
  echo "container_running_after_test=$running" | tee -a "$log_file"
  docker logs "$container" >>"$log_file" 2>&1 || true
  cat "$log_file"

  if [[ "$sql_rc" -ne 0 ]]; then
    echo "FAIL: SQL test did not complete for $name" >&2
    failures=$((failures + 1))
  elif ! grep -q $'1\tprobe' "$log_file"; then
    echo "FAIL: expected row was not returned for $name" >&2
    failures=$((failures + 1))
  else
    echo "PASS: SQL completed and returned expected row for $name"
  fi

  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$sql_file"
}

run_case baseline "ordinary.csv"
run_case extra-s "d_%s%s%s%s.csv"
run_case percent-n "d_%n.csv"

if [[ "$failures" -ne 0 ]]; then
  echo "Validation harness had $failures failed case(s)." >&2
  exit 1
fi

echo "All SQL cases completed. This is not, by itself, proof of exploitability."
