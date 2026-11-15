# MariaDB CONNECT CWE-134 validation harness

This directory is an isolated research harness. It does not modify Node.js runtime code.

## Reproduced result

On the GitHub Actions image tested on 2026-11-15:

- MariaDB: `11.4.13-MariaDB-ubu2404`
- CONNECT plugin: `1.07.0002`, status `ACTIVE`
- Baseline partitioned CONNECT CSV table: succeeds and returns the inserted row.
- Filename with extra `%s` conversions: CREATE/INSERT/SELECT completes; CONNECT emits a warning for the derived partition filename. No crash was observed.
- Filename containing `%n`: MariaDB prints `*** %n in writable segment detected ***`, aborts with signal 6, and the backtrace includes libc `__snprintf_chk` called from `ha_connect.so`.

The last case is a reproducible server-process denial of service on this tested build. It also confirms that the format string reaches a fortified snprintf path. The abort is caused by glibc fortification rejecting `%n`; this test does **not** show an arbitrary write or RCE.

## Independent upstream confirmation

MariaDB upstream subsequently committed [b01a176de5d4c814333fead0c85e431666e00fee](https://github.com/MariaDB/server/commit/b01a176de5d4c814333fead0c85e431666e00fee), titled:

`MDEV-41946 CONNECT: table option value used as printf format string, crash in ha_connect::GetRealString`

The commit message explicitly states that, for partitioned tables, `GetRealString()` and `FileExists()` passed option values as the `snprintf()` format string while substituting the partition name. The fix substitutes only the first literal `%s` and copies the remainder literally. The same commit adds an upstream regression test using `FILE_NAME='P[%p-%d-%n-%%]-%s-%s.csv'` and verifies the literal format tokens survive in generated filenames. This independently confirms the root cause and the affected code path; it does not establish arbitrary-write or RCE impact.

## Run locally

Requirements: Docker Engine.

```sh
cd security-research/mariadb-connect-cwe134
bash run.sh
```

The runner waits for the final TCP listener (not the temporary socket-only initialization server), creates and selects a dedicated database, and asserts the baseline and extra-`%s` cases complete. For `%n`, it asserts the expected fortified abort signature and stopped server. Each test uses a disposable container and a test-only root password.

## Security interpretation

- Confirmed: SQL-controlled CONNECT `FILE_NAME` containing `%n` reaches `__snprintf_chk` through `ha_connect.so` and terminates the MariaDB server on the tested build.
- Independently confirmed by MariaDB upstream: the partition-name substitution passed table-option data as a printf format string; upstream fixed `GetRealString()` and `FileExists()` and added a regression test.
- Impact demonstrated: database server process crash / denial of service.
- Not demonstrated: arbitrary memory write, information disclosure, code execution, privilege escalation, or unauthenticated remote reachability.
- The test uses a privileged local database connection to create a partitioned CONNECT table. Exploitability depends on whether an attacker can obtain the required SQL privileges in a target deployment.
- A crash in this fortified build is not proof that all MariaDB builds behave identically. Results apply only to the exact image digest and binary tested.

The safe implementation uses a constant format string and treats user-controlled option data literally, while preserving the intended first-`%s` partition substitution.
