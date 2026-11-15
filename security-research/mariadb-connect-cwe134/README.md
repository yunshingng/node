# MariaDB CONNECT CWE-134 validation harness

This directory is an isolated research harness. It does not modify Node.js runtime code.

## Reproduced result

On the GitHub Actions image tested on 2026-11-15:

- MariaDB: `11.4.13-MariaDB-ubu2404`
- CONNECT plugin: `1.07.0002`, status `ACTIVE`
- Baseline partitioned CONNECT CSV table: succeeds and returns the inserted row.
- Filename with extra `%s` conversions: CREATE/INSERT/SELECT completes; CONNECT emits a warning for the derived partition filename. No crash was observed.
- Filename containing `%n`: MariaDB prints `*** %n in writable segment detected ***`, aborts with signal 6, and the backtrace includes libc `__snprintf_chk` called from `ha_connect.so`.

The last case is a reproducible server-process denial of service on this tested build. The abort is caused by glibc fortification rejecting `%n`; this test does **not** show an arbitrary write or RCE.

## Independent upstream confirmation

MariaDB upstream committed [b01a176de5d4c814333fead0c85e431666e00fee](https://github.com/MariaDB/server/commit/b01a176de5d4c814333fead0c85e431666e00fee), titled:

`MDEV-41946 CONNECT: table option value used as printf format string, crash in ha_connect::GetRealString`

The commit message explicitly states that, for partitioned tables, `GetRealString()` and `FileExists()` passed option values as the `snprintf()` format string while substituting the partition name. The fix substitutes only the first literal `%s` and copies the remainder literally. The commit adds an upstream regression test using format tokens such as `%p`, `%d`, `%n`, and `%%`. This independently confirms the root cause and affected code path; it does not establish RCE.

## RCE assessment

A source-level review of the vulnerable call is important to avoid overstating impact:

- `GetRealString()` calls `snprintf(sv, size, s, partname)`: the attacker-controlled option supplies the format string, but the call supplies only one explicit variadic argument.
- In `ha_connect.h`, `partname` is an in-object `char partname[65]` buffer; `GetPartName()` returns that same buffer for partitioned tables.
- Consequently, a plain `%n` at the first conversion uses the supplied `partname` pointer as its destination. That is a fixed internal buffer, not an attacker-selected pointer. Other conversions that request additional arguments read arguments that were not supplied, which is undefined behavior but is not, by itself, proof of a controllable instruction pointer or RCE.
- The tested fortified build aborts on `%n` before a write occurs.

No controlled instruction pointer, executable memory, command execution, arbitrary-address write, or end-to-end RCE has been demonstrated for this specific MDEV-41946 path. RCE must therefore be treated as **unproven**, not as an established impact. A successful crash test and the upstream fix do not change that conclusion.

Do not conflate this finding with the older [CVE-2022-24051 / ZDI-22-318](https://www.zerodayinitiative.com/advisories/ZDI-22-318/), which is separately described by ZDI as a CONNECT format-string privilege-escalation issue with arbitrary code execution. That historical advisory does not prove that MDEV-41946 shares its exploit primitive or is exploitable in the same way.

## Run locally

Requirements: Docker Engine.

```sh
cd security-research/mariadb-connect-cwe134
bash run.sh
```

The runner waits for the final TCP listener (not the temporary socket-only initialization server), creates and selects a dedicated database, and asserts the baseline and extra-`%s` cases complete. For `%n`, it asserts the expected fortified abort signature and stopped server. Each test uses a disposable container and a test-only root password.

## Security interpretation

- Confirmed: SQL-controlled CONNECT `FILE_NAME` containing `%n` reaches `__snprintf_chk` through `ha_connect.so` and terminates MariaDB on the tested fortified build.
- Independently confirmed by MariaDB upstream: partition-name substitution passed table-option data as a printf format string; upstream fixed `GetRealString()` and `FileExists()` and added a regression test.
- Impact demonstrated: database server process crash / denial of service.
- Not demonstrated: arbitrary memory write, information disclosure, code execution, privilege escalation, or unauthenticated remote reachability.
- The test uses a privileged local database connection to create a partitioned CONNECT table. Exploitability depends on whether an attacker can obtain the required SQL privileges in a target deployment.
- Results apply only to the tested image and build configuration.

The safe implementation uses a constant format string and treats user-controlled option data literally, while preserving the intended first-`%s` partition substitution.
