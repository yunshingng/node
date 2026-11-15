# MariaDB CONNECT CWE-134 validation harness

This directory is an isolated research harness. It does not modify Node.js runtime code.

## Goal

Validate the reported call path in a real MariaDB server with CONNECT loaded:

`CREATE TABLE` options -> `GetStringOption()` -> `ha_connect::GetRealString()` -> `snprintf(sv, size, s, partname)`.

The harness records server version, CONNECT availability, SQL output, process exit status, and server logs. It does **not** claim RCE, arbitrary write, or information disclosure.

## Run locally

Requirements: Docker Engine and Docker Compose v2.

```sh
cd security-research/mariadb-connect-cwe134
./run.sh
```

The runner creates a disposable MariaDB container, installs/loads CONNECT if the image package provides it, and runs one test case per fresh server container. A crashing server is recorded as a result rather than treated as a successful exploit.

## Cases

- `baseline`: partitioned CONNECT CSV table with a plain filename.
- `extra-s`: extra `%s` conversions; this is undefined behavior and may crash.
- `percent-n`: `%n` conversion; outcome depends on the actual libc/build hardening and argument interpretation.

The SQL payloads are executed only against the disposable local container created by this harness. Do not point the script at a production server.

## Important limitations

- MariaDB image package names and CONNECT plugin availability vary by release and distribution. The Docker build intentionally fails visibly if the plugin package cannot be installed.
- This harness does not establish that the tested binary has the same compiler flags or libc as a vendor release.
- A process abort is evidence of a crash/DoS condition, not a memory disclosure or RCE.
- A successful `%n` test is not by itself proof of a controllable arbitrary write. The pointer value and write target must be independently established.
- GitHub Actions results are authoritative only for the exact image digest and logs recorded by that run.
