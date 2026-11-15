# MariaDB CONNECT CWE-134 validation harness

This directory is an isolated research harness. It does not modify Node.js runtime code.

## Goal

Exercise a real MariaDB server with CONNECT loaded using partitioned CONNECT CSV tables. The suspected source-level call is:

`snprintf(sv, size, s, partname)`

The harness runs a baseline filename, a filename containing extra `%s` conversions, and a `%n` filename. It records SQL output and server logs for each fresh container.

## Run locally

Requirements: Docker Engine.

```sh
cd security-research/mariadb-connect-cwe134
bash run.sh
```

The runner waits for the final TCP listener (not the temporary socket-only initialization server), creates and selects a dedicated database, and requires each SQL case to complete and return the inserted row. A SQL failure or missing row fails the workflow. The containers are disposable and use a test-only root password.

## Interpretation

- A passing baseline confirms the test table syntax and CONNECT CSV path work on the tested image.
- A passing malformed-format case means only that this input completed on that exact build; it does not establish safety or exploitability.
- A crash/abort is evidence of availability impact, not RCE.
- A successful `%n` execution is not proof of a controllable arbitrary write. The actual pointer value, memory permissions, and write effect must be independently established.
- No RCE, arbitrary write, or information disclosure is claimed by this harness.

## Scope and limitations

The Docker image tag defaults to `mariadb:11.4`; set `MARIADB_IMAGE` to test another official image. The plugin package and binary hardening vary by release and distribution. Results apply only to the exact image digest recorded by the workflow.
