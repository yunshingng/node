# MariaDB CONNECT REST SSRF validation

This isolated GitHub Actions harness tests report #4123581 / MDEV-41641.

It uses MariaDB's `mariadb:11.8` image and installs the CONNECT plugin. At the time of this run, Docker Hub resolves that tag to MariaDB 11.8.9, which predates the MDEV-41641 curl-protocol fix.

The harness:

1. Creates a disposable MariaDB container and enables CONNECT.
2. Starts a harmless HTTP fixture bound only to `127.0.0.1` inside that container.
3. Creates a MariaDB account with only `CREATE` and `SELECT` on a test schema (no `FILE` or `SUPER`).
4. Tests a CONNECT REST table with empty `FILE_NAME` against the loopback HTTP fixture.
5. Reproduces the original `file://` read against a mysql-owned, mode-0600 sentinel file on the unpatched 11.8.9 image.
6. Checks the negative control: non-empty `FILE_NAME` must be denied without `FILE`.
7. Wraps the container's curl executable with the exact option added by upstream commit [c9589bed1f20bd268d68eb00b997670201f24f4b](https://github.com/MariaDB/server/commit/c9589bed1f20bd268d68eb00b997670201f24f4b), `--proto =http,https`.
8. Re-tests through the real MariaDB CONNECT REST path: `file://` should now be blocked, while the local HTTP URL should remain accessible.

The wrapper stage emulates the production curl argument change while retaining the actual MariaDB/CONNECT request path. It is **not** a full test against a MariaDB binary rebuilt with the MDEV-41641 source patch.

No cloud metadata endpoint, external private IP, production database, or third-party service is contacted.

## Run locally

Requirements: Docker Engine.

```sh
bash security-research/mariadb-connect-rest-ssrf/run.sh
```

The logs are written under `results/` and uploaded as a GitHub Actions artifact.

## Interpretation

A successful loopback HTTP fetch proves that protocol allowlisting alone does not block access to loopback destinations. The test does not claim that every private-network route, redirect, or cloud metadata endpoint is reachable.

The source patch changes the curl protocol allowlist. The separate empty-`FILE_NAME` early return in CONNECT's `checkPrivileges()` remains a distinct authorization concern and is not altered by that curl argument change.
