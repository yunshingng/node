# MariaDB CONNECT REST SSRF regression check

This isolated GitHub Actions harness tests the MDEV-41641 fix on a patched MariaDB 11.8 image.

It installs CONNECT, starts a harmless HTTP server bound only to `127.0.0.1` inside the disposable MariaDB container, and connects as a MariaDB user granted only `CREATE` and `SELECT`.

Tests:

1. HTTP request to the loopback fixture with `HTTP=` and no `FILE_NAME`.
2. `file://` request against a mysql-owned, mode-0600 sentinel file. The patched curl protocol restriction should block it.
3. A negative control with non-empty `FILE_NAME`, which should hit the normal FILE privilege check and fail for the low-privilege account.

No real cloud metadata endpoint, external internal network, production database, or third-party host is contacted.

Run locally:

```sh
bash security-research/mariadb-connect-rest-ssrf/run.sh
```

The expected result is that `file://` is blocked but a loopback HTTP URL remains reachable from the server process. This demonstrates the remaining SSRF exposure in the tested build; it does not prove every private address or redirect scenario is reachable.
