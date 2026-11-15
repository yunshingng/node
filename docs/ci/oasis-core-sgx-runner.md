# Oasis Core SGX E2E runner

This directory documents the dedicated Intel SGX runner used by
`.github/workflows/oasis-core-sgx-e2e.yml`.

## What the workflow does

The workflow checks out the Oasis Core source at the pinned revision
`5d4b23dad0a07c358d94f784fdc87cb4099ffe50`, verifies that the runner exposes
an SGX device and AESM socket, builds Oasis Core using its SGX build settings,
and runs the upstream `make test-e2e` suite with
`OASIS_TEE_HARDWARE=intel-sgx`.

**A passing run validates the upstream SGX build and E2E environment only.**
It does not, by itself, prove any particular enclave/committee security
hypothesis. A dedicated regression test must exercise the relevant runtime
request path and assert the resulting authenticated state transition.

## Runner requirements

Use a dedicated Linux x86-64 machine with:

- Intel SGX supported by the CPU and enabled in firmware/kernel.
- A usable SGX device node: normally `/dev/sgx_enclave` (and, where required,
  `/dev/sgx_provision`), or the legacy `/dev/isgx`.
- The Intel AESM service running and its socket exposed at
  `/var/run/aesmd/aesm.socket`.
- Docker if AESM is provided by the Oasis AESM container.
- GitHub Actions self-hosted runner labels: `self-hosted`, `linux`, `x64`,
  and `oasis-sgx`.
- The Oasis Core build prerequisites listed in
  [Oasis Core prerequisites](https://github.com/oasisprotocol/oasis-core/blob/5d4b23dad0a07c358d94f784fdc87cb4099ffe50/docs/development-setup/prerequisites.md).

Do not register a normal cloud runner with the `oasis-sgx` label. The workflow
will fail its hardware preflight if the device or AESM socket is absent.

## Host setup

1. Enable SGX in BIOS/UEFI and configure the Linux SGX driver/kernel support.
2. Install the system packages listed in the Oasis Core prerequisites
   (including GCC/G++, Clang, Bubblewrap, Protobuf, Make, CMake, OpenSSL and
   libseccomp development files).
3. Install Rust via rustup. In the checked-out Oasis Core repository, the
   `rust-toolchain.toml` pins the nightly compiler and the
   `x86_64-fortanix-unknown-sgx` target.
4. Make sure `go`, `rustup`, `cargo`, and `docker` are available to the
   runner user. The workflow installs the Go version declared by Oasis Core's
   `go/go.mod`.
5. Start AESM and ensure `/var/run/aesmd/aesm.socket` is visible to the runner.
6. Register the GitHub Actions runner and add the custom `oasis-sgx` label.

For a new-style SGX driver, verify `/dev/sgx_enclave`; for a legacy driver,
verify `/dev/isgx`. Do not expose the runner to untrusted pull-request jobs.
Prefer a dedicated, disposable runner with no unrelated credentials.

## Run

After the runner is online with all four labels, the workflow can be started
from **Actions → Oasis Core SGX E2E → Run workflow**. The branch also has a
push trigger so the first commit can queue a run; it will remain queued until
a matching self-hosted runner is online.

## Logs

The workflow uploads:

- SGX host diagnostics.
- The Oasis test-runner log directories under `/tmp/oasis-test-runner*`.

The job is intentionally fail-closed: missing SGX hardware, the AESM socket,
or the `sgx-detect` utility causes a failed preflight rather than silently
running a non-SGX test.
