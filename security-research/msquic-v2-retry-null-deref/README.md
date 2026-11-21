# MsQuic v2 compatible-version Retry null-dereference E2E

This isolated test exercises the reported client-side crash using:

- Official .NET runtime 10.0.15 (System.Net.Quic).
- Microsoft MsQuic source tag v2.5.11, built as an optimized Release shared library.
- A loopback QUIC server/client and UDP relay.
- Normal TLS certificate validation. The test installs a temporary local CA and does not disable validation or use an insecure flag.

The client writes a marker only after QuicConnection.ConnectAsync completes. The relay waits for that marker and a subsequent server datagram before injecting, so the input is delivered after the handshake has completed.

## Cases

| Case | Injected bytes | Expected |
|---|---|---|
| Original reported attack | 80 6b 33 43 cf 00 00 | Release client SIGSEGV (139) |
| Fixed-Fixed-Bit attack | c0 6b 33 43 cf 00 00 | Release client SIGSEGV (139) |
| Original v1 control | 80 00 00 00 01 00 00 | Client survives |
| v1 Retry control | f0 00 00 00 01 00 00 | Client survives |

The test records /proc/<client-pid>/maps to prove that the .NET process loaded the MsQuic shared library built from tag v2.5.11 via LD_LIBRARY_PATH.

## Run

The GitHub Actions workflow builds MsQuic v2.5.11, installs the .NET 10.0.15 runtime, builds the app in Release, creates a trusted loopback certificate, then executes all four cases.

The attack is considered reproduced only if both v2 cases cause exit code 139 and both v1 controls exit with code 0. A build failure, TLS failure, missing injection, missing loaded-library evidence, hang, or different exit code fails the workflow.

This is a localhost-only reproduction and does not scan or contact third-party targets.
