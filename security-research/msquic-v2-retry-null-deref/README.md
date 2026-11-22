# MsQuic v2 compatible-version Retry null-dereference E2E

This isolated test exercises a client-side crash using:

- Official .NET runtime 10.0.15 (System.Net.Quic).
- Microsoft MsQuic source tag **v2.6.4** (latest published release when this test was updated), built as an optimized Release shared library.
- A loopback QUIC server/client and UDP relay.
- Ordinary TLS certificate validation. The test creates a temporary local CA and does not disable certificate validation.

The client writes a marker only after `QuicConnection.ConnectAsync` completes. The relay waits for that marker and a subsequent server datagram before injecting, so the test packet is sent after the client reports the QUIC connection established.

## Cases

| Case | Injected bytes | Expected |
|---|---|---|
| Original reported attack | `80 6b 33 43 cf 00 00` | Release client SIGSEGV (139) |
| Fixed-Bit variation | `c0 6b 33 43 cf 00 00` | Release client SIGSEGV (139) |
| QUIC v1 Initial control | `80 00 00 00 01 00 00` | Client survives |
| QUIC v1 Retry control | `f0 00 00 00 01 00 00` | Client survives |

The harness records `/proc/<client-pid>/maps` to prove which native MsQuic shared library the .NET process loaded. It also enables core dumps and attempts to produce a GDB thread backtrace for each expected crash; backtraces are uploaded with the workflow artifact.

## Crash backtrace and root-cause status

Release core dumps from both v2 attack variants were captured and inspected with GDB. The faulting thread's top frame is `QuicPacketBuilderGetPacketTypeAndKeyForControlFrames`, called through `QuicPacketBuilderPrepareForControlFrames`, `QuicSendFlush`, and `QuicConnDrainOperations`. This is the observed crash path in the core; it supersedes the earlier static hypothesis that `QuicCryptoOnVersionChange` itself was the faulting frame.

The current symbolized backtrace identifies the faulting native function, but the exact faulting instruction and invalid operand still require register/disassembly correlation. The workflow now records the faulting instruction and general-purpose registers in addition to the full thread backtrace. Do not describe a NULL dereference in `QuicCryptoOnVersionChange` as the confirmed root cause unless that evidence establishes it.
## Run and limitations

The GitHub Actions workflow builds official MsQuic v2.6.4 in Release, installs .NET 10.0.15, builds the app in Release, creates a trusted loopback certificate, then executes all four cases.

The test uses a UDP relay that sends the injected packet from the same local peer endpoint used by the established connection. It demonstrates a post-handshake, unauthenticated QUIC datagram reaching the connected client and causing the observed crash. It does **not** yet demonstrate off-path spoofing from an arbitrary Internet host, cross-platform impact, or every deployment configuration.

A build failure, TLS failure, missing injection, missing loaded-library evidence, hang, absent expected SIGSEGV, or a failing control causes the workflow to fail.

This is a localhost-only reproduction and does not scan or contact third-party targets.
