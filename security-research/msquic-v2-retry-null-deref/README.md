# MsQuic compatible-version Retry post-handshake client crash

## Tested targets

- .NET Runtime 10.0.15 using `System.Net.Quic`.
- Official MsQuic v2.5.11 (the native dependency pinned by .NET 10.0.15), v2.6.4 Release, and the current MsQuic main snapshot at `3e870278781a6d34524fc55c6bae220e182d6124` (v2.7.0).
- Ubuntu 24.04, optimized native Release shared library and .NET Release application.
- Loopback client/server with normal TLS certificate validation; the test does not disable certificate validation.

The .NET client creates a marker only after `QuicConnection.ConnectAsync` completes. The relay waits for that marker and subsequent server traffic before injecting, proving the reproduction occurs after the application has established the QUIC connection.

## Trigger and controls

| Case | Injected packet | Expected / observed meaning |
|---|---|---|
| Original v2 Retry | `80 6b 33 43 cf 00 00` | SIGSEGV / exit 139 on same established peer endpoint |
| Fixed-Bit v2 Retry | `c0 6b 33 43 cf 00 00` | SIGSEGV / exit 139 on same established peer endpoint |
| Different source IP and port | Same v2 packet, `127.0.0.2:<ephemeral>` | No crash in first current-main test |
| Different UDP port only | Same v2 packet, `127.0.0.1:<ephemeral>` | Isolated source-port control in the current workflow |
| Different IP only | Same v2 packet, `127.0.0.2:4567` | Isolated source-IP control in the current workflow |
| QUIC v1 Initial control | `80 00 00 00 01 00 00` | Client survives |
| QUIC v1 Retry control | `f0 00 00 00 01 00 00` | Client survives |

Earlier completed GitHub Actions runs passed all four attack/v1-control cases on MsQuic v2.5.11 and v2.6.4. On current MsQuic main (v2.7.0), both same-peer v2 packets were also observed to crash the Release client (exit 139). In the first current-main source-tuple probe, sending the packet from `127.0.0.2` and an ephemeral UDP port did not crash the client. A follow-up workflow now separates the source-IP and source-port variables and records the outcome of each control.

## Source-level root cause

MsQuic's default client version is QUIC v1. Its compatibility map includes an upgrade from QUIC v1 to QUIC v2. In `QuicConnRecvHeader`, a long-header packet whose version differs from the connection version can cause the client to set `Stats.QuicVersion` to the incoming version and call `QuicCryptoOnVersionChange` before packet-type dispatch. The later dispatch then recognizes a v2 Retry and calls `QuicConnRecvRetry`; that function's `GotFirstServerResponse` state check is therefore too late to prevent the earlier version-state mutation.

During normal handshake progression, the client discards Initial keys and `QuicCryptoDiscardKeys` also uninitializes `Connection->Packets[QUIC_ENCRYPT_LEVEL_INITIAL]` and sets that packet-space pointer to `NULL`. `QuicCryptoOnVersionChange` recreates Initial crypto keys for the new version but does not recreate the discarded Initial packet space. The connection is left with an Initial write key but no corresponding Initial packet-space object.

When the normal send path subsequently selects that Initial key for a control frame, `QuicPacketBuilderGetPacketTypeAndKeyForControlFrames` obtains `Connection->Packets[EncryptLevel]`. In an optimized Release build the `CXPLAT_DBG_ASSERT(Packets != NULL)` is compiled out, and the following `Packets->AckTracker` access dereferences the null packet-space pointer.

## Native crash evidence

The Release core from the original v2 trigger records:

```text
Program terminated with signal SIGSEGV
#0 QuicPacketBuilderGetPacketTypeAndKeyForControlFrames
#1 QuicPacketBuilderPrepareForControlFrames
#2 QuicSendFlush
#3 QuicConnDrainOperations
#4 QuicWorkerProcessConnection
#5 QuicWorkerLoop
#6 CxPlatRunExecutionContexts
#7 CxPlatWorkerThread
```

The faulting instruction from GDB is:

```asm
mov    0xbc8(%r12,%rax,8),%rax
cmpw   $0x0,0x188(%rax)   # SIGSEGV here; GDB reports rax = 0
```

This confirms the null dereference in the packet-space lookup used by `QuicPacketBuilderGetPacketTypeAndKeyForControlFrames`, rather than merely identifying a crash somewhere in MsQuic. The same faulting instruction and `rax = 0` were recorded for both original and Fixed-Bit attack variants.

## Attack preconditions and limits

The currently demonstrated trigger is an unauthenticated, malformed 7-byte v2 Retry datagram delivered from the exact established peer endpoint tuple. The datagram is not validated as a Retry before the version-change side effect. A datagram injected from a different source IP and UDP port did not crash in the first current-main probe. That result means this PoC does not establish arbitrary off-path Internet spoofing or source-independent packet injection. The updated workflow separately tests IP-only and port-only changes to pin down the tuple constraint more precisely.

The demonstrated impact is termination of a connected .NET client process using `System.Net.Quic`; the ordinary network peer must be able to send a datagram that the local QUIC stack associates with the established connection's peer path. Do not describe this as unauthenticated arbitrary-Internet DoS without additional proof of the required network source/path conditions.

## Reproduction workflow

The GitHub Actions workflow builds the pinned official MsQuic main commit as Release, installs .NET Runtime 10.0.15, builds the PoC as Release, verifies the loaded native library through `/proc/<pid>/maps`, and runs the attack and control cases. For each expected crash, it collects the GDB backtrace, faulting instruction, registers and shared-library list, preserves the original core dump, and records its SHA-256 digest in the uploaded artifact.

This is a localhost-only research reproduction. It does not scan or contact third-party targets.
