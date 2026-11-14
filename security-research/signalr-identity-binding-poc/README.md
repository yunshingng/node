# SignalR identity-binding runtime PoC

This is a **local-only, non-destructive** test harness for checking whether a
SignalR connection's authenticated identity remains bound across the initial
Long Polling attach and subsequent send requests.

It starts an in-process ASP.NET Core SignalR server bound to `127.0.0.1`,
uses synthetic identities (`Alice` and `Bob`), and sends only a harmless
`WhoAmI` Hub invocation. It does not contact or target any external server.

## Test sequence

For each scenario:

1. Negotiate as Alice.
2. Start the first Long Polling GET under the configured attach identity.
3. While that poll is pending, POST the JSON Hub handshake and `WhoAmI`
   invocation under the configured send identity.
4. Inspect the Hub completion result, which is the identity observed by
   `Hub.Context.User`.

A same-identity Alice/Alice/Alice positive control runs first. The cross-identity
case uses Alice for negotiate, Bob for the initial attach, and Alice for send.
The test is meaningful only if the positive control succeeds.

**Important limitation:** this valid Long Polling sequence does not attempt to
send Hub protocol data before a transport is attached. The first attempt to do
that was rejected with HTTP 400 by SignalR. Therefore this harness tests
identity consistency between attach and send; it does not, by itself, prove or
disprove the narrower pre-attach queued-invocation hypothesis. That requires a
protocol-valid way to queue data before identity binding, if such a path exists.

## Run locally

Requires the .NET 11.0 SDK:

```sh
dotnet --info
dotnet run --project SignalRIdentityBindingPoc.csproj --configuration Release
```

## Result interpretation

- `VULNERABILITY_REPRODUCED`: the cross-identity invocation completed and
  the Hub observed Bob. This is evidence of identity confusion in the exact
  runtime used by the test.
- `NOT_REPRODUCED`: the invocation completed, but the Hub did not observe
  Bob.
- `INCONCLUSIVE`: the positive control failed, the request was rejected, or
  no matching Hub completion was observed.

A non-reproduction is not proof that every transport or deployment
configuration is safe. Record the exact SDK/runtime version and repeat against
the official .NET 11.0.0 release runtime. Do not describe a source-only result
as a runtime exploit.

## Scope and safety

The test server binds to loopback only. It has no privileged Hub methods, data
access, persistence, or external target. The synthetic identity header is test
scaffolding, not a production authentication design.
