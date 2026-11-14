# SignalR negotiate-identity binding runtime PoC

This is a **local-only, non-destructive** test harness for the hypothesis that a
SignalR Hub invocation queued before the first Long Polling attach can execute
under the identity presented by that first attach request rather than the
identity present during negotiate.

It starts an in-process ASP.NET Core SignalR server bound to
`127.0.0.1`, uses synthetic identities (`Alice` and `Bob`), and sends only
a harmless `WhoAmI` Hub invocation. It does not contact or target any external
server.

## Test sequence

1. Negotiate as Alice.
2. Before the first transport poll, POST a valid SignalR JSON handshake and
   `WhoAmI` invocation as Alice.
3. Make the first Long Polling GET as Bob.
4. Inspect the Hub completion result, which is the identity observed by
   `Hub.Context.User`.

A same-identity Alice/Alice/Alice positive control runs first. The cross-identity
case is meaningful only if that control succeeds.

## Run locally

Requires the .NET 11.0 SDK:

```sh
dotnet --info
dotnet run --project SignalRIdentityBindingPoc.csproj --configuration Release
```

## Result interpretation

- `VULNERABILITY_REPRODUCED`: the cross-identity invocation completed and the
  Hub observed Bob. This is evidence of the suspected identity-confusion
  behavior in the exact runtime used by the test.
- `NOT_REPRODUCED`: the invocation completed, but the Hub did not observe Bob.
- `INCONCLUSIVE`: the positive control failed, the request was rejected, or
  no matching Hub completion was observed.

A non-reproduction is not proof that every transport or deployment configuration
is safe. Record the exact SDK/runtime version and repeat against the official
.NET 11.0.0 release runtime. Do not describe a source-only result as a runtime
exploit.

## Scope and safety

The test server binds to loopback only. It has no privileged Hub methods, data
access, persistence, or external target. The synthetic identity header is
test scaffolding, not a production authentication design.


CI trigger: this branch update runs the workflow registered on the repository default branch.
