# SignalR identity-binding runtime PoC

A local-only, non-destructive test harness for checking whether a SignalR
connection's identity remains bound across negotiation, the initial Long
Polling attach, and later send requests.

The harness starts an ASP.NET Core SignalR server on `127.0.0.1`, uses
synthetic identities (`Alice` and `Bob`), and invokes only a harmless
`WhoAmI` Hub method. It does not contact an external server.

## Scenarios

Each scenario negotiates a connection, performs its first Long Polling GET,
then POSTs a valid JSON Hub handshake and `WhoAmI` invocation. The response
from the Hub reports `Context.User.Identity.Name`.

1. Positive control: Alice negotiates, attaches, and sends.
2. Authenticated send-time switch: Alice negotiates and attaches; Bob sends.
3. Anonymous send-time switch: anonymous negotiation and attach; Bob sends.
4. Initial-attach switch control: Alice negotiates; Bob performs the first
   attach; Alice sends.

The critical send-time cases keep the identity stable during negotiation and
initial attach. This avoids confusing a rejection at initial attach with a
rejection of a later send request.

## Run locally

Requires the .NET 11 SDK:

```sh
dotnet --info
dotnet run --project SignalRIdentityBindingPoc.csproj --configuration Release
```

## Result interpretation

- `VULNERABILITY_REPRODUCED`: a Hub invocation completed and the Hub observed
  Bob in a scenario where the connection was initially bound as Alice or
  anonymous. This is evidence of identity confusion in this exact runtime.
- `NOT_REPRODUCED`: no candidate invocation completed as Bob. A request
  rejected before Hub execution is a negative result for that specific path.
- `INCONCLUSIVE`: the positive control failed or a candidate did not produce
  a definitive response.

A non-reproduction does not prove every transport, authentication handler,
proxy, or race condition is safe. The test uses a synthetic header-based
principal middleware, not a production authentication scheme. Record the
exact SDK/runtime version and repeat with the official target runtime.

## Scope and safety

The server binds to loopback only. It has no privileged Hub methods, data
access, persistence, or external target. The `X-Test-User` header is test
scaffolding, not a production authentication design.
