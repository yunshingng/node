# SignalR identity-binding runtime PoC

A local-only, non-destructive runtime test harness for ASP.NET Core SignalR
on .NET 11. It binds only to `127.0.0.1`, uses synthetic JWT Bearer
identities (`Alice` and `Bob`), and invokes a harmless `WhoAmI` Hub method.
It never contacts an external target.

## Coverage matrix

### Raw Long Polling protocol checks

1. Alice negotiate / Alice initial attach / Alice invocation (positive control).
2. Alice negotiate / Alice attach / Bob send-time request.
3. Anonymous negotiate / anonymous attach / Bob send-time request.
4. Alice negotiate / Bob initial attach (attach-time switch).
5. Alice connection / Bob authentication refresh; then verify the connection
   still invokes as Alice.
6. Alice connection / Alice authentication refresh (same-user positive control).

### Real SignalR client transport checks

The harness uses the .NET SignalR client and forces each transport separately:

- WebSockets: Alice-to-Bob and anonymous-to-Bob changes on an already
  established socket. The socket remains bound to the principal authenticated
  when the WebSocket was opened; there is no new HTTP authentication request
  for each Hub invocation on that socket.
- Server-Sent Events: Alice-to-Bob and anonymous-to-Bob changes on the HTTP
  send request. A changed principal must be rejected before Hub invocation.
- Long Polling: Alice-to-Bob and anonymous-to-Bob changes on subsequent HTTP
  requests. A changed principal must be rejected before Hub invocation.

Each transport scenario first proves a positive control by invoking the Hub
as the initial identity. It then changes the token returned by the client's
access-token provider and verifies the transport-specific result.

### Stateful Reconnect

1. Same-user Alice-to-Alice stateful reconnect: the connection should recover,
   preserve its connection ID, and continue invoking as Alice.
2. Cross-user Alice-to-Bob stateful reconnect: the server must reject the
   reconnect and emit the `UserNameChangedRejected` diagnostic with both
   identities.

Stateful reconnect is enabled on the Hub endpoint and on the .NET client.
The reconnect test uses a real WebSocket and deliberately disposes the
underlying client socket to trigger the reconnect path.

## Run locally

Requires the .NET 11 SDK:

```sh
dotnet --info
dotnet run --project SignalRIdentityBindingPoc.csproj --configuration Release
```

## Result interpretation

- `VULNERABILITY_REPRODUCED`: a Hub invocation observed Bob on an existing
  connection initially authenticated as Alice or anonymous, or the server
  accepted a stateful reconnect after the authenticated user changed.
- `NOT_REPRODUCED`: every positive control passed and all tested identity
  changes were rejected or remained bound to the original WebSocket principal.
- `INCONCLUSIVE`: a positive control failed, a transport could not be tested,
  or the expected rejection/identity result could not be established.

A successful run is evidence only for the exact .NET runtime, authentication
configuration, and scenarios in this harness. It is not proof that every
proxy, hosting configuration, custom authentication handler, race, or future
runtime is safe. The harness uses local synthetic HS256 JWTs and does not
attempt to test production key management.

## Scope and safety

The server binds to loopback only. It has no privileged Hub methods, external
data access, persistence, or external target. The JWT signing key is a fixed
test-only secret and must never be reused in production.
