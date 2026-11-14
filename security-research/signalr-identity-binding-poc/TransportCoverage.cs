using System.Net.WebSockets;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Http.Connections.Client;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.Logging;

public static class TransportCoverage
{
    public static async Task<CoverageResult> RunAsync(string address, SignalRLogCaptureProvider logs)
    {
        var outcomes = new List<string>();
        var inconclusive = false;
        var vulnerable = false;

        foreach (var transport in new[]
        {
            HttpTransportType.WebSockets,
            HttpTransportType.ServerSentEvents,
            HttpTransportType.LongPolling
        })
        {
            foreach (var initialIdentity in new string?[] { "Alice", null })
            {
                var result = await RunIdentityChangeAsync(address, transport, initialIdentity, "Bob");
                outcomes.Add(result.Detail);
                vulnerable |= result.Status == CoverageStatus.VulnerabilityReproduced;
                inconclusive |= result.Status == CoverageStatus.Inconclusive;
            }
        }

        var sameUserReconnect = await RunStatefulReconnectAsync(address, logs, "Alice", "Alice", expectRejection: false);
        outcomes.Add(sameUserReconnect.Detail);
        vulnerable |= sameUserReconnect.Status == CoverageStatus.VulnerabilityReproduced;
        inconclusive |= sameUserReconnect.Status == CoverageStatus.Inconclusive;

        var changedUserReconnect = await RunStatefulReconnectAsync(address, logs, "Alice", "Bob", expectRejection: true);
        outcomes.Add(changedUserReconnect.Detail);
        vulnerable |= changedUserReconnect.Status == CoverageStatus.VulnerabilityReproduced;
        inconclusive |= changedUserReconnect.Status == CoverageStatus.Inconclusive;

        var status = vulnerable
            ? CoverageStatus.VulnerabilityReproduced
            : inconclusive ? CoverageStatus.Inconclusive : CoverageStatus.Passed;

        return new(status, string.Join(Environment.NewLine, outcomes));
    }

    private static async Task<CoverageCase> RunIdentityChangeAsync(
        string address, HttpTransportType transport, string? initialIdentity, string changedIdentity)
    {
        var currentIdentity = initialIdentity;
        var bobRequestCount = 0;
        var bobResponseCodes = new ConcurrentQueue<int>();
        var options = new Action<HttpConnectionOptions>(o =>
        {
            o.Transports = transport;
            o.HttpMessageHandlerFactory = handler =>
                new DynamicBearerHandler(handler, () => currentIdentity, code =>
                {
                    Interlocked.Increment(ref bobRequestCount);
                    if (code.HasValue)
                        bobResponseCodes.Enqueue(code.Value);
                });

            if (transport == HttpTransportType.WebSockets)
            {
                o.WebSocketFactory = async (context, cancellationToken) =>
                {
                    var socket = new ClientWebSocket();
                    if (currentIdentity is not null)
                        socket.Options.SetRequestHeader("Authorization", $"Bearer {TestJwt.CreateToken(currentIdentity)}");
                    await socket.ConnectAsync(context.Uri, cancellationToken);
                    return socket;
                };
            }
        });

        await using var connection = new HubConnectionBuilder()
            .WithUrl($"{address.TrimEnd('/')}/probe", options)
            .Build();

        try
        {
            await connection.StartAsync().WaitAsync(TimeSpan.FromSeconds(15));
            var expectedInitial = initialIdentity ?? "<anonymous>";
            var initial = await connection.InvokeAsync<string>("WhoAmI").WaitAsync(TimeSpan.FromSeconds(10));
            if (initial != expectedInitial)
                return new(CoverageStatus.Inconclusive,
                    $"{TransportName(transport)} {expectedInitial}->Bob: positive control returned '{initial}'.");

            currentIdentity = changedIdentity;

            try
            {
                var after = await connection.InvokeAsync<string>("WhoAmI").WaitAsync(TimeSpan.FromSeconds(10));
                if (after == changedIdentity)
                    return new(CoverageStatus.VulnerabilityReproduced,
                        $"{TransportName(transport)} {expectedInitial}->Bob: Hub observed Bob on the existing connection.");

                if (transport == HttpTransportType.WebSockets && after == expectedInitial)
                    return new(CoverageStatus.Passed,
                        $"WebSockets {expectedInitial}->Bob: existing socket remained bound to {expectedInitial}; no per-invocation HTTP authentication request exists.");

                if (transport != HttpTransportType.WebSockets &&
                    after == expectedInitial &&
                    Volatile.Read(ref bobRequestCount) > 0)
                    return new(CoverageStatus.Passed,
                        $"{TransportName(transport)} {expectedInitial}->Bob: Bob-authenticated HTTP request(s) were sent; Hub identity remained {expectedInitial}. HTTP statuses: {string.Join(",", bobResponseCodes)}.");

                return new(CoverageStatus.Inconclusive,
                    $"{TransportName(transport)} {expectedInitial}->Bob: invocation completed as '{after}', Bob-authenticated requests={Volatile.Read(ref bobRequestCount)}.");
            }
            catch (Exception ex)
            {
                var bobRequestWasSent = Volatile.Read(ref bobRequestCount) > 0;
                if (transport != HttpTransportType.WebSockets && bobRequestWasSent && IsForbidden(ex))
                    return new(CoverageStatus.Passed,
                        $"{TransportName(transport)} {expectedInitial}->Bob: changed-identity HTTP request rejected ({ex.GetType().Name}: {ex.Message}); HTTP statuses: {string.Join(",", bobResponseCodes)}.");

                return new(CoverageStatus.Inconclusive,
                    $"{TransportName(transport)} {expectedInitial}->Bob: request failed without a confirmed identity-binding 403 (Bob-authenticated request sent={bobRequestWasSent}): {ex.GetType().Name}: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            return new(CoverageStatus.Inconclusive,
                $"{TransportName(transport)} {initialIdentity ?? "<anonymous>"}->Bob: setup/positive control failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static async Task<CoverageCase> RunStatefulReconnectAsync(
        string address,
        SignalRLogCaptureProvider logs,
        string initialIdentity,
        string reconnectIdentity,
        bool expectRejection)
    {
        var currentIdentity = initialIdentity;
        ClientWebSocket? firstSocket = null;
        var connectCount = 0;
        var secondSocketCreated = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var connection = new HubConnectionBuilder()
            .WithUrl($"{address.TrimEnd('/')}/probe", HttpTransportType.WebSockets, options =>
            {
                options.AccessTokenProvider = () => Task.FromResult<string?>(TestJwt.CreateToken(currentIdentity));
                options.WebSocketFactory = async (context, cancellationToken) =>
                {
                    var socket = new ClientWebSocket();
                    socket.Options.SetRequestHeader("Authorization", $"Bearer {TestJwt.CreateToken(currentIdentity)}");
                    await socket.ConnectAsync(context.Uri, cancellationToken);
                    var count = Interlocked.Increment(ref connectCount);
                    if (count == 1)
                        firstSocket = socket;
                    else
                        secondSocketCreated.TrySetResult();
                    return socket;
                };
            })
            .WithStatefulReconnect()
            .Build();

        await using (connection)
        {
            try
            {
                await connection.StartAsync().WaitAsync(TimeSpan.FromSeconds(15));
                var originalConnectionId = connection.ConnectionId;
                var initial = await connection.InvokeAsync<string>("WhoAmI").WaitAsync(TimeSpan.FromSeconds(10));
                if (initial != initialIdentity)
                    return new(CoverageStatus.Inconclusive,
                        $"Stateful reconnect {initialIdentity}->{reconnectIdentity}: initial Hub identity was '{initial}'.");

                if (expectRejection)
                {
                    var rejectionTask = logs.WaitForUserNameChangedRejectedAsync(TimeSpan.FromSeconds(15));
                    currentIdentity = reconnectIdentity;
                    firstSocket!.Dispose();
                    var message = await rejectionTask;
                    if (message.Contains($"from '{initialIdentity}' to '{reconnectIdentity}'", StringComparison.Ordinal))
                        return new(CoverageStatus.Passed,
                            $"Stateful reconnect {initialIdentity}->{reconnectIdentity}: server rejected changed identity: {message}");

                    return new(CoverageStatus.Inconclusive,
                        $"Stateful reconnect {initialIdentity}->{reconnectIdentity}: rejection log did not contain the expected identity transition: {message}");
                }

                currentIdentity = reconnectIdentity;
                firstSocket!.Dispose();
                await secondSocketCreated.Task.WaitAsync(TimeSpan.FromSeconds(15));
                var deadline = DateTime.UtcNow.AddSeconds(15);
                while (DateTime.UtcNow < deadline)
                {
                    try
                    {
                        var after = await connection.InvokeAsync<string>("WhoAmI").WaitAsync(TimeSpan.FromSeconds(3));
                        if (after == reconnectIdentity && connection.ConnectionId == originalConnectionId)
                            return new(CoverageStatus.Passed,
                                $"Stateful reconnect {initialIdentity}->{reconnectIdentity}: same-user reconnect preserved connection ID and Hub identity.");

                        return new(CoverageStatus.Inconclusive,
                            $"Stateful reconnect {initialIdentity}->{reconnectIdentity}: after reconnect Hub saw '{after}', connection ID preserved={connection.ConnectionId == originalConnectionId}.");
                    }
                    catch (Exception)
                    {
                        await Task.Delay(100);
                    }
                }

                return new(CoverageStatus.Inconclusive,
                    $"Stateful reconnect {initialIdentity}->{reconnectIdentity}: same-user reconnect did not become invokable.");
            }
            catch (Exception ex)
            {
                return new(CoverageStatus.Inconclusive,
                    $"Stateful reconnect {initialIdentity}->{reconnectIdentity}: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    private static bool IsForbidden(Exception exception)
    {
        var message = exception.ToString();
        return message.Contains("403", StringComparison.OrdinalIgnoreCase)
            || message.Contains("Forbidden", StringComparison.OrdinalIgnoreCase)
            || message.Contains("user associated with this connection changed", StringComparison.OrdinalIgnoreCase);
    }

    private static string TransportName(HttpTransportType transport) => transport switch
    {
        HttpTransportType.WebSockets => "WebSockets",
        HttpTransportType.ServerSentEvents => "ServerSentEvents",
        HttpTransportType.LongPolling => "LongPolling",
        _ => transport.ToString()
    };
}

public enum CoverageStatus { Passed, VulnerabilityReproduced, Inconclusive }
public sealed record CoverageResult(CoverageStatus Status, string Detail);
public sealed record CoverageCase(CoverageStatus Status, string Detail);

public sealed class SignalRLogCaptureProvider : ILoggerProvider
{
    private readonly TaskCompletionSource<string> _userNameChangedRejected =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task<string> WaitForUserNameChangedRejectedAsync(TimeSpan timeout) =>
        _userNameChangedRejected.Task.WaitAsync(timeout);

    public ILogger CreateLogger(string categoryName) => new CaptureLogger(this);
    public void Dispose() { }

    private void Record(string message) => _userNameChangedRejected.TrySetResult(message);

    private sealed class CaptureLogger(SignalRLogCaptureProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (eventId.Name == "UserNameChangedRejected")
                owner.Record(formatter(state, exception));
        }
    }
}


public sealed class DynamicBearerHandler : DelegatingHandler
{
    private readonly Func<string?> _identityProvider;
    private readonly Action<int?> _observeBobResponse;

    public DynamicBearerHandler(
        HttpMessageHandler innerHandler,
        Func<string?> identityProvider,
        Action<int?> observeBobResponse) : base(innerHandler)
    {
        _identityProvider = identityProvider;
        _observeBobResponse = observeBobResponse;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var identity = _identityProvider();
        if (identity is null)
        {
            request.Headers.Authorization = null;
        }
        else
        {
            request.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", TestJwt.CreateToken(identity));
        }

        var response = await base.SendAsync(request, cancellationToken);
        if (identity == "Bob")
            _observeBobResponse((int)response.StatusCode);
        return response;
    }
}
