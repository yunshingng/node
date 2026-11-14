using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.SignalR;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:0");
builder.Services.AddSignalR();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => options.TokenValidationParameters = TestJwt.ValidationParameters);
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Use(async (context, next) =>
{
    Console.WriteLine($"REQUEST {context.Request.Method} {context.Request.Path}: name={context.User.Identity?.Name ?? "<null>"}; nameId={context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "<null>"}");
    await next();
});
app.MapHub<IdentityProbeHub>("/probe", options => options.EnableAuthenticationRefresh = true);
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
    Print("CONTROL Alice negotiate / Alice attach / Alice send", control);
    if (control.Status != ScenarioStatus.Completed || control.Identity != "Alice")
    {
        Console.WriteLine("INCONCLUSIVE: positive control failed; candidate results are not reliable.");
        Environment.ExitCode = 2;
        return;
    }

    // Keep the connection identity stable through negotiation and initial attach.
    // Change it only on the subsequent POST carrying the Hub invocation.
    var authenticatedSwitch = await RunScenario(client, address, "Alice", "Bob", "Alice");
    Print("AUTHENTICATED Alice negotiate / Alice attach / Bob send", authenticatedSwitch);

    // Also test the null-to-authenticated transition after an anonymous attach.
    var anonymousSwitch = await RunScenario(client, address, "", "Bob", "");
    Print("ANONYMOUS negotiate / anonymous attach / Bob send", anonymousSwitch);

    // Separate control: identity changes during initial attach, before Hub send.
    var attachSwitch = await RunScenario(client, address, "Alice", "Alice", "Bob");
    Print("ATTACH SWITCH Alice negotiate / Bob attach / Alice send", attachSwitch);

    // .NET 11 authentication refresh endpoint: verify changed user is rejected
    // and the existing connection retains Alice after a rejected refresh.
    var refreshChanged = await RunRefreshScenario(client, address, "Alice", "Bob");
    Console.WriteLine($"REFRESH Alice connection / Bob refresh: HTTP {refreshChanged.RefreshStatus}; Hub after refresh saw: {refreshChanged.Identity ?? "<none>"}; {refreshChanged.Detail ?? ""}");

    // Positive control: refreshing credentials for the same user should succeed.
    var refreshSame = await RunRefreshScenario(client, address, "Alice", "Alice");
    Console.WriteLine($"REFRESH Alice connection / Alice refresh: HTTP {refreshSame.RefreshStatus}; Hub after refresh saw: {refreshSame.Identity ?? "<none>"}; {refreshSame.Detail ?? ""}");

    var candidates = new[]
    {
        ("authenticated send switch", authenticatedSwitch),
        ("anonymous send switch", anonymousSwitch),
        ("initial attach switch", attachSwitch)
    };

    var reproduced = candidates.FirstOrDefault(x =>
        x.Item2.Status == ScenarioStatus.Completed && x.Item2.Identity == "Bob");
    if (reproduced.Item2 is not null)
    {
        Console.WriteLine($"VULNERABILITY_REPRODUCED: {reproduced.Item1}; Hub observed Bob.");
        Environment.ExitCode = 0;
    }
    else if (candidates.Any(x => x.Item2.Status == ScenarioStatus.NoCompletion))
    {
        Console.WriteLine("INCONCLUSIVE: at least one candidate did not produce a definitive response.");
        Environment.ExitCode = 2;
    }
    else if (refreshChanged.RefreshStatus == 403 &&
             refreshChanged.Identity == "Alice" &&
             refreshSame.RefreshStatus >= 200 && refreshSame.RefreshStatus < 300 &&
             refreshSame.Identity == "Alice")
    {
        Console.WriteLine("NOT_REPRODUCED: send-time identity switches and cross-user authentication refresh were rejected; same-user refresh succeeded and Hub remained Alice.");
        Environment.ExitCode = 0;
    }
    else
    {
        Console.WriteLine("INCONCLUSIVE: refresh behavior did not match expected identity-binding controls.");
        Environment.ExitCode = 2;
    }
}
finally
{
    await app.StopAsync();
}

static void Print(string label, ScenarioResult result) =>
    Console.WriteLine($"{label}: {result.Status}; Hub saw: {result.Identity ?? "<none>"}; {result.Detail ?? ""}");

static async Task<ScenarioResult> RunScenario(
    HttpClient client, string baseAddress,
    string negotiateIdentity, string sendIdentity, string attachIdentity)
{
    var root = baseAddress.TrimEnd('/');
    using var negotiate = new HttpRequestMessage(HttpMethod.Post, $"{root}/probe/negotiate?negotiateVersion=1");
    if (!string.IsNullOrWhiteSpace(negotiateIdentity))
        TestJwt.AddIdentity(negotiate, negotiateIdentity);
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
        if (!string.IsNullOrWhiteSpace(attachIdentity))
            TestJwt.AddIdentity(attach, attachIdentity);
        using var attachResponse = await client.SendAsync(attach);
        if (!attachResponse.IsSuccessStatusCode)
            return new(ScenarioStatus.Rejected, null, $"Initial attach HTTP {(int)attachResponse.StatusCode}: {await attachResponse.Content.ReadAsStringAsync()}");
    }

    const char rs = '\u001e';
    var frames = "{\"protocol\":\"json\",\"version\":1}" + rs +
                 "{\"type\":1,\"invocationId\":\"identity-check-1\",\"target\":\"WhoAmI\",\"arguments\":[]}" + rs;
    using (var send = new HttpRequestMessage(HttpMethod.Post, $"{root}/probe?id={Uri.EscapeDataString(token)}"))
    {
        if (!string.IsNullOrWhiteSpace(sendIdentity))
            TestJwt.AddIdentity(send, sendIdentity);
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
        if (!string.IsNullOrWhiteSpace(attachIdentity))
            TestJwt.AddIdentity(poll, attachIdentity);
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


static async Task<RefreshScenarioResult> RunRefreshScenario(
    HttpClient client, string baseAddress, string initialIdentity, string refreshIdentity)
{
    var root = baseAddress.TrimEnd('/');
    using var negotiate = new HttpRequestMessage(HttpMethod.Post, $"{root}/probe/negotiate?negotiateVersion=1");
    TestJwt.AddIdentity(negotiate, initialIdentity);
    using var negotiateResponse = await client.SendAsync(negotiate);
    var negotiateBody = await negotiateResponse.Content.ReadAsStringAsync();
    if (!negotiateResponse.IsSuccessStatusCode)
        return new((int)negotiateResponse.StatusCode, null, $"Negotiate failed: {negotiateBody}");

    using var json = JsonDocument.Parse(negotiateBody);
    var token = json.RootElement.GetProperty("connectionToken").GetString();
    if (string.IsNullOrWhiteSpace(token))
        return new(0, null, "Missing connectionToken.");

    using (var attach = new HttpRequestMessage(HttpMethod.Get, $"{root}/probe?id={Uri.EscapeDataString(token)}"))
    {
        TestJwt.AddIdentity(attach, initialIdentity);
        using var response = await client.SendAsync(attach);
        if (!response.IsSuccessStatusCode)
            return new((int)response.StatusCode, null, $"Initial attach failed: {await response.Content.ReadAsStringAsync()}");
    }

    int refreshStatus;
    using (var refresh = new HttpRequestMessage(HttpMethod.Post, $"{root}/probe/refresh"))
    {
        refresh.Headers.Add("X-SignalR-Connection-Token", token);
        TestJwt.AddIdentity(refresh, refreshIdentity);
        using var response = await client.SendAsync(refresh);
        refreshStatus = (int)response.StatusCode;
        if (!response.IsSuccessStatusCode && refreshStatus != 403)
            return new(refreshStatus, null, $"Unexpected refresh response: {await response.Content.ReadAsStringAsync()}");
    }

    // Invoke as the original identity. A rejected refresh must leave the
    // connection principal unchanged.
    const char rs = '\u001e';
    var frames = "{\"protocol\":\"json\",\"version\":1}" + rs +
                 "{\"type\":1,\"invocationId\":\"refresh-check-1\",\"target\":\"WhoAmI\",\"arguments\":[]}" + rs;
    using (var send = new HttpRequestMessage(HttpMethod.Post, $"{root}/probe?id={Uri.EscapeDataString(token)}"))
    {
        TestJwt.AddIdentity(send, initialIdentity);
        send.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(frames));
        send.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var response = await client.SendAsync(send);
        if (!response.IsSuccessStatusCode)
            return new(refreshStatus, null, $"Post-refresh invocation rejected: {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    var deadline = DateTime.UtcNow.AddSeconds(10);
    while (DateTime.UtcNow < deadline)
    {
        using var poll = new HttpRequestMessage(HttpMethod.Get, $"{root}/probe?id={Uri.EscapeDataString(token)}");
        TestJwt.AddIdentity(poll, initialIdentity);
        using var response = await client.SendAsync(poll);
        if (!response.IsSuccessStatusCode)
            return new(refreshStatus, null, $"Post-refresh poll rejected: {(int)response.StatusCode}");
        var body = await response.Content.ReadAsStringAsync();
        foreach (var frame in body.Split(rs, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                using var message = JsonDocument.Parse(frame);
                var obj = message.RootElement;
                if (obj.TryGetProperty("type", out var type) && type.GetInt32() == 3 &&
                    obj.TryGetProperty("invocationId", out var id) && id.GetString() == "refresh-check-1" &&
                    obj.TryGetProperty("result", out var result))
                    return new(refreshStatus, result.GetString(), null);
            }
            catch (JsonException) { }
        }
        await Task.Delay(50);
    }

    return new(refreshStatus, null, "No post-refresh Hub invocation completion within 10 seconds.");
}


public static class TestJwt
{
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("signalr-identity-binding-poc-key-2026");

    public static TokenValidationParameters ValidationParameters => new()
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Key),
        NameClaimType = ClaimTypes.Name,
        RoleClaimType = ClaimTypes.Role,
        ClockSkew = TimeSpan.Zero
    };

    public static void AddIdentity(HttpRequestMessage request, string identity)
    {
        if (!string.IsNullOrWhiteSpace(identity))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken(identity));
    }

    private static string CreateToken(string identity)
    {
        static string Encode(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var header = Encode(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
        var payload = Encode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            sub = identity,
            name = identity,
            exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds()
        }));
        var input = header + "." + payload;
        var signature = HMACSHA256.HashData(Key, Encoding.ASCII.GetBytes(input));
        return input + "." + Encode(signature);
    }
}

public sealed record RefreshScenarioResult(int RefreshStatus, string? Identity, string? Detail);

public sealed class IdentityProbeHub : Hub
{
    public string WhoAmI() => Context.User?.Identity?.Name ?? "<anonymous>";
}

public enum ScenarioStatus { Completed, Rejected, NoCompletion }
public sealed record ScenarioResult(ScenarioStatus Status, string? Identity, string? Detail);
