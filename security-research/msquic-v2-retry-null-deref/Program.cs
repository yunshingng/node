using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

internal static class Program
{
    private static readonly SslApplicationProtocol Alpn = new("msquic-v2-retry-e2e");
    private static readonly List<SslApplicationProtocol> Alpns = new() { Alpn };

    private static async Task<int> Main(string[] args)
    {
        Console.WriteLine($"RUNTIME={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"QUIC_SUPPORTED={QuicListener.IsSupported}");

        if (args.Length == 1 && args[0] == "--check-runtime")
        {
            if (!RuntimeInformation.FrameworkDescription.Contains("10.0.15", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The test must execute on .NET runtime 10.0.15.");
            }

            if (!QuicListener.IsSupported)
            {
                throw new InvalidOperationException("System.Net.Quic is not supported by the loaded native MsQuic.");
            }

            return 0;
        }

        if (args.Length == 0)
        {
            throw new ArgumentException("Expected: server <cert.pem> <key.pem> | client <marker-path>");
        }

        if (args[0] == "public-h3-client" && args.Length == 2)
        {
            await RunPublicH3ClientAsync(args[1]);
            return 0;
        }

        if (args[0] == "server" && args.Length == 3)
        {
            await RunServerAsync(args[1], args[2]);
            return 0;
        }

        if (args[0] == "client" && args.Length == 2)
        {
            await RunClientAsync(args[1]);
            return 0;
        }

        throw new ArgumentException("Invalid arguments.");
    }

    private static async Task RunServerAsync(string certificatePath, string privateKeyPath)
    {
        using X509Certificate2 certificate =
            X509Certificate2.CreateFromPemFile(certificatePath, privateKeyPath);

        var listenerOptions = new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Parse(Environment.GetEnvironmentVariable("QUIC_LISTEN_IP") ?? "127.0.0.1"), int.Parse(Environment.GetEnvironmentVariable("QUIC_LISTEN_PORT") ?? "4568")),
            ApplicationProtocols = Alpns,
            ConnectionOptionsCallback = (_, _, _) =>
                ValueTask.FromResult(new QuicServerConnectionOptions
                {
                    DefaultStreamErrorCode = 0x100,
                    DefaultCloseErrorCode = 0x101,
                    ServerAuthenticationOptions = new SslServerAuthenticationOptions
                    {
                        ApplicationProtocols = Alpns,
                        ServerCertificate = certificate
                    }
                })
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Console.WriteLine($"SERVER_LISTENING={listener.LocalEndPoint}");

        await using QuicConnection connection = await listener.AcceptConnectionAsync();
        Console.WriteLine("SERVER_CONNECTED");
        Console.WriteLine($"SERVER_CLIENT_REMOTE={connection.RemoteEndPoint}");

        await using QuicStream stream = await connection.AcceptInboundStreamAsync();
        byte[] request = new byte[1024];
        while (await stream.ReadAsync(request) != 0)
        {
        }

        byte[] payload = new byte[1000];
        for (int i = 0; i < 300; i++)
        {
            Random.Shared.NextBytes(payload);
            try
            {
                await stream.WriteAsync(payload);
            }
            catch (QuicException ex)
            {
                Console.WriteLine($"SERVER_WRITE_STOPPED={ex.QuicError}");
                return;
            }

            await Task.Delay(100);
        }

        stream.CompleteWrites();
        Console.WriteLine("SERVER_STREAM_FINISHED");
        await Task.Delay(500);
    }

    private static async Task RunClientAsync(string markerPath)
    {
        var clientOptions = new QuicClientConnectionOptions
        {
            DefaultStreamErrorCode = 0x200,
            DefaultCloseErrorCode = 0x201,
            RemoteEndPoint = new IPEndPoint(IPAddress.Parse(Environment.GetEnvironmentVariable("QUIC_REMOTE_IP") ?? "127.0.0.1"), int.Parse(Environment.GetEnvironmentVariable("QUIC_REMOTE_PORT") ?? "4567")),
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                ApplicationProtocols = Alpns
            }
        };

        await using QuicConnection connection = await QuicConnection.ConnectAsync(clientOptions);
        Console.WriteLine($"CLIENT_CONNECTED={connection.RemoteEndPoint}");
        Console.WriteLine($"CLIENT_LOCAL={connection.LocalEndPoint}");

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(markerPath))!);
        File.WriteAllText(markerPath, DateTimeOffset.UtcNow.ToString("O"));

        await using QuicStream stream =
            await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        await stream.WriteAsync(Encoding.ASCII.GetBytes("post-handshake-ready"));
        stream.CompleteWrites();

        byte[] buffer = new byte[2048];
        long received = 0;
        while (true)
        {
            int count = await stream.ReadAsync(buffer);
            if (count == 0)
            {
                break;
            }

            received += count;
        }

        Console.WriteLine($"CLIENT_STREAM_EOF bytes={received}");
        await Task.Delay(250);
    }

    private static async Task RunPublicH3ClientAsync(string markerPath)
    {
        const string host = "cloudflare-quic.com";
        int localPort = int.Parse(Environment.GetEnvironmentVariable("QUIC_LOCAL_PORT") ?? "45678");
        IPAddress remoteIp = IPAddress.Parse(Environment.GetEnvironmentVariable("QUIC_REMOTE_IP")
            ?? throw new InvalidOperationException("QUIC_REMOTE_IP is required."));
        var h3 = new SslApplicationProtocol("h3");
        var options = new QuicClientConnectionOptions
        {
            LocalEndPoint = new IPEndPoint(IPAddress.Any, localPort),
            RemoteEndPoint = new IPEndPoint(remoteIp, 443),
            DefaultStreamErrorCode = 0x200,
            DefaultCloseErrorCode = 0x201,
            KeepAliveInterval = TimeSpan.FromSeconds(1),
            IdleTimeout = TimeSpan.FromMinutes(3),
            MaxInboundUnidirectionalStreams = 16,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                ApplicationProtocols = new List<SslApplicationProtocol> { h3 }
            }
        };

        await using QuicConnection connection = await QuicConnection.ConnectAsync(options);
        Console.WriteLine($"CLIENT_CONNECTED={connection.RemoteEndPoint}");
        Console.WriteLine($"CLIENT_LOCAL={connection.LocalEndPoint}");
        Console.WriteLine($"CLIENT_ALPN={connection.NegotiatedApplicationProtocol}");

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(markerPath))!);
        File.WriteAllText(markerPath, DateTimeOffset.UtcNow.ToString("O"));

        // HTTP/3 control stream: stream type 0x00, then an empty SETTINGS frame.
        var control = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional);
        await control.WriteAsync(new byte[] { 0x00, 0x04, 0x00 });

        // QPACK encoder and decoder streams. Their static-only configuration
        // uses the default zero dynamic-table capacity and zero blocked streams.
        var encoder = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional);
        await encoder.WriteAsync(new byte[] { 0x02 });
        var decoder = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional);
        await decoder.WriteAsync(new byte[] { 0x03 });

        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        Task acceptTask = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    QuicStream inbound = await connection.AcceptInboundStreamAsync(stop.Token);
                    _ = Task.Run(async () =>
                    {
                        await using (inbound)
                        {
                            byte[] input = new byte[4096];
                            try
                            {
                                while (await inbound.ReadAsync(input, stop.Token) != 0) { }
                            }
                            catch (OperationCanceledException) { }
                            catch (QuicException) { }
                        }
                    });
                }
                catch (OperationCanceledException) { break; }
                catch (QuicException) { break; }
                catch (ObjectDisposedException) { break; }
            }
        });

        byte[] authority = Encoding.ASCII.GetBytes(host);
        var qpack = new List<byte> { 0x00, 0x00, 0xD1, 0xD7, 0x50, checked((byte)authority.Length) };
        qpack.AddRange(authority);
        qpack.Add(0xC1);
        var h3Headers = new List<byte> { 0x01, checked((byte)qpack.Count) };
        h3Headers.AddRange(qpack);

        int request = 0;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                await using QuicStream stream =
                    await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, stop.Token);
                await stream.WriteAsync(h3Headers.ToArray(), stop.Token);
                stream.CompleteWrites();

                byte[] response = new byte[8192];
                long received = 0;
                while (true)
                {
                    int count = await stream.ReadAsync(response, stop.Token);
                    if (count == 0) break;
                    received += count;
                }
                Console.WriteLine($"HTTP3_GET_{request}_RESPONSE_BYTES={received}");
            }
            catch (OperationCanceledException) { break; }
            catch (QuicException ex)
            {
                Console.WriteLine($"HTTP3_REQUEST_STOPPED={ex.QuicError}");
                break;
            }

            request++;
            await Task.Delay(500, stop.Token).ContinueWith(_ => { });
        }

        stop.Cancel();
        try { await acceptTask; } catch (OperationCanceledException) { }
        Console.WriteLine($"HTTP3_REQUESTS_COMPLETED={request}");
    }

}
