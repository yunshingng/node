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
}
