// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Net;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

internal static class LocalRpcCollection
{
    internal const string Name = "LocalRpc process-wide state";
}

/// <summary>A generated LocalBootstrap service that records dispatch; it echoes the challenge bytes.</summary>
internal sealed class RecordingBootstrapService : LocalBootstrapService.LocalBootstrapServiceBase
{
    private int _dispatched;

    internal int Dispatched => Volatile.Read(ref _dispatched);

    internal TaskCompletionSource CancellationObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public override async Task<LocalBootstrapServiceChallengeResponse> Challenge(
        LocalBootstrapServiceChallengeRequest request,
        ServerCallContext context)
    {
        Interlocked.Increment(ref _dispatched);
        if (request.Challenge.Length > 0 && request.Challenge[0] == 0xEE)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, context.CancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
            {
                CancellationObserved.TrySetResult();
                throw;
            }
        }

        if (request.Challenge.Length > 0 && request.Challenge[0] == 0xBB)
        {
            throw new InvalidOperationException("secret-detail-must-not-leave-the-process");
        }

        var echoed = request.Challenge.Length > 0 && request.Challenge[0] == 0xAA
            ? ByteString.CopyFrom(new byte[128 * 1024])
            : request.Challenge;
        return new LocalBootstrapServiceChallengeResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new LocalBootstrapServiceChallengeValue { ServerChallenge = echoed },
        };
    }
}

internal static class Requests
{
    internal static LocalBootstrapServiceChallengeRequest Challenge(int bytes, byte first = 0x01)
    {
        var payload = new byte[bytes];
        if (bytes > 0)
        {
            payload[0] = first;
        }

        return new LocalBootstrapServiceChallengeRequest
        {
            Meta = new RequestMeta { CorrelationId = NewId(), CommandId = NewId() },
            Challenge = ByteString.CopyFrom(payload),
        };
    }

    /// <summary>A valid, serialized request frame; gzip-compressed when <paramref name="gzip"/> is set.</summary>
    internal static byte[] Frame(int challengeBytes, bool gzip)
    {
        var message = Challenge(challengeBytes).ToByteArray();
        if (gzip)
        {
            using var output = new MemoryStream();
            using (var compressor = new System.IO.Compression.GZipStream(output, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
            {
                compressor.Write(message);
            }

            message = output.ToArray();
        }

        var frame = new byte[5 + message.Length];
        frame[0] = gzip ? (byte)1 : (byte)0;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), (uint)message.Length);
        message.CopyTo(frame, 5);
        return frame;
    }

    internal static string ChallengePath => $"/{LocalBootstrapService.Descriptor.FullName}/Challenge";

    private static Id NewId() => new() { Value = ByteString.CopyFrom(Guid.NewGuid().ToByteArray()) };
}

/// <summary>A server over supplied in-memory streams plus the means to open client connections to it.</summary>
internal sealed class SuppliedHarness : IAsyncDisposable
{
    private int _connects;

    private SuppliedHarness(LocalRpcStreamSupplier supplier, RecordingBootstrapService service, LocalRpcServer server)
    {
        Supplier = supplier;
        Service = service;
        Server = server;
    }

    internal LocalRpcStreamSupplier Supplier { get; }

    internal RecordingBootstrapService Service { get; }

    internal LocalRpcServer Server { get; }

    internal int Connects => Volatile.Read(ref _connects);

    internal static async Task<SuppliedHarness> StartAsync(
        Action<LocalRpcServerBuilder>? configure = null,
        CancellationToken cancellationToken = default)
    {
        var supplier = new LocalRpcStreamSupplier();
        var service = new RecordingBootstrapService();
        var builder = LocalRpcServer.CreateBuilder(supplier).AddService(service);
        configure?.Invoke(builder);
        var server = builder.Build();
        await server.StartAsync(cancellationToken).ConfigureAwait(false);
        return new SuppliedHarness(supplier, service, server);
    }

    /// <summary>Supplies a fresh connected pair to the server and returns the client end.</summary>
    internal Stream NewClientStream()
    {
        var (client, server) = InMemoryDuplexStream.CreatePair();
        if (!Supplier.TrySupply(server))
        {
            server.Dispose();
            client.Dispose();
            throw new InvalidOperationException("The supplier refused a stream.");
        }

        Interlocked.Increment(ref _connects);
        return client;
    }

    internal LocalRpcClientChannel NewChannel(LocalRpcLimits? limits = null) =>
        LocalRpcClientChannel.CreateFromStreams(_ => ValueTask.FromResult(NewClientStream()), limits);

    public ValueTask DisposeAsync() => Server.DisposeAsync();
}

/// <summary>Raw HTTP/2 and gRPC frame builders and readers that bypass every well-behaved client.</summary>
internal static class RawFrames
{
    internal static readonly byte[] Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    internal static byte[] Frame(int length, byte type, byte flags, int streamId, byte[]? payload = null)
    {
        var frame = new byte[9 + (payload?.Length ?? 0)];
        frame[0] = (byte)(length >> 16);
        frame[1] = (byte)(length >> 8);
        frame[2] = (byte)length;
        frame[3] = type;
        frame[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(5), streamId);
        payload?.CopyTo(frame, 9);
        return frame;
    }

    internal static byte[] Concat(params byte[][] parts) => [.. parts.SelectMany(part => part)];

    internal static byte[] GrpcMessage(byte flag, uint declaredLength, int actualBytes)
    {
        var message = new byte[5 + actualBytes];
        message[0] = flag;
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(1), declaredLength);
        return message;
    }

    /// <summary>Reads HTTP/2 frames until the peer closes the stream. Fails if it stays open past the timeout.</summary>
    internal static async Task<List<(byte Type, int StreamId, byte[] Payload)>> ReadUntilClosedAsync(
        Stream stream,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(timeout);
        var frames = new List<(byte, int, byte[])>();
        var header = new byte[9];
        try
        {
            while (await ReadExactlyOrEndAsync(stream, header, bounded.Token).ConfigureAwait(false))
            {
                var length = (header[0] << 16) | (header[1] << 8) | header[2];
                var payload = new byte[length];
                if (!await ReadExactlyOrEndAsync(stream, payload, bounded.Token).ConfigureAwait(false))
                {
                    break;
                }

                frames.Add((header[3], BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5)) & 0x7FFFFFFF, payload));
            }
        }
        catch (IOException)
        {
            // A reset connection is a closed connection.
        }
        catch (OperationCanceledException) when (bounded.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The server kept the connection open after a malformed frame.");
        }

        return frames;
    }

    private static async Task<bool> ReadExactlyOrEndAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                return false;
            }

            read += count;
        }

        return true;
    }

    /// <summary>The GOAWAY error code the peer sent before closing, or null if it sent no GOAWAY.</summary>
    internal static int? GoAwayCode(IEnumerable<(byte Type, int StreamId, byte[] Payload)> frames)
    {
        foreach (var (type, _, payload) in frames)
        {
            if (type == 0x7 && payload.Length >= 8)
            {
                return BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(4));
            }
        }

        return null;
    }
}

/// <summary>Posts a hand-built gRPC body over any verified stream and reads the grpc-status the server answers.</summary>
internal static class RawGrpc
{
    internal static async Task<StatusCode> PostAsync(
        Func<CancellationToken, ValueTask<Stream>> openStream,
        string path,
        byte[] body,
        string? encoding,
        CancellationToken cancellationToken)
    {
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            EnableMultipleHttp2Connections = false,
            ConnectCallback = async (_, token) => await openStream(token).ConfigureAwait(false),
        };
        using var client = new HttpClient(handler);
        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc");
        using var request = new HttpRequestMessage(HttpMethod.Post, "http://arcforges.invalid" + path)
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = content,
        };
        request.Headers.TryAddWithoutValidation("te", "trailers");
        if (encoding is not null)
        {
            request.Headers.TryAddWithoutValidation("grpc-encoding", encoding);
        }

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        _ = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var status = Find(response.TrailingHeaders, "grpc-status") ?? Find(response.Headers, "grpc-status")
            ?? throw new InvalidOperationException("The server answered without a grpc-status.");
        return (StatusCode)int.Parse(status, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string? Find(System.Net.Http.Headers.HttpHeaders headers, string name) =>
        headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;
}
