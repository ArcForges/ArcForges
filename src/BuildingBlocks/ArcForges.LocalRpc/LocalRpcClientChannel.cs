// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Principal;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;
using Grpc.Net.Compression;

namespace ArcForges.LocalRpc;

/// <summary>
/// A generated-client channel whose only connection source is a verified OS stream. The HTTP authority is the
/// non-resolvable <c>http://arcforges.invalid</c>; the connect callback never falls back to DNS or TCP, the
/// channel keeps one HTTP/2 connection, and it never retries, hedges or recycles connections by itself.
/// </summary>
public sealed class LocalRpcClientChannel : IAsyncDisposable
{
    internal const string Authority = "http://arcforges.invalid";

    private readonly GrpcChannel _channel;

    private LocalRpcClientChannel(GrpcChannel channel)
    {
        _channel = channel;
        CallInvoker = channel.CreateCallInvoker().Intercept(new LocalRpcCallbackInterceptor());
    }

    /// <summary>The invoker generated clients are constructed over.</summary>
    public CallInvoker CallInvoker { get; }

    /// <summary>Creates a channel that connects to one private endpoint.</summary>
    public static LocalRpcClientChannel Create(LocalRpcEndpoint endpoint, LocalRpcLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var bounds = (limits ?? new LocalRpcLimits()).Validated();
        return new LocalRpcClientChannel(CreateGrpcChannel(
            (cancellationToken) => ConnectAsync(endpoint, bounds.ConnectTimeout, cancellationToken), bounds));
    }

    /// <summary>
    /// Creates a channel over a stream source the launcher owns, for example the connected end of a pair it
    /// provisioned. The callback is invoked once per HTTP/2 connection and must return a verified duplex stream.
    /// </summary>
    public static LocalRpcClientChannel CreateFromStreams(
        Func<CancellationToken, ValueTask<Stream>> openStream,
        LocalRpcLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(openStream);
        var bounds = (limits ?? new LocalRpcLimits()).Validated();
        return new LocalRpcClientChannel(CreateGrpcChannel(openStream, bounds));
    }

    /// <summary>Completes in-flight calls' resources and closes the OS stream.</summary>
    public async ValueTask DisposeAsync()
    {
        try
        {
            await _channel.ShutdownAsync().ConfigureAwait(false);
        }
        finally
        {
            _channel.Dispose();
        }
    }

    private static GrpcChannel CreateGrpcChannel(Func<CancellationToken, ValueTask<Stream>> openStream, LocalRpcLimits limits)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            EnableMultipleHttp2Connections = false,
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            ConnectTimeout = limits.ConnectTimeout,
            ConnectCallback = async (_, cancellationToken) => await openStream(cancellationToken).ConfigureAwait(false),
        };
        return GrpcChannel.ForAddress(Authority, new GrpcChannelOptions
        {
            HttpHandler = handler,
            DisposeHttpClient = true,
            MaxReceiveMessageSize = limits.MaxMessageBytes,
            MaxSendMessageSize = limits.MaxMessageBytes,
            MaxRetryAttempts = null,
            ServiceConfig = null,
            CompressionProviders = new List<ICompressionProvider>(),
        });
    }

    private static async ValueTask<Stream> ConnectAsync(LocalRpcEndpoint endpoint, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(timeout);
        return endpoint.Transport switch
        {
            LocalRpcTransport.NamedPipe => await ConnectNamedPipeAsync(endpoint.Address, bounded.Token).ConfigureAwait(false),
            LocalRpcTransport.UnixDomainSocket => await ConnectUnixSocketAsync(endpoint.Address, bounded.Token).ConfigureAwait(false),
            _ => throw new InvalidOperationException("A local RPC endpoint names exactly one private stream transport."),
        };
    }

    private static async ValueTask<Stream> ConnectNamedPipeAsync(string name, CancellationToken cancellationToken)
    {
        // CurrentUserOnly makes the runtime verify that the server end is owned by this user after connecting.
        var pipe = new NamedPipeClientStream(
            ".",
            name,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            TokenImpersonationLevel.Anonymous);
        try
        {
            await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return pipe;
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the connected socket passes to the returned stream; failures dispose it.")]
    private static async ValueTask<Stream> ConnectUnixSocketAsync(string path, CancellationToken cancellationToken)
    {
        UnixSocketAcceptSource.RequireOwnerOnlyDirectory(path);
        if (new FileInfo(path).LinkTarget is not null)
        {
            throw new UnauthorizedAccessException("A Unix socket endpoint is never a symbolic link.");
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
