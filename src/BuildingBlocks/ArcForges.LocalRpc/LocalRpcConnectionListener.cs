// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Connections;

namespace ArcForges.LocalRpc;

/// <summary>Describes one accepted connection to the authorization decision, before any byte is read from it.</summary>
public sealed record LocalRpcConnectionInfo(LocalRpcTransport Transport, long Sequence);

/// <summary>The Kestrel endpoint that selects this transport. It carries the owner's listener recipe.</summary>
internal sealed class LocalRpcListenEndPoint : EndPoint
{
    internal LocalRpcListenEndPoint(
        LocalRpcEndpoint? endpoint,
        LocalRpcStreamSupplier? supplier,
        LocalRpcLimits limits,
        Func<LocalRpcConnectionInfo, bool>? authorizer)
    {
        Endpoint = endpoint;
        Supplier = supplier;
        Limits = limits;
        Authorizer = authorizer;
    }

    internal LocalRpcEndpoint? Endpoint { get; }

    internal LocalRpcStreamSupplier? Supplier { get; }

    internal LocalRpcLimits Limits { get; }

    internal Func<LocalRpcConnectionInfo, bool>? Authorizer { get; }

    internal LocalRpcTransport Transport => Endpoint?.Transport ?? (OperatingSystem.IsWindows()
        ? LocalRpcTransport.NamedPipe : LocalRpcTransport.UnixDomainSocket);

    public override AddressFamily AddressFamily => AddressFamily.Unspecified;

    public override string ToString() => Endpoint is null
        ? "localrpc:supplied-streams"
        : $"localrpc:{Endpoint.Transport}:{Endpoint.Address}";
}

/// <summary>
/// The only <see cref="IConnectionListenerFactory"/> a server registers: it can bind nothing but
/// <see cref="LocalRpcListenEndPoint"/>, so an IP, loopback or port endpoint cannot be listened on.
/// </summary>
internal sealed class LocalRpcConnectionListenerFactory : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    public bool CanBind(EndPoint endpoint) => endpoint is LocalRpcListenEndPoint;

    [SuppressMessage("Reliability", "CA2000", Justification = "The listener owns the accept source and Kestrel disposes the listener.")]
    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not LocalRpcListenEndPoint local)
        {
            throw new NotSupportedException("Only private local RPC endpoints can be bound.");
        }

        IStreamAcceptSource source;
        if (local.Supplier is { } supplier)
        {
            source = new SuppliedStreamAcceptSource(supplier);
        }
        else if (local.Endpoint is { Transport: LocalRpcTransport.NamedPipe } pipe)
        {
            source = NamedPipeAcceptSource.Bind(pipe.Address);
        }
        else if (local.Endpoint is { Transport: LocalRpcTransport.UnixDomainSocket } socket)
        {
            source = UnixSocketAcceptSource.Bind(socket.Address, LocalRpcConnectionListener.Backlog);
        }
        else
        {
            throw new NotSupportedException("A local RPC endpoint names exactly one private stream transport.");
        }

        return ValueTask.FromResult<IConnectionListener>(new LocalRpcConnectionListener(local, source));
    }
}

/// <summary>
/// Accepts connected streams, applies the connection authorizer and hands HTTP/2 only authorized ones. At most
/// <see cref="LocalRpcLimits.MaxConnections"/> connections are served at once: the listener waits for a free slot
/// before it accepts, so an extra peer waits in the OS backlog instead of being reset, and a slot is freed only when
/// the previous connection has been fully torn down.
/// </summary>
internal sealed class LocalRpcConnectionListener : IConnectionListener
{
    /// <summary>Pending OS connections allowed to wait for a slot; independent of the connection bound.</summary>
    internal const int Backlog = 16;

    private readonly LocalRpcListenEndPoint _endPoint;
    private readonly IStreamAcceptSource _source;
    private readonly SemaphoreSlim _slots;
    private readonly CancellationTokenSource _stop = new();
    private long _sequence;

    internal LocalRpcConnectionListener(LocalRpcListenEndPoint endPoint, IStreamAcceptSource source)
    {
        _endPoint = endPoint;
        _source = source;
        _slots = new SemaphoreSlim(endPoint.Limits.MaxConnections, endPoint.Limits.MaxConnections);
    }

    public EndPoint EndPoint => _endPoint;

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        try
        {
            while (true)
            {
                await _slots.WaitAsync(linked.Token).ConfigureAwait(false);
                var handedOver = false;
                try
                {
                    var stream = await _source.AcceptAsync(linked.Token).ConfigureAwait(false);
                    if (stream is null)
                    {
                        return null;
                    }

                    var sequence = Interlocked.Increment(ref _sequence);
                    if (!Authorize(new LocalRpcConnectionInfo(_endPoint.Transport, sequence)))
                    {
                        // Fail closed: an unauthorized peer receives no byte and its stream is dropped without being read.
                        await stream.DisposeAsync().ConfigureAwait(false);
                        continue;
                    }

                    handedOver = true;
                    return new StreamConnectionContext($"localrpc-{sequence}", stream, _endPoint, ReleaseSlot);
                }
                finally
                {
                    if (!handedOver)
                    {
                        ReleaseSlot();
                    }
                }
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException)
        {
            return null;
        }
    }

    public async ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        await _source.UnbindAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await UnbindAsync().ConfigureAwait(false);
        await _source.DisposeAsync().ConfigureAwait(false);
        _stop.Dispose();
        _slots.Dispose();
    }

    private void ReleaseSlot()
    {
        try
        {
            _ = _slots.Release();
        }
        catch (ObjectDisposedException)
        {
            // The listener was disposed while a connection was still tearing down.
        }
        catch (SemaphoreFullException)
        {
            // Never raised by a once-only release; kept so a teardown race cannot fault Kestrel.
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "A throwing authorizer must deny rather than expose an unauthenticated connection.")]
    private bool Authorize(LocalRpcConnectionInfo connection)
    {
        if (_endPoint.Authorizer is not { } authorizer)
        {
            return true;
        }

        try
        {
            return authorizer(connection);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return false;
        }
    }
}
