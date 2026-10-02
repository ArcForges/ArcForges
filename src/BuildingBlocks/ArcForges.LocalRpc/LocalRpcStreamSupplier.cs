// SPDX-License-Identifier: AGPL-3.0-only
using System.Threading.Channels;

namespace ArcForges.LocalRpc;

/// <summary>
/// The only way a launcher hands already-connected OS streams (a parent-created pipe end or an inherited
/// connected Unix socket) to a server. The server accepts nothing but streams supplied here.
/// </summary>
public sealed class LocalRpcStreamSupplier
{
    private const int Capacity = 8;
    private readonly Channel<Stream> _streams = Channel.CreateBounded<Stream>(new BoundedChannelOptions(Capacity)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.Wait,
    });

    private int _claimed;

    /// <summary>
    /// Offers a connected duplex stream. Returns true when the server now owns it; on false the caller keeps
    /// ownership (the supplier is completed, or too many streams wait to be accepted).
    /// </summary>
    public bool TrySupply(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanWrite)
        {
            throw new ArgumentException("A supplied stream must be readable and writable.", nameof(stream));
        }

        return _streams.Writer.TryWrite(stream);
    }

    /// <summary>States that no further stream will be supplied; the server stops accepting once it drains.</summary>
    public void Complete() => _ = _streams.Writer.TryComplete();

    internal void Claim()
    {
        if (Interlocked.Exchange(ref _claimed, 1) != 0)
        {
            throw new InvalidOperationException("A stream supplier serves exactly one server.");
        }
    }

    internal async ValueTask<Stream?> AcceptAsync(CancellationToken cancellationToken)
    {
        while (await _streams.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (_streams.Reader.TryRead(out var stream))
            {
                return stream;
            }
        }

        return null;
    }

    internal async ValueTask DisposeUnacceptedAsync()
    {
        _ = _streams.Writer.TryComplete();
        while (_streams.Reader.TryRead(out var stream))
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
    }
}
