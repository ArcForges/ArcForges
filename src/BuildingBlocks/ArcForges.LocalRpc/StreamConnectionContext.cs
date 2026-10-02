// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.Pipelines;
using System.Net;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

namespace ArcForges.LocalRpc;

/// <summary>Adapts one verified duplex OS stream to a Kestrel connection. It never exposes an IP address.</summary>
internal sealed class StreamConnectionContext : ConnectionContext, IConnectionLifetimeFeature
{
    private readonly Stream _stream;
    private readonly CancellationTokenSource _closed = new();
    private readonly DuplexPipe _pipe;
    private readonly Action? _released;
    private int _disposed;

    internal StreamConnectionContext(string connectionId, Stream stream, EndPoint localEndPoint, Action? released = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _stream = stream;
        _released = released;
        ConnectionId = connectionId;
        LocalEndPoint = localEndPoint;
        _pipe = new DuplexPipe(
            PipeReader.Create(stream, new StreamPipeReaderOptions(bufferSize: 16 * 1024, minimumReadSize: 4 * 1024, leaveOpen: true)),
            PipeWriter.Create(stream, new StreamPipeWriterOptions(minimumBufferSize: 4 * 1024, leaveOpen: true)));
        Transport = _pipe;
        Features = new FeatureCollection();
        Features.Set<IConnectionLifetimeFeature>(this);
        Items = new Dictionary<object, object?>();
        ConnectionClosed = _closed.Token;
    }

    public override string ConnectionId { get; set; }

    public override IFeatureCollection Features { get; }

    public override IDictionary<object, object?> Items { get; set; }

    public override IDuplexPipe Transport { get; set; }

    public override CancellationToken ConnectionClosed { get; set; }

    public override EndPoint? LocalEndPoint { get; set; }

    public override EndPoint? RemoteEndPoint { get; set; }

    public override void Abort(ConnectionAbortedException abortReason) => Abort();

    public override void Abort()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            _pipe.Input.CancelPendingRead();
            _pipe.Output.CancelPendingFlush();
            _closed.Cancel();
            _stream.Dispose();
        }
        catch (ObjectDisposedException)
        {
            // The connection already ended.
        }
        catch (IOException)
        {
            // The peer already closed the OS stream.
        }
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await _closed.CancelAsync().ConfigureAwait(false);
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            // The peer already closed the OS stream.
        }
        finally
        {
            _closed.Dispose();
            _released?.Invoke();
            await base.DisposeAsync().ConfigureAwait(false);
        }
    }

    private sealed class DuplexPipe(PipeReader input, PipeWriter output) : IDuplexPipe
    {
        public PipeReader Input { get; } = input;

        public PipeWriter Output { get; } = output;
    }
}
