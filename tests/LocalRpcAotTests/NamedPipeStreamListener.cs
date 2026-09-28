// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.Pipelines;
using System.Net;
using System.IO.Pipes;
using Microsoft.AspNetCore.Connections;

internal sealed class NamedPipeStreamListenerFactory : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    public bool CanBind(EndPoint endpoint) => endpoint is NamedPipeEndPoint;

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not NamedPipeEndPoint namedPipe)
        {
            throw new NotSupportedException("This listener accepts only Kestrel NamedPipeEndPoint values.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IConnectionListener>(new NamedPipeStreamListener(namedPipe));
    }
}

internal sealed class NamedPipeStreamListener(NamedPipeEndPoint endpoint) : IConnectionListener
{
    private readonly SemaphoreSlim _acceptLock = new(1, 1);
    private NamedPipeServerStream? _pending;
    private StreamConnectionContext? _active;
    private bool _stopping;

    public EndPoint EndPoint { get; } = endpoint;

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        await _acceptLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_stopping)
            {
                return null;
            }

            if (_active is not null)
            {
                await _active.Closed.WaitAsync(cancellationToken).ConfigureAwait(false);
                _active = null;
            }

            var pipe = new NamedPipeServerStream(
                endpoint.PipeName,
                PipeDirection.InOut,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                inBufferSize: 64 * 1024,
                outBufferSize: 64 * 1024);
            _pending = pipe;
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                _pending = null;
                await pipe.DisposeAsync().ConfigureAwait(false);
                if (_stopping || cancellationToken.IsCancellationRequested)
                {
                    return null;
                }

                throw;
            }

            _pending = null;
            var connection = new StreamConnectionContext(pipe, endpoint);
            _active = connection;
            return connection;
        }
        finally
        {
            _acceptLock.Release();
        }
    }

    public ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        _stopping = true;
        _pending?.Dispose();
        _active?.Abort(new ConnectionAbortedException("The LocalRpc probe listener is stopping."));
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await UnbindAsync().ConfigureAwait(false);
        if (_active is not null)
        {
            await _active.DisposeAsync().ConfigureAwait(false);
        }

        _acceptLock.Dispose();
    }
}

internal sealed class StreamConnectionContext : DefaultConnectionContext
{
    private readonly Stream _stream;
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _disposed;

    public StreamConnectionContext(Stream stream, EndPoint endpoint)
        : base(Guid.NewGuid().ToString("N"))
    {
        _stream = stream;
        LocalEndPoint = endpoint;
        RemoteEndPoint = endpoint;
        var reader = PipeReader.Create(stream, new StreamPipeReaderOptions(
            bufferSize: 64 * 1024,
            minimumReadSize: 4096,
            leaveOpen: true));
        var writer = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true));
        Transport = new DuplexPipe(reader, writer);
    }

    public Task Closed => _closed.Task;

    public override void Abort(ConnectionAbortedException abortReason)
    {
        base.Abort(abortReason);
        _ = DisposeAsync();
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await Transport.Input.CompleteAsync().ConfigureAwait(false);
            await Transport.Output.CompleteAsync().ConfigureAwait(false);
        }
        finally
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
            _closed.TrySetResult();
        }
    }
}

internal sealed class DuplexPipe(PipeReader input, PipeWriter output) : IDuplexPipe
{
    public PipeReader Input { get; } = input;
    public PipeWriter Output { get; } = output;
}
