// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.IO.Pipelines;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// One end of a connected in-memory duplex byte stream. It is the deterministic, hosted-CI substitute for an
/// OS stream: it exercises real Kestrel HTTP/2 and Grpc.Net.Client framing but proves nothing about an OS pipe
/// or socket, which only the explicit local checks observe.
/// </summary>
internal sealed class InMemoryDuplexStream : Stream
{
    private readonly PipeReader _input;
    private readonly PipeWriter _output;
    private int _disposed;

    private InMemoryDuplexStream(PipeReader input, PipeWriter output)
    {
        _input = input;
        _output = output;
    }

    public override bool CanRead => true;

    public override bool CanWrite => true;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    internal static (InMemoryDuplexStream Client, InMemoryDuplexStream Server) CreatePair()
    {
        var clientToServer = new Pipe(new PipeOptions(useSynchronizationContext: false));
        var serverToClient = new Pipe(new PipeOptions(useSynchronizationContext: false));
        return (
            new InMemoryDuplexStream(serverToClient.Reader, clientToServer.Writer),
            new InMemoryDuplexStream(clientToServer.Reader, serverToClient.Writer));
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var result = await _input.ReadAsync(cancellationToken).ConfigureAwait(false);
            var sequence = result.Buffer;
            if (!sequence.IsEmpty)
            {
                var count = (int)Math.Min(sequence.Length, buffer.Length);
                sequence.Slice(0, count).CopyTo(buffer.Span);
                _input.AdvanceTo(sequence.GetPosition(count));
                return count;
            }

            _input.AdvanceTo(sequence.End);
            if (result.IsCompleted || result.IsCanceled)
            {
                return 0;
            }
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var result = await _output.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (result.IsCompleted)
        {
            throw new IOException("The in-memory peer closed the stream.");
        }
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _output.Complete();
            _input.CancelPendingRead();
            try
            {
                _input.Complete();
            }
            catch (InvalidOperationException)
            {
                // A read was still unwinding; the cancelled read ends it.
            }
        }

        base.Dispose(disposing);
    }
}
