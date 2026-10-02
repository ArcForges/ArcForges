// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Events.V1;
using Google.Protobuf;
using Grpc.Core;

namespace RealtimeAotProbe;

internal enum EndKind
{
    /// <summary>The server closed the stream normally (it does so after five minutes).</summary>
    ServerClosed,

    /// <summary>No frame, heartbeat included, arrived within the silence timeout.</summary>
    Silence,

    /// <summary>The server sent a reset frame.</summary>
    Reset,

    /// <summary>A retryable typed failure ended the connection.</summary>
    Retryable,

    /// <summary>The run must stop with <see cref="ConnectionEnd.Stop"/>.</summary>
    Stopped,

    /// <summary>The caller cancelled.</summary>
    Cancelled,
}

internal sealed record ResetDirective(string Reason, bool SnapshotRequired, string? ResumeFrom, bool Truncated);

internal readonly record struct ConnectionEnd(
    EndKind Kind,
    string Detail,
    StopReason Stop = StopReason.Cancelled,
    ResetDirective? Reset = null,
    TimeSpan RetryAfter = default)
{
    public static ConnectionEnd Cancelled() => new(EndKind.Cancelled, "cancelled");

    public static ConnectionEnd StopWith(StopReason reason, string detail) => new(EndKind.Stopped, detail, reason);

    public static ConnectionEnd From(Classified classified) => classified.Disposition switch
    {
        Disposition.Retry => new ConnectionEnd(EndKind.Retryable, classified.Detail, RetryAfter: classified.RetryAfter),
        Disposition.StopAuthorization => StopWith(StopReason.AuthorizationLost, classified.Detail),
        Disposition.StopUnsupported => StopWith(StopReason.Unsupported, classified.Detail),
        Disposition.StopProtocol => StopWith(StopReason.ProtocolViolation, classified.Detail),
        _ => StopWith(StopReason.NonRetryable, classified.Detail),
    };
}

/// <summary>The reconnecting server-stream loop shared by <c>EventService.Watch</c> and <c>ExecutionService.WatchOutput</c>.</summary>
/// <remarks>
/// One run opens the stream from the last verified cursor and reads frames until the server closes, 45 seconds
/// pass without any frame, a typed failure arrives or the caller cancels. Then it reconnects after an
/// exponential full-jitter delay, honoring a server retry time, and never retries a permission failure.
/// Heartbeat, reset, error and empty frames are handled here; the subclass owns the content frames.
/// All waiting goes through the injected <see cref="TimeProvider"/> and all randomness through the injected source.
/// </remarks>
internal abstract class ReconnectingStream(RealtimeObserver observer, TimeProvider time, Func<double> random, RealtimePolicy policy)
{
    private readonly Func<double> _random = random ?? throw new ArgumentNullException(nameof(random));

    protected RealtimeObserver Observer { get; } = observer ?? throw new ArgumentNullException(nameof(observer));

    protected TimeProvider Time { get; } = time ?? throw new ArgumentNullException(nameof(time));

    protected RealtimePolicy Policy { get; } = policy ?? throw new ArgumentNullException(nameof(policy));

    public ReconnectBackoff Backoff { get; } = new(policy);

    /// <summary>The number of reconnect delays taken.</summary>
    public long Reconnects { get; private set; }

    public long Frames { get; private set; }

    public long Heartbeats { get; private set; }

    public long Resets { get; private set; }

    public long Silences { get; private set; }

    /// <summary>The last verified cursor this stream resumes from.</summary>
    public abstract string? Cursor { get; set; }

    protected abstract IAsyncEnumerable<StreamFrame> Open(string? cursor, CancellationToken cancellationToken);

    /// <summary>Handle a content frame; return null to keep reading or an end to stop reading this connection.</summary>
    protected abstract Task<ConnectionEnd?> HandleContentAsync(StreamFrame frame, CancellationToken cancellationToken);

    /// <summary>Called after a connection ended other than by a stop or cancellation. May stop the run.</summary>
    protected abstract Task<ConnectionEnd?> OnConnectionEndedAsync(ConnectionEnd end, CancellationToken cancellationToken);

    public async Task<WatchResult> RunAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return await FinishAsync(ConnectionEnd.Cancelled(), cancellationToken).ConfigureAwait(false);
            }

            await Observer.ConnectionChangedAsync(ConnectionState.Connecting, "opening the stream", cancellationToken).ConfigureAwait(false);
            long started = Time.GetTimestamp();
            ConnectionEnd end = await ConsumeAsync(cancellationToken).ConfigureAwait(false);
            TimeSpan connectedFor = Time.GetElapsedTime(started);
            if (end.Kind is EndKind.Cancelled or EndKind.Stopped)
            {
                return await FinishAsync(end, cancellationToken).ConfigureAwait(false);
            }

            ConnectionEnd? replacement = await OnConnectionEndedAsync(end, cancellationToken).ConfigureAwait(false);
            if (replacement is { } next)
            {
                if (next.Kind is EndKind.Cancelled or EndKind.Stopped)
                {
                    return await FinishAsync(next, cancellationToken).ConfigureAwait(false);
                }

                end = next;
            }

            Backoff.ConnectionEnded(connectedFor);
            TimeSpan delay = Backoff.NextDelay(_random);
            if (end.RetryAfter > delay)
            {
                delay = end.RetryAfter;
            }

            Reconnects++;
            await Observer.ConnectionChangedAsync(ConnectionState.Reconnecting, end.Detail, cancellationToken).ConfigureAwait(false);
            try
            {
                await Task.Delay(delay, Time, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return await FinishAsync(ConnectionEnd.Cancelled(), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    protected static ResetDirective ToDirective(StreamReset reset)
    {
        ArgumentNullException.ThrowIfNull(reset);
        return new ResetDirective(
            reset.HasReason ? reset.Reason : string.Empty,
            reset.HasSnapshotRequired && reset.SnapshotRequired,
            reset.HasResumeFrom && reset.ResumeFrom.Length > 0 ? reset.ResumeFrom : null,
            reset.HasTruncated && reset.Truncated);
    }

    private async Task<WatchResult> FinishAsync(ConnectionEnd end, CancellationToken cancellationToken)
    {
        StopReason reason = end.Kind == EndKind.Cancelled ? StopReason.Cancelled : end.Stop;
        // The stopped notification is best effort for a cancelled caller: it must still reach the observer.
        await Observer.ConnectionChangedAsync(ConnectionState.Stopped, end.Detail, CancellationToken.None).ConfigureAwait(false);
        return new WatchResult(reason, end.Detail);
    }

    private async Task<ConnectionEnd> ConsumeAsync(CancellationToken cancellationToken)
    {
        using var connection = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        IAsyncEnumerator<StreamFrame> frames = Open(Cursor, connection.Token).GetAsyncEnumerator(connection.Token);
        bool live = false;
        try
        {
            while (true)
            {
                Task<bool> next = frames.MoveNextAsync().AsTask();
                using var silence = new CancellationTokenSource();
                Task timer = Task.Delay(Policy.SilenceTimeout, Time, silence.Token);
                await Task.WhenAny(next, timer).ConfigureAwait(false);
                if (!next.IsCompleted)
                {
                    await connection.CancelAsync().ConfigureAwait(false);
                    await DrainAsync(next).ConfigureAwait(false);
                    Silences++;
                    return new ConnectionEnd(EndKind.Silence, "no frame within the silence timeout");
                }

                await silence.CancelAsync().ConfigureAwait(false);
                bool hasFrame;
                try
                {
                    hasFrame = await next.ConfigureAwait(false);
                }
                catch (Exception ex) when (FailureMapper.TryMap(ex, cancellationToken, out ConnectionEnd mapped))
                {
                    return mapped;
                }

                if (!hasFrame)
                {
                    return new ConnectionEnd(EndKind.ServerClosed, "the server closed the stream");
                }

                Frames++;
                if (!live)
                {
                    live = true;
                    await Observer.ConnectionChangedAsync(ConnectionState.Live, "first frame received", cancellationToken).ConfigureAwait(false);
                }

                ConnectionEnd? decision = await DispatchAsync(frames.Current, cancellationToken).ConfigureAwait(false);
                if (decision is { } end)
                {
                    return end;
                }
            }
        }
        finally
        {
            await connection.CancelAsync().ConfigureAwait(false);
            await frames.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task<ConnectionEnd?> DispatchAsync(StreamFrame frame, CancellationToken cancellationToken)
    {
        switch (frame.FrameCase)
        {
            case StreamFrame.FrameOneofCase.Heartbeat:
                Heartbeats++;
                return null;
            case StreamFrame.FrameOneofCase.Reset:
                Resets++;
                ResetDirective directive = ToDirective(frame.Reset);
                return string.Equals(directive.Reason, "permissionChanged", StringComparison.Ordinal)
                    ? ConnectionEnd.StopWith(StopReason.AuthorizationLost, "reset: permissionChanged")
                    : new ConnectionEnd(EndKind.Reset, "reset: " + directive.Reason, Reset: directive);
            case StreamFrame.FrameOneofCase.Error:
                return ConnectionEnd.From(ErrorClassifier.FromArcError(frame.Error, Time.GetUtcNow(), Policy));
            case StreamFrame.FrameOneofCase.None:
                return ConnectionEnd.StopWith(StopReason.ProtocolViolation, "a frame without a variant");
            default:
                return await HandleContentAsync(frame, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task DrainAsync(Task<bool> pending)
    {
        try
        {
            await pending.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or RpcException or IOException or HttpRequestException)
        {
            // The pending read was cancelled to end a silent connection; its outcome is irrelevant.
        }
    }
}

/// <summary>Maps the failures a generated call or stream read can raise to the end of the connection.</summary>
internal static class FailureMapper
{
    /// <returns>True for a failure this client understands; anything else is a defect and propagates.</returns>
    public static bool TryMap(Exception exception, CancellationToken cancellationToken, out ConnectionEnd end)
    {
        ArgumentNullException.ThrowIfNull(exception);
        switch (exception)
        {
            case InvalidProtocolBufferException:
                // It derives from IOException, so it must be matched before the network failures.
                end = ConnectionEnd.StopWith(StopReason.ProtocolViolation, "malformed message");
                return true;
            case OperationCanceledException when cancellationToken.IsCancellationRequested:
                end = ConnectionEnd.Cancelled();
                return true;
            case OperationCanceledException:
                end = new ConnectionEnd(EndKind.Retryable, "the transport cancelled the call");
                return true;
            case RpcException rpc:
                end = cancellationToken.IsCancellationRequested ? ConnectionEnd.Cancelled() : ConnectionEnd.From(ErrorClassifier.FromRpc(rpc));
                return true;
            case HttpRequestException or IOException:
                end = new ConnectionEnd(EndKind.Retryable, "network failure");
                return true;
            default:
                end = default;
                return false;
        }
    }
}
