// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.PublicApi.V1;
using Grpc.Core;

namespace RealtimeAotProbe;

/// <summary>The cursor, offset and terminal state of one execution output, shared by WatchOutput and ReadOutput.</summary>
internal sealed class OutputSession
{
    public OutputSession(ExecutionOwner owner, RealtimePolicy policy)
    {
        Owner = owner ?? throw new ArgumentNullException(nameof(owner));
        Tracker = new OutputTracker(owner, policy);
    }

    public ExecutionOwner Owner { get; }

    public string? Cursor { get; set; }

    public OutputTracker Tracker { get; }

    /// <summary>A terminal frame seen on the stream. It is not a commit until an authoritative read agrees.</summary>
    public ExecutionOutput? StreamTerminal { get; set; }

    /// <summary>The terminal outcome returned by ReadOutput: the only completion this client accepts.</summary>
    public ExecutionOutput? AuthoritativeTerminal { get; set; }

    public long Pages { get; set; }

    public long Progress { get; set; }

    public long Restarts { get; set; }

    /// <summary>Discard everything received: the output is read again from its first offset.</summary>
    public void Restart()
    {
        Cursor = null;
        Tracker.Reset();
        StreamTerminal = null;
        AuthoritativeTerminal = null;
        Restarts++;
    }
}

internal enum PageKind
{
    /// <summary>The page was consumed; <see cref="PageResult.Chunks"/> says how many chunks it carried.</summary>
    Consumed,

    /// <summary>An authoritative terminal outcome was read.</summary>
    Completed,

    /// <summary>The server required a reset: the output was discarded and must be read again.</summary>
    Restart,

    /// <summary>A retryable failure: repeat the read after the delay.</summary>
    Retry,

    /// <summary>Stop with <see cref="PageResult.Stop"/>.</summary>
    Stop,
}

internal readonly record struct PageResult(PageKind Kind, int Chunks = 0, WatchResult Stop = default, Classified Retry = default);

internal enum ChunkKind
{
    /// <summary>The chunk was appended, or discarded as an identical duplicate.</summary>
    Delivered,

    /// <summary>Bytes before the chunk are missing.</summary>
    Gap,

    /// <summary>The chunk is invalid or contradicts what was received: stop.</summary>
    Stop,
}

internal readonly record struct ChunkResult(ChunkKind Kind, WatchResult Stop = default);

/// <summary>Validates and applies one chunk or one ReadOutput page to an output session.</summary>
internal static class OutputDelivery
{
    public static async Task<ChunkResult> DeliverChunkAsync(OutputSession session, RealtimeObserver observer, OutputChunk chunk, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(observer);
        ArgumentNullException.ThrowIfNull(chunk);
        OutputVerdict verdict = session.Tracker.Evaluate(chunk);
        switch (verdict.Outcome)
        {
            case OutputOutcome.Duplicate:
                session.Tracker.RecordDuplicate();
                return new ChunkResult(ChunkKind.Delivered);
            case OutputOutcome.Gap:
                session.Tracker.RecordGap();
                return new ChunkResult(ChunkKind.Gap);
            case OutputOutcome.Conflict:
                return new ChunkResult(ChunkKind.Stop, new WatchResult(StopReason.IntegrityViolation, verdict.Detail));
            case OutputOutcome.Violation:
                return new ChunkResult(ChunkKind.Stop, new WatchResult(StopReason.ProtocolViolation, verdict.Detail));
            default:
                await observer.OutputAsync(chunk, cancellationToken).ConfigureAwait(false);
                session.Tracker.Accept(chunk, verdict);
                return new ChunkResult(ChunkKind.Delivered);
        }
    }

    public static async Task<PageResult> ApplyPageAsync(
        OutputSession session,
        RealtimeObserver observer,
        RealtimePolicy policy,
        TimeProvider time,
        ExecutionServiceReadOutputResponse response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(observer);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(response);
        session.Pages++;
        switch (response.OutcomeCase)
        {
            case ExecutionServiceReadOutputResponse.OutcomeOneofCase.Error:
                return new PageResult(PageKind.Retry, Retry: ErrorClassifier.FromArcError(response.Error, time.GetUtcNow(), policy));
            case ExecutionServiceReadOutputResponse.OutcomeOneofCase.Value:
                break;
            default:
                return Stopped(StopReason.ProtocolViolation, "a ReadOutput response without a value or an error");
        }

        ExecutionServiceReadOutputValue value = response.Value;
        if (value.HasResetRequired && value.ResetRequired)
        {
            // The cursor is no longer usable. Whatever this page carries is not applied: the output is read
            // again from its first offset and the observer discards what it displayed.
            session.Restart();
            await observer.OutputResetAsync("ReadOutput required a reset", cancellationToken).ConfigureAwait(false);
            return new PageResult(PageKind.Restart);
        }

        if (value.Chunks.Count > policy.MaximumPageChunks)
        {
            return Stopped(StopReason.ProtocolViolation, "a ReadOutput page with more chunks than the page bound");
        }

        long bytes = 0;
        foreach (OutputChunk chunk in value.Chunks)
        {
            bytes += chunk.Data.Length;
        }

        if (bytes > policy.MaximumPageBytes)
        {
            return Stopped(StopReason.ProtocolViolation, "a ReadOutput page with more chunk bytes than the page bound");
        }

        foreach (OutputChunk chunk in value.Chunks)
        {
            ChunkResult delivered = await DeliverChunkAsync(session, observer, chunk, cancellationToken).ConfigureAwait(false);
            if (delivered.Kind == ChunkKind.Gap)
            {
                // A gap inside an authoritative contiguous read cannot be repaired by reading again.
                return Stopped(StopReason.IntegrityViolation, "the authoritative read left a gap before the chunk");
            }

            if (delivered.Kind == ChunkKind.Stop)
            {
                return new PageResult(PageKind.Stop, Stop: delivered.Stop);
            }
        }

        if (value.Position is { HasCursor: true } position && position.Cursor.Length > 0)
        {
            session.Cursor = position.Cursor;
        }

        if (value.Terminal is not { } terminal)
        {
            return new PageResult(PageKind.Consumed, value.Chunks.Count);
        }

        if (terminal.Execution is null || !terminal.Execution.Equals(session.Owner))
        {
            return Stopped(StopReason.ProtocolViolation, "a terminal outcome for another execution owner");
        }

        if (session.StreamTerminal is { } seen && Disagree(seen, terminal))
        {
            return Stopped(StopReason.IntegrityViolation, "the stream terminal and the authoritative terminal disagree");
        }

        session.AuthoritativeTerminal = terminal;
        return new PageResult(PageKind.Completed, value.Chunks.Count);
    }

    private static bool Disagree(ExecutionOutput stream, ExecutionOutput authoritative) =>
        (stream.HasFinalHash && authoritative.HasFinalHash && !string.Equals(stream.FinalHash, authoritative.FinalHash, StringComparison.Ordinal))
        || (stream.HasState && authoritative.HasState && !string.Equals(stream.State, authoritative.State, StringComparison.Ordinal));

    private static PageResult Stopped(StopReason reason, string detail) => new(PageKind.Stop, Stop: new WatchResult(reason, detail));
}

/// <summary>A reconnecting <c>ExecutionService.WatchOutput</c> consumer that recovers through ReadOutput.</summary>
/// <remarks>
/// A stream that drops, falls silent, is reset, leaves a gap or delivers a terminal frame is never trusted to
/// say how the output ended: the authoritative ReadOutput is read from the verified cursor, and the output is
/// complete only when that read returns the terminal outcome. A stream reset restarts the output from offset
/// zero (the resume cursor is not used for output: partial text is never a commit).
/// </remarks>
internal sealed class OutputWatcher(
    OutputSession session,
    IRealtimeTransport transport,
    RealtimeObserver observer,
    TimeProvider time,
    Func<double> random,
    RealtimePolicy policy) : ReconnectingStream(observer, time, random, policy)
{
    private const int MaximumRestartsPerRecovery = 1;

    private readonly OutputSession _session = session ?? throw new ArgumentNullException(nameof(session));
    private readonly IRealtimeTransport _transport = transport ?? throw new ArgumentNullException(nameof(transport));

    public override string? Cursor
    {
        get => _session.Cursor;
        set => _session.Cursor = value;
    }

    protected override IAsyncEnumerable<StreamFrame> Open(string? cursor, CancellationToken cancellationToken) =>
        _transport.WatchOutputAsync(_session.Owner, cursor, cancellationToken);

    protected override async Task<ConnectionEnd?> HandleContentAsync(StreamFrame frame, CancellationToken cancellationToken)
    {
        switch (frame.FrameCase)
        {
            case StreamFrame.FrameOneofCase.Output:
                ChunkResult delivered = await OutputDelivery.DeliverChunkAsync(_session, Observer, frame.Output, cancellationToken).ConfigureAwait(false);
                if (delivered.Kind == ChunkKind.Gap)
                {
                    return new ConnectionEnd(EndKind.Retryable, "an output gap: recovering through ReadOutput");
                }

                if (delivered.Kind == ChunkKind.Stop)
                {
                    return ConnectionEnd.StopWith(delivered.Stop.Reason, delivered.Stop.Detail);
                }

                AdoptCursor(frame);
                return null;
            case StreamFrame.FrameOneofCase.Progress:
                if (frame.Progress.Execution is null || !frame.Progress.Execution.Equals(_session.Owner))
                {
                    return ConnectionEnd.StopWith(StopReason.ProtocolViolation, "a progress frame for another execution owner");
                }

                _session.Progress++;
                return null;
            case StreamFrame.FrameOneofCase.Terminal:
                if (frame.Terminal.Execution is null || !frame.Terminal.Execution.Equals(_session.Owner))
                {
                    return ConnectionEnd.StopWith(StopReason.ProtocolViolation, "a terminal frame for another execution owner");
                }

                _session.StreamTerminal = frame.Terminal;
                return new ConnectionEnd(EndKind.ServerClosed, "terminal frame: confirming through ReadOutput");
            default:
                return ConnectionEnd.StopWith(StopReason.ProtocolViolation, "the output stream carried a " + frame.FrameCase + " frame");
        }
    }

    protected override async Task<ConnectionEnd?> OnConnectionEndedAsync(ConnectionEnd end, CancellationToken cancellationToken)
    {
        if (end.Kind == EndKind.Reset && end.Reset is { } reset)
        {
            _session.Restart();
            await Observer.OutputResetAsync(reset.Reason, cancellationToken).ConfigureAwait(false);
        }

        return await RecoverAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Read the authoritative output until it is caught up or complete.</summary>
    /// <returns>Null when caught up and not complete; otherwise the end that stops or delays the run.</returns>
    private async Task<ConnectionEnd?> RecoverAsync(CancellationToken cancellationToken)
    {
        int restarts = 0;
        while (true)
        {
            ulong before = _session.Tracker.NextOffset;
            ExecutionServiceReadOutputResponse response;
            try
            {
                response = await _transport.ReadOutputAsync(_session.Owner, _session.Cursor, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (FailureMapper.TryMap(ex, cancellationToken, out ConnectionEnd mapped))
            {
                return mapped;
            }

            PageResult page = await OutputDelivery.ApplyPageAsync(_session, Observer, Policy, Time, response, cancellationToken).ConfigureAwait(false);
            switch (page.Kind)
            {
                case PageKind.Completed:
                    await Observer.TerminalAsync(_session.AuthoritativeTerminal!, cancellationToken).ConfigureAwait(false);
                    return ConnectionEnd.StopWith(StopReason.Completed, "the authoritative read returned the terminal outcome");
                case PageKind.Stop:
                    return ConnectionEnd.StopWith(page.Stop.Reason, page.Stop.Detail);
                case PageKind.Retry:
                    return ConnectionEnd.From(page.Retry);
                case PageKind.Restart:
                    if (++restarts > MaximumRestartsPerRecovery)
                    {
                        return new ConnectionEnd(EndKind.Retryable, "the authoritative read keeps requiring a reset");
                    }

                    break;
                default:
                    // Caught up: an empty page, or a page that appended nothing (a server repeating itself must not spin this loop).
                    if (page.Chunks == 0 || _session.Tracker.NextOffset == before)
                    {
                        return null;
                    }

                    break;
            }
        }
    }

    private void AdoptCursor(StreamFrame frame)
    {
        if (frame.Position is { HasCursor: true } position && position.Cursor.Length > 0)
        {
            _session.Cursor = position.Cursor;
        }
    }
}
