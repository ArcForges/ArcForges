// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Events.V1;

namespace RealtimeAotProbe;

/// <summary>The cursor and sequence state of one subscription, shared by Watch and Poll.</summary>
/// <remarks>
/// One session is the single source of "where we are": switching between the stream and the Poll fallback
/// resumes from the same verified cursor and deduplicates by the same sequence, so a switch never replays a
/// hint to the observer and never skips one silently (annex 10 section 5, browser fallback).
/// </remarks>
internal sealed class EventSession(string subscriptionKey)
{
    public string Key { get; } = !string.IsNullOrEmpty(subscriptionKey) ? subscriptionKey : throw new ArgumentException("A subscription key is required.", nameof(subscriptionKey));

    public string? Cursor { get; set; }

    public EventSequenceTracker Tracker { get; } = new();

    /// <summary>The number of authoritative snapshots the observer was asked for.</summary>
    public long Snapshots { get; set; }
}

/// <summary>Validates one hint against the subscription and delivers it through the sequence rules.</summary>
internal static class EventDelivery
{
    /// <returns>Null when the hint was applied, a gap or a discarded duplicate; otherwise the reason to stop.</returns>
    public static async Task<WatchResult?> DeliverAsync(EventSession session, RealtimeObserver observer, Event hint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(observer);
        ArgumentNullException.ThrowIfNull(hint);
        if (!hint.HasSeq)
        {
            return new WatchResult(StopReason.ProtocolViolation, "a hint without a sequence");
        }

        if (!hint.HasSubscriptionKey || !string.Equals(hint.SubscriptionKey, session.Key, StringComparison.Ordinal))
        {
            return new WatchResult(StopReason.ProtocolViolation, "a hint outside the subscription scope");
        }

        if (hint.PayloadCase == Event.PayloadOneofCase.None)
        {
            return new WatchResult(StopReason.ProtocolViolation, "a hint without a payload");
        }

        SequenceVerdict verdict = session.Tracker.Evaluate(hint);
        if (verdict.Outcome == SequenceOutcome.Conflict)
        {
            return new WatchResult(StopReason.IntegrityViolation, "a hint contradicts the one applied at its sequence");
        }

        if (verdict.Outcome == SequenceOutcome.Duplicate)
        {
            session.Tracker.RecordDuplicate();
            return null;
        }

        if (verdict.Outcome == SequenceOutcome.Gap)
        {
            await observer.GapAsync(new SequenceGap(session.Key, verdict.Expected, verdict.Actual), cancellationToken).ConfigureAwait(false);
        }

        await observer.HintAsync(hint, cancellationToken).ConfigureAwait(false);
        session.Tracker.Accept(hint, verdict);
        return null;
    }
}

/// <summary>A reconnecting <c>EventService.Watch</c> consumer with scoped snapshot recovery.</summary>
internal sealed class EventWatcher(
    EventSession session,
    IRealtimeTransport transport,
    RealtimeObserver observer,
    TimeProvider time,
    Func<double> random,
    RealtimePolicy policy) : ReconnectingStream(observer, time, random, policy)
{
    private readonly EventSession _session = session ?? throw new ArgumentNullException(nameof(session));
    private readonly IRealtimeTransport _transport = transport ?? throw new ArgumentNullException(nameof(transport));

    public override string? Cursor
    {
        get => _session.Cursor;
        set => _session.Cursor = value;
    }

    protected override IAsyncEnumerable<StreamFrame> Open(string? cursor, CancellationToken cancellationToken) =>
        _transport.WatchAsync(_session.Key, cursor, cancellationToken);

    protected override async Task<ConnectionEnd?> HandleContentAsync(StreamFrame frame, CancellationToken cancellationToken)
    {
        if (frame.FrameCase != StreamFrame.FrameOneofCase.Hint)
        {
            return ConnectionEnd.StopWith(StopReason.ProtocolViolation, "the events stream carried a " + frame.FrameCase + " frame");
        }

        WatchResult? stop = await EventDelivery.DeliverAsync(_session, Observer, frame.Hint, cancellationToken).ConfigureAwait(false);
        if (stop is { } failure)
        {
            return ConnectionEnd.StopWith(failure.Reason, failure.Detail);
        }

        if (frame.Position is { HasCursor: true } position && position.Cursor.Length > 0)
        {
            _session.Cursor = position.Cursor;
        }

        return null;
    }

    protected override async Task<ConnectionEnd?> OnConnectionEndedAsync(ConnectionEnd end, CancellationToken cancellationToken)
    {
        if (end.Kind != EndKind.Reset || end.Reset is not { } reset)
        {
            return null;
        }

        // A reset invalidates the sequence baseline. Without a cursor to resume from, or when the server says
        // so, the authoritative scoped snapshot is read first and the stream resumes after its high water.
        _session.Tracker.Reset();
        bool snapshot = reset.SnapshotRequired || reset.ResumeFrom is null;
        _session.Cursor = reset.ResumeFrom;
        if (snapshot)
        {
            _session.Snapshots++;
            await Observer.SnapshotRequiredAsync(reset.Reason, cancellationToken).ConfigureAwait(false);
        }

        return null;
    }
}
