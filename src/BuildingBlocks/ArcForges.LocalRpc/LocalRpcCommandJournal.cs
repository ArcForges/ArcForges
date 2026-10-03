// SPDX-License-Identifier: AGPL-3.0-only
using Grpc.Core;

namespace ArcForges.LocalRpc;

/// <summary>One recorded command. Every field is read and written only under the journal lock.</summary>
internal sealed class JournalEntry
{
    internal JournalEntry(LocalRpcCommand command)
    {
        Id = command.CommandId;
        Operation = command.Operation;
        Digest = command.InputDigest.ToArray();
        Idempotency = command.Idempotency;
    }

    internal Guid Id { get; }

    internal string Operation { get; }

    internal byte[] Digest { get; }

    internal LocalRpcIdempotency Idempotency { get; }

    internal LocalRpcCommandState State { get; set; } = LocalRpcCommandState.InFlight;

    internal LocalRpcOutcomeKind Kind { get; set; } = LocalRpcOutcomeKind.Failure;

    internal LocalRpcEffect Effect { get; set; } = LocalRpcEffect.Unknown;

    internal LocalRpcFailureReason Reason { get; set; }

    internal StatusCode? Status { get; set; }

    internal LocalRpcRefusal? Refusal { get; set; }

    internal object? Response { get; set; }

    internal bool HasResponse { get; set; }

    internal int Attempts { get; set; }

    internal LocalRpcPeerGeneration Generation { get; set; }

    /// <summary>When the command's first attempt began: the replay window runs from it (conservative: the attempt may have reached the helper any time after).</summary>
    internal long? FirstAttemptAt { get; set; }

    internal long SettledAt { get; set; }

    internal bool CancelRequested { get; set; }

    internal LocalRpcEffect? CancelReport { get; set; }

    internal bool PeerLost { get; set; }

    internal bool Reconciling { get; set; }

    /// <summary>
    /// Whether any attempt of this command may have reached a helper without proving its effect: a later attempt that is refused or finds no connection
    /// proves only itself and cannot turn that earlier uncertainty into <see cref="LocalRpcEffect.DidNotHappen"/>.
    /// </summary>
    internal bool MayHaveHappened { get; set; }

    /// <summary>Cancelled when the owner declares the launch lost: aborts the running attempt and any wait.</summary>
    internal CancellationTokenSource? Lost { get; set; }

    /// <summary>Cancelled when a cancel is requested: ends a wait before a retry; the running attempt is left to finish.</summary>
    internal CancellationTokenSource? Wake { get; set; }

    internal LinkedListNode<JournalEntry>? SettledNode { get; set; }
}

/// <summary>An immutable copy of an entry, taken under the lock, from which an outcome is built after the lock is released.</summary>
internal readonly record struct JournalSnapshot(
    Guid Id,
    string Operation,
    LocalRpcIdempotency Idempotency,
    LocalRpcCommandState State,
    LocalRpcOutcomeKind Kind,
    LocalRpcEffect Effect,
    LocalRpcFailureReason Reason,
    StatusCode? Status,
    LocalRpcRefusal? Refusal,
    object? Response,
    bool HasResponse,
    int Attempts,
    LocalRpcPeerGeneration Generation,
    bool CancelRequested)
{
    internal LocalRpcCommandRecord ToRecord() => new(
        Id,
        Operation,
        Idempotency,
        State,
        State == LocalRpcCommandState.InFlight ? null : Kind,
        State == LocalRpcCommandState.InFlight ? LocalRpcEffect.Unknown : Effect,
        Reason,
        Attempts,
        Generation,
        CancelRequested,
        HasResponse);
}

internal enum BeginKind
{
    /// <summary>The caller runs the command: a new entry, or a restart of an entry whose effect certainly did not happen or whose replay is allowed.</summary>
    Started,

    /// <summary>The entry is settled; the call answers from it and sends nothing.</summary>
    Recorded,

    /// <summary>The entry is unknown and this call may not replay it.</summary>
    ReplayRefused,

    /// <summary>Another call runs the command.</summary>
    InFlight,

    /// <summary>The id is recorded with another operation, input or idempotency.</summary>
    Conflict,

    /// <summary>No room: every recorded command is one the journal may not forget.</summary>
    Full,
}

internal readonly record struct BeginResult(BeginKind Kind, JournalEntry? Entry, JournalSnapshot Snapshot);

/// <summary>What the loop does after an attempt ended.</summary>
internal readonly record struct AttemptDecision(bool Retry, TimeSpan Delay, JournalSnapshot Snapshot);

/// <summary>The disposition of an explicit cancel.</summary>
public enum LocalRpcCancelDisposition
{
    /// <summary>Not a disposition; never reported.</summary>
    None = 0,

    /// <summary>No command with this id is recorded.</summary>
    NotFound = 1,

    /// <summary>The command had already finished with a known effect that is not a cancellation; the cancel came too late.</summary>
    TooLate = 2,

    /// <summary>The command is cancelled and its effect is known.</summary>
    Cancelled = 3,

    /// <summary>The cancel is recorded but the effect is not yet known: the cancel did not reach the helper, or the helper could not say.</summary>
    Requested = 4,
}

/// <summary>The result of an explicit cancel.</summary>
/// <param name="Disposition">What the cancel achieved.</param>
/// <param name="Delivered">Whether the cancel request reached the helper and was answered.</param>
/// <param name="Record">The command as recorded after the cancel; null when it is not found.</param>
public sealed record LocalRpcCancelResult(LocalRpcCancelDisposition Disposition, bool Delivered, LocalRpcCommandRecord? Record);

/// <summary>
/// The parent-side, in-memory record of commands: their stable identity, attempts, effect certainty and cancel intent,
/// surviving the loss of any helper launch. Nothing here is durable (a restart of the parent loses it; durable receipts are
/// owned by the persistence tasks). A command that is in flight or whose effect is unknown is never forgotten, a settled
/// one is kept for <c>retention</c> so a duplicate submission is answered from the record, and when the journal holds nothing
/// it may forget, a new command is refused rather than an old one evicted.
/// </summary>
internal sealed class LocalRpcCommandJournal
{
    private readonly object _sync = new();
    private readonly Dictionary<Guid, JournalEntry> _entries = [];
    private readonly LinkedList<JournalEntry> _settledOrder = new();
    private readonly TimeProvider _time;
    private readonly int _capacity;
    private readonly TimeSpan _retention;
    private readonly TimeSpan _replayWindow;

    internal LocalRpcCommandJournal(TimeProvider time, int capacity, TimeSpan retention, TimeSpan replayWindow)
    {
        _time = time;
        _capacity = capacity;
        _retention = retention;
        _replayWindow = replayWindow;
    }

    internal int Count
    {
        get
        {
            lock (_sync)
            {
                return _entries.Count;
            }
        }
    }

    internal BeginResult Begin(LocalRpcCommand command, LocalRpcPeerGeneration generation)
    {
        lock (_sync)
        {
            var now = _time.GetTimestamp();
            if (!_entries.TryGetValue(command.CommandId, out var entry))
            {
                EvictExpired(now);
                if (_entries.Count >= _capacity)
                {
                    return new BeginResult(BeginKind.Full, null, default);
                }

                entry = new JournalEntry(command) { Effect = LocalRpcEffect.DidNotHappen };
                _entries.Add(entry.Id, entry);
                Restart(entry, generation, mayHaveHappened: false);
                return new BeginResult(BeginKind.Started, entry, default);
            }

            if (!command.IsSameCommandAs(entry.Operation, entry.Digest, entry.Idempotency))
            {
                return new BeginResult(BeginKind.Conflict, null, default);
            }

            switch (entry.State)
            {
                case LocalRpcCommandState.InFlight:
                    return new BeginResult(BeginKind.InFlight, null, Snapshot(entry));
                case LocalRpcCommandState.Resolved:
                    if (entry.Kind == LocalRpcOutcomeKind.Failure && entry.Effect == LocalRpcEffect.DidNotHappen && !entry.CancelRequested)
                    {
                        UnlinkSettled(entry);
                        Restart(entry, generation, mayHaveHappened: false);
                        return new BeginResult(BeginKind.Started, entry, default);
                    }

                    return new BeginResult(BeginKind.Recorded, null, Snapshot(entry));
                default:
                    if (CanReplay(entry, command, generation, now))
                    {
                        Restart(entry, generation, mayHaveHappened: true);
                        return new BeginResult(BeginKind.Started, entry, default);
                    }

                    return new BeginResult(BeginKind.ReplayRefused, null, Snapshot(entry));
            }
        }
    }

    /// <summary>
    /// Starts an attempt: counts it and returns its number and the token that aborts it when the launch is lost, or null when a cancel,
    /// a lost launch or the caller's cancellation ends the loop before it sends.
    /// </summary>
    internal (int Attempt, CancellationToken Lost)? StartAttempt(JournalEntry entry, bool callerCancelled)
    {
        lock (_sync)
        {
            if (callerCancelled || entry.CancelRequested || entry.PeerLost || entry.Lost is null)
            {
                return null;
            }

            entry.Attempts++;
            entry.FirstAttemptAt ??= _time.GetTimestamp();

            return (entry.Attempts, entry.Lost.Token);
        }
    }

    /// <summary>The tokens a wait before a retry must honour besides the caller's: a lost launch and a cancel request.</summary>
    internal (CancellationToken Lost, CancellationToken Wake) WaitTokens(JournalEntry entry)
    {
        lock (_sync)
        {
            return (entry.Lost?.Token ?? new CancellationToken(canceled: true), entry.Wake?.Token ?? new CancellationToken(canceled: true));
        }
    }

    /// <summary>Records the end of an attempt and decides whether the loop sends again.</summary>
    internal AttemptDecision EndAttempt(
        JournalEntry entry,
        LocalRpcCommand command,
        AttemptResult result,
        int maxAttempts,
        LocalRpcBackoff backoff)
    {
        lock (_sync)
        {
            if (entry.State != LocalRpcCommandState.InFlight)
            {
                // An explicit cancel settled the command while this attempt ran: the first settlement stands.
                return new AttemptDecision(false, TimeSpan.Zero, Snapshot(entry));
            }

            if (result.IsResponse)
            {
                SettleResponse(entry, result);
                return new AttemptDecision(false, TimeSpan.Zero, Snapshot(entry));
            }

            var failure = result.Failure;
            var effect = failure.Effect;
            var reason = failure.Reason;

            // A refusal or a missing connection proves only the attempt it ended; the peer's own report (a receipt) proves the command.
            if (effect == LocalRpcEffect.DidNotHappen && reason != LocalRpcFailureReason.ReportedByPeer && entry.MayHaveHappened)
            {
                effect = LocalRpcEffect.Unknown;
            }

            if (effect == LocalRpcEffect.Unknown && entry.PeerLost)
            {
                reason = LocalRpcFailureReason.PeerLost;
            }

            // The helper's own report of a cancel stands in for an effect the failed call could not name.
            if (effect == LocalRpcEffect.Unknown && entry.CancelReport is { } report)
            {
                effect = report;
            }

            entry.MayHaveHappened = effect == LocalRpcEffect.Unknown || (entry.MayHaveHappened && reason != LocalRpcFailureReason.ReportedByPeer && effect != LocalRpcEffect.Happened);
            var cancelled = failure.CancelledByCaller || entry.CancelRequested;
            if (cancelled && entry.CancelRequested && !failure.CancelledByCaller)
            {
                reason = LocalRpcFailureReason.CancelRequested;
            }

            var stop = cancelled || entry.PeerLost || entry.Attempts >= maxAttempts;
            if (!stop && IsRetryable(entry, command, failure, effect))
            {
                // Remember what the failed attempt proved while the entry waits to retry.
                entry.Effect = effect;
                entry.Reason = reason;
                entry.Status = failure.Status;
                entry.Refusal = failure.Refusal;
                return new AttemptDecision(true, backoff.Next(entry.Attempts), default);
            }

            Settle(entry, cancelled ? LocalRpcOutcomeKind.Cancelled : LocalRpcOutcomeKind.Failure, effect, reason, failure.Status, failure.Refusal, null, hasResponse: false);
            return new AttemptDecision(false, TimeSpan.Zero, Snapshot(entry));
        }
    }

    /// <summary>The loop found, before an attempt, that a cancel or a lost launch ends it: settles the entry on what the last attempt proved.</summary>
    internal JournalSnapshot SettleWithoutAttempt(JournalEntry entry, bool callerCancelled)
    {
        lock (_sync)
        {
            if (entry.State != LocalRpcCommandState.InFlight)
            {
                return Snapshot(entry);
            }

            var effect = entry.Effect;
            if (entry.CancelRequested || callerCancelled)
            {
                if (effect == LocalRpcEffect.Unknown && entry.CancelReport is { } report)
                {
                    effect = report;
                }

                var reason = entry.CancelRequested ? LocalRpcFailureReason.CancelRequested : LocalRpcFailureReason.CancelledByCaller;
                Settle(entry, LocalRpcOutcomeKind.Cancelled, effect, reason, entry.Status, entry.Refusal, null, hasResponse: false);
            }
            else
            {
                Settle(entry, LocalRpcOutcomeKind.Failure, effect, LocalRpcFailureReason.PeerLost, entry.Status, entry.Refusal, null, hasResponse: false);
            }

            return Snapshot(entry);
        }
    }

    /// <summary>Settles an entry whose delegate threw something that is not a transport failure: the effect is unknown.</summary>
    internal void SettleUnclassified(JournalEntry entry)
    {
        lock (_sync)
        {
            if (entry.State == LocalRpcCommandState.InFlight)
            {
                Settle(entry, LocalRpcOutcomeKind.Failure, LocalRpcEffect.Unknown, LocalRpcFailureReason.Unclassified, null, null, null, hasResponse: false);
            }
        }
    }

    /// <summary>The owner declared a launch lost: every command in flight on it stops, and its running attempt is aborted.</summary>
    internal int PeerLost(LocalRpcPeerGeneration generation)
    {
        List<CancellationTokenSource>? abort = null;
        var count = 0;
        lock (_sync)
        {
            foreach (var entry in _entries.Values)
            {
                if (entry.State == LocalRpcCommandState.InFlight && entry.Generation == generation && !entry.PeerLost)
                {
                    entry.PeerLost = true;
                    count++;
                    abort ??= [];
                    if (entry.Lost is { } lost)
                    {
                        abort.Add(lost);
                    }

                    if (entry.Wake is { } wake)
                    {
                        abort.Add(wake);
                    }
                }
            }
        }

        CancelAll(abort);
        return count;
    }

    internal JournalSnapshot? Get(Guid commandId)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(commandId, out var entry) ? Snapshot(entry) : null;
        }
    }

    /// <summary>Records a cancel request. The returned wake tokens must be cancelled by the caller after the lock is released.</summary>
    internal (LocalRpcCancelDisposition Disposition, JournalSnapshot? Snapshot, CancellationTokenSource? Wake, bool NeedsSend) RequestCancel(Guid commandId)
    {
        lock (_sync)
        {
            if (!_entries.TryGetValue(commandId, out var entry))
            {
                return (LocalRpcCancelDisposition.NotFound, null, null, false);
            }

            if (entry.State == LocalRpcCommandState.Resolved)
            {
                if (entry.Kind == LocalRpcOutcomeKind.Cancelled)
                {
                    return (LocalRpcCancelDisposition.Cancelled, Snapshot(entry), null, false);
                }

                if (entry.Effect == LocalRpcEffect.DidNotHappen && !entry.CancelRequested)
                {
                    // Nothing ran and nothing is running: the cancel is final and there is nothing to send.
                    entry.CancelRequested = true;
                    UnlinkSettled(entry);
                    Settle(entry, LocalRpcOutcomeKind.Cancelled, LocalRpcEffect.DidNotHappen, LocalRpcFailureReason.CancelRequested, entry.Status, entry.Refusal, null, hasResponse: false);
                    return (LocalRpcCancelDisposition.Cancelled, Snapshot(entry), null, false);
                }

                return (LocalRpcCancelDisposition.TooLate, Snapshot(entry), null, false);
            }

            entry.CancelRequested = true;
            if (entry.State == LocalRpcCommandState.Unknown)
            {
                // The command is no longer running anywhere we know of: from now on it reads as cancelled, with the effect still unknown.
                entry.Kind = LocalRpcOutcomeKind.Cancelled;
                entry.Reason = LocalRpcFailureReason.CancelRequested;
            }

            return (LocalRpcCancelDisposition.Requested, Snapshot(entry), entry.Wake, true);
        }
    }

    /// <summary>Applies what the helper reported for a cancel (null when the request was not delivered).</summary>
    internal (LocalRpcCancelDisposition Disposition, JournalSnapshot? Snapshot) ApplyCancelReport(Guid commandId, LocalRpcEffect? delivered)
    {
        var report = delivered is { } value ? Known(value) : (LocalRpcEffect?)null;
        lock (_sync)
        {
            if (!_entries.TryGetValue(commandId, out var entry))
            {
                return (LocalRpcCancelDisposition.NotFound, null);
            }

            if (report is { } known && entry.State != LocalRpcCommandState.Resolved)
            {
                entry.CancelReport = known;
                if (known == LocalRpcEffect.DidNotHappen)
                {
                    // The helper stopped the effect before its commit point: nothing happened, so the call that may still be running can only fail.
                    Settle(entry, LocalRpcOutcomeKind.Cancelled, LocalRpcEffect.DidNotHappen, LocalRpcFailureReason.CancelRequested, entry.Status, entry.Refusal, null, hasResponse: false);
                }
                else if (known == LocalRpcEffect.Happened && entry.State == LocalRpcCommandState.Unknown)
                {
                    // The cancel lost the race with the commit: the effect happened and no response was seen.
                    Settle(entry, LocalRpcOutcomeKind.Success, LocalRpcEffect.Happened, LocalRpcFailureReason.None, entry.Status, entry.Refusal, null, hasResponse: false);
                }
            }

            var disposition = entry.State == LocalRpcCommandState.Resolved
                ? entry.Kind == LocalRpcOutcomeKind.Cancelled ? LocalRpcCancelDisposition.Cancelled : LocalRpcCancelDisposition.TooLate
                : LocalRpcCancelDisposition.Requested;
            return (disposition, Snapshot(entry));
        }
    }

    /// <summary>Starts a reconciliation of an unknown command; false when it is not unknown or one is already running.</summary>
    internal bool TryBeginReconcile(Guid commandId, out JournalSnapshot snapshot)
    {
        lock (_sync)
        {
            if (_entries.TryGetValue(commandId, out var entry) && entry.State == LocalRpcCommandState.Unknown && !entry.Reconciling)
            {
                entry.Reconciling = true;
                snapshot = Snapshot(entry);
                return true;
            }

            snapshot = _entries.TryGetValue(commandId, out var existing) ? Snapshot(existing) : default;
            return false;
        }
    }

    /// <summary>Ends a reconciliation: <paramref name="resolved"/> is what the owner established, or null when it could not.</summary>
    internal JournalSnapshot? EndReconcile(Guid commandId, LocalRpcEffect? resolved)
    {
        lock (_sync)
        {
            if (!_entries.TryGetValue(commandId, out var entry))
            {
                return null;
            }

            entry.Reconciling = false;
            if (entry.State == LocalRpcCommandState.Unknown && resolved is LocalRpcEffect.Happened or LocalRpcEffect.DidNotHappen)
            {
                var effect = resolved.Value;
                if (effect == LocalRpcEffect.Happened)
                {
                    Settle(entry, LocalRpcOutcomeKind.Success, LocalRpcEffect.Happened, LocalRpcFailureReason.None, entry.Status, entry.Refusal, null, hasResponse: false);
                }
                else
                {
                    var kind = entry.CancelRequested ? LocalRpcOutcomeKind.Cancelled : LocalRpcOutcomeKind.Failure;
                    Settle(entry, kind, LocalRpcEffect.DidNotHappen, entry.CancelRequested ? LocalRpcFailureReason.CancelRequested : entry.Reason, entry.Status, entry.Refusal, null, hasResponse: false);
                }
            }

            return Snapshot(entry);
        }
    }

    private bool CanReplay(JournalEntry entry, LocalRpcCommand command, LocalRpcPeerGeneration generation, long now) =>
        command.ReplayAfterUnknown
        && command.Idempotency == LocalRpcIdempotency.DuplicateSafe
        && !entry.CancelRequested
        && !entry.Reconciling
        && entry.Generation == generation
        && entry.FirstAttemptAt is { } first
        && _time.GetElapsedTime(first, now) <= _replayWindow;

    private bool IsRetryable(JournalEntry entry, LocalRpcCommand command, LocalRpcAttemptFailure failure, LocalRpcEffect effect)
    {
        var attemptIsTransient = failure.Refusal is { } refusal
            ? LocalRpcFailureClassifier.IsTransient(refusal)
            : failure.Reason is LocalRpcFailureReason.ConnectFailed or LocalRpcFailureReason.TransportLost or LocalRpcFailureReason.DeadlineExceeded;
        switch (effect)
        {
            case LocalRpcEffect.DidNotHappen:
                // Nothing happened, so sending again is safe whatever the class of the command; only a refusal that clears or a connection that may come back is worth it.
                return attemptIsTransient && failure.Reason is LocalRpcFailureReason.Refused or LocalRpcFailureReason.ConnectFailed;
            case LocalRpcEffect.Unknown:
                // An unknown effect is sent again only when the command explicitly allows it and only inside the replay window. Every attempt
                // of one call goes to the same launch (the generation is fixed when the call begins), so the same-launch rule holds here.
                return attemptIsTransient
                    && command.ReplayAfterUnknown
                    && command.Idempotency == LocalRpcIdempotency.DuplicateSafe
                    && entry.FirstAttemptAt is { } first
                    && _time.GetElapsedTime(first) <= _replayWindow;
            default:
                return false;
        }
    }

    /// <summary>An owner-supplied or helper-supplied effect that is not one of the three certainties (unspecified, or a value outside the enum) is unknown, never a settlement.</summary>
    private static LocalRpcEffect Known(LocalRpcEffect effect) =>
        effect is LocalRpcEffect.DidNotHappen or LocalRpcEffect.Happened ? effect : LocalRpcEffect.Unknown;

    private void SettleResponse(JournalEntry entry, AttemptResult result)
    {
        var effect = Known(result.ResponseEffect);
        if (effect == LocalRpcEffect.Happened)
        {
            Settle(entry, LocalRpcOutcomeKind.Success, effect, LocalRpcFailureReason.None, null, null, result.Response, hasResponse: true);
            return;
        }

        Settle(entry, LocalRpcOutcomeKind.Failure, effect, LocalRpcFailureReason.ReportedByPeer, null, null, result.Response, hasResponse: true);
    }

    private void Settle(
        JournalEntry entry,
        LocalRpcOutcomeKind kind,
        LocalRpcEffect effect,
        LocalRpcFailureReason reason,
        StatusCode? status,
        LocalRpcRefusal? refusal,
        object? response,
        bool hasResponse)
    {
        // A failed or cancelled call that names a happened effect is a success the response of which was lost.
        if (kind != LocalRpcOutcomeKind.Success && effect == LocalRpcEffect.Happened && !hasResponse)
        {
            kind = LocalRpcOutcomeKind.Success;
            reason = LocalRpcFailureReason.None;
        }

        entry.Kind = kind;
        entry.Effect = effect;
        entry.Reason = reason;
        entry.Status = status;
        entry.Refusal = refusal;
        entry.Response = response;
        entry.HasResponse = hasResponse;
        entry.Reconciling = false;
        if (effect == LocalRpcEffect.Unknown)
        {
            entry.State = LocalRpcCommandState.Unknown;
        }
        else
        {
            entry.State = LocalRpcCommandState.Resolved;
            entry.SettledAt = _time.GetTimestamp();
            entry.SettledNode ??= _settledOrder.AddLast(entry);
        }

        ReleaseSources(entry);
    }

    private static void Restart(JournalEntry entry, LocalRpcPeerGeneration generation, bool mayHaveHappened)
    {
        entry.State = LocalRpcCommandState.InFlight;
        entry.MayHaveHappened = mayHaveHappened;
        entry.Generation = generation;
        entry.PeerLost = false;
        entry.Reconciling = false;
        entry.Response = null;
        entry.HasResponse = false;
        entry.Lost = new CancellationTokenSource();
        entry.Wake = new CancellationTokenSource();
    }

    private void UnlinkSettled(JournalEntry entry)
    {
        if (entry.SettledNode is { } node)
        {
            _settledOrder.Remove(node);
            entry.SettledNode = null;
        }
    }

    private void EvictExpired(long now)
    {
        while (_settledOrder.First is { } first && _time.GetElapsedTime(first.Value.SettledAt, now) >= _retention)
        {
            _ = _entries.Remove(first.Value.Id);
            first.Value.SettledNode = null;
            _settledOrder.RemoveFirst();
        }
    }

    private static void ReleaseSources(JournalEntry entry)
    {
        // The two sources hold no timer and no wait handle, so they are released to the collector rather than disposed: a concurrent
        // cancel of a source collected before this point, or a wait that still holds its token, then never meets a disposed source.
        entry.Lost = null;
        entry.Wake = null;
    }

    private static JournalSnapshot Snapshot(JournalEntry entry) => new(
        entry.Id,
        entry.Operation,
        entry.Idempotency,
        entry.State,
        entry.Kind,
        entry.Effect,
        entry.Reason,
        entry.Status,
        entry.Refusal,
        entry.Response,
        entry.HasResponse,
        entry.Attempts,
        entry.Generation,
        entry.CancelRequested);

    /// <summary>Cancels sources outside the journal lock: a cancel runs callbacks, which must never run under it.</summary>
    internal static void CancelAll(IEnumerable<CancellationTokenSource?>? sources)
    {
        if (sources is null)
        {
            return;
        }

        foreach (var source in sources)
        {
            try
            {
                source?.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The command settled and released its sources between the collection and this cancel.
            }
            catch (AggregateException)
            {
                // A callback registered on the token threw; the source is cancelled either way.
            }
        }
    }
}

/// <summary>What one attempt produced: a response, or a failure.</summary>
internal readonly record struct AttemptResult(bool IsResponse, object? Response, LocalRpcEffect ResponseEffect, LocalRpcAttemptFailure Failure)
{
    internal static AttemptResult OfResponse(object? response, LocalRpcEffect effect) => new(true, response, effect, default);

    internal static AttemptResult OfFailure(LocalRpcAttemptFailure failure) => new(false, null, LocalRpcEffect.Unknown, failure);
}
