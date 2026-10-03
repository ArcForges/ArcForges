// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.LocalRpc;

/// <summary>Bounds and policy of a <see cref="LocalRpcCommandExecutor"/>. Every value is validated when the executor is created.</summary>
public sealed record LocalRpcCommandExecutorOptions
{
    /// <summary>Most times one call sends a command, first send included (1 through 10, default 3).</summary>
    public int MaxAttempts { get; init; } = 3;

    /// <summary>The wait between attempts. Default: full jitter from 250 ms doubling to 30 s.</summary>
    public LocalRpcBackoff Backoff { get; init; } = new();

    /// <summary>
    /// How long after its first send an unknown command may still be replayed when its command allows replay (default 5 minutes). It
    /// must stay below how long the helper keeps its receipts (<see cref="LocalRpcCommandReceiptOptions.Retention"/>, 10 minutes).
    /// </summary>
    public TimeSpan ReplayWindow { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Most commands the journal records (1 through 65536, default 4096). A new command over this is refused, never an older one forgotten.</summary>
    public int JournalCapacity { get; init; } = 4096;

    /// <summary>How long a command whose effect is known stays recorded, so a duplicate submission is answered from the record (default 10 minutes).</summary>
    public TimeSpan SettledRetention { get; init; } = TimeSpan.FromMinutes(10);

    internal LocalRpcCommandExecutorOptions Validated()
    {
        if (MaxAttempts is < 1 or > 10)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxAttempts), MaxAttempts, "The attempt bound is 1 through 10.");
        }

        ArgumentNullException.ThrowIfNull(Backoff);
        if (ReplayWindow <= TimeSpan.Zero || ReplayWindow > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(nameof(ReplayWindow), ReplayWindow, "The replay window is positive and at most one hour.");
        }

        if (JournalCapacity is < 1 or > 65536)
        {
            throw new ArgumentOutOfRangeException(nameof(JournalCapacity), JournalCapacity, "The journal capacity is 1 through 65536.");
        }

        if (SettledRetention <= TimeSpan.Zero || SettledRetention > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(nameof(SettledRetention), SettledRetention, "The retention is positive and at most one day.");
        }

        return this;
    }
}

/// <summary>
/// Runs commands against a helper and keeps what is known about each one's effect across disconnects, cancellations and the
/// loss of the helper itself. Every command has one stable id; the executor records each attempt in an in-memory journal and
/// classifies a failure by what it proves: a typed refusal, a stream that never opened or a receipt report prove that the effect did not happen,
/// and anything else after a request may have been sent leaves it <see cref="LocalRpcEffect.Unknown"/>. An unknown effect is never
/// replayed unless the command allows it, never guessed, and only an owner reconciliation or a helper report resolves it.
/// Nothing is durable: the journal is lost with the parent process.
/// </summary>
public sealed class LocalRpcCommandExecutor
{
    private readonly LocalRpcCommandJournal _journal;
    private readonly LocalRpcCommandExecutorOptions _options;
    private readonly TimeProvider _time;

    /// <summary>Creates an executor with its own journal.</summary>
    public LocalRpcCommandExecutor(LocalRpcCommandExecutorOptions? options = null)
        : this(options, TimeProvider.System)
    {
    }

    internal LocalRpcCommandExecutor(LocalRpcCommandExecutorOptions? options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(time);
        _options = (options ?? new LocalRpcCommandExecutorOptions()).Validated();
        _time = time;
        _journal = new LocalRpcCommandJournal(time, _options.JournalCapacity, _options.SettledRetention, _options.ReplayWindow);
    }

    /// <summary>How many commands the journal records right now.</summary>
    public int RecordedCommands => _journal.Count;

    /// <summary>
    /// Sends a command and settles what is known about its effect. The <paramref name="send"/> delegate makes the generated call
    /// for the attempt number it is given and must honour the token (it carries the caller's cancellation and the loss of the launch)
    /// and set a deadline of its own. A query is retried after a transient failure and is not recorded; a mutation is recorded under its
    /// command id and sent again only when its effect certainly did not happen (or, when the command allows it, when it is unknown and
    /// the launch is the same). A command that is already recorded is answered from the record without sending.
    /// </summary>
    /// <typeparam name="TResponse">The response message.</typeparam>
    /// <param name="command">The command identity.</param>
    /// <param name="generation">The launch the command is sent to.</param>
    /// <param name="send">Makes one attempt: the attempt number and a token.</param>
    /// <param name="interpret">What the effect of a received response is (for example from an <c>ArcError</c> it carries); default <see cref="LocalRpcEffect.Happened"/>.</param>
    /// <param name="cancellationToken">The caller's token. Cancelling it abandons the call: the effect of a command already sent stays unknown.</param>
    public async Task<LocalRpcCommandOutcome<TResponse>> ExecuteAsync<TResponse>(
        LocalRpcCommand command,
        LocalRpcPeerGeneration generation,
        Func<int, CancellationToken, Task<TResponse>> send,
        Func<TResponse, LocalRpcEffect>? interpret = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(send);
        if (command.Idempotency == LocalRpcIdempotency.Query)
        {
            return await RunQueryAsync(command, send, cancellationToken).ConfigureAwait(false);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return Outcome<TResponse>(command.CommandId, LocalRpcOutcomeKind.Cancelled, LocalRpcEffect.DidNotHappen, LocalRpcFailureReason.CancelledByCaller, 0, sent: false);
        }

        var begin = _journal.Begin(command, generation);
        switch (begin.Kind)
        {
            case BeginKind.Started:
                return await RunAsync(begin.Entry!, command, send, interpret, cancellationToken).ConfigureAwait(false);
            case BeginKind.Recorded:
                return From<TResponse>(begin.Snapshot, sent: false, begin.Snapshot.Reason);
            case BeginKind.ReplayRefused:
                return From<TResponse>(begin.Snapshot, sent: false, begin.Snapshot.CancelRequested ? LocalRpcFailureReason.CancelRequested : LocalRpcFailureReason.ReplayNotAllowed);
            case BeginKind.InFlight:
                return Outcome<TResponse>(command.CommandId, LocalRpcOutcomeKind.Failure, LocalRpcEffect.Unknown, LocalRpcFailureReason.AlreadyInFlight, begin.Snapshot.Attempts, sent: false);
            case BeginKind.Conflict:
                return Outcome<TResponse>(command.CommandId, LocalRpcOutcomeKind.Failure, LocalRpcEffect.DidNotHappen, LocalRpcFailureReason.CommandConflict, 0, sent: false);
            default:
                return Outcome<TResponse>(command.CommandId, LocalRpcOutcomeKind.Failure, LocalRpcEffect.DidNotHappen, LocalRpcFailureReason.JournalFull, 0, sent: false);
        }
    }

    /// <summary>
    /// The owner declares a launch lost (its process exited, its lease lapsed, its stream broke for good). Every command in flight on
    /// it is aborted and recorded: an attempt that may have been sent is <see cref="LocalRpcEffect.Unknown"/> and one that was
    /// not stays <see cref="LocalRpcEffect.DidNotHappen"/>. Returns the number of commands stopped.
    /// </summary>
    public int PeerLost(LocalRpcPeerGeneration generation) => _journal.PeerLost(generation);

    /// <summary>Declares the launch lost as soon as <paramref name="lost"/> is cancelled (for example the launch's <c>Revoked</c> token). Dispose the registration to stop watching.</summary>
    public CancellationTokenRegistration WatchPeer(LocalRpcPeerGeneration generation, CancellationToken lost) =>
        lost.Register(() => _ = _journal.PeerLost(generation));

    /// <summary>The command as recorded, or null when no command with this id is recorded.</summary>
    public LocalRpcCommandRecord? GetRecord(Guid commandId) => _journal.Get(commandId)?.ToRecord();

    /// <summary>
    /// Resolves a command whose effect is unknown by asking the owner. The delegate looks the command up where its effect lives (a
    /// durable store, a query such as the contract's own read of the object the command changed) and returns what it found;
    /// <see cref="LocalRpcEffect.Unknown"/> leaves the command unknown. A command that is not unknown, or that is already being reconciled, is returned unchanged.
    /// </summary>
    public async Task<LocalRpcCommandRecord?> ReconcileAsync(
        Guid commandId,
        Func<LocalRpcCommandRecord, CancellationToken, ValueTask<LocalRpcEffect>> resolve,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolve);
        if (!_journal.TryBeginReconcile(commandId, out var snapshot))
        {
            return _journal.Get(commandId)?.ToRecord();
        }

        LocalRpcEffect? resolved = null;
        try
        {
            resolved = await resolve(snapshot.ToRecord(), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = _journal.EndReconcile(commandId, resolved);
        }

        return _journal.Get(commandId)?.ToRecord();
    }

    /// <summary>
    /// Cancels a command. The intent is recorded first, so it survives the loss of the helper and stops every retry and replay, and
    /// then <paramref name="send"/> carries it to the helper (through a control method declared with <c>RegisterControl</c>, so it
    /// uses a reserved control slot). The delegate returns what the helper reports: <see cref="LocalRpcEffect.DidNotHappen"/> when the
    /// command was stopped before its commit point, <see cref="LocalRpcEffect.Happened"/> when it was too late, <see cref="LocalRpcEffect.Unknown"/> when the helper cannot say.
    /// A cancel that cannot be delivered leaves the command recorded as cancel-requested with an unknown effect; calling this again after
    /// the helper is back delivers it. A command whose effect is known and was not cancelled is reported as too late.
    /// </summary>
    public async Task<LocalRpcCancelResult> CancelAsync(
        Guid commandId,
        Func<LocalRpcCommandRecord, CancellationToken, Task<LocalRpcEffect>> send,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(send);
        var (disposition, snapshot, wake, needsSend) = _journal.RequestCancel(commandId);
        LocalRpcCommandJournal.CancelAll([wake]);
        if (!needsSend)
        {
            return new LocalRpcCancelResult(disposition, Delivered: false, snapshot?.ToRecord());
        }

        LocalRpcEffect? report = null;
        var delivered = false;
        try
        {
            report = await send(snapshot!.Value.ToRecord(), cancellationToken).ConfigureAwait(false);
            delivered = true;
        }
        catch (Exception exception) when (LocalRpcFailureClassifier.Classify(exception, cancellationToken) is not null)
        {
            // The cancel could not be delivered (the helper is gone or the call failed): the intent stays recorded.
        }

        var (final, settled) = _journal.ApplyCancelReport(commandId, report);
        return new LocalRpcCancelResult(final, delivered, settled?.ToRecord());
    }

    private async Task<LocalRpcCommandOutcome<TResponse>> RunAsync<TResponse>(
        JournalEntry entry,
        LocalRpcCommand command,
        Func<int, CancellationToken, Task<TResponse>> send,
        Func<TResponse, LocalRpcEffect>? interpret,
        CancellationToken caller)
    {
        var sent = false;
        while (true)
        {
            var started = _journal.StartAttempt(entry, caller.IsCancellationRequested);
            if (started is null)
            {
                return From<TResponse>(_journal.SettleWithoutAttempt(entry, caller.IsCancellationRequested), sent, null);
            }

            var (attempt, lost) = started.Value;
            AttemptResult result;
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(caller, lost))
            {
                try
                {
                    sent = true;
                    var response = await send(attempt, linked.Token).ConfigureAwait(false);
                    result = AttemptResult.OfResponse(response, interpret is null ? LocalRpcEffect.Happened : interpret(response));
                }
                catch (Exception exception) when (LocalRpcFailureClassifier.Classify(exception, caller) is { } classified)
                {
                    result = AttemptResult.OfFailure(classified);
                }
                catch
                {
                    // Not a transport failure: record that the effect is unknown, then let the exception reach the caller.
                    _journal.SettleUnclassified(entry);
                    throw;
                }
            }

            var decision = _journal.EndAttempt(entry, command, result, _options.MaxAttempts, _options.Backoff);
            if (!decision.Retry)
            {
                return From<TResponse>(decision.Snapshot, sent, null);
            }

            var (lostToken, wakeToken) = _journal.WaitTokens(entry);
            try
            {
                using var waiting = CancellationTokenSource.CreateLinkedTokenSource(caller, lostToken, wakeToken);
                await Task.Delay(decision.Delay, _time, waiting.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // A cancel, a lost launch or the caller's token ended the wait; the next loop turn settles the entry.
            }
        }
    }

    private async Task<LocalRpcCommandOutcome<TResponse>> RunQueryAsync<TResponse>(
        LocalRpcCommand command,
        Func<int, CancellationToken, Task<TResponse>> send,
        CancellationToken caller)
    {
        var attempts = 0;
        LocalRpcAttemptFailure last = default;
        while (true)
        {
            if (caller.IsCancellationRequested)
            {
                return Outcome<TResponse>(command.CommandId, LocalRpcOutcomeKind.Cancelled, attempts == 0 ? LocalRpcEffect.DidNotHappen : last.Effect, LocalRpcFailureReason.CancelledByCaller, attempts, sent: attempts > 0);
            }

            attempts++;
            try
            {
                var response = await send(attempts, caller).ConfigureAwait(false);
                return Outcome(command.CommandId, LocalRpcOutcomeKind.Success, LocalRpcEffect.Happened, LocalRpcFailureReason.None, attempts, sent: true, response);
            }
            catch (Exception exception) when (LocalRpcFailureClassifier.Classify(exception, caller) is { } classified)
            {
                last = classified;
                var transient = classified.Reason is LocalRpcFailureReason.ConnectFailed or LocalRpcFailureReason.TransportLost or LocalRpcFailureReason.DeadlineExceeded
                    || (classified.Refusal is { } refusal && LocalRpcFailureClassifier.IsTransient(refusal));
                if (classified.CancelledByCaller || !transient || attempts >= _options.MaxAttempts)
                {
                    return new LocalRpcCommandOutcome<TResponse>(
                        command.CommandId,
                        classified.CancelledByCaller ? LocalRpcOutcomeKind.Cancelled : LocalRpcOutcomeKind.Failure,
                        classified.Effect,
                        classified.Reason,
                        attempts,
                        sent: true,
                        classified.Status,
                        classified.Refusal,
                        hasResponse: false,
                        default);
                }
            }

            try
            {
                await Task.Delay(_options.Backoff.Next(attempts), _time, caller).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The caller's token ended the wait; the next loop turn reports the cancellation.
            }
        }
    }

    private static LocalRpcCommandOutcome<TResponse> Outcome<TResponse>(
        Guid commandId,
        LocalRpcOutcomeKind kind,
        LocalRpcEffect effect,
        LocalRpcFailureReason reason,
        int attempts,
        bool sent,
        TResponse? response = default) =>
        new(commandId, kind, effect, reason, attempts, sent, status: null, refusal: null, hasResponse: kind == LocalRpcOutcomeKind.Success, response);

    private static LocalRpcCommandOutcome<TResponse> From<TResponse>(JournalSnapshot snapshot, bool sent, LocalRpcFailureReason? reasonOverride)
    {
        var matched = snapshot.HasResponse && snapshot.Response is TResponse;
        var response = matched ? (TResponse?)snapshot.Response : default;
        var kind = snapshot.State == LocalRpcCommandState.InFlight ? LocalRpcOutcomeKind.Failure : snapshot.Kind;
        var effect = snapshot.State == LocalRpcCommandState.InFlight ? LocalRpcEffect.Unknown : snapshot.Effect;
        var reason = reasonOverride ?? snapshot.Reason;
        return new LocalRpcCommandOutcome<TResponse>(
            snapshot.Id,
            kind,
            effect,
            kind == LocalRpcOutcomeKind.Success ? LocalRpcFailureReason.None : reason,
            snapshot.Attempts,
            sent,
            snapshot.Status,
            snapshot.Refusal,
            matched,
            response);
    }
}
