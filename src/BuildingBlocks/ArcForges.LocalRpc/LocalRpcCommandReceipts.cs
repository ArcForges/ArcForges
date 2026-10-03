// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using Grpc.Core;

namespace ArcForges.LocalRpc;

/// <summary>Bounds of a helper's <see cref="LocalRpcCommandReceipts"/>. Every value is validated when the table is created.</summary>
public sealed record LocalRpcCommandReceiptOptions
{
    /// <summary>Most commands the table records (1 through 65536, default 1024). A new command over this is refused with a typed refusal, never an older one forgotten.</summary>
    public int Capacity { get; init; } = 1024;

    /// <summary>
    /// How long a command whose effect is known stays recorded (default 10 minutes). The parent replays within its replay window
    /// (<see cref="LocalRpcCommandExecutorOptions.ReplayWindow"/>, default 5 minutes), which must stay shorter than this.
    /// </summary>
    public TimeSpan Retention { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>The longest an effect may run before its token is cancelled (default 30 s, the longest call deadline; 1 s through 10 minutes).</summary>
    public TimeSpan EffectTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Bytes of responses kept for replay across all recorded commands (default 32 MiB). A response that does not fit is not kept; the command still records that its effect happened.</summary>
    public long MaxRetainedResponseBytes { get; init; } = 32L * 1024 * 1024;

    /// <summary>The longest <see cref="LocalRpcCommandReceipts.DisposeAsync"/> waits for cancelled effects to finish (default 5 s).</summary>
    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(5);

    internal LocalRpcCommandReceiptOptions Validated()
    {
        if (Capacity is < 1 or > 65536)
        {
            throw new ArgumentOutOfRangeException(nameof(Capacity), Capacity, "The receipt capacity is 1 through 65536.");
        }

        if (Retention <= TimeSpan.Zero || Retention > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(nameof(Retention), Retention, "The retention is positive and at most one day.");
        }

        if (EffectTimeout < TimeSpan.FromSeconds(1) || EffectTimeout > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(EffectTimeout), EffectTimeout, "The effect timeout is one second through ten minutes.");
        }

        if (MaxRetainedResponseBytes is < 0 or > 1L << 32)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxRetainedResponseBytes), MaxRetainedResponseBytes, "The retained response budget is zero through 4 GiB.");
        }

        if (ShutdownTimeout < TimeSpan.Zero || ShutdownTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(ShutdownTimeout), ShutdownTimeout, "The shutdown timeout is zero through one minute.");
        }

        return this;
    }
}

/// <summary>Where a recorded command stands in a helper's table.</summary>
public enum LocalRpcReceiptState
{
    /// <summary>Not a state; never reported.</summary>
    None = 0,

    /// <summary>The effect is running.</summary>
    InFlight = 1,

    /// <summary>The effect completed.</summary>
    Succeeded = 2,

    /// <summary>The effect was cancelled (explicitly, by its timeout or by shutdown).</summary>
    Cancelled = 3,

    /// <summary>The effect threw.</summary>
    Faulted = 4,
}

/// <summary>A point-in-time view of one recorded command in a helper's table.</summary>
/// <param name="State">Where the command stands.</param>
/// <param name="Effect">What is known: <see cref="LocalRpcEffect.Happened"/> once the effect committed or completed, <see cref="LocalRpcEffect.DidNotHappen"/> once it ended before its commit point, <see cref="LocalRpcEffect.Unknown"/> while it runs before its commit point.</param>
/// <param name="Committed">Whether the effect passed its commit point.</param>
/// <param name="ResponseRetained">Whether the response is still held for replay.</param>
public readonly record struct LocalRpcReceiptSnapshot(LocalRpcReceiptState State, LocalRpcEffect Effect, bool Committed, bool ResponseRetained);

/// <summary>What a helper reports about an explicit cancel.</summary>
/// <param name="Disposition"><see cref="LocalRpcCancelDisposition.Cancelled"/> when the effect ended before its commit point, <see cref="LocalRpcCancelDisposition.TooLate"/> when it had committed or completed, <see cref="LocalRpcCancelDisposition.Requested"/> when it did not stop in time, <see cref="LocalRpcCancelDisposition.NotFound"/> for an unknown id.</param>
/// <param name="Effect">The effect to report on the wire.</param>
public readonly record struct LocalRpcCancelReport(LocalRpcCancelDisposition Disposition, LocalRpcEffect Effect);

/// <summary>
/// What an effect sees: its command id, a token that is cancelled by an explicit cancel, by the effect timeout and by shutdown (never by a
/// disconnect of the call that started it), and the commit point.
/// </summary>
public sealed class LocalRpcCommandContext
{
    private readonly LocalRpcCommandReceipts _owner;
    private readonly ReceiptEntry _entry;

    internal LocalRpcCommandContext(LocalRpcCommandReceipts owner, ReceiptEntry entry, CancellationToken token)
    {
        _owner = owner;
        _entry = entry;
        CancellationToken = token;
    }

    /// <summary>The command id.</summary>
    public Guid CommandId => _entry.Id;

    /// <summary>Cancelled by an explicit cancel, by the effect timeout and by shutdown.</summary>
    public CancellationToken CancellationToken { get; }

    /// <summary>Whether <see cref="Commit"/> has passed.</summary>
    public bool IsCommitted => _owner.IsCommitted(_entry);

    /// <summary>
    /// Passes the commit point: from here the effect can no longer be cancelled by an explicit cancel and counts as having happened, even if
    /// it throws afterwards. Throws <see cref="OperationCanceledException"/> when a cancel (or the timeout, or shutdown) came first, which
    /// ends the effect with nothing done. An effect must change nothing durable before it commits.
    /// </summary>
    public void Commit() => _owner.Commit(_entry);
}

/// <summary>One command in a helper's table. Every field is read and written only under the table lock.</summary>
internal sealed class ReceiptEntry
{
    internal ReceiptEntry(Guid id, byte[] digest)
    {
        Id = id;
        Digest = digest;
    }

    internal Guid Id { get; }

    internal byte[] Digest { get; }

    internal LocalRpcReceiptState State { get; set; } = LocalRpcReceiptState.InFlight;

    internal LocalRpcEffect Effect { get; set; } = LocalRpcEffect.Unknown;

    internal bool Committed { get; set; }

    internal bool CancelRequested { get; set; }

    internal StatusCode FailureStatus { get; set; }

    internal object? Response { get; set; }

    internal long RetainedBytes { get; set; }

    internal CancellationTokenSource? Source { get; set; }

    internal TaskCompletionSource<bool> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal long SettledAt { get; set; }

    internal LinkedListNode<ReceiptEntry>? SettledNode { get; set; }
}

/// <summary>
/// A helper's in-memory table of the commands it has run, keyed by the parent's command id. It makes a command's effect happen at most
/// once per helper launch however many times the same command arrives: a duplicate with the same input joins the running effect or is
/// answered from the record, a different input under the same id is refused, and the effect keeps running when the call that started
/// it disconnects, so a parent that lost the answer can ask again and get it. It also carries the effect certainty: the effect names its
/// commit point, and a command that ended before it did not happen while one that passed it did. <b>Nothing is durable.</b> A helper
/// that dies takes the table with it, and the parent then sees an unknown effect that only the owner's own durable record can resolve.
/// The effect must change nothing durable before <see cref="LocalRpcCommandContext.Commit"/>.
/// </summary>
public sealed class LocalRpcCommandReceipts : IAsyncDisposable
{
    internal const string EffectTrailer = "x-af-effect";

    private readonly object _sync = new();
    private readonly Dictionary<Guid, ReceiptEntry> _entries = [];
    private readonly LinkedList<ReceiptEntry> _settledOrder = new();
    private readonly LocalRpcCommandReceiptOptions _options;
    private readonly TimeProvider _time;
    private long _retainedBytes;
    private bool _disposed;

    /// <summary>Creates an empty table.</summary>
    public LocalRpcCommandReceipts(LocalRpcCommandReceiptOptions? options = null)
        : this(options, TimeProvider.System)
    {
    }

    internal LocalRpcCommandReceipts(LocalRpcCommandReceiptOptions? options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(time);
        _options = (options ?? new LocalRpcCommandReceiptOptions()).Validated();
        _time = time;
    }

    /// <summary>Commands recorded right now.</summary>
    public int RecordedCommands
    {
        get
        {
            lock (_sync)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Bytes of responses held for replay right now.</summary>
    public long RetainedResponseBytes
    {
        get
        {
            lock (_sync)
            {
                return _retainedBytes;
            }
        }
    }

    /// <summary>Reads the effect a helper attached to a failed command call; false when the call carried none.</summary>
    public static bool TryReadEffect(RpcException exception, out LocalRpcEffect effect)
    {
        ArgumentNullException.ThrowIfNull(exception);
        effect = default;
        foreach (var entry in exception.Trailers)
        {
            if (!entry.IsBinary && string.Equals(entry.Key, EffectTrailer, StringComparison.Ordinal))
            {
                switch (entry.Value)
                {
                    case "did-not-happen":
                        effect = LocalRpcEffect.DidNotHappen;
                        return true;
                    case "happened":
                        effect = LocalRpcEffect.Happened;
                        return true;
                    case "unknown":
                        effect = LocalRpcEffect.Unknown;
                        return true;
                    default:
                        return false;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Runs the effect of a command once. A first arrival starts <paramref name="effect"/> under a token the call does not own and waits for it
    /// (an exception thrown by the wait only abandons the wait); a duplicate with the same input joins it or is answered from the record; a
    /// different input is refused <c>command-conflict</c> and a full table <c>receipts-full</c>, both before the effect runs. A failure is
    /// raised as an <see cref="RpcException"/> carrying the effect certainty (<see cref="TryReadEffect"/>).
    /// </summary>
    /// <typeparam name="TResponse">The response message.</typeparam>
    /// <param name="commandId">The parent's command id.</param>
    /// <param name="inputDigest">The 32-byte digest of the canonical input; the same id with another digest is a conflict.</param>
    /// <param name="effect">The effect. It must call <see cref="LocalRpcCommandContext.Commit"/> before it changes anything durable.</param>
    /// <param name="sizeOf">The size in bytes of a response, so the table can keep it for replay within its budget.</param>
    /// <param name="callToken">The call's token (the handler's cancellation token).</param>
    public async Task<TResponse> ExecuteAsync<TResponse>(
        Guid commandId,
        ReadOnlyMemory<byte> inputDigest,
        Func<LocalRpcCommandContext, Task<TResponse>> effect,
        Func<TResponse, long> sizeOf,
        CancellationToken callToken)
    {
        if (commandId == Guid.Empty)
        {
            throw new ArgumentException("A command id is never empty.", nameof(commandId));
        }

        if (inputDigest.Length != LocalRpcCommand.DigestBytes)
        {
            throw new ArgumentException("An input digest is exactly 32 bytes.", nameof(inputDigest));
        }

        ArgumentNullException.ThrowIfNull(effect);
        ArgumentNullException.ThrowIfNull(sizeOf);
        ReceiptEntry? entry = null;
        var owner = false;
        LocalRpcRefusalReason? refusal = null;
        var shuttingDown = false;
        lock (_sync)
        {
            if (_disposed)
            {
                shuttingDown = true;
            }
            else
            {
                EvictExpired();
                if (_entries.TryGetValue(commandId, out var existing))
                {
                    if (existing.Digest.AsSpan().SequenceEqual(inputDigest.Span))
                    {
                        entry = existing;
                    }
                    else
                    {
                        refusal = LocalRpcRefusalReason.CommandConflict;
                    }
                }
                else if (_entries.Count >= _options.Capacity)
                {
                    refusal = LocalRpcRefusalReason.ReceiptsFull;
                }
                else
                {
                    entry = new ReceiptEntry(commandId, inputDigest.ToArray())
                    {
                        Source = new CancellationTokenSource(_options.EffectTimeout, _time),
                    };
                    _entries.Add(commandId, entry);
                    owner = true;
                }
            }
        }

        if (shuttingDown)
        {
            throw Failure(StatusCode.Unavailable, "The helper is shutting down.", LocalRpcEffect.DidNotHappen, null);
        }

        if (refusal is { } reason)
        {
            throw Failure(LocalRpcRefusal.StatusOf(reason), "The command was refused before its effect ran: " + LocalRpcRefusal.NameOf(reason) + ".", LocalRpcEffect.DidNotHappen, reason);
        }

        Task<TResponse>? ran = null;
        if (owner)
        {
            ran = StartEffect(entry!, effect, sizeOf);
        }

        await entry!.Completion.Task.WaitAsync(callToken).ConfigureAwait(false);

        // The call that ran the effect always gets its own response; only a later replay depends on the response having been kept.
        return ran is { IsCompletedSuccessfully: true } ? await ran.ConfigureAwait(false) : ReadResult<TResponse>(entry);
    }

    /// <summary>
    /// Cancels a running command by id and reports what became of it. Before the commit point the effect's token is cancelled and the
    /// report waits (until <paramref name="cancellationToken"/>, the control call's deadline) for the effect to end: a command that ended
    /// without committing reports <see cref="LocalRpcEffect.DidNotHappen"/>; one that had committed, completed anyway or ignored the cancel
    /// reports <see cref="LocalRpcEffect.Happened"/>; one that did not stop in time reports <see cref="LocalRpcEffect.Unknown"/>.
    /// </summary>
    public async Task<LocalRpcCancelReport> CancelAsync(Guid commandId, CancellationToken cancellationToken = default)
    {
        ReceiptEntry? found;
        CancellationTokenSource? source = null;
        lock (_sync)
        {
            if (!_entries.TryGetValue(commandId, out found))
            {
                return new LocalRpcCancelReport(LocalRpcCancelDisposition.NotFound, LocalRpcEffect.Unknown);
            }

            if (found.State != LocalRpcReceiptState.InFlight)
            {
                return Report(found);
            }

            if (found.Committed)
            {
                return new LocalRpcCancelReport(LocalRpcCancelDisposition.TooLate, LocalRpcEffect.Happened);
            }

            found.CancelRequested = true;
            source = found.Source;
        }

        var entry = found;

        Cancel(source);
        try
        {
            await entry.Completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new LocalRpcCancelReport(LocalRpcCancelDisposition.Requested, LocalRpcEffect.Unknown);
        }

        lock (_sync)
        {
            return Report(entry);
        }
    }

    /// <summary>What the table records about a command, or null when it is not recorded (never run, forgotten, or lost with a helper that died).</summary>
    public LocalRpcReceiptSnapshot? Get(Guid commandId)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(commandId, out var entry)
                ? new LocalRpcReceiptSnapshot(entry.State, EffectOf(entry), entry.Committed, entry.Response is not null)
                : null;
        }
    }

    /// <summary>Cancels every running effect, waits for them for at most <see cref="LocalRpcCommandReceiptOptions.ShutdownTimeout"/> and releases the table.</summary>
    public async ValueTask DisposeAsync()
    {
        List<CancellationTokenSource> sources = [];
        List<Task> waits = [];
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            foreach (var entry in _entries.Values)
            {
                if (entry.State == LocalRpcReceiptState.InFlight)
                {
                    if (entry.Source is { } source)
                    {
                        sources.Add(source);
                    }

                    waits.Add(entry.Completion.Task);
                }
            }
        }

        foreach (var source in sources)
        {
            Cancel(source);
        }

        try
        {
            await Task.WhenAll(waits).WaitAsync(_options.ShutdownTimeout, _time).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // An effect that ignores its token is abandoned; its entry stays in flight and nothing waits for it.
        }
    }

    internal bool IsCommitted(ReceiptEntry entry)
    {
        lock (_sync)
        {
            return entry.Committed;
        }
    }

    internal void Commit(ReceiptEntry entry)
    {
        lock (_sync)
        {
            var token = entry.Source?.Token ?? new CancellationToken(canceled: true);
            if (entry.CancelRequested || token.IsCancellationRequested || _disposed)
            {
                throw new OperationCanceledException("The command was cancelled before its commit point.", token);
            }

            entry.Committed = true;
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "An effect that throws before its first await is recorded like one that throws later: the receipt names the failure.")]
    private Task<TResponse> StartEffect<TResponse>(ReceiptEntry entry, Func<LocalRpcCommandContext, Task<TResponse>> effect, Func<TResponse, long> sizeOf)
    {
        Task<TResponse> task;
        try
        {
            task = effect(new LocalRpcCommandContext(this, entry, entry.Source!.Token));
        }
        catch (Exception exception)
        {
            task = Task.FromException<TResponse>(exception);
        }

        _ = SettleAsync(entry, task, sizeOf);
        return task;
    }

    [SuppressMessage("Design", "CA1031", Justification = "Whatever the effect threw is recorded in its receipt and reported to the parent as a typed failure.")]
    private async Task SettleAsync<TResponse>(ReceiptEntry entry, Task<TResponse> task, Func<TResponse, long> sizeOf)
    {
        TResponse? response = default;
        Exception? failure = null;
        try
        {
            response = await task.ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        var size = failure is null ? SizeOf(response, sizeOf) : long.MaxValue;
        CancellationTokenSource? release;
        lock (_sync)
        {
            if (failure is null)
            {
                entry.State = LocalRpcReceiptState.Succeeded;
                entry.Effect = LocalRpcEffect.Happened;
                Retain(entry, response, size);
            }
            else if (failure is OperationCanceledException && !entry.Committed)
            {
                entry.State = LocalRpcReceiptState.Cancelled;
                entry.Effect = LocalRpcEffect.DidNotHappen;
                entry.FailureStatus = entry.CancelRequested ? StatusCode.Cancelled : _disposed ? StatusCode.Unavailable : StatusCode.DeadlineExceeded;
            }
            else
            {
                entry.State = LocalRpcReceiptState.Faulted;
                entry.Effect = entry.Committed ? LocalRpcEffect.Happened : LocalRpcEffect.DidNotHappen;
                entry.FailureStatus = failure is RpcException { StatusCode: not StatusCode.OK } rpc ? rpc.StatusCode : StatusCode.Internal;
            }

            entry.SettledAt = _time.GetTimestamp();
            entry.SettledNode = _settledOrder.AddLast(entry);
            release = entry.Source;
            entry.Source = null;
        }

        release?.Dispose();
        _ = entry.Completion.TrySetResult(true);
    }

    private static long SizeOf<TResponse>(TResponse? response, Func<TResponse, long> sizeOf)
    {
        try
        {
            return response is null ? 0 : Math.Max(0, sizeOf(response));
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // A response whose size cannot be computed is not retained; the command still records that its effect happened.
            return long.MaxValue;
        }
    }

    private void Retain(ReceiptEntry entry, object? response, long size)
    {
        if (size > _options.MaxRetainedResponseBytes)
        {
            return;
        }

        // Make room by dropping the oldest retained responses, never the receipts themselves.
        var node = _settledOrder.First;
        while (_retainedBytes + size > _options.MaxRetainedResponseBytes && node is not null)
        {
            var older = node.Value;
            if (older.Response is not null)
            {
                _retainedBytes -= older.RetainedBytes;
                older.Response = null;
                older.RetainedBytes = 0;
            }

            node = node.Next;
        }

        entry.Response = response;
        entry.RetainedBytes = size;
        _retainedBytes += size;
    }

    private TResponse ReadResult<TResponse>(ReceiptEntry entry)
    {
        LocalRpcReceiptState state;
        LocalRpcEffect effect;
        StatusCode status;
        object? response;
        lock (_sync)
        {
            state = entry.State;
            effect = entry.Effect;
            status = entry.FailureStatus;
            response = entry.Response;
        }

        switch (state)
        {
            case LocalRpcReceiptState.Succeeded when response is TResponse typed:
                return typed;
            case LocalRpcReceiptState.Succeeded:
                throw Failure(StatusCode.FailedPrecondition, "The command happened; its response is not retained.", LocalRpcEffect.Happened, null);
            case LocalRpcReceiptState.Cancelled:
                throw Failure(status, "The command was cancelled.", effect, null);
            default:
                throw Failure(status, "The command failed.", effect, null);
        }
    }

    private static LocalRpcCancelReport Report(ReceiptEntry entry) => entry.State switch
    {
        LocalRpcReceiptState.Cancelled => new LocalRpcCancelReport(LocalRpcCancelDisposition.Cancelled, entry.Effect),
        LocalRpcReceiptState.InFlight => new LocalRpcCancelReport(LocalRpcCancelDisposition.Requested, LocalRpcEffect.Unknown),
        _ => new LocalRpcCancelReport(LocalRpcCancelDisposition.TooLate, entry.Effect),
    };

    private static LocalRpcEffect EffectOf(ReceiptEntry entry) => entry.State == LocalRpcReceiptState.InFlight
        ? entry.Committed ? LocalRpcEffect.Happened : LocalRpcEffect.Unknown
        : entry.Effect;

    private static RpcException Failure(StatusCode status, string message, LocalRpcEffect effect, LocalRpcRefusalReason? refusal)
    {
        var trailers = new Metadata
        {
            { EffectTrailer, effect switch
                {
                    LocalRpcEffect.DidNotHappen => "did-not-happen",
                    LocalRpcEffect.Happened => "happened",
                    _ => "unknown",
                } },
        };
        if (refusal is { } reason)
        {
            trailers.Add(LocalRpcRefusal.ReasonTrailer, LocalRpcRefusal.NameOf(reason));
            trailers.Add(LocalRpcRefusal.DispatchedTrailer, "0");
        }

        return new RpcException(new Status(status, message), trailers);
    }

    private void EvictExpired()
    {
        while (_settledOrder.First is { } first && _time.GetElapsedTime(first.Value.SettledAt) >= _options.Retention)
        {
            var entry = first.Value;
            _retainedBytes -= entry.RetainedBytes;
            _ = _entries.Remove(entry.Id);
            entry.SettledNode = null;
            _settledOrder.RemoveFirst();
        }
    }

    private static void Cancel(CancellationTokenSource? source)
    {
        // Cancel outside the table lock: it runs the effect's registered callbacks.
        try
        {
            source?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The effect settled and released its token between the collection and this cancel.
        }
        catch (AggregateException)
        {
            // A callback registered on the token threw; the token is cancelled either way.
        }
    }
}
