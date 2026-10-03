// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Events.V1;

namespace RealtimeAotProbe;

/// <summary>The visible connection state. A drop is reported as reconnecting and never as complete.</summary>
internal enum ConnectionState
{
    Connecting,
    Live,
    Reconnecting,
    Stopped,
}

/// <summary>Why a watcher or reader returned.</summary>
internal enum StopReason
{
    /// <summary>The caller cancelled.</summary>
    Cancelled,

    /// <summary>A typed permission failure or a permission reset: no retry until a new authorized session.</summary>
    AuthorizationLost,

    /// <summary>The server does not implement the operation.</summary>
    Unsupported,

    /// <summary>The server sent something the closed contract does not allow.</summary>
    ProtocolViolation,

    /// <summary>The server contradicted data this client already accepted.</summary>
    IntegrityViolation,

    /// <summary>A refusal that a retry cannot change.</summary>
    NonRetryable,

    /// <summary>The execution output ended with a terminal outcome confirmed by an authoritative read.</summary>
    Completed,
}

internal readonly record struct WatchResult(StopReason Reason, string Detail);

internal readonly record struct SequenceGap(string SubscriptionKey, ulong Expected, ulong Actual);

/// <summary>Receives what a watcher or reader decided. Exceptions it throws end the run unswallowed.</summary>
/// <remarks>
/// A hint is only a hint: the observer re-reads the owner RPC it names, and a gap or snapshot request obliges
/// it to read the authoritative state before it continues. The probe has no owner RPC to read, so its
/// observers only record the obligation.
/// </remarks>
internal abstract class RealtimeObserver
{
    public virtual Task ConnectionChangedAsync(ConnectionState state, string detail, CancellationToken cancellationToken) => Task.CompletedTask;

    public virtual Task HintAsync(Event hint, CancellationToken cancellationToken) => Task.CompletedTask;

    public virtual Task GapAsync(SequenceGap gap, CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Read the authoritative scoped snapshot, then the run resumes after its high-water cursor.</summary>
    public virtual Task SnapshotRequiredAsync(string reason, CancellationToken cancellationToken) => Task.CompletedTask;

    public virtual Task OutputAsync(OutputChunk chunk, CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>The output restarts from offset zero; discard what was displayed.</summary>
    public virtual Task OutputResetAsync(string reason, CancellationToken cancellationToken) => Task.CompletedTask;

    public virtual Task TerminalAsync(ExecutionOutput terminal, CancellationToken cancellationToken) => Task.CompletedTask;
}
