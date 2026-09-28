// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Foundation.Errors;

namespace ArcForges.Capabilities;

/// <summary>Closed kinds of non-authoritative in-process state hints.</summary>
public enum StateHintKind
{
    Resource = 1,
    Capability = 2,
    Health = 3,
    Context = 4,
    ProductJob = 5,
}

/// <summary>A hint contains only a kind and stable target ID; it never carries state or content.</summary>
public sealed class StateHint
{
    internal StateHint(StateHintKind kind, string targetId)
    {
        Kind = kind;
        TargetId = targetId;
    }

    public StateHintKind Kind { get; }
    public string TargetId { get; }
}

/// <summary>An opaque, ephemeral cursor bound to one in-process feed and its current instance.</summary>
public sealed class StateHintCursor
{
    internal StateHintCursor(Guid feedId, Guid instanceId, ulong instanceEpoch, long sequence, long issuedTimestamp)
    {
        FeedId = feedId;
        InstanceId = instanceId;
        InstanceEpoch = instanceEpoch;
        Sequence = sequence;
        IssuedTimestamp = issuedTimestamp;
    }

    internal Guid FeedId { get; }
    internal Guid InstanceId { get; }
    internal ulong InstanceEpoch { get; }
    internal long Sequence { get; }
    internal long IssuedTimestamp { get; }
}

/// <summary>One poll result and, when hints or reset require it, the owning application's fresh read.</summary>
public sealed class StateHintReconciliation<TState>
{
    internal StateHintReconciliation(StateHintCursor cursor, IReadOnlyList<StateHint> hints,
        bool resetRequired, bool hasAuthoritativeState, TState? authoritativeState)
    {
        Cursor = cursor;
        Hints = hints;
        ResetRequired = resetRequired;
        HasAuthoritativeState = hasAuthoritativeState;
        AuthoritativeState = authoritativeState;
    }

    public StateHintCursor Cursor { get; }
    public IReadOnlyList<StateHint> Hints { get; }
    public bool ResetRequired { get; }
    public bool HasAuthoritativeState { get; }
    public TState? AuthoritativeState { get; }
}

/// <summary>Reads authoritative owner state for IDs named by a hint page, or the complete scope on reset.</summary>
public delegate ValueTask<Outcome<TState>> AuthoritativeStateRead<TState>(IReadOnlyList<StateHint> hints,
    bool resetRequired, CancellationToken cancellationToken);

/// <summary>
/// A bounded in-process hint feed for one authorized subscriber scope and one application instance.
/// Hints are only invalidation signals: a page with hints or a reset cannot be returned as successful
/// reconciliation until the owner read completes. Allocate a separate feed per authorized subscriber;
/// its random identity binds cursors to that scope. A new feed after restart invalidates old cursors.
/// </summary>
public sealed class InProcessStateHintFeed
{
    private static readonly TimeSpan Retention = TimeSpan.FromSeconds(60);
    private const int MaximumBufferedHints = 256;
    private const int MaximumPageSize = 128;
    private const int MaximumResponseBytes = 256 * 1024;
    private const int MaximumTargetIdLength = 128;

    private readonly object _gate = new();
    private readonly LinkedList<BufferedHint> _hints = [];
    private readonly Dictionary<HintKey, LinkedListNode<BufferedHint>> _byTarget = [];
    private readonly Guid _feedId = Guid.NewGuid();
    private readonly InstanceIdentity _instance;
    private readonly TimeProvider _timeProvider;
    private long _sequence;

    /// <summary>Creates an in-process feed for one authorized subscriber and immutable application instance.</summary>
    public InProcessStateHintFeed(InstanceIdentity instance, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(instance);
        _instance = instance;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Publishes a bounded invalidation hint. Repeated kind/target pairs coalesce; invalid IDs and
    /// unspecified kinds are rejected before entering the feed.
    /// </summary>
    public bool Publish(StateHintKind kind, string targetId)
    {
        if (!Enum.IsDefined(kind) || !IsStableTargetId(targetId))
        {
            return false;
        }

        lock (_gate)
        {
            var now = _timeProvider.GetTimestamp();
            PruneExpired(now);
            var key = new HintKey(kind, targetId);
            if (_byTarget.TryGetValue(key, out var previous))
            {
                _hints.Remove(previous);
                _byTarget.Remove(key);
            }

            var item = new BufferedHint(++_sequence, kind, targetId, now);
            var node = _hints.AddLast(item);
            _byTarget.Add(key, node);
            while (_hints.Count > MaximumBufferedHints)
            {
                RemoveFirst();
            }
        }

        return true;
    }

    /// <summary>
    /// Polls a bounded page and forces an authoritative owner read for every non-empty page or
    /// reset. The opaque cursor expires after the retention window and cannot cross feed/restart boundaries.
    /// </summary>
    public async ValueTask<Outcome<StateHintReconciliation<TState>>> PollAndReadAsync<TState>(
        StateHintCursor? cursor,
        AuthoritativeStateRead<TState> authoritativeRead,
        int limit = 50,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authoritativeRead);
        if (limit is < 1 or > MaximumPageSize)
        {
            return Failure<StateHintReconciliation<TState>>("validation.invalid_request");
        }

        StateHintReconciliation<TState> page;
        lock (_gate)
        {
            var now = _timeProvider.GetTimestamp();
            PruneExpired(now);
            bool resetRequired = RequiresReset(cursor, now);
            StateHint[] hints;
            long nextSequence;
            if (resetRequired)
            {
                hints = [];
                nextSequence = _sequence;
            }
            else
            {
                var afterCursor = _hints.Where(item => item.Sequence > cursor!.Sequence).Take(limit).ToArray();
                var accepted = new List<StateHint>(afterCursor.Length);
                var responseBytes = 64;
                foreach (var item in afterCursor)
                {
                    int itemBytes = 32 + Encoding.UTF8.GetByteCount(item.TargetId);
                    if (responseBytes + itemBytes > MaximumResponseBytes)
                    {
                        break;
                    }

                    responseBytes += itemBytes;
                    accepted.Add(new StateHint(item.Kind, item.TargetId));
                }

                hints = accepted.ToArray();
                nextSequence = accepted.Count == 0 ? cursor!.Sequence : afterCursor[accepted.Count - 1].Sequence;
            }

            var readOnlyHints = Array.AsReadOnly(hints);
            bool needsRead = resetRequired || hints.Length != 0;
            page = new StateHintReconciliation<TState>(
                new StateHintCursor(_feedId, _instance.InstanceId.Value, _instance.Epoch, nextSequence, now), readOnlyHints, resetRequired,
                hasAuthoritativeState: false, authoritativeState: default);
            if (!needsRead)
            {
                return Outcome.Success(page);
            }
        }

        var read = await authoritativeRead(page.Hints, page.ResetRequired, cancellationToken).ConfigureAwait(false);
        if (read is null)
        {
            return Failure<StateHintReconciliation<TState>>("internal.unexpected");
        }

        if (read.TryGetFailure(out var failure))
        {
            return Outcome.Failure<StateHintReconciliation<TState>>(failure!);
        }

        if (read.Kind == OutcomeKind.Cancelled)
        {
            return Outcome.Cancelled<StateHintReconciliation<TState>>(read.CancellationEffect);
        }

        if (!read.TryGetValue(out var state))
        {
            return Failure<StateHintReconciliation<TState>>("internal.unexpected");
        }

        return Outcome.Success(new StateHintReconciliation<TState>(page.Cursor, page.Hints,
            page.ResetRequired, hasAuthoritativeState: true, state));
    }

    private bool RequiresReset(StateHintCursor? cursor, long now)
    {
        if (cursor is null || cursor.FeedId != _feedId || cursor.InstanceId != _instance.InstanceId.Value ||
            cursor.InstanceEpoch != _instance.Epoch || cursor.Sequence > _sequence)
        {
            return true;
        }

        var cursorAge = _timeProvider.GetElapsedTime(cursor.IssuedTimestamp, now);
        if (cursorAge < TimeSpan.Zero || cursorAge > Retention)
        {
            return true;
        }

        long firstRetainedSequence = _hints.First?.Value.Sequence ?? _sequence + 1;
        return cursor.Sequence < firstRetainedSequence - 1;
    }

    private void PruneExpired(long now)
    {
        while (_hints.First is { } first &&
               _timeProvider.GetElapsedTime(first.Value.PublishedTimestamp, now) > Retention)
        {
            RemoveFirst();
        }
    }

    private void RemoveFirst()
    {
        var first = _hints.First;
        if (first is null)
        {
            return;
        }
        _hints.RemoveFirst();
        _byTarget.Remove(new HintKey(first.Value.Kind, first.Value.TargetId));
    }

    private static bool IsStableTargetId(string? targetId) => targetId is { Length: >= 1 and <= MaximumTargetIdLength } &&
        targetId is not "." and not ".." && targetId.All(character =>
            character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.' or ':');

    private static Outcome<T> Failure<T>(string code) => Outcome.Failure<T>(TypedFailure.Create(code));

    private readonly record struct HintKey(StateHintKind Kind, string TargetId);
    private sealed record BufferedHint(long Sequence, StateHintKind Kind, string TargetId, long PublishedTimestamp);
}
