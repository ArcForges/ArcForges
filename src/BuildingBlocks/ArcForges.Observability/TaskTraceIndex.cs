// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Foundation.Execution;

namespace ArcForges.Observability;

/// <summary>
/// A bounded, process-local index from user-visible task/run identities to the trace that observed them.
/// Entries are evicted oldest-first; an identity already associated with another trace is never overwritten.
/// </summary>
public sealed class TaskTraceIndex
{
    public const int DefaultCapacity = 4096;

    private readonly object _gate = new();
    private readonly Dictionary<TraceKey, ActivityTraceId> _traces = new();
    private readonly Queue<TraceKey> _insertionOrder = new();

    public TaskTraceIndex(int capacity = DefaultCapacity)
    {
        if (capacity < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity), "Capacity must hold both a task and run identity.");
        }

        Capacity = capacity;
    }

    /// <summary>The maximum number of typed task/run mappings retained by this index.</summary>
    public int Capacity { get; }

    /// <summary>
    /// Associates the supplied task and/or run with a real trace. Returns false without changing the index
    /// if either identity already points at a different trace. Re-recording the same mapping is idempotent.
    /// With no identifiers, the call succeeds without storing an entry.
    /// </summary>
    public bool TryRecord(TaskId? task, RunId? run, ActivityTraceId traceId)
    {
        if (traceId == default)
        {
            throw new ArgumentException("A non-empty trace identity is required.", nameof(traceId));
        }

        Span<TraceKey> keys = stackalloc TraceKey[2];
        int count = 0;
        if (task is { } taskId)
        {
            if (taskId.Value == Guid.Empty)
            {
                throw new ArgumentException("A non-empty task identity is required.", nameof(task));
            }

            keys[count++] = new TraceKey(IdentifierKind.Task, taskId.Value);
        }

        if (run is { } runId)
        {
            if (runId.Value == Guid.Empty)
            {
                throw new ArgumentException("A non-empty run identity is required.", nameof(run));
            }

            keys[count++] = new TraceKey(IdentifierKind.Run, runId.Value);
        }

        lock (_gate)
        {
            for (int index = 0; index < count; index++)
            {
                if (_traces.TryGetValue(keys[index], out ActivityTraceId existing) && existing != traceId)
                {
                    return false;
                }
            }

            for (int index = 0; index < count; index++)
            {
                TraceKey key = keys[index];
                if (_traces.ContainsKey(key))
                {
                    continue;
                }

                while (_traces.Count >= Capacity)
                {
                    TraceKey oldest = _insertionOrder.Dequeue();
                    _traces.Remove(oldest);
                }

                _traces.Add(key, traceId);
                _insertionOrder.Enqueue(key);
            }
        }

        return true;
    }

    /// <summary>Returns the trace for a task identity, or false when it is absent or has been evicted.</summary>
    public bool TryResolve(TaskId task, out ActivityTraceId traceId)
    {
        if (task.Value == Guid.Empty)
        {
            throw new ArgumentException("A non-empty task identity is required.", nameof(task));
        }

        return TryResolve(new TraceKey(IdentifierKind.Task, task.Value), out traceId);
    }

    /// <summary>Returns the trace for a run identity, or false when it is absent or has been evicted.</summary>
    public bool TryResolve(RunId run, out ActivityTraceId traceId)
    {
        if (run.Value == Guid.Empty)
        {
            throw new ArgumentException("A non-empty run identity is required.", nameof(run));
        }

        return TryResolve(new TraceKey(IdentifierKind.Run, run.Value), out traceId);
    }

    private bool TryResolve(TraceKey key, out ActivityTraceId traceId)
    {
        lock (_gate)
        {
            return _traces.TryGetValue(key, out traceId);
        }
    }

    private enum IdentifierKind : byte { Task, Run }

    private readonly record struct TraceKey(IdentifierKind Kind, Guid Value);
}
