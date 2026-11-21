// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Execution;

/// <summary>An adoption container the node tracks, with the task and attempt that record it.</summary>
/// <param name="TaskId">The ADOPTED task.</param>
/// <param name="AttemptId">Its ADOPTED attempt.</param>
/// <param name="Container">The container.</param>
public sealed record AdoptedTask(byte[] TaskId, byte[] AttemptId, IAdoptedContainer Container);

/// <summary>
/// Recovers and drains already recorded adopted processes. A retained container can be inspected or cancelled until it empties.
/// </summary>
public sealed class Adoptions : IDisposable
{
    /// <summary>The reason of an adopted task whose container emptied by itself (04 section 10).</summary>
    public const string NoExitStatus = "no exit status: the node is not the adopted process's parent";

    /// <summary>The reason prefix of an adopted task whose container could not be re-opened after a restart (SM-TASK recovery).</summary>
    public const string ContainerMissing = "container_missing";

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    private readonly ExecutionSupervisor _execution;
    private readonly NodeStore _store;
    private readonly CommandProcessor _processor;
    private readonly NodeLog _log;
    private readonly ConcurrentDictionary<string, AdoptedTask> _tracked = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, bool> _cancelled = new(StringComparer.Ordinal);
    private Timer? _timer;
    private int _polling;

    internal Adoptions(ExecutionSupervisor execution, NodeStore store, CommandProcessor processor, NodeLog log)
    {
        _execution = execution;
        _store = store;
        _processor = processor;
        _log = log;
    }

    /// <summary>The adoption containers tracked now.</summary>
    public IReadOnlyCollection<AdoptedTask> Tracked => [.. _tracked.Values];

    /// <summary>
    /// Cancels an ADOPTED task (in the writer's command): its container is terminated, and the task ends CANCELLED once the container is empty.
    /// Returns the task's state now, or <see langword="null"/> when <paramref name="taskId"/> is not a tracked adopted task.
    /// </summary>
    public TaskState? Cancel(CommandContext context, ReadOnlySpan<byte> taskId, string reason)
    {
        ArgumentNullException.ThrowIfNull(context);
        var key = taskId.ToArray();
        var adopted = _tracked.Values.FirstOrDefault(candidate => candidate.TaskId.AsSpan().SequenceEqual(key));
        if (adopted is null)
        {
            return null;
        }

        var name = IdText.Format(adopted.AttemptId);
        _cancelled[name] = true;
        try
        {
            adopted.Container.Terminate();
        }
        catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            _log.Warning("execution.adopted.terminate_failed", new LogField("attempt", name), new LogField("errorType", exception.GetType().Name));
        }

        if (context.Transaction.Execute("UPDATE attempt SET state = 7, rev = rev + 1 WHERE attempt_id = $id AND state = 4;", ("$id", adopted.AttemptId)) > 0
            && TaskRecords.GetAttempt(context.Transaction, adopted.AttemptId) is { } stopping)
        {
            context.Emit(EventTopic.Tasks, new NodeEvent { Attempt = new AttemptChanged { Attempt = stopping, PreviousState = AttemptState.Running } });
        }

        context.Transaction.Execute("UPDATE task SET state_reason = $reason, rev = rev + 1 WHERE task_id = $id;", ("$reason", Truncate(reason, 500)), ("$id", key));
        _execution.EmitTask(context, key, TaskState.Running);
        Wake();
        return TaskState.Running;
    }

    /// <summary>Re-opens containers of live ADOPTED attempts or records authoritative absence. Unavailable custody leaves the attempt live.</summary>
    internal async Task RecoverAsync(bool bootChanged)
    {
        var live = _store.Read(reader =>
        {
            var rows = new List<(byte[] Attempt, byte[] Task, string? Container, int State, string? Boot)>();
            using var command = reader.CreateCommand("SELECT attempt_id, task_id, container_name, state, boot_identity FROM attempt WHERE kind = 4 AND state BETWEEN 1 AND 8;");
            using var result = command.ExecuteReader();
            while (result.Read())
            {
                rows.Add(((byte[])result.GetValue(0), (byte[])result.GetValue(1), result.IsDBNull(2) ? null : result.GetString(2), result.GetInt32(3),
                    result.IsDBNull(4) ? null : result.GetString(4)));
            }

            return rows;
        });
        foreach (var row in live)
        {
            var name = IdText.Format(row.Attempt);
            IAdoptedContainer? container = null;
            string? why = null;
            if (bootChanged && !string.Equals(row.Boot, _store.Metadata.BootIdentity, StringComparison.Ordinal))
            {
                why = "boot_changed: the machine restarted since the process was adopted";
            }
            else
            {
                if (row.Container is { } containerName)
                {
                    try
                    {
                        var platform = _execution.Platform ?? throw new LegacyCustodyUnavailableException("The legacy execution platform is unavailable.");
                        container = platform.ReopenAdopted(containerName);
                    }
                    catch (Exception exception) when (exception is Win32Exception or IOException or TimeoutException or InvalidOperationException or UnauthorizedAccessException)
                    {
                        _log.Warning("execution.adopted.reopen_failed", new LogField("attempt", name),
                            new LogField("errorType", exception.GetType().Name),
                            new LogField("error", exception is Win32Exception native ? native.NativeErrorCode : NodeLog.OneLine(exception.Message)));
                        throw new LegacyCustodyUnavailableException("Legacy adoption custody could not be confirmed.", exception);
                    }
                }

                why = ContainerMissing + ": the adoption container " + (row.Container ?? "(none)") + " no longer exists";
            }

            if (container is null)
            {
                await FinishAsync(row.Task, row.Attempt, TaskState.Lost, TerminationReason.Lost, why!).ConfigureAwait(false);
                continue;
            }

            _tracked[name] = new AdoptedTask(row.Task, row.Attempt, container);
            if (row.State == (int)AttemptState.Stopping)
            {
                _cancelled[name] = true;
            }
        }
    }

    /// <summary>Starts watching the tracked containers.</summary>
    internal void Start() => _timer ??= new Timer(_ => Poll(), null, PollInterval, PollInterval);

    /// <summary>Checks the containers now (also on demand, for example right after a cancel).</summary>
    internal void Wake() => _ = Task.Run(Poll);

    /// <summary>Stops watching and releases the container handles; the adopted processes keep running.</summary>
    public void Dispose()
    {
        _timer?.Dispose();
        _timer = null;
        foreach (var adopted in _tracked.Values)
        {
            adopted.Container.Dispose();
        }

        _tracked.Clear();
        _cancelled.Clear();
    }

    private void Poll()
    {
        if (Interlocked.Exchange(ref _polling, 1) == 1)
        {
            return;
        }

        try
        {
            foreach (var (name, adopted) in _tracked)
            {
                IReadOnlyList<int> processes;
                try
                {
                    processes = adopted.Container.Processes();
                }
                catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException or ObjectDisposedException)
                {
                    _log.Warning("execution.adopted.read_failed", new LogField("attempt", name), new LogField("errorType", exception.GetType().Name));
                    continue;
                }

                if (processes.Count > 0)
                {
                    continue;
                }

                // Review round 1: the entry stays tracked until its end is recorded, so a failed record is retried at the next poll instead of
                // leaving the task RUNNING until a restart records it with another reason.
                var cancelled = _cancelled.ContainsKey(name);
                try
                {
                    FinishAsync(adopted.TaskId, adopted.AttemptId, cancelled ? TaskState.Cancelled : TaskState.Lost,
                        cancelled ? TerminationReason.Cancelled : TerminationReason.Lost,
                        cancelled ? "the adopted processes were terminated on request" : NoExitStatus).GetAwaiter().GetResult();
                }
                catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
                {
                    _log.Warning("execution.adopted.record_failed", new LogField("attempt", name), new LogField("errorType", exception.GetType().Name));
                    continue;
                }

                if (_tracked.TryRemove(name, out _))
                {
                    _cancelled.TryRemove(name, out _);
                    adopted.Container.Dispose();
                }
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // A timer callback must never throw: anything unexpected is logged and the next poll runs.
            _log.Warning("execution.adopted.poll_failed", new LogField("errorType", exception.GetType().Name));
        }
        finally
        {
            Volatile.Write(ref _polling, 0);
        }
    }

    private async Task FinishAsync(byte[] taskId, byte[] attemptId, TaskState state, TerminationReason reason, string detail)
    {
        await _processor.ExecuteAsync(context =>
        {
            var transaction = context.Transaction;
            var now = transaction.NowMicroseconds;
            var previous = (AttemptState)Convert.ToInt32(transaction.Scalar("SELECT state FROM attempt WHERE attempt_id = $id;", ("$id", attemptId)) ?? 0L,
                CultureInfo.InvariantCulture);
            transaction.Execute(
                "UPDATE attempt SET state = 9, finished_at = $now, termination_reason = $reason, effect = $effect, detail = $detail, rev = rev + 1 WHERE attempt_id = $id AND state <> 9;",
                ("$now", now), ("$reason", (int)reason), ("$effect", (int)(reason == TerminationReason.Cancelled ? EffectCertainty.Happened : EffectCertainty.Unknown)),
                ("$detail", detail), ("$id", attemptId));
            transaction.Execute("UPDATE task SET state = $state, state_reason = $detail, finished_at = $now, rev = rev + 1 WHERE task_id = $id AND state IN (4, 5);",
                ("$state", (int)state), ("$detail", Truncate(detail, 500)), ("$now", now), ("$id", taskId));
            if (TaskRecords.GetAttempt(transaction, attemptId) is { } attempt)
            {
                context.Emit(EventTopic.Tasks, new NodeEvent { Attempt = new AttemptChanged { Attempt = attempt, PreviousState = previous } });
            }

            _execution.EmitTask(context, taskId, TaskState.Running);
            return 0;
        }).ConfigureAwait(false);
        _log.Info("execution.adopted.ended", new LogField("task", IdText.Format(taskId)), new LogField("state", state));
    }

    private static string Truncate(string text, int length) => text.Length <= length ? text : text[..length];
}
