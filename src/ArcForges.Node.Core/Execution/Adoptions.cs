// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Execution;

/// <summary>An adoption container the node tracks, with the task and attempt that record it.</summary>
/// <param name="TaskId">The ADOPTED task.</param>
/// <param name="AttemptId">Its ADOPTED attempt.</param>
/// <param name="Container">The container.</param>
public sealed record AdoptedTask(byte[] TaskId, byte[] AttemptId, IAdoptedContainer Container);

/// <summary>
/// A process the platform placed in an adoption container (<see cref="Adoptions.Prepare"/>, outside the store writer), not yet recorded
/// (<see cref="Adoptions.Record"/>).
/// </summary>
/// <param name="TaskId">The ADOPTED task to record.</param>
/// <param name="AttemptId">Its ADOPTED attempt.</param>
/// <param name="Pid">The process.</param>
/// <param name="Start">Its start time.</param>
/// <param name="Title">The title, or <see langword="null"/>.</param>
/// <param name="Pool">The pool.</param>
/// <param name="Result">What the platform did.</param>
public sealed record PreparedAdoption(byte[] TaskId, byte[] AttemptId, int Pid, DateTimeOffset Start, string? Title, string Pool, AdoptionResult Result);

/// <summary>What <see cref="Adoptions.Record"/> recorded.</summary>
/// <param name="TaskId">The new ADOPTED task.</param>
/// <param name="AdoptedChildren">Children placed individually.</param>
/// <param name="FailedChildren">Children that could not be placed.</param>
public sealed record AdoptionOutcome(byte[] TaskId, int AdoptedChildren, int FailedChildren);

/// <summary>
/// Adoption (04 section 10; R-RES-013): an existing same-user process, and the children it has at that moment (each individually, best effort,
/// with each result recorded), is placed in an adoption container by the platform, and a synthetic task (<c>kind=ADOPTED</c>) with one
/// ADOPTED attempt records it, so the process appears in every surface: the task lists, <c>ListProcesses</c> (label ADOPTED) and the process
/// controls. Adoption is explicit and HUMAN-only (11 section 1). An adopted task is never admitted, queued, preempted, paused or retried:
/// it is RUNNING from adoption until its container is empty. A container that empties by itself ends the task LOST ("no exit status: the
/// node is not the adopted process's parent"); <c>CancelTask</c> terminates the container and ends it CANCELLED. After a node restart the
/// container is re-opened by name; one the node cannot re-open (a Windows adoption job has no holder, L-14) follows the SM-TASK recovery rule
/// "container missing -> LOST".
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
    /// Places the process in an adoption container through the platform, outside the store writer (review round 1: a D-Bus call and a job wait
    /// of up to 10 s never hold the single writer). The caller records the result with <see cref="Record"/> in a command, or releases it with
    /// <see cref="Release"/> when it is not recorded.
    /// </summary>
    /// <exception cref="AdoptionRefusedException">The platform refused (not found, another user, already managed, or the OS refused).</exception>
    public PreparedAdoption Prepare(int pid, DateTimeOffset start, string? title, string pool)
    {
        var platform = _execution.Platform ?? throw new AdoptionRefusedException("no execution platform could be started on this node (see the node log)");
        if (_execution.RunningAttempts.Any(attempt => attempt.Handle?.Usage(null).Pids.Contains(pid) == true)
            || _tracked.Values.Any(adopted => adopted.Container.Processes().Contains(pid)))
        {
            throw new AdoptionRefusedException("the process is already managed by this node") { AlreadyManaged = true };
        }

        var taskId = StoreIds.NewUuid7(_store.Clock);
        var attemptId = StoreIds.NewUuid7(_store.Clock);
        var result = platform.Adopt(new AdoptionRequest(_execution.NodeName, IdText.Format(attemptId), pid, start));
        return new PreparedAdoption(taskId, attemptId, pid, start, title, pool, result);
    }

    /// <summary>Releases a prepared adoption that was not recorded (the container's handle; its processes keep running).</summary>
    public static void Release(PreparedAdoption prepared)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        prepared.Result.Container.Dispose();
    }

    /// <summary>Records a prepared adoption's ADOPTED task and attempt (in the writer's command) and starts tracking its container.</summary>
    public AdoptionOutcome Record(CommandContext context, PreparedAdoption prepared, ActorRef owner)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(owner);
        var (taskId, attemptId, pid, start, title, pool, result) = prepared;
        var name = IdText.Format(attemptId);
        var transaction = context.Transaction;
        try
        {
            var image = result.Image;
            var summary = Path.GetFileName(image) is { Length: > 0 } file ? file : image;
            var spec = new TaskSpec
            {
                Kind = TaskKind.Adopted,
                Title = Truncate(title is { Length: > 0 } ? title : "adopted " + summary, 200),
                Pool = pool,
                Command = new CommandSpec { Argv = new ArgvCommand { Argv = { image } } },
            };
            var specBytes = spec.ToByteArray();
            var now = transaction.NowMicroseconds;
            var digest = SHA256.HashData(Encoding.UTF8.GetBytes("adopted\n" + pid.ToString(CultureInfo.InvariantCulture) + "\n" + StoreTime.ToMicroseconds(start)));
            transaction.Execute(
                """
                INSERT INTO task (task_id, state, state_reason, kind, title, command_summary, spec, env_digest, spec_digest, owner, owner_origin, owner_session_id,
                                  workspace_id, pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at,
                                  queued_at, started_at, current_attempt_id, attempt_count, pinned, labels_json, rev)
                VALUES ($id, 4, 'adopted', 3, $title, $summary, $spec, NULL, $specDigest, $owner, $origin, NULL, NULL, $pool, 3, 3, 4, 1, $fingerprint, $digest,
                        $now, NULL, $now, $attempt, 1, 0, '{}', 0);
                """,
                ("$id", taskId), ("$title", spec.Title), ("$summary", Truncate(image, 500)), ("$spec", specBytes), ("$specDigest", SHA256.HashData(specBytes)),
                ("$owner", owner.ToByteArray()), ("$origin", (int)owner.Origin), ("$pool", pool), ("$fingerprint", "adopted:" + summary), ("$digest", digest),
                ("$now", now), ("$attempt", attemptId));
            transaction.Execute(
                """
                INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, container_name, root_pid, root_start, boot_identity,
                                     request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source, accounted_mem_bytes,
                                     unenforced, created_at, started_at, detail, rev)
                VALUES ($id, $task, 1, 4, 4, $node, $container, $pid, $start, $boot, 1, 1, 0, 4, 1, 0, $now, $now, $detail, 0);
                """,
                ("$id", attemptId), ("$task", taskId), ("$node", _store.Metadata.NodeId.ToArray()), ("$container", result.Container.ContainerName),
                ("$pid", pid), ("$start", StoreTime.ToMicroseconds(start)), ("$boot", _store.Metadata.BootIdentity), ("$now", now),
                ("$detail", Truncate(result.ChildResults.Count == 0 ? "adopted (no children at adoption time)" : "children at adoption: " + string.Join("; ", result.ChildResults), 500)));
            transaction.Execute(
                """
                INSERT INTO process_record (attempt_id, pid, start_at, parent_pid, executable, arguments_redacted, first_seen, last_seen, mem_peak_bytes, label)
                VALUES ($attempt, $pid, $start, NULL, $image, NULL, $now, $now, 0, $label);
                """,
                ("$attempt", attemptId), ("$pid", pid), ("$start", StoreTime.ToMicroseconds(start)), ("$image", image), ("$now", now), ("$label", (int)ProcessLabel.Adopted));
            _execution.EmitTask(context, taskId, null);
            context.Emit(EventTopic.Tasks, new NodeEvent { Attempt = new AttemptChanged { Attempt = TaskRecords.GetAttempt(transaction, attemptId) } });
        }
        catch
        {
            // The record could not be written: the container must not outlive the command that created it.
            result.Container.Dispose();
            throw;
        }

        _tracked[name] = new AdoptedTask(taskId, attemptId, result.Container);
        _log.Info("execution.adopted", new LogField("task", IdText.Format(taskId)), new LogField("pid", pid), new LogField("container", result.Container.ContainerName),
            new LogField("children", result.AdoptedChildren), new LogField("childrenFailed", result.FailedChildren));
        return new AdoptionOutcome(taskId, result.AdoptedChildren, result.FailedChildren);
    }

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

        context.Transaction.Execute("UPDATE attempt SET state = 7, rev = rev + 1 WHERE attempt_id = $id AND state = 4;", ("$id", adopted.AttemptId));
        context.Transaction.Execute("UPDATE task SET state_reason = $reason, rev = rev + 1 WHERE task_id = $id;", ("$reason", Truncate(reason, 500)), ("$id", key));
        _execution.EmitTask(context, key, TaskState.Running);
        Wake();
        return TaskState.Running;
    }

    /// <summary>Re-opens the containers of the ADOPTED attempts the store records as live (node start), or records them LOST.</summary>
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
            else if (row.Container is null || _execution.Platform?.ReopenAdopted(row.Container) is not { } reopened)
            {
                why = ContainerMissing + ": the adoption container " + (row.Container ?? "(none)") + " could not be re-opened after the node restarted";
            }
            else
            {
                container = reopened;
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
