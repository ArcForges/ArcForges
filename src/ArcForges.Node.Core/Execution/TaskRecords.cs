// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Execution;

/// <summary>A task row as the supervisor needs it.</summary>
public sealed class TaskRow
{
    /// <summary>The task ID.</summary>
    public required byte[] TaskId { get; init; }

    /// <summary>SM-TASK state.</summary>
    public TaskState State { get; init; }

    /// <summary>The kind.</summary>
    public TaskKind Kind { get; init; }

    /// <summary>The stored (redacted) spec.</summary>
    public required TaskSpec Spec { get; init; }

    /// <summary>The caller environment snapshot's digest, or null.</summary>
    public byte[]? EnvDigest { get; init; }

    /// <summary>The owner.</summary>
    public required ActorRef Owner { get; init; }

    /// <summary>The effective priority.</summary>
    public Priority Priority { get; init; }

    /// <summary>The side-effect class.</summary>
    public SideEffectClass SideEffect { get; init; }

    /// <summary>Who established the class (AD-0006 section 4).</summary>
    public SideEffectSource SideEffectSource { get; init; } = SideEffectSource.Default;

    /// <summary>The pool.</summary>
    public string Pool { get; init; } = "default";

    /// <summary><c>state_reason</c>, or <see langword="null"/>.</summary>
    public string? StateReason { get; init; }

    /// <summary>Attempts so far.</summary>
    public int AttemptCount { get; init; }

    /// <summary>The current attempt.</summary>
    public byte[]? CurrentAttemptId { get; init; }

    /// <summary>When ReleaseCallerBinding ran.</summary>
    public long? CallerReleasedAt { get; init; }

    /// <summary>Whether the record was purged.</summary>
    public bool Purged { get; init; }

    /// <summary>The row revision.</summary>
    public long Revision { get; init; }

    /// <summary>True in SUCCEEDED, FAILED, CANCELLED or LOST.</summary>
    public bool Terminal => TaskRecords.IsTerminal(State);
}

/// <summary>An attempt row as the supervisor needs it.</summary>
public sealed class AttemptRow
{
    /// <summary>The attempt ID.</summary>
    public required byte[] AttemptId { get; init; }

    /// <summary>The task ID.</summary>
    public required byte[] TaskId { get; init; }

    /// <summary>The attempt number (1-based).</summary>
    public int Number { get; init; }

    /// <summary>SM-ATTEMPT state.</summary>
    public AttemptState State { get; init; }

    /// <summary>The container name.</summary>
    public string? ContainerName { get; init; }

    /// <summary>The root PID.</summary>
    public int? RootPid { get; init; }

    /// <summary>The root start (microseconds).</summary>
    public long? RootStart { get; init; }

    /// <summary>The boot identity at launch.</summary>
    public string? BootIdentity { get; init; }

    /// <summary>Indexed bytes of stdout.</summary>
    public long StdoutOffset { get; init; }

    /// <summary>Indexed bytes of stderr.</summary>
    public long StderrOffset { get; init; }

    /// <summary>Index records written.</summary>
    public long IndexOffset { get; init; }

    /// <summary>The pending stop cause in STOPPING or FINALIZING, or the final termination reason in FINISHED.</summary>
    public TerminationReason? Reason { get; init; }

    /// <summary>The stored pending stop detail, or final result detail.</summary>
    public string? Detail { get; init; }

    /// <summary>When it started (microseconds).</summary>
    public long? StartedAt { get; init; }
}

/// <summary>
/// The SQL of tasks and attempts (node-store.md <c>task</c>, <c>attempt</c>) and their contract views (<c>ManagedTask</c>, <c>Attempt</c>):
/// the scheduler and the supervisor write them through the command processor; the API reads them on reader connections.
/// </summary>
public static class TaskRecords
{
    private const string AttemptColumns =
        "attempt_id, task_id, number, kind, state, executor_node_id, container_name, root_pid, root_start, boot_identity, request_cpu_millicores, " +
        "request_mem_expected_bytes, request_mem_ceiling_bytes, request_source, unenforced, node_gap, created_at, started_at, finished_at, exit_code, " +
        "signal, windows_status, termination_reason, effect, detail, leftover_count, leftover_images_json, cpu_time_ms, mem_peak_bytes, io_read_bytes, " +
        "io_write_bytes, stdout_bytes, stderr_bytes, stdout_offset, stderr_offset, index_offset, limit_enforced_by, guard_lost, rev, core_dumped, tool, operation, " +
        "tool_parallelism";

    private const string TaskColumns =
        "task_id, state, state_reason, kind, title, command_summary, spec, env_digest, owner, owner_origin, owner_session_id, workspace_id, pool, " +
        "priority, effective_priority, side_effect, side_effect_source, created_at, queued_at, started_at, finished_at, caller_released_at, " +
        "current_attempt_id, attempt_count, ready, pinned, labels_json, purged_at, rev";

    /// <summary>True for the terminal task states.</summary>
    public static bool IsTerminal(TaskState state) =>
        state is TaskState.Succeeded or TaskState.Failed or TaskState.Cancelled or TaskState.Lost;

    /// <summary>The task row, or <see langword="null"/>.</summary>
    public static TaskRow? GetRow(StoreReader reader, ReadOnlySpan<byte> taskId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand(
            "SELECT task_id, state, kind, spec, env_digest, owner, effective_priority, side_effect, attempt_count, current_attempt_id, caller_released_at, purged_at, rev, " +
            "side_effect_source, pool, state_reason FROM task WHERE task_id = $id;");
        command.Parameters.AddWithValue("$id", taskId.ToArray());
        using var rows = command.ExecuteReader();
        if (!rows.Read())
        {
            return null;
        }

        return new TaskRow
        {
            TaskId = (byte[])rows.GetValue(0),
            State = (TaskState)rows.GetInt32(1),
            Kind = (TaskKind)rows.GetInt32(2),
            Spec = TaskSpec.Parser.ParseFrom((byte[])rows.GetValue(3)),
            EnvDigest = rows.IsDBNull(4) ? null : (byte[])rows.GetValue(4),
            Owner = ActorRef.Parser.ParseFrom((byte[])rows.GetValue(5)),
            Priority = (Priority)rows.GetInt32(6),
            SideEffect = (SideEffectClass)rows.GetInt32(7),
            AttemptCount = rows.GetInt32(8),
            CurrentAttemptId = rows.IsDBNull(9) ? null : (byte[])rows.GetValue(9),
            CallerReleasedAt = rows.IsDBNull(10) ? null : rows.GetInt64(10),
            Purged = !rows.IsDBNull(11),
            Revision = rows.GetInt64(12),
            SideEffectSource = (SideEffectSource)rows.GetInt32(13),
            Pool = rows.GetString(14),
            StateReason = rows.IsDBNull(15) ? null : rows.GetString(15),
        };
    }

    /// <summary>The attempt row, or <see langword="null"/>.</summary>
    public static AttemptRow? GetAttemptRow(StoreReader reader, ReadOnlySpan<byte> attemptId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand(
            "SELECT attempt_id, task_id, number, state, container_name, root_pid, root_start, boot_identity, stdout_offset, stderr_offset, index_offset, " +
            "termination_reason, started_at, detail FROM attempt WHERE attempt_id = $id;");
        command.Parameters.AddWithValue("$id", attemptId.ToArray());
        using var rows = command.ExecuteReader();
        return rows.Read() ? ReadAttemptRow(rows) : null;
    }

    /// <summary>
    /// Attempts the supervisor must recover: STARTING, RUNNING, PAUSING, PAUSED, STOPPING or FINALIZING. ADOPTED attempts have no holder or
    /// exit record; <see cref="Adoptions"/> recovers them.
    /// </summary>
    public static List<AttemptRow> LiveAttempts(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand(
            "SELECT attempt_id, task_id, number, state, container_name, root_pid, root_start, boot_identity, stdout_offset, stderr_offset, index_offset, " +
            "termination_reason, started_at, detail FROM attempt WHERE state BETWEEN 1 AND 8 AND kind <> 4 ORDER BY created_at;");
        using var rows = command.ExecuteReader();
        var result = new List<AttemptRow>();
        while (rows.Read())
        {
            result.Add(ReadAttemptRow(rows));
        }

        return result;
    }

    /// <summary>The task view (SUMMARY, or FULL with the stored spec), or <see langword="null"/>.</summary>
    public static ManagedTask? GetTask(StoreReader reader, ReadOnlySpan<byte> taskId, bool full)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand($"SELECT {TaskColumns} FROM task WHERE task_id = $id;");
        command.Parameters.AddWithValue("$id", taskId.ToArray());
        using var rows = command.ExecuteReader();
        if (!rows.Read())
        {
            return null;
        }

        var task = ReadTask(rows, full);
        rows.Close();
        Complete(reader, task);
        return task;
    }

    /// <summary>A page of tasks, newest first.</summary>
    public static (List<ManagedTask> Tasks, string? Next) ListTasks(StoreReader reader, TaskFilter? filter, PageCursor? cursor, int limit)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var conditions = new List<string> { "1 = 1" };
        var parameters = new List<(string, object?)>();
        if (filter is not null)
        {
            if (filter.States.Count > 0)
            {
                conditions.Add("state IN (" + string.Join(", ", filter.States.Select(state => ((int)state).ToString(CultureInfo.InvariantCulture))) + ")");
            }

            if (filter.HasPool)
            {
                conditions.Add("pool = $pool");
                parameters.Add(("$pool", filter.Pool));
            }

            if (ProtoTime.ToDateTimeOffset(filter.CreatedAfter) is { } after)
            {
                conditions.Add("created_at > $after");
                parameters.Add(("$after", StoreTime.ToMicroseconds(after)));
            }

            if (ProtoTime.ToDateTimeOffset(filter.CreatedBefore) is { } before)
            {
                conditions.Add("created_at < $before");
                parameters.Add(("$before", StoreTime.ToMicroseconds(before)));
            }

            if (filter.HasText && filter.Text.Length > 0)
            {
                conditions.Add("(instr(lower(title), lower($text)) > 0 OR instr(lower(command_summary), lower($text)) > 0)");
                parameters.Add(("$text", filter.Text));
            }

            var index = 0;
            foreach (var (key, value) in filter.Labels)
            {
                conditions.Add($"json_extract(labels_json, $labelPath{index}) = $labelValue{index}");
                parameters.Add(($"$labelPath{index}", "$.\"" + key.Replace("\"", "\\\"", StringComparison.Ordinal) + "\""));
                parameters.Add(($"$labelValue{index}", value));
                index++;
            }
        }

        if (cursor is { } position)
        {
            conditions.Add("(created_at < $cursorCreated OR (created_at = $cursorCreated AND task_id < $cursorId))");
            parameters.Add(("$cursorCreated", position.CreatedAt));
            parameters.Add(("$cursorId", position.Id));
        }

        var tasks = new List<ManagedTask>();
        using (var command = reader.CreateCommand($"SELECT {TaskColumns} FROM task WHERE {string.Join(" AND ", conditions)} ORDER BY created_at DESC, task_id DESC LIMIT $limit;"))
        {
            foreach (var (name, value) in parameters)
            {
                command.Parameters.AddWithValue(name, value ?? DBNull.Value);
            }

            command.Parameters.AddWithValue("$limit", limit + 1);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                tasks.Add(ReadTask(rows, full: false));
            }
        }

        string? next = null;
        if (tasks.Count > limit)
        {
            tasks.RemoveAt(tasks.Count - 1);
            var last = tasks[^1];
            next = new PageCursor(StoreTime.ToMicroseconds(ProtoTime.ToDateTimeOffset(last.CreatedAt)!.Value), last.TaskId.Value.ToByteArray()).ToString();
        }

        foreach (var task in tasks)
        {
            Complete(reader, task);
        }

        return (tasks, next);
    }

    /// <summary>Live (non-terminal) tasks, for the TASKS snapshot.</summary>
    public static List<ManagedTask> LiveTasks(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var tasks = new List<ManagedTask>();
        using (var command = reader.CreateCommand($"SELECT {TaskColumns} FROM task WHERE state IN (1, 2, 3, 4, 5, 6) ORDER BY created_at LIMIT 10000;"))
        {
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                tasks.Add(ReadTask(rows, full: false));
            }
        }

        foreach (var task in tasks)
        {
            Complete(reader, task);
        }

        return tasks;
    }

    /// <summary>The attempt view, or <see langword="null"/>.</summary>
    public static Attempt? GetAttempt(StoreReader reader, ReadOnlySpan<byte> attemptId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand($"SELECT {AttemptColumns} FROM attempt WHERE attempt_id = $id;");
        command.Parameters.AddWithValue("$id", attemptId.ToArray());
        using var rows = command.ExecuteReader();
        return rows.Read() ? ReadAttempt(rows) : null;
    }

    /// <summary>The attempts of a task, oldest first.</summary>
    public static List<Attempt> ListAttempts(StoreReader reader, ReadOnlySpan<byte> taskId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand($"SELECT {AttemptColumns} FROM attempt WHERE task_id = $id ORDER BY number;");
        command.Parameters.AddWithValue("$id", taskId.ToArray());
        using var rows = command.ExecuteReader();
        var result = new List<Attempt>();
        while (rows.Read())
        {
            result.Add(ReadAttempt(rows));
        }

        return result;
    }

    /// <summary>
    /// The 1-based position of a queued task within its pool's order without the round robin: the effective class, then the queue time
    /// (the admission pass's own order, with the fair share across owners, is in <c>QueueService.GetQueue</c>).
    /// </summary>
    public static uint QueuePosition(StoreReader reader, ReadOnlySpan<byte> taskId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var value = reader.Scalar(
            "SELECT count(*) FROM task t, (SELECT pool, effective_priority, queued_at, created_at, task_id FROM task WHERE task_id = $id) s " +
            "WHERE t.state = 1 AND t.pool = s.pool AND (t.effective_priority, t.queued_at, t.created_at, t.task_id) <= (s.effective_priority, s.queued_at, s.created_at, s.task_id);",
            ("$id", taskId.ToArray()));
        return (uint)Convert.ToInt64(value ?? 0L, CultureInfo.InvariantCulture);
    }

    private static void Complete(StoreReader reader, ManagedTask task)
    {
        var id = task.TaskId.Value.ToByteArray();
        if (task.State is TaskState.Queued or TaskState.WaitingDependency)
        {
            var queuedAt = reader.Scalar("SELECT queued_at FROM task WHERE task_id = $id;", ("$id", id));
            task.Queue = new QueueInfo
            {
                // The admission pass records why a queued task waits in state_reason (03 section 4); a dependency wait is "dependency".
                BlockingReason = task.State == TaskState.WaitingDependency ? "dependency" : task.HasStateReason && task.StateReason.Length > 0 && task.StateReason != "retry"
                    ? task.StateReason
                    : "global_limit",
                WaitedMs = queuedAt is long since ? (ulong)Math.Max(0, (reader.NowMicroseconds - since) / 1000) : 0,
            };
            if (task.State == TaskState.Queued)
            {
                task.Queue.Position = QueuePosition(reader, id);
            }
        }

        using (var keys = reader.CreateCommand("SELECT concurrency_key, mode FROM task_concurrency_key WHERE task_id = $id ORDER BY concurrency_key;"))
        {
            keys.Parameters.AddWithValue("$id", id);
            using var rows = keys.ExecuteReader();
            while (rows.Read())
            {
                (rows.GetInt32(1) == 1 ? task.ExclusiveKeys : task.SharedKeys).Add(rows.GetString(0));
            }
        }

        if (reader.Scalar("SELECT current_attempt_id FROM task WHERE task_id = $id;", ("$id", id)) is byte[] attemptId)
        {
            task.CurrentAttempt = GetAttempt(reader, attemptId);
        }
    }

    private static ManagedTask ReadTask(SqliteDataReader rows, bool full)
    {
        var spec = TaskSpec.Parser.ParseFrom((byte[])rows.GetValue(6));
        var task = new ManagedTask
        {
            TaskId = Id(rows, 0)!,
            State = (TaskState)rows.GetInt32(1),
            Title = rows.GetString(4),
            CommandSummary = rows.GetString(5),
            Owner = ActorRef.Parser.ParseFrom((byte[])rows.GetValue(8)),
            Pool = rows.GetString(12),
            EffectivePriority = (Priority)rows.GetInt32(14),
            SideEffect = (SideEffectClass)rows.GetInt32(15),
            SideEffectSource = (SideEffectSource)rows.GetInt32(16),
            CreatedAt = Notifications.Time(rows.GetInt64(17)),
            AttemptCount = (uint)rows.GetInt32(23),
            Ready = rows.GetInt32(24) == 1,
            Pinned = rows.GetInt32(25) == 1,
            Revision = new Revision { Value = rows.GetInt64(28) },
        };
        if (!rows.IsDBNull(2))
        {
            task.StateReason = rows.GetString(2);
        }

        if (Id(rows, 11) is { } workspace)
        {
            task.WorkspaceId = workspace;
        }

        if (!rows.IsDBNull(19))
        {
            task.StartedAt = Notifications.Time(rows.GetInt64(19));
        }

        if (!rows.IsDBNull(20))
        {
            task.FinishedAt = Notifications.Time(rows.GetInt64(20));
        }

        foreach (var (key, value) in JsonSerializer.Deserialize(rows.GetString(26), ExecutionJsonContext.Default.DictionaryStringString) ?? [])
        {
            task.Labels[key] = value;
        }

        if (full)
        {
            task.Spec = spec;
        }

        return task;
    }

    private static Attempt ReadAttempt(SqliteDataReader rows)
    {
        var attempt = new Attempt
        {
            AttemptId = Id(rows, 0)!,
            TaskId = Id(rows, 1)!,
            Number = (uint)rows.GetInt32(2),
            Kind = (AttemptKind)rows.GetInt32(3),
            State = (AttemptState)rows.GetInt32(4),
            Executor = new NodeRef { NodeId = Id(rows, 5) },
            Request = new ResourceDemand
            {
                CpuMillicores = (uint)rows.GetInt64(10),
                MemExpectedBytes = (ulong)rows.GetInt64(11),
                MemCeilingBytes = (ulong)rows.GetInt64(12),
                Source = (EstimateSource)rows.GetInt32(13),
            },
            Unenforced = rows.GetInt32(14) == 1,
            NodeGap = rows.GetInt32(15) == 1,
            CreatedAt = Notifications.Time(rows.GetInt64(16)),
            Usage = new ResourceUsage
            {
                CpuTimeMs = (ulong)rows.GetInt64(27),
                MemPeakBytes = (ulong)rows.GetInt64(28),
                IoReadBytes = (ulong)rows.GetInt64(29),
                IoWriteBytes = (ulong)rows.GetInt64(30),
            },
            GuardLost = rows.GetInt32(37) == 1,
            Revision = new Revision { Value = rows.GetInt64(38) },
        };
        if (!rows.IsDBNull(40))
        {
            attempt.Tool = rows.GetString(40);
        }

        if (!rows.IsDBNull(41))
        {
            attempt.Operation = rows.GetString(41);
        }

        if (!rows.IsDBNull(42))
        {
            attempt.ToolParallelism = (uint)rows.GetInt32(42);
        }
        if (!rows.IsDBNull(17))
        {
            attempt.StartedAt = Notifications.Time(rows.GetInt64(17));
        }

        if (!rows.IsDBNull(18))
        {
            attempt.FinishedAt = Notifications.Time(rows.GetInt64(18));
        }

        if (!rows.IsDBNull(36))
        {
            attempt.LimitEnforcedBy = rows.GetString(36);
        }

        if (attempt.State == AttemptState.Finished && !rows.IsDBNull(22))
        {
            var result = new AttemptResult
            {
                TerminationReason = (TerminationReason)rows.GetInt32(22),
                LeftoverProcessesTerminated = (uint)rows.GetInt32(25),
            };
            if (!rows.IsDBNull(19))
            {
                result.ExitCode = rows.GetInt32(19);
            }

            if (!rows.IsDBNull(20))
            {
                result.Signal = rows.GetInt32(20);
            }

            if (!rows.IsDBNull(39))
            {
                result.CoreDumped = rows.GetInt32(39) == 1;
            }

            if (!rows.IsDBNull(21))
            {
                result.WindowsStatus = unchecked((uint)rows.GetInt64(21));
            }

            if (!rows.IsDBNull(23))
            {
                result.Effect = (EffectCertainty)rows.GetInt32(23);
            }

            if (!rows.IsDBNull(24))
            {
                result.Detail = rows.GetString(24);
            }

            result.LeftoverImages.AddRange(JsonSerializer.Deserialize(rows.GetString(26), ExecutionJsonContext.Default.ListString) ?? []);
            attempt.Result = result;
        }

        return attempt;
    }

    private static AttemptRow ReadAttemptRow(SqliteDataReader rows) => new()
    {
        AttemptId = (byte[])rows.GetValue(0),
        TaskId = (byte[])rows.GetValue(1),
        Number = rows.GetInt32(2),
        State = (AttemptState)rows.GetInt32(3),
        ContainerName = rows.IsDBNull(4) ? null : rows.GetString(4),
        RootPid = rows.IsDBNull(5) ? null : rows.GetInt32(5),
        RootStart = rows.IsDBNull(6) ? null : rows.GetInt64(6),
        BootIdentity = rows.IsDBNull(7) ? null : rows.GetString(7),
        StdoutOffset = rows.GetInt64(8),
        StderrOffset = rows.GetInt64(9),
        IndexOffset = rows.GetInt64(10),
        Reason = rows.IsDBNull(11) ? null : (TerminationReason)rows.GetInt32(11),
        StartedAt = rows.IsDBNull(12) ? null : rows.GetInt64(12),
        Detail = rows.IsDBNull(13) ? null : rows.GetString(13),
    };

    private static Id? Id(SqliteDataReader rows, int column) =>
        rows.IsDBNull(column) ? null : new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(column)) };
}
