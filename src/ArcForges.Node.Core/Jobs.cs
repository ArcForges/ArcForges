// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core;

/// <summary>One page of node jobs.</summary>
public sealed record JobPage(IReadOnlyList<JobView> Items, string? NextCursor);

/// <summary>
/// Node jobs (node-store.md <c>job</c>; architecture 02 section 1: long operations run as node jobs with their own records): reading,
/// listing newest first and cancelling. The subsystems that run job kinds (storage analysis, cleanup, detection, export, bundles,
/// doctor, updates) arrive with their own tasks; cancellation here records the request on the job (a pending or running job becomes
/// CANCELLED) and journals it on topic JOBS, which those runners observe. Retention: 30 days after finishing.
/// </summary>
public static class Jobs
{
    private const string Columns =
        "job_id, kind, state, progress_percent, progress_text, task_id, requested_by, created_at, finished_at, error, result_kind, result_id";

    /// <summary>How long a finished job is kept.</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromDays(30);

    /// <summary>The job with <paramref name="id"/>, or <see langword="null"/>.</summary>
    public static JobView? Get(StoreReader reader, ReadOnlySpan<byte> id)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand($"SELECT {Columns} FROM job WHERE job_id = $id;");
        command.Parameters.AddWithValue("$id", id.ToArray());
        using var rows = command.ExecuteReader();
        return rows.Read() ? Read(rows) : null;
    }

    /// <summary>A page of jobs in <paramref name="states"/> (all when empty), newest first.</summary>
    public static JobPage List(StoreReader reader, IReadOnlyCollection<JobState> states, PageCursor? cursor, int limit)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(states);
        var filter = states.Count == 0 ? string.Empty : " AND state IN (" + string.Join(", ", states.Select(state => ((int)state).ToString(System.Globalization.CultureInfo.InvariantCulture))) + ")";
        var sql = $"SELECT {Columns} FROM job WHERE 1 = 1" + filter
            + (cursor is null ? string.Empty : " AND (created_at < $created OR (created_at = $created AND job_id < $id))")
            + " ORDER BY created_at DESC, job_id DESC LIMIT $limit;";
        var items = new List<JobView>();
        using (var command = reader.CreateCommand(sql))
        {
            if (cursor is { } position)
            {
                command.Parameters.AddWithValue("$created", position.CreatedAt);
                command.Parameters.AddWithValue("$id", position.Id);
            }

            command.Parameters.AddWithValue("$limit", limit + 1);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                items.Add(Read(rows));
            }
        }

        string? next = null;
        if (items.Count > limit)
        {
            items.RemoveAt(items.Count - 1);
            var last = items[^1];
            next = new PageCursor(Notifications.Micros(last.CreatedAt), last.JobId.Value.ToByteArray()).ToString();
        }

        return new JobPage(items, next);
    }

    /// <summary>Every job that is pending, running, or finished within retention (the snapshot of topic JOBS), newest first.</summary>
    public static List<JobView> All(StoreReader reader)
    {
        var items = new List<JobView>();
        using var command = reader.CreateCommand($"SELECT {Columns} FROM job ORDER BY created_at DESC, job_id DESC LIMIT 10000;");
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            items.Add(Read(rows));
        }

        return items;
    }

    /// <summary>
    /// Cancels a pending or running job and journals it; returns the job, or an error: <c>STATE/not_found</c>, or
    /// <c>STATE/invalid_state</c> for a finished job.
    /// </summary>
    public static (JobView? Job, ArcError? Error) Cancel(CommandContext context, ReadOnlySpan<byte> id)
    {
        ArgumentNullException.ThrowIfNull(context);
        var transaction = context.Transaction;
        var job = Get(transaction, id);
        if (job is null)
        {
            return (null, NodeErrors.NotFound("job", id));
        }

        if (job.State is not (JobState.Pending or JobState.Running))
        {
            return (null, NodeErrors.InvalidState(job.State.ToString().ToUpperInvariant(), "the job has finished"));
        }

        transaction.Execute("UPDATE job SET state = $state, finished_at = $now, rev = rev + 1 WHERE job_id = $id;",
            ("$state", (int)JobState.Cancelled), ("$now", transaction.NowMicroseconds), ("$id", id.ToArray()));
        var cancelled = Get(transaction, id)!;
        context.Emit(EventTopic.Jobs, new NodeEvent { Job = cancelled });
        return (cancelled, null);
    }

    /// <summary>Retention (housekeeping): deletes jobs finished more than 30 days ago.</summary>
    internal static int Prune(StoreTransaction transaction) => transaction.Execute(
        "DELETE FROM job WHERE finished_at IS NOT NULL AND finished_at < $cutoff;",
        ("$cutoff", transaction.NowMicroseconds - (long)(Retention.TotalMilliseconds * 1000)));

    private static JobView Read(SqliteDataReader rows)
    {
        var job = new JobView
        {
            JobId = new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(0)) },
            Kind = (JobKind)rows.GetInt32(1),
            State = (JobState)rows.GetInt32(2),
            ProgressPercent = (uint)rows.GetInt32(3),
            RequestedBy = ActorRef.Parser.ParseFrom((byte[])rows.GetValue(6)),
            CreatedAt = Notifications.Time(rows.GetInt64(7)),
        };
        if (!rows.IsDBNull(4))
        {
            job.ProgressText = rows.GetString(4);
        }

        if (!rows.IsDBNull(5))
        {
            job.TaskId = new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(5)) };
        }

        if (!rows.IsDBNull(8))
        {
            job.FinishedAt = Notifications.Time(rows.GetInt64(8));
        }

        if (!rows.IsDBNull(9))
        {
            job.Error = ArcError.Parser.ParseFrom((byte[])rows.GetValue(9));
        }

        if (!rows.IsDBNull(10))
        {
            job.Result = new AggregateRef { Kind = rows.GetString(10) };
            if (!rows.IsDBNull(11))
            {
                job.Result.Id = new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(11)) };
            }
        }

        return job;
    }
}
