// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Resources;

/// <summary>One row of <c>resource_sample</c> (node-store.md): cumulative counters are as of <see cref="At"/>.</summary>
/// <param name="Scope">MACHINE, MANAGED or ATTEMPT.</param>
/// <param name="SubjectId">The node ID (MACHINE, MANAGED) or the attempt ID.</param>
/// <param name="At">Microseconds since the Unix epoch.</param>
/// <param name="ResolutionMs">1,000, 5,000, 10,000 or 60,000.</param>
/// <param name="CpuMillicores">The CPU rate over the sample's interval.</param>
/// <param name="CpuTimeMs">Processor time so far.</param>
/// <param name="MemoryBytes">Memory in use (MACHINE: <c>C_mem - available</c>; MANAGED and ATTEMPT: resident without reclaimable cache).</param>
/// <param name="MemoryPeakBytes">The peak (ATTEMPT: <c>peak_observed</c>, 03 section 3; MACHINE and MANAGED: the highest 1 s value of the interval).</param>
/// <param name="ProcessCount">Processes.</param>
/// <param name="IoReadBytes">Bytes read so far.</param>
/// <param name="IoWriteBytes">Bytes written so far.</param>
public sealed record SampleRow(SampleScope Scope, byte[] SubjectId, long At, int ResolutionMs, long CpuMillicores, long CpuTimeMs, long MemoryBytes,
    long MemoryPeakBytes, long ProcessCount, long IoReadBytes, long IoWriteBytes);

/// <summary>
/// Sample storage and downsampling (03 section 1; R-RES-001, R-REC-005; node-store.md <c>resource_sample</c>): attempts at 1 s while
/// they run and 10 s once finished; the machine and managed totals at 5 s for 24 h, then 1 min for 30 days, then dropped. A rollup keeps
/// the mean CPU rate and the maxima of memory, peak, process count and the cumulative counters of each bucket.
/// </summary>
public static class ResourceSamples
{
    /// <summary>Machine and managed samples older than this are rolled up to 1 min.</summary>
    public static readonly TimeSpan FineRetention = TimeSpan.FromHours(24);

    /// <summary>Machine and managed samples older than this are dropped.</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromDays(30);

    private const long MicrosPerMs = 1000;

    /// <summary>The finished attempts rolled up in one housekeeping pass.</summary>
    private const int AttemptBatch = 200;

    /// <summary>The machine and managed rows rolled up in one housekeeping pass (about 14 h at 5 s for both scopes).</summary>
    private const int MachineBatch = 20_000;

    /// <summary>Writes rows (the monitor's buffered samples).</summary>
    public static void Insert(StoreTransaction transaction, IEnumerable<SampleRow> rows)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(rows);
        foreach (var row in rows)
        {
            transaction.Execute(
                """
                INSERT INTO resource_sample (scope, subject_id, at, resolution_ms, cpu_millicores, cpu_time_ms, mem_bytes, mem_peak_bytes, process_count,
                                             io_read_bytes, io_write_bytes)
                VALUES ($scope, $subject, $at, $resolution, $cpu, $cpuTime, $mem, $peak, $count, $read, $write)
                ON CONFLICT (scope, subject_id, at) DO NOTHING;
                """,
                ("$scope", (int)row.Scope), ("$subject", row.SubjectId), ("$at", row.At), ("$resolution", row.ResolutionMs), ("$cpu", row.CpuMillicores),
                ("$cpuTime", row.CpuTimeMs), ("$mem", row.MemoryBytes), ("$peak", row.MemoryPeakBytes), ("$count", row.ProcessCount),
                ("$read", row.IoReadBytes), ("$write", row.IoWriteBytes));
        }
    }

    /// <summary>
    /// Housekeeping (every 10 min): finished attempts' 1 s samples become 10 s samples; machine and managed samples older than 24 h become
    /// 1 min samples; machine and managed samples older than 30 days are dropped. Returns the rows removed (net).
    /// </summary>
    public static int Housekeep(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        var now = transaction.NowMicroseconds;
        var removed = transaction.Execute("DELETE FROM resource_sample WHERE scope IN (1, 2) AND at < $cutoff;",
            ("$cutoff", now - (long)Retention.TotalMicroseconds));

        var finished = new List<byte[]>();
        using (var command = transaction.CreateCommand(
            """
            SELECT a.attempt_id FROM attempt a
            WHERE a.finished_at IS NOT NULL
              AND EXISTS (SELECT 1 FROM resource_sample s WHERE s.scope = 3 AND s.subject_id = a.attempt_id AND s.resolution_ms = 1000)
            LIMIT $limit;
            """))
        {
            command.Parameters.AddWithValue("$limit", AttemptBatch);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                finished.Add((byte[])rows.GetValue(0));
            }
        }

        foreach (var attempt in finished)
        {
            removed += Rollup(transaction, ReadRows(transaction, "scope = 3 AND subject_id = $subject AND resolution_ms = 1000", ("$subject", attempt)), 10_000);
        }

        // Whole minutes only: the cutoff is aligned, and a batch cut inside a minute leaves that minute for the next pass.
        const long Minute = 60_000 * MicrosPerMs;
        var cutoff = (now - (long)FineRetention.TotalMicroseconds) / Minute * Minute;
        var old = ReadRows(transaction, "scope IN (1, 2) AND resolution_ms = 5000 AND at < $cutoff ORDER BY at LIMIT " + MachineBatch, ("$cutoff", cutoff));
        if (old.Count == MachineBatch)
        {
            var last = old[^1].At / Minute;
            old.RemoveAll(row => row.At / Minute == last);
        }

        removed += Rollup(transaction, old, 60_000);
        return removed;
    }

    /// <summary>
    /// The samples of a subject between <paramref name="from"/> and <paramref name="until"/> (microseconds, inclusive), at most
    /// <paramref name="maxPoints"/>: when there are more, they are merged into equal buckets (mean CPU rate, maxima otherwise), and the
    /// resolution is the bucket width. Returns the samples and the resolution in milliseconds (0 when there are none).
    /// </summary>
    public static (List<ResourceSample> Samples, long ResolutionMs) Read(StoreReader reader, SampleScope scope, byte[] subject, long from, long until, int maxPoints,
        IEnumerable<SampleRow>? pending = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(subject);
        var rows = ReadRows(reader, "scope = $scope AND subject_id = $subject AND at BETWEEN $from AND $until ORDER BY at",
            ("$scope", (int)scope), ("$subject", subject), ("$from", from), ("$until", until));
        if (pending is not null)
        {
            var stored = rows.Select(row => row.At).ToHashSet();
            rows.AddRange(pending.Where(row => row.Scope == scope && row.SubjectId.AsSpan().SequenceEqual(subject) && row.At >= from && row.At <= until
                && !stored.Contains(row.At)));
            rows.Sort((left, right) => left.At.CompareTo(right.At));
        }

        if (rows.Count == 0)
        {
            return ([], 0);
        }

        long resolution = rows.Max(row => row.ResolutionMs);
        if (rows.Count > maxPoints)
        {
            var span = rows[^1].At - rows[0].At + (resolution * MicrosPerMs);
            var width = (span + maxPoints - 1) / maxPoints;
            width = ((width + (resolution * MicrosPerMs) - 1) / (resolution * MicrosPerMs)) * resolution * MicrosPerMs;
            rows = Merge(rows, rows[0].At, width, (int)(width / MicrosPerMs));
            resolution = width / MicrosPerMs;
        }

        return ([.. rows.Select(ToSample)], resolution);
    }

    /// <summary>A stored row as the contract's sample.</summary>
    public static ResourceSample ToSample(SampleRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        return new ResourceSample
        {
            At = ProtoTime.ToInstant(StoreTime.FromMicroseconds(row.At)),
            Usage = new ResourceUsage
            {
                CpuMillicores = (uint)Math.Clamp(row.CpuMillicores, 0, uint.MaxValue),
                CpuTimeMs = (ulong)Math.Max(0, row.CpuTimeMs),
                MemBytes = (ulong)Math.Max(0, row.MemoryBytes),
                MemPeakBytes = (ulong)Math.Max(0, row.MemoryPeakBytes),
                ProcessCount = (uint)Math.Clamp(row.ProcessCount, 0, uint.MaxValue),
                IoReadBytes = (ulong)Math.Max(0, row.IoReadBytes),
                IoWriteBytes = (ulong)Math.Max(0, row.IoWriteBytes),
            },
        };
    }

    /// <summary>Merges rows into buckets of <paramref name="width"/> microseconds starting at <paramref name="origin"/>.</summary>
    internal static List<SampleRow> Merge(List<SampleRow> rows, long origin, long width, int resolutionMs)
    {
        var merged = new List<SampleRow>();
        foreach (var bucket in rows.GroupBy(row => (row.Scope, Subject: Convert.ToHexString(row.SubjectId), Start: origin + ((row.At - origin) / width * width))))
        {
            var items = bucket.ToList();
            merged.Add(new SampleRow(bucket.Key.Scope, items[0].SubjectId, bucket.Key.Start, resolutionMs,
                (long)Math.Round(items.Average(item => (double)item.CpuMillicores)), items.Max(item => item.CpuTimeMs), items.Max(item => item.MemoryBytes),
                items.Max(item => item.MemoryPeakBytes), items.Max(item => item.ProcessCount), items.Max(item => item.IoReadBytes),
                items.Max(item => item.IoWriteBytes)));
        }

        return [.. merged.OrderBy(row => row.At)];
    }

    /// <summary>Replaces <paramref name="rows"/> by their buckets of <paramref name="resolutionMs"/> (aligned to the epoch); returns the rows removed (net).</summary>
    private static int Rollup(StoreTransaction transaction, List<SampleRow> rows, int resolutionMs)
    {
        if (rows.Count == 0)
        {
            return 0;
        }

        var merged = Merge(rows, 0, resolutionMs * MicrosPerMs, resolutionMs);
        foreach (var row in rows)
        {
            transaction.Execute("DELETE FROM resource_sample WHERE scope = $scope AND subject_id = $subject AND at = $at;",
                ("$scope", (int)row.Scope), ("$subject", row.SubjectId), ("$at", row.At));
        }

        // A bucket can already hold a coarser row from an earlier pass (the rest of a partially rolled-up minute): it is merged in.
        var result = new List<SampleRow>();
        foreach (var row in merged)
        {
            var existing = ReadRows(transaction, "scope = $scope AND subject_id = $subject AND at = $at", ("$scope", (int)row.Scope), ("$subject", row.SubjectId),
                ("$at", row.At));
            if (existing.Count > 0)
            {
                transaction.Execute("DELETE FROM resource_sample WHERE scope = $scope AND subject_id = $subject AND at = $at;",
                    ("$scope", (int)row.Scope), ("$subject", row.SubjectId), ("$at", row.At));
                result.AddRange(Merge([.. existing, row], 0, resolutionMs * MicrosPerMs, resolutionMs));
            }
            else
            {
                result.Add(row);
            }
        }

        Insert(transaction, result);
        return rows.Count - result.Count;
    }

    private static List<SampleRow> ReadRows(StoreReader reader, string where, params (string Name, object Value)[] parameters)
    {
        var rows = new List<SampleRow>();
        using var command = reader.CreateCommand(
            "SELECT scope, subject_id, at, resolution_ms, cpu_millicores, cpu_time_ms, mem_bytes, mem_peak_bytes, process_count, io_read_bytes, io_write_bytes "
            + "FROM resource_sample WHERE " + where + ";");
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        using var result = command.ExecuteReader();
        while (result.Read())
        {
            rows.Add(new SampleRow((SampleScope)result.GetInt32(0), (byte[])result.GetValue(1), result.GetInt64(2), result.GetInt32(3), result.GetInt64(4),
                result.GetInt64(5), result.GetInt64(6), result.GetInt64(7), result.GetInt64(8), result.GetInt64(9), result.GetInt64(10)));
        }

        return rows;
    }
}
