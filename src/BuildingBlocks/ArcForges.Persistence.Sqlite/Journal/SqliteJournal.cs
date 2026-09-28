// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using Microsoft.Data.Sqlite;

namespace ArcForges.Persistence.Sqlite;

/// <summary>Journal operations participate in the owning store's transaction; none commits independently.</summary>
internal sealed class SqliteJournal(IJournalSnapshotVerifier? snapshotVerifier = null, JournalSnapshotPolicy? snapshotPolicy = null) : IJournalWriter, IJournalReader, IJournalRetention
{
    private readonly JournalSnapshotPolicy policy = snapshotPolicy ?? new JournalSnapshotPolicy();

    public void Initialize(SqliteCommitContext context)
    {
        using var command = context.CreateCommand("""
            CREATE TABLE IF NOT EXISTS journal_state (
                store_id TEXT PRIMARY KEY NOT NULL,
                last_sequence INTEGER NOT NULL CHECK(last_sequence >= 0),
                truncated_through INTEGER NOT NULL CHECK(truncated_through >= 0 AND truncated_through <= last_sequence),
                truncated_checksum BLOB NOT NULL CHECK(length(truncated_checksum) = 32));
            CREATE TABLE IF NOT EXISTS journal (
                store_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence > 0),
                local_seq INTEGER CHECK(local_seq > 0),
                aggregate_kind TEXT NOT NULL,
                aggregate_id TEXT NOT NULL,
                previous_version TEXT NOT NULL,
                next_version TEXT NOT NULL,
                command_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                operation_version INTEGER NOT NULL CHECK(operation_version > 0),
                payload BLOB NOT NULL,
                durable_reference TEXT,
                actor_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                causation_id TEXT,
                committed_seconds INTEGER NOT NULL,
                committed_nanos INTEGER NOT NULL CHECK(committed_nanos >= 0 AND committed_nanos < 1000000000),
                encoded_length INTEGER NOT NULL CHECK(encoded_length > 0),
                checksum BLOB NOT NULL CHECK(length(checksum) = 32),
                PRIMARY KEY(store_id, sequence),
                UNIQUE(store_id, command_id),
                CHECK((length(payload) > 0 AND durable_reference IS NULL) OR
                    (length(payload) = 0 AND length(durable_reference) > 0)));
            CREATE INDEX IF NOT EXISTS journal_aggregate_sequence ON journal(store_id, aggregate_kind, aggregate_id, sequence);
            INSERT OR IGNORE INTO journal_state(store_id,last_sequence,truncated_through,truncated_checksum)
                VALUES($store,0,0,zeroblob(32));
            """);
        command.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        command.ExecuteNonQuery();
    }

    public JournalSequence GetNextSequence(SqliteCommitContext context)
    {
        using var command = context.CreateCommand("SELECT last_sequence FROM journal_state WHERE store_id=$store");
        command.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        var current = command.ExecuteScalar();
        if (current is not long value || value < 0) throw new InvalidDataException("The journal has no valid durable high watermark.");
        return new JournalSequence(context.StoreId, checked(value + 1));
    }

    public void Append(SqliteCommitContext context, JournalEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        entry.Sequence.RequireStore(context.StoreId);
        if (entry.Sequence != GetNextSequence(context)) throw new InvalidOperationException("Journal appends must follow the durable high watermark.");
        using (var capacity = context.CreateCommand("SELECT COUNT(*),COALESCE(SUM(encoded_length),0) FROM journal WHERE store_id=$store"))
        {
            capacity.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
            using var usage = capacity.ExecuteReader();
            if (!usage.Read() || usage.GetInt64(0) >= policy.MaximumEntries ||
                entry.EncodedLength > policy.MaximumBytes - usage.GetInt64(1))
                throw new JournalCapacityException();
        }
        using (var previous = context.CreateCommand("SELECT next_version FROM journal WHERE store_id=$store AND aggregate_kind=$kind AND aggregate_id=$aggregate ORDER BY sequence DESC LIMIT 1"))
        {
            previous.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
            previous.Parameters.AddWithValue("$kind", entry.AggregateKind);
            previous.Parameters.AddWithValue("$aggregate", entry.AggregateId.ToString("D"));
            if (previous.ExecuteScalar() is string version && version != entry.Previous.CanonicalText)
                throw new InvalidOperationException("The journal does not continue the aggregate's committed source version.");
        }
        if (entry.LocalSequence is { } localSequence)
        {
            using var previousLocal = context.CreateCommand("SELECT MAX(local_seq) FROM journal WHERE store_id=$store AND aggregate_kind=$kind AND aggregate_id=$aggregate");
            previousLocal.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
            previousLocal.Parameters.AddWithValue("$kind", entry.AggregateKind);
            previousLocal.Parameters.AddWithValue("$aggregate", entry.AggregateId.ToString("D"));
            if (previousLocal.ExecuteScalar() is long prior && localSequence <= prior)
                throw new InvalidOperationException("A per-aggregate local edit identity cannot be reused or reset.");
        }
        using var command = context.CreateCommand("""
            INSERT INTO journal(store_id,sequence,aggregate_kind,aggregate_id,previous_version,next_version,
                command_id,operation,operation_version,payload,durable_reference,actor_id,correlation_id,
                causation_id,committed_seconds,committed_nanos,encoded_length,checksum,local_seq)
            VALUES($store,$sequence,$kind,$aggregate,$previous,$next,$command,$operation,$operationVersion,
                $payload,$reference,$actor,$correlation,$causation,$seconds,$nanos,$length,$checksum,$localSequence);
            UPDATE journal_state SET last_sequence=$sequence WHERE store_id=$store AND last_sequence=$expected;
            """);
        command.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        command.Parameters.AddWithValue("$sequence", entry.Sequence.Value);
        command.Parameters.AddWithValue("$expected", entry.Sequence.Value - 1);
        command.Parameters.AddWithValue("$kind", entry.AggregateKind);
        command.Parameters.AddWithValue("$aggregate", entry.AggregateId.ToString("D"));
        command.Parameters.AddWithValue("$previous", entry.Previous.CanonicalText);
        command.Parameters.AddWithValue("$next", entry.Next.CanonicalText);
        command.Parameters.AddWithValue("$command", entry.CommandId.Value.ToString("D"));
        command.Parameters.AddWithValue("$operation", entry.Operation);
        command.Parameters.AddWithValue("$operationVersion", entry.OperationVersion);
        command.Parameters.AddWithValue("$payload", entry.Payload.ToArray());
        command.Parameters.AddWithValue("$reference", (object?)entry.DurableReference ?? DBNull.Value);
        command.Parameters.AddWithValue("$actor", entry.ActorId.Value.ToString("D"));
        command.Parameters.AddWithValue("$correlation", entry.CorrelationId.ToString("D"));
        command.Parameters.AddWithValue("$causation", (object?)entry.CausationId?.ToString("D") ?? DBNull.Value);
        command.Parameters.AddWithValue("$seconds", entry.CommittedAt.UnixSeconds);
        command.Parameters.AddWithValue("$nanos", entry.CommittedAt.Nanoseconds);
        command.Parameters.AddWithValue("$length", entry.EncodedLength);
        command.Parameters.AddWithValue("$checksum", entry.Checksum.ToArray());
        command.Parameters.AddWithValue("$localSequence", entry.LocalSequence.HasValue ? entry.LocalSequence.Value : DBNull.Value);
        if (command.ExecuteNonQuery() != 2) throw new InvalidDataException("The journal append and high watermark must advance together.");
    }

    internal bool RequiresSnapshot(SqliteReadContext context, Instant now)
    {
        using var command = context.CreateCommand("SELECT COUNT(*),COALESCE(SUM(encoded_length),0),MIN(committed_seconds) FROM journal WHERE store_id=$store");
        command.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetInt64(0) == 0) return false;
        return reader.GetInt64(0) >= policy.MaximumEntries || reader.GetInt64(1) >= policy.MaximumBytes ||
            now.UnixSeconds - reader.GetInt64(2) >= policy.MaximumAgeSeconds;
    }

    public IReadOnlyList<JournalEntry> Read(SqliteReadContext context, JournalSequence? after, int limit)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 4096);
        after?.RequireStore(context.StoreId);
        using var state = context.CreateCommand("SELECT last_sequence,truncated_through FROM journal_state WHERE store_id=$store");
        state.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        long head;
        long floor;
        using (var reader = state.ExecuteReader())
        {
            if (!reader.Read()) throw new InvalidDataException("The journal has no durable state.");
            head = reader.GetInt64(0);
            floor = reader.GetInt64(1);
            if (head < floor || floor < 0) throw new InvalidDataException("The journal watermarks are invalid.");
        }
        var position = after?.Value ?? floor;
        if (after is null && floor > 0)
            throw new InvalidOperationException("Replay must explicitly start from the verified snapshot after prefix truncation.");
        if (position < floor) throw new InvalidOperationException("Replay requires the verified snapshot for the truncated prefix.");
        if (position > head) throw new InvalidOperationException("Replay cannot start after the durable head.");
        using var command = context.CreateCommand("""
            SELECT sequence,aggregate_kind,aggregate_id,previous_version,next_version,command_id,
                operation,operation_version,payload,durable_reference,actor_id,correlation_id,causation_id,
                committed_seconds,committed_nanos,checksum,encoded_length,local_seq
            FROM journal WHERE store_id=$store AND sequence>$after ORDER BY sequence LIMIT $limit
            """);
        command.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        command.Parameters.AddWithValue("$after", position);
        command.Parameters.AddWithValue("$limit", limit);
        using var rows = command.ExecuteReader();
        var result = new List<JournalEntry>();
        while (rows.Read())
        {
            if (rows.GetInt64(0) != checked(position + result.Count + 1))
                throw new InvalidDataException("A journal sequence is missing; replay cannot cross a corrupt gap.");
            var entry = Restore(context.StoreId, rows);
            result.Add(entry);
        }
        if (result.Count != Math.Min((long)limit, head - position))
            throw new InvalidDataException("The journal tail does not reach its committed high watermark.");
        return result.AsReadOnly();
    }

    /// <summary>Returns only the checksummed contiguous suffix. Recovery callers must report any omitted tail.</summary>
    internal static JournalPrefix ReadValidPrefix(SqliteReadContext context, JournalSequence after)
    {
        after.RequireStore(context.StoreId);
        using var state = context.CreateCommand("SELECT last_sequence,truncated_through FROM journal_state WHERE store_id=$store");
        state.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        long head;
        long floor;
        using (var reader = state.ExecuteReader())
        {
            if (!reader.Read()) throw new InvalidDataException("The journal has no durable state.");
            head = reader.GetInt64(0);
            floor = reader.GetInt64(1);
            if (head < floor || floor < 0) throw new InvalidDataException("The journal watermarks are invalid.");
        }

        var position = after.Value;
        if (position > head) return new([], position, head, true);
        if (position < floor) return new([], floor, head, true);
        var result = new List<JournalEntry>();
        var expected = checked(position + 1);
        var corrupt = false;
        using (var command = context.CreateCommand("""
            SELECT sequence,aggregate_kind,aggregate_id,previous_version,next_version,command_id,
                operation,operation_version,payload,durable_reference,actor_id,correlation_id,causation_id,
                committed_seconds,committed_nanos,checksum,encoded_length,local_seq
            FROM journal WHERE store_id=$store AND sequence>$after AND sequence<=$head ORDER BY sequence
            """))
        {
            command.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
            command.Parameters.AddWithValue("$after", position);
            command.Parameters.AddWithValue("$head", head);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                if (rows.GetInt64(0) != expected)
                {
                    corrupt = true;
                    break;
                }

                try
                {
                    result.Add(Restore(context.StoreId, rows));
                }
                catch (Exception exception) when (exception is InvalidDataException or ArgumentException or FormatException or OverflowException or InvalidCastException)
                {
                    corrupt = true;
                    break;
                }
                expected = checked(expected + 1);
            }
        }

        var through = expected - 1;
        if (through != head || HasRowsBeyondHead(context, head)) corrupt = true;
        return new(result.AsReadOnly(), through, head, corrupt);
    }

    private static bool HasRowsBeyondHead(SqliteReadContext context, long head)
    {
        using var command = context.CreateCommand("SELECT 1 FROM journal WHERE store_id=$store AND sequence>$head LIMIT 1");
        command.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        command.Parameters.AddWithValue("$head", head);
        return command.ExecuteScalar() is not null;
    }

    public void Truncate(SqliteCommitContext context, VerifiedSnapshotBoundary boundary)
    {
        ArgumentNullException.ThrowIfNull(boundary);
        boundary.Through.RequireStore(context.StoreId);
        if (snapshotVerifier?.IsVerified(boundary) != true)
            throw new InvalidOperationException("No verified durable snapshot authorizes journal truncation.");
        using (var check = context.CreateCommand("SELECT checksum FROM journal WHERE store_id=$store AND sequence=$through"))
        {
            check.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
            check.Parameters.AddWithValue("$through", boundary.Through.Value);
            if (check.ExecuteScalar() is not byte[] checksum || !CryptographicOperations.FixedTimeEquals(checksum, boundary.JournalChecksum.Span))
                throw new InvalidDataException("The verified snapshot does not bind this committed journal boundary.");
        }
        using var command = context.CreateCommand("""
            DELETE FROM journal WHERE store_id=$store AND sequence<=$through;
            UPDATE journal_state SET truncated_through=$through,truncated_checksum=$checksum
                WHERE store_id=$store AND truncated_through<$through AND last_sequence>=$through;
            """);
        command.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        command.Parameters.AddWithValue("$through", boundary.Through.Value);
        command.Parameters.AddWithValue("$checksum", boundary.JournalChecksum.ToArray());
        if (command.ExecuteNonQuery() < 2) throw new InvalidDataException("The journal prefix and snapshot watermark must change together.");
    }

    private static JournalEntry Restore(Guid storeId, SqliteDataReader row)
    {
        try
        {
            var entry = JournalEntry.Create(new JournalSequence(storeId, row.GetInt64(0)), row.GetString(1),
                Guid.ParseExact(row.GetString(2), "D"), StoreVersion.ParseCanonicalText(row.GetString(3)),
                StoreVersion.ParseCanonicalText(row.GetString(4)), new CommandId(Guid.ParseExact(row.GetString(5), "D")),
                row.GetString(6), row.GetInt32(7), (byte[])row.GetValue(8), row.IsDBNull(9) ? null : row.GetString(9),
                new UserId(Guid.ParseExact(row.GetString(10), "D")), Guid.ParseExact(row.GetString(11), "D"),
                row.IsDBNull(12) ? null : Guid.ParseExact(row.GetString(12), "D"),
                new Instant(row.GetInt64(13), checked((uint)row.GetInt64(14))),
                row.IsDBNull(17) ? null : row.GetInt64(17));
            entry.Verify((byte[])row.GetValue(15));
            if (entry.EncodedLength != row.GetInt64(16))
                throw new InvalidDataException("The journal size accounting differs from its verified replay record.");
            return entry;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException or InvalidCastException)
        {
            throw new InvalidDataException("The journal contains a malformed replay entry.", exception);
        }
    }
}

internal sealed record JournalPrefix(IReadOnlyList<JournalEntry> Entries, long Through, long Head, bool HasCorruption);
