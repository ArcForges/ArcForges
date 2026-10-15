// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.Node.Store;

/// <summary>
/// The payload digest of an idempotent mutation (contracts README section 6): SHA-256 over the request's top-level fields
/// in wire order, without field 1 (<c>RequestMeta meta</c>, which carries the command ID and per-attempt correlation).
/// A client retries with the same request, so the same request always has the same digest.
/// </summary>
public static class PayloadDigest
{
    /// <summary>The digest of a request message.</summary>
    public static byte[] Compute(IMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Compute(request.ToByteArray());
    }

    /// <summary>The digest of a serialized request.</summary>
    public static byte[] Compute(byte[] serializedRequest)
    {
        ArgumentNullException.ThrowIfNull(serializedRequest);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var input = new CodedInputStream(serializedRequest);
        while (true)
        {
            var start = checked((int)input.Position);
            var tag = input.ReadTag();
            if (tag == 0)
            {
                break;
            }

            input.SkipLastField();
            if (WireFormat.GetTagFieldNumber(tag) != 1)
            {
                hash.AppendData(serializedRequest, start, checked((int)input.Position) - start);
            }
        }

        return hash.GetHashAndReset();
    }
}

/// <summary>What <see cref="CommandDeduplication.Begin"/> found for a command ID.</summary>
public enum DedupStatus
{
    /// <summary>New (or expired) command ID: a row was inserted with no outcome; execute the command and call <see cref="CommandDeduplication.Complete"/> in the same transaction.</summary>
    Execute = 0,

    /// <summary>Same ID and payload with a stored outcome: return it without executing again.</summary>
    Replay = 1,

    /// <summary>Same ID, different payload digest or method: <c>CONFLICT/command_id_reused</c>.</summary>
    Conflict = 2,

    /// <summary>Same ID and payload, still executing (an outcome was never stored, for example a long-running job).</summary>
    InProgress = 3,
}

/// <summary>The decision for one command ID.</summary>
public sealed class DedupDecision
{
    internal DedupDecision(DedupStatus status, byte[]? outcome)
    {
        Status = status;
        Outcome = outcome is null ? (ReadOnlyMemory<byte>?)null : outcome;
    }

    /// <summary>What to do.</summary>
    public DedupStatus Status { get; }

    /// <summary>The stored serialized response, for <see cref="DedupStatus.Replay"/>.</summary>
    public ReadOnlyMemory<byte>? Outcome { get; }

    /// <summary>The error to return, for <see cref="DedupStatus.Conflict"/>.</summary>
    public ArcError? Error => Status == DedupStatus.Conflict ? StoreErrors.CommandIdReused() : null;
}

/// <summary>The result of <see cref="CommandDeduplication.Execute"/>.</summary>
public sealed class IdempotentResult
{
    internal IdempotentResult(bool replayed, byte[]? outcome, ArcError? error)
    {
        Replayed = replayed;
        Outcome = outcome is null ? (ReadOnlyMemory<byte>?)null : outcome;
        Error = error;
    }

    /// <summary>The outcome was stored by an earlier execution and returned without executing again.</summary>
    public bool Replayed { get; }

    /// <summary>The serialized response (new or replayed); <see langword="null"/> with an <see cref="Error"/>.</summary>
    public ReadOnlyMemory<byte>? Outcome { get; }

    /// <summary><c>CONFLICT/command_id_reused</c>, or <see langword="null"/>.</summary>
    public ArcError? Error { get; }
}

/// <summary>
/// <c>command_dedup</c> (R-EXE-016; contracts README section 6): mutations deduplicate by <c>meta.command_id</c> for 24 hours.
/// The same ID with the same payload returns the stored outcome; with a different payload, <c>CONFLICT/command_id_reused</c>.
/// Commits that record a command use <c>synchronous=FULL</c>, so an acknowledged command ID survives power loss.
/// </summary>
public sealed class CommandDeduplication
{
    /// <summary>The deduplication window (and the row's retention).</summary>
    public static readonly TimeSpan Window = TimeSpan.FromHours(24);

    private const long WindowMicroseconds = 24L * 60 * 60 * 1_000_000;
    private readonly NodeStore _store;

    internal CommandDeduplication(NodeStore store) => _store = store;

    /// <summary>
    /// Looks up <paramref name="commandId"/> in an open transaction and, for a new or expired ID, inserts its row with no
    /// outcome. The caller executes the command in the same transaction, calls <see cref="Complete"/> and commits with
    /// <see cref="CommitDurability.Full"/>.
    /// </summary>
    public static DedupDecision Begin(StoreTransaction transaction, ReadOnlySpan<byte> commandId, string method,
        ReadOnlySpan<byte> payloadDigest, Origin origin)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.Durability != CommitDurability.Full)
        {
            throw new InvalidOperationException("command_dedup is written only in transactions committed with synchronous=FULL.");
        }

        StoreIds.Validate(commandId, nameof(commandId));
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        if (payloadDigest.Length != SHA256.HashSizeInBytes)
        {
            throw new ArgumentException("A payload digest is a 32-byte SHA-256.", nameof(payloadDigest));
        }

        var id = commandId.ToArray();
        var now = transaction.NowMicroseconds;
        using (var command = transaction.CreateCommand(
            "SELECT method, payload_digest, outcome, expires_at FROM command_dedup WHERE command_id = $id;"))
        {
            command.Parameters.AddWithValue("$id", id);
            using var row = command.ExecuteReader();
            if (row.Read())
            {
                if (row.GetInt64(3) > now)
                {
                    var sameMethod = string.Equals(row.GetString(0), method, StringComparison.Ordinal);
                    var samePayload = CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(1), payloadDigest);
                    if (!sameMethod || !samePayload)
                    {
                        return new DedupDecision(DedupStatus.Conflict, null);
                    }

                    return row.IsDBNull(2)
                        ? new DedupDecision(DedupStatus.InProgress, null)
                        : new DedupDecision(DedupStatus.Replay, (byte[])row.GetValue(2));
                }
            }
        }

        // New, or past its window: the ID starts a new record.
        transaction.Execute("DELETE FROM command_dedup WHERE command_id = $id;", ("$id", id));
        transaction.Execute(
            """
            INSERT INTO command_dedup (command_id, method, payload_digest, origin, outcome, created_at, expires_at)
            VALUES ($id, $method, $digest, $origin, NULL, $now, $expires);
            """,
            ("$id", id),
            ("$method", method),
            ("$digest", payloadDigest.ToArray()),
            ("$origin", (int)origin),
            ("$now", now),
            ("$expires", now + WindowMicroseconds));
        return new DedupDecision(DedupStatus.Execute, null);
    }

    /// <summary>Stores the serialized response of a command begun in this transaction.</summary>
    public static void Complete(StoreTransaction transaction, ReadOnlySpan<byte> commandId, ReadOnlySpan<byte> outcome)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        StoreIds.Validate(commandId, nameof(commandId));
        var changed = transaction.Execute(
            "UPDATE command_dedup SET outcome = $outcome WHERE command_id = $id AND outcome IS NULL;",
            ("$outcome", outcome.ToArray()),
            ("$id", commandId.ToArray()));
        if (changed != 1)
        {
            throw new InvalidOperationException("Complete needs a command begun in this transaction without an outcome.");
        }
    }

    /// <summary>
    /// Executes a mutation at most once per command ID: in one <see cref="CommitDurability.Full"/> transaction it records the
    /// command, runs <paramref name="execute"/> (which writes the command's effects through the transaction and returns the
    /// serialized response) and stores the response. A repeated ID with the same payload returns the stored response without
    /// running <paramref name="execute"/>; a different payload returns <c>CONFLICT/command_id_reused</c>. If
    /// <paramref name="execute"/> throws, nothing is recorded.
    /// </summary>
    public IdempotentResult Execute(ReadOnlySpan<byte> commandId, string method, ReadOnlySpan<byte> payloadDigest, Origin origin,
        Func<StoreTransaction, byte[]> execute)
    {
        ArgumentNullException.ThrowIfNull(execute);
        var id = commandId.ToArray();
        var digest = payloadDigest.ToArray();
        return _store.Write(transaction =>
        {
            var decision = Begin(transaction, id, method, digest, origin);
            switch (decision.Status)
            {
                case DedupStatus.Replay:
                    return new IdempotentResult(replayed: true, decision.Outcome!.Value.ToArray(), error: null);
                case DedupStatus.Conflict:
                    return new IdempotentResult(replayed: false, outcome: null, decision.Error);
                case DedupStatus.InProgress:
                    throw new InvalidOperationException("The command is still executing; it has no stored outcome yet.");
                default:
                    var outcome = execute(transaction);
                    ArgumentNullException.ThrowIfNull(outcome);
                    Complete(transaction, id, outcome);
                    return new IdempotentResult(replayed: false, outcome, error: null);
            }
        }, CommitDurability.Full);
    }

    /// <summary>Housekeeping: deletes records past their 24-hour window. Returns the number deleted.</summary>
    public int PurgeExpired() => _store.Write(transaction =>
        transaction.Execute("DELETE FROM command_dedup WHERE expires_at <= $now;", ("$now", transaction.NowMicroseconds)));
}
