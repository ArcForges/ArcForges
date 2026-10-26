// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Store.Proto;
using Google.Protobuf;

namespace ArcForges.Node.Store;

/// <summary>Whether a task's sealed environment values can be restored.</summary>
public enum UnsealStatus
{
    /// <summary>The task has no sealed values: its environment is complete without them.</summary>
    None = 0,

    /// <summary>The values were opened with the node data key.</summary>
    Available = 1,

    /// <summary>The values were purged, or the node data key cannot open them: <c>STATE/secrets_unavailable</c>.</summary>
    Unavailable = 2,
}

/// <summary>The result of <see cref="TaskSecrets.Unseal(ReadOnlySpan{byte})"/>.</summary>
public sealed class UnsealResult
{
    internal UnsealResult(UnsealStatus status, SecretEnvironment? values, IReadOnlyList<string> names, ArcError? error,
        string? unavailableReason = null)
    {
        Status = status;
        Values = values;
        Names = names;
        Error = error;
        UnavailableReason = unavailableReason;
    }

    /// <summary>The outcome.</summary>
    public UnsealStatus Status { get; }

    /// <summary>The opened values, for <see cref="UnsealStatus.Available"/>.</summary>
    public SecretEnvironment? Values { get; }

    /// <summary>The sealed variable names (presence only); kept after a purge.</summary>
    public IReadOnlyList<string> Names { get; }

    /// <summary><c>STATE/secrets_unavailable</c>, for <see cref="UnsealStatus.Unavailable"/>.</summary>
    public ArcError? Error { get; }

    /// <summary>
    /// Why the values are unavailable, for node logs and diagnostics only (never part of the error on the wire): the purge
    /// time, or why the node data key cannot open them. Contains no secret material.
    /// </summary>
    public string? UnavailableReason { get; }
}

/// <summary>
/// <c>task_secret</c> (04-execution section 2; AD-0006 section 1): the values of a task's secret-shaped environment variables,
/// sealed with AES-256-GCM under the node data key with the task ID as associated data, so queued tasks, restarts and retries
/// run with the submitted environment. When a task is terminal, its values are purged after
/// <c>storage.secret_retention_hours</c> (default 24); a retry afterwards fails with <c>STATE/secrets_unavailable</c>.
/// </summary>
/// <remarks>
/// A purge destroys the values and keeps the row as a tombstone: <c>key_id</c> <see cref="PurgedKeyId"/>, a zero nonce, tag and
/// one-byte ciphertext, the sealed names (presence only, shown in records) and <c>purge_after</c> (the purge time, which the
/// error reports as <c>details.state.reason</c>, an RFC 3339 UTC instant). The row goes with its task (<c>ON DELETE CASCADE</c>, <c>PurgeTaskRecord</c> and record retention). The writer
/// runs with <c>secure_delete</c>, so the overwritten values are zeroed in the database pages, and a purge checkpoints the WAL.
/// </remarks>
public sealed class TaskSecrets
{
    /// <summary>The <c>key_id</c> of a purged row.</summary>
    public const string PurgedKeyId = "purged";

    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int MaxCiphertextBytes = 1024 * 1024;
    private readonly NodeStore _store;
    private readonly NodeDataKeyRing _keys;

    /// <summary>Creates the sealed-secret store over the node data key ring.</summary>
    public TaskSecrets(NodeStore store, NodeDataKeyRing keys)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
    }

    /// <summary>Seals <paramref name="secrets"/> for the task <paramref name="taskId"/> (whose row exists) in the open transaction.</summary>
    /// <exception cref="NodeDataKeyUnavailableException">The node data key could not be created in the selected secret store.</exception>
    public void Seal(StoreTransaction transaction, ReadOnlySpan<byte> taskId, SecretEnvironment secrets)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(secrets);
        StoreIds.Validate(taskId, nameof(taskId));
        var names = secrets.Caller.Select(entry => entry.Name).Concat(secrets.Set.Select(entry => entry.Name))
            .Distinct(StringComparer.Ordinal).Order(Utf8Order.Instance).ToList();
        if (names.Count == 0)
        {
            throw new ArgumentException("There is nothing to seal.", nameof(secrets));
        }

        var plaintext = secrets.ToByteArray();
        try
        {
            if (plaintext.Length > MaxCiphertextBytes)
            {
                throw new ArgumentException("Sealed environment values are at most 1 MiB.", nameof(secrets));
            }

            var (keyId, key) = _keys.GetOrCreateCurrent(transaction);
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagBytes];
            using (var aes = new AesGcm(key, TagBytes))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: taskId);
            }

            transaction.Execute(
                """
                INSERT INTO task_secret (task_id, key_id, nonce, ciphertext, tag, names_json, purge_after, created_at)
                VALUES ($task, $key, $nonce, $ciphertext, $tag, $names, NULL, $now);
                """,
                ("$task", taskId.ToArray()),
                ("$key", keyId),
                ("$nonce", nonce),
                ("$ciphertext", ciphertext),
                ("$tag", tag),
                ("$names", JsonSerializer.Serialize(names, SecretJsonContext.Default.ListString)),
                ("$now", transaction.NowMicroseconds));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Opens a task's sealed values on a read-only connection (a retry, or recovery after a restart).</summary>
    public UnsealResult Unseal(ReadOnlySpan<byte> taskId)
    {
        var id = taskId.ToArray();
        return _store.Read(reader => Unseal(reader, id));
    }

    /// <summary>Opens a task's sealed values in an open transaction.</summary>
    public UnsealResult Unseal(StoreReader reader, ReadOnlySpan<byte> taskId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        StoreIds.Validate(taskId, nameof(taskId));
        string keyId;
        byte[] nonce, ciphertext, tag;
        IReadOnlyList<string> names;
        long? purgeAfter;
        using (var command = reader.CreateCommand(
            "SELECT key_id, nonce, ciphertext, tag, names_json, purge_after FROM task_secret WHERE task_id = $task;"))
        {
            command.Parameters.AddWithValue("$task", taskId.ToArray());
            using var row = command.ExecuteReader();
            if (!row.Read())
            {
                return new UnsealResult(UnsealStatus.None, values: null, [], error: null);
            }

            keyId = row.GetString(0);
            nonce = (byte[])row.GetValue(1);
            ciphertext = (byte[])row.GetValue(2);
            tag = (byte[])row.GetValue(3);
            names = JsonSerializer.Deserialize(row.GetString(4), SecretJsonContext.Default.ListString) ?? [];
            purgeAfter = row.IsDBNull(5) ? null : row.GetInt64(5);
        }

        if (string.Equals(keyId, PurgedKeyId, StringComparison.Ordinal))
        {
            var at = purgeAfter ?? 0;
            return new UnsealResult(UnsealStatus.Unavailable, values: null, names, StoreErrors.SecretsUnavailable(at),
                $"the sealed environment values were purged at {StoreTime.ToRfc3339(at)}");
        }

        if (!_keys.TryGet(reader, keyId, out var key, out var reason))
        {
            return new UnsealResult(UnsealStatus.Unavailable, values: null, names, StoreErrors.SecretsUnavailable(purgedAt: null),
                $"the sealed environment values cannot be opened: {reason}");
        }

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using (var aes = new AesGcm(key, TagBytes))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: taskId);
            }

            return new UnsealResult(UnsealStatus.Available, SecretEnvironment.Parser.ParseFrom(plaintext), names, error: null);
        }
        catch (AuthenticationTagMismatchException)
        {
            return new UnsealResult(UnsealStatus.Unavailable, values: null, names, StoreErrors.SecretsUnavailable(purgedAt: null),
                $"the sealed environment values do not open with node data key {keyId}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Sets the purge time of a task that became terminal: <paramref name="terminalAt"/> plus <paramref name="retention"/>
    /// (policy <c>storage.secret_retention_hours</c>). Returns whether the task has sealed values.
    /// </summary>
    public static bool SchedulePurge(StoreTransaction transaction, ReadOnlySpan<byte> taskId, long terminalAt, TimeSpan retention)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        StoreIds.Validate(taskId, nameof(taskId));
        ArgumentOutOfRangeException.ThrowIfLessThan(retention, TimeSpan.Zero);
        return transaction.Execute(
            "UPDATE task_secret SET purge_after = $at WHERE task_id = $task AND key_id <> $purged;",
            ("$at", terminalAt + (long)retention.TotalMicroseconds),
            ("$task", taskId.ToArray()),
            ("$purged", PurgedKeyId)) == 1;
    }

    /// <summary>Purges a task's sealed values now (<c>PurgeTaskRecord</c> before the record itself is removed).</summary>
    public static bool PurgeNow(StoreTransaction transaction, ReadOnlySpan<byte> taskId)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        StoreIds.Validate(taskId, nameof(taskId));
        return transaction.Execute(
            $"UPDATE task_secret SET {Tombstone}, purge_after = $now WHERE task_id = $task AND key_id <> $purged;",
            ("$now", transaction.NowMicroseconds),
            ("$task", taskId.ToArray()),
            ("$purged", PurgedKeyId)) == 1;
    }

    /// <summary>
    /// Housekeeping: purges every sealed value whose <c>purge_after</c> has passed and attempts a truncating checkpoint,
    /// also when no new value is due. Returns the number logically purged; an older reader can defer physical erasure to a later pass.
    /// </summary>
    public int PurgeDue()
    {
        var purged = _store.Write(transaction => transaction.Execute(
            $"UPDATE task_secret SET {Tombstone} WHERE purge_after IS NOT NULL AND purge_after <= $now AND key_id <> $purged;",
            ("$now", transaction.NowMicroseconds),
            ("$purged", PurgedKeyId)));
        // Retry even with no newly purged row: a previous pass (or manual purge) may have been blocked by
        // an older read snapshot. No in-memory pending flag is needed, so a restart cannot lose the retry.
        _store.Checkpoint();

        return purged;
    }

    internal const string Tombstone = "key_id = 'purged', nonce = zeroblob(12), ciphertext = x'00', tag = zeroblob(16)";
}

[System.Text.Json.Serialization.JsonSerializable(typeof(List<string>))]
internal sealed partial class SecretJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
