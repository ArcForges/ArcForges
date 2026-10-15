// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArcForges.Security.Secrets;

namespace ArcForges.Node.Store;

/// <summary>A node data key recorded in the store: which version it is and which backend holds it.</summary>
public sealed class DataKeyInfo
{
    /// <summary>The key version (<c>task_secret.key_id</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>The <see cref="SecretStoreBackend"/> that holds the key.</summary>
    public required string Backend { get; init; }

    /// <summary>The <see cref="SecretStoreProtection"/> of that backend when the key was created.</summary>
    public required string Protection { get; init; }

    /// <summary>When the key was created (microseconds since the Unix epoch).</summary>
    public required long CreatedAt { get; init; }
}

/// <summary>The node data key could not be created or read; nothing was sealed.</summary>
public sealed class NodeDataKeyUnavailableException : InvalidOperationException
{
    /// <summary>Creates the exception.</summary>
    public NodeDataKeyUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception.</summary>
    public NodeDataKeyUnavailableException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public NodeDataKeyUnavailableException()
    {
    }
}

/// <summary>
/// The node data key (AES-256) that seals task secrets (04-execution section 2), held in the OS secret store selected by
/// DesktopPlatform's <c>OsSecretStore.SelectForCurrentPlatform</c>: Windows Credential Manager, the Linux Secret Service,
/// or the reported owner-only file fallback. The store records each key version with the backend that holds it
/// (<c>node_setting</c> <see cref="SettingName"/>), because selection can differ between runs (Security.Secrets consumer
/// obligation): a key is read only from the backend recorded for it. When the recorded key is missing, or the selected
/// backend changed, a new key version is created in the selected backend; values sealed under an unreachable key are then
/// unavailable and their retries fail with <c>STATE/secrets_unavailable</c> (never a partial environment).
/// </summary>
/// <remarks>
/// A locked Linux keyring without a desktop prompter fails closed in Security.Secrets; this ring reports it as an
/// unavailable key and never redirects the key to the file fallback on its own.
/// </remarks>
public sealed class NodeDataKeyRing : IDisposable
{
    /// <summary>The <c>node_setting</c> row that records the key versions.</summary>
    public const string SettingName = "store.node_data_keys";

    /// <summary>The key length (AES-256).</summary>
    public const int KeyBytes = 32;

    private const string TargetPrefix = "ArcForges.Secrets.v1.";
    private readonly Lock _gate = new();
    private readonly Dictionary<string, byte[]> _cache = new(StringComparer.Ordinal);
    private readonly NodeStore _store;
    private readonly SecretStoreSelection _selection;
    private bool _disposed;

    /// <summary>Creates the ring over the store and the selected secret store.</summary>
    public NodeDataKeyRing(NodeStore store, SecretStoreSelection selection)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _selection = selection ?? throw new ArgumentNullException(nameof(selection));
    }

    /// <summary>The selected backend; new keys are created there.</summary>
    public SecretStoreBackend Backend => _selection.Backend;

    /// <summary>How the selected backend protects the key at rest; anything but the OS secret store is reported as weaker.</summary>
    public SecretStoreProtection Protection => _selection.Protection;

    /// <summary>Why the OS secret store was not selected, or <see langword="null"/>.</summary>
    public string? FallbackReason => _selection.FallbackReason;

    /// <summary>The secret store target of a key: <c>ArcForges.Secrets.v1.</c> and 64 uppercase hexadecimal digits.</summary>
    public static string TargetName(ReadOnlySpan<byte> nodeId, string keyId)
    {
        StoreIds.Validate(nodeId, nameof(nodeId));
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        var identity = Encoding.UTF8.GetBytes("arcforges.node-data-key.v1|" + Convert.ToHexStringLower(nodeId) + "|" + keyId);
        return TargetPrefix + Convert.ToHexString(SHA256.HashData(identity));
    }

    /// <summary>The recorded key versions, oldest first.</summary>
    public IReadOnlyList<DataKeyInfo> Keys() => _store.Read(reader => ReadRecords(reader).Keys);

    /// <summary>
    /// Deletes every recorded key held by the selected backend from that backend and returns how many existed. Used when a
    /// store is discarded (and by tests, which use uniquely named entries). Sealed values become unavailable.
    /// </summary>
    public int DeleteKeys()
    {
        lock (_gate)
        {
            var deleted = 0;
            var nodeId = _store.Metadata.NodeId.Span;
            foreach (var key in _store.Read(reader => ReadRecords(reader).Keys))
            {
                if (string.Equals(key.Backend, _selection.Backend.ToString(), StringComparison.Ordinal)
                    && _selection.Store.Delete(TargetName(nodeId, key.KeyId)))
                {
                    deleted++;
                }

                if (_cache.Remove(key.KeyId, out var cached))
                {
                    CryptographicOperations.ZeroMemory(cached);
                }
            }

            return deleted;
        }
    }

    /// <summary>
    /// Loads the current node data key into memory at node startup, creating a new key version in the selected backend when none is
    /// usable, so that sealing never waits on the secret store while it holds the store's writer lock (Security.Secrets calls can
    /// block for their timeouts). The secret-store read or write happens outside any store transaction; only recording a new
    /// version takes a short write transaction. Returns the current key ID, or <see langword="null"/> with the reason when the
    /// backend is unavailable (sealing then fails closed until it is).
    /// </summary>
    public string? Prepare(out string? unavailableReason)
    {
        string keyId;
        byte[] created;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var records = _store.Read(ReadRecords);
            var current = records.Keys.LastOrDefault(key => string.Equals(key.KeyId, records.Current, StringComparison.Ordinal));
            if (current is not null && string.Equals(current.Backend, _selection.Backend.ToString(), StringComparison.Ordinal)
                && TryLoad(current.KeyId, out _, out _))
            {
                unavailableReason = null;
                return current.KeyId;
            }

            var next = records.Keys.Count == 0
                ? 1
                : records.Keys.Max(key => int.Parse(key.KeyId, NumberStyles.None, CultureInfo.InvariantCulture)) + 1;
            keyId = next.ToString(CultureInfo.InvariantCulture);
            created = RandomNumberGenerator.GetBytes(KeyBytes);
            try
            {
                _selection.Store.Write(TargetName(_store.Metadata.NodeId.Span, keyId), created);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                CryptographicOperations.ZeroMemory(created);
                unavailableReason = $"the node data key could not be stored in {_selection.Backend}: {exception.Message}";
                return null;
            }
        }

        // Record the new version; the lock order (writer, then ring) is the one GetOrCreateCurrent uses inside a transaction.
        var recorded = _store.Write(transaction =>
        {
            lock (_gate)
            {
                var records = ReadRecords(transaction);
                var current = records.Keys.LastOrDefault(key => string.Equals(key.KeyId, records.Current, StringComparison.Ordinal));
                if (current is not null && string.Equals(current.Backend, _selection.Backend.ToString(), StringComparison.Ordinal)
                    && _cache.ContainsKey(current.KeyId))
                {
                    // Another caller created a usable key meanwhile; it stays current.
                    return current.KeyId;
                }

                records.Keys.Add(new DataKeyInfo
                {
                    KeyId = keyId,
                    Backend = _selection.Backend.ToString(),
                    Protection = _selection.Protection.ToString(),
                    CreatedAt = transaction.NowMicroseconds,
                });
                records.Current = keyId;
                transaction.Execute(
                    """
                    INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ($name, $value, $now, 0)
                    ON CONFLICT (name) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, rev = rev + 1;
                    """,
                    ("$name", SettingName),
                    ("$value", JsonSerializer.Serialize(records, StoreJsonContext.Default.DataKeyRecords)),
                    ("$now", transaction.NowMicroseconds));
                if (_cache.Remove(keyId, out var stale))
                {
                    CryptographicOperations.ZeroMemory(stale);
                }

                _cache[keyId] = created;
                return keyId;
            }
        });
        if (!string.Equals(recorded, keyId, StringComparison.Ordinal))
        {
            _selection.Store.Delete(TargetName(_store.Metadata.NodeId.Span, keyId));
            CryptographicOperations.ZeroMemory(created);
        }

        unavailableReason = null;
        return recorded;
    }

    /// <summary>Zeroes the cached key material.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var key in _cache.Values)
            {
                CryptographicOperations.ZeroMemory(key);
            }

            _cache.Clear();
            _disposed = true;
        }
    }

    /// <summary>
    /// The current key for sealing, read from the backend recorded for it; creates a new key version in the selected backend
    /// (recorded in <paramref name="transaction"/>) when there is none, it is missing, or the backend changed.
    /// </summary>
    internal (string KeyId, byte[] Key) GetOrCreateCurrent(StoreTransaction transaction)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var records = ReadRecords(transaction);
            var current = records.Keys.LastOrDefault(key => string.Equals(key.KeyId, records.Current, StringComparison.Ordinal));
            if (current is not null && string.Equals(current.Backend, _selection.Backend.ToString(), StringComparison.Ordinal)
                && TryLoad(current.KeyId, out var existing, out _))
            {
                return (current.KeyId, existing);
            }

            var next = records.Keys.Count == 0
                ? 1
                : records.Keys.Max(key => int.Parse(key.KeyId, NumberStyles.None, CultureInfo.InvariantCulture)) + 1;
            var keyId = next.ToString(CultureInfo.InvariantCulture);
            var key = RandomNumberGenerator.GetBytes(KeyBytes);
            try
            {
                _selection.Store.Write(TargetName(_store.Metadata.NodeId.Span, keyId), key);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                CryptographicOperations.ZeroMemory(key);
                throw new NodeDataKeyUnavailableException(
                    $"The node data key could not be stored in {_selection.Backend}: {exception.Message}", exception);
            }

            records.Keys.Add(new DataKeyInfo
            {
                KeyId = keyId,
                Backend = _selection.Backend.ToString(),
                Protection = _selection.Protection.ToString(),
                CreatedAt = transaction.NowMicroseconds,
            });
            records.Current = keyId;
            transaction.Execute(
                """
                INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ($name, $value, $now, 0)
                ON CONFLICT (name) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, rev = rev + 1;
                """,
                ("$name", SettingName),
                ("$value", JsonSerializer.Serialize(records, StoreJsonContext.Default.DataKeyRecords)),
                ("$now", transaction.NowMicroseconds));
            if (_cache.Remove(keyId, out var stale))
            {
                CryptographicOperations.ZeroMemory(stale);
            }

            _cache[keyId] = key;
            return (keyId, key);
        }
    }

    /// <summary>The key of <paramref name="keyId"/>, or why it cannot be used.</summary>
    internal bool TryGet(StoreReader reader, string keyId, out byte[] key, out string reason)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var record = ReadRecords(reader).Keys.LastOrDefault(item => string.Equals(item.KeyId, keyId, StringComparison.Ordinal));
            if (record is null)
            {
                key = [];
                reason = $"node data key {keyId} is not recorded in this store";
                return false;
            }

            if (!string.Equals(record.Backend, _selection.Backend.ToString(), StringComparison.Ordinal))
            {
                key = [];
                reason = $"node data key {keyId} is held by {record.Backend}, which is not the selected secret store ({_selection.Backend})";
                return false;
            }

            return TryLoad(keyId, out key, out reason);
        }
    }

    private bool TryLoad(string keyId, out byte[] key, out string reason)
    {
        if (_cache.TryGetValue(keyId, out var cached))
        {
            key = cached;
            reason = string.Empty;
            return true;
        }

        byte[]? loaded;
        try
        {
            loaded = _selection.Store.Read(TargetName(_store.Metadata.NodeId.Span, keyId));
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            key = [];
            reason = $"node data key {keyId} could not be read from {_selection.Backend}: {exception.Message}";
            return false;
        }

        if (loaded is null)
        {
            key = [];
            reason = $"node data key {keyId} is missing from {_selection.Backend}";
            return false;
        }

        if (loaded.Length != KeyBytes)
        {
            CryptographicOperations.ZeroMemory(loaded);
            key = [];
            reason = $"node data key {keyId} in {_selection.Backend} has the wrong length";
            return false;
        }

        _cache[keyId] = loaded;
        key = loaded;
        reason = string.Empty;
        return true;
    }

    private static DataKeyRecords ReadRecords(StoreReader reader)
    {
        var json = reader.Scalar("SELECT value_json FROM node_setting WHERE name = $name;", ("$name", SettingName)) as string;
        return json is null
            ? new DataKeyRecords()
            : JsonSerializer.Deserialize(json, StoreJsonContext.Default.DataKeyRecords) ?? new DataKeyRecords();
    }
}

/// <summary>The value of <c>node_setting</c> <see cref="NodeDataKeyRing.SettingName"/>.</summary>
internal sealed class DataKeyRecords
{
    public string? Current { get; set; }

    public List<DataKeyInfo> Keys { get; set; } = [];
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(DataKeyRecords))]
internal sealed partial class StoreJsonContext : JsonSerializerContext;
