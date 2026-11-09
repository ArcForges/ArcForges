// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Files;

/// <summary>A closed refusal from the internal registered-workspace component.</summary>
internal sealed class RegisteredWorkspaceException(string reason, Exception? inner = null) : IOException(reason, inner)
{
    internal string Reason { get; } = reason;
}

/// <summary>Persisted registered-workspace metadata; no file contents or Git claims.</summary>
internal sealed record RegisteredWorkspace(byte[] Id, string Name, string RootPath, long CreatedAt, long LastUsedAt);

/// <summary>A bounded internal page. This key is not a transport cursor or a serialized-response size guarantee.</summary>
internal sealed record RegisteredWorkspacePage(IReadOnlyList<RegisteredWorkspace> Workspaces, byte[]? NextAfter);

/// <summary>
/// Native root registration backed by the node's actual SQLite store. Mutation entry points are a TRUSTED application boundary:
/// the eventual caller must already have independently verified the fixed HUMAN origin and permission. This component does
/// not classify callers, run Git, expose RPCs, implement command receipts or accept a caller-supplied origin assertion.
/// All future workspace file/cleanup/approval paths must coordinate through the same use registry and transaction rules.
/// </summary>
internal sealed class RegisteredWorkspaces
{
    private const int FormatVersion = 1;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly Lock SharedGate = new();
    private static readonly Dictionary<string, WeakReference<SharedState>> Shared =
        new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    private readonly NodeStore _store;
    private readonly SharedState _state;

    internal RegisteredWorkspaces(NodeStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
        _state = GetSharedState(store.DatabasePath);
    }

    /// <summary>Called only after the application has verified HUMAN authority for this registration.</summary>
    internal RegisteredWorkspace RegisterFromVerifiedHuman(string absolutePath, string? name = null, CancellationToken cancellationToken = default) =>
        RegisterFromVerifiedHuman(absolutePath, name, afterOpen: null, cancellationToken: cancellationToken);

    // The callback only coordinates changes to real test-owned roots between opening and transactional revalidation.
    internal RegisteredWorkspace RegisterFromVerifiedHuman(string absolutePath, string? name, Action? afterOpen, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var opened = WorkspacePath.OpenRoot(absolutePath);
        var native = RootIdentity.Encode(opened.RootIdentity);
        var canonical = opened.RootPath;
        ValidatePath(canonical);
        var selectedName = ValidateName(name ?? DefaultName(canonical));
        afterOpen?.Invoke();

        lock (_state.Gate)
        {
            return _store.Write(transaction =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var existing = FindByIdentity(transaction, native.Platform, native.Bytes);
                if (existing is not null)
                {
                    // A duplicate is valid only while its original recorded path still names the same opened root.
                    using var verified = OpenVerified(existing);
                    using var candidate = ReopenCandidate(canonical, opened.RootIdentity, native);
                    cancellationToken.ThrowIfCancellationRequested();
                    return existing.Public();
                }

                if (transaction.Scalar("""
                    SELECT 1 FROM workspace_root_identity
                    WHERE released_at IS NULL AND platform = $platform AND native_identity = $identity LIMIT 1;
                    """, ("$platform", native.Platform), ("$identity", native.Bytes)) is not null)
                {
                    // An orphaned or inconsistent active identity is not silently reassigned.
                    throw new RegisteredWorkspaceException("workspace_identity_conflict");
                }

                var occupied = transaction.Scalar(
                    "SELECT 1 FROM workspace WHERE removed_at IS NULL AND root_path = $path LIMIT 1;",
                    ("$path", canonical));
                if (occupied is not null)
                {
                    // Includes legacy rows: do not invent an identity for their historical root.
                    throw new RegisteredWorkspaceException("workspace_path_conflict");
                }

                using var checkedRoot = ReopenCandidate(canonical, opened.RootIdentity, native);
                cancellationToken.ThrowIfCancellationRequested();
                var id = StoreIds.NewUuid7(transaction.Clock);
                var now = transaction.NowMicroseconds;
                transaction.Execute("""
                    INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                    VALUES ($id, 1, 2, $name, $path, $now, $now, 0);
                    """, ("$id", id), ("$name", selectedName), ("$path", canonical), ("$now", now));
                transaction.Execute("""
                    INSERT INTO workspace_root_identity (workspace_id, format_version, platform, native_identity, canonical_path, registered_at)
                    VALUES ($id, 1, $platform, $identity, $path, $now);
                    """, ("$id", id), ("$platform", native.Platform), ("$identity", native.Bytes), ("$path", canonical), ("$now", now));
                cancellationToken.ThrowIfCancellationRequested();
                return new RegisteredWorkspace(id, selectedName, canonical, now, now);
            }, CommitDurability.Full);
        }
    }

    /// <summary>Reads one live record and verifies its recorded path against the actual currently opened root.</summary>
    internal RegisteredWorkspace Get(ReadOnlySpan<byte> id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = CopyId(id);
        lock (_state.Gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var row = _store.Read(reader => FindById(reader, key)) ?? throw new RegisteredWorkspaceException("workspace_not_found");
            using var root = OpenVerified(row);
            cancellationToken.ThrowIfCancellationRequested();
            return row.Public();
        }
    }

    /// <summary>Reads a key-ordered page of registered records; an unverifiable root refuses the page rather than being silently omitted.</summary>
    internal RegisteredWorkspacePage List(int limit, byte[]? after = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (limit is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        var cursor = after is null ? null : CopyId(after);
        lock (_state.Gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var rows = _store.Read(reader => ReadPage(reader, limit + 1, cursor));
            var more = rows.Count > limit;
            if (more)
            {
                rows.RemoveAt(rows.Count - 1);
            }

            var result = new List<RegisteredWorkspace>(rows.Count);
            foreach (var row in rows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var root = OpenVerified(row);
                cancellationToken.ThrowIfCancellationRequested();
                result.Add(row.Public());
            }

            cancellationToken.ThrowIfCancellationRequested();
            return new RegisteredWorkspacePage(result, more ? result[^1].Id.ToArray() : null);
        }
    }

    /// <summary>Holds a verified opened root and an in-process use lease until disposal.</summary>
    internal RegisteredWorkspaceUse OpenForUse(ReadOnlySpan<byte> id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = CopyId(id);
        lock (_state.Gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var row = _store.Read(reader => FindById(reader, key)) ?? throw new RegisteredWorkspaceException("workspace_not_found");
            var root = OpenVerified(row);
            var text = Convert.ToHexString(key);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                _state.Users.TryGetValue(text, out var current);
                _state.Users[text] = checked(current + 1);
                return new RegisteredWorkspaceUse(_state, text, root);
            }
            catch
            {
                root.Dispose();
                throw;
            }
        }
    }

    /// <summary>
    /// Called only after the application has verified HUMAN authority. It retains the old workspace row and all files.
    /// Pending file plans and approvals require workspace-bound persistent checks when their records are implemented;
    /// the component is not an exposed product endpoint until that integration exists.
    /// </summary>
    internal void UnregisterFromVerifiedHuman(ReadOnlySpan<byte> id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = CopyId(id);
        var text = Convert.ToHexString(key);
        lock (_state.Gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_state.Users.ContainsKey(text))
            {
                throw new RegisteredWorkspaceException("workspace_in_use");
            }

            _store.Write(transaction =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _ = FindById(transaction, key) ?? throw new RegisteredWorkspaceException("workspace_not_found");
                if (IsReferenced(transaction, key))
                {
                    throw new RegisteredWorkspaceException("workspace_in_use");
                }

                var now = transaction.NowMicroseconds;
                var removed = transaction.Execute("""
                    UPDATE workspace SET state = 5, removed_at = $now, rev = rev + 1
                    WHERE workspace_id = $id AND kind = 1 AND removed_at IS NULL;
                    """, ("$id", key), ("$now", now));
                if (removed != 1)
                {
                    throw new RegisteredWorkspaceException("workspace_not_found");
                }

                // A legacy row can be explicitly forgotten without fabricating an identity.
                transaction.Execute("""
                    UPDATE workspace_root_identity SET released_at = max(registered_at, $now)
                    WHERE workspace_id = $id AND released_at IS NULL;
                    """, ("$id", key), ("$now", now));
                cancellationToken.ThrowIfCancellationRequested();
            }, CommitDurability.Full);
        }
    }

    private static bool IsReferenced(StoreReader reader, byte[] id) => Convert.ToInt64(reader.Scalar("""
        SELECT EXISTS(SELECT 1 FROM task WHERE workspace_id = $id AND state IN (3, 4, 5));
        """, ("$id", id)), System.Globalization.CultureInfo.InvariantCulture) != 0;

    private static Stored? FindById(StoreReader reader, byte[] id)
    {
        using var command = reader.CreateCommand("""
            SELECT w.workspace_id, w.name, w.root_path, w.created_at, w.last_used_at,
                   i.format_version, i.platform, i.native_identity, i.canonical_path, w.state
            FROM workspace AS w LEFT JOIN workspace_root_identity AS i
                 ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE w.workspace_id = $id AND w.kind = 1 AND w.removed_at IS NULL;
            """);
        command.Parameters.AddWithValue("$id", id);
        using var rows = command.ExecuteReader();
        return rows.Read() ? ReadRow(rows) : null;
    }

    private static Stored? FindByIdentity(StoreReader reader, int platform, byte[] identity)
    {
        using var command = reader.CreateCommand("""
            SELECT w.workspace_id, w.name, w.root_path, w.created_at, w.last_used_at,
                   i.format_version, i.platform, i.native_identity, i.canonical_path, w.state
            FROM workspace AS w JOIN workspace_root_identity AS i ON i.workspace_id = w.workspace_id
            WHERE w.kind = 1 AND w.removed_at IS NULL AND i.released_at IS NULL
              AND i.platform = $platform AND i.native_identity = $identity;
            """);
        command.Parameters.AddWithValue("$platform", platform);
        command.Parameters.AddWithValue("$identity", identity);
        using var rows = command.ExecuteReader();
        return rows.Read() ? ReadRow(rows) : null;
    }

    private static List<Stored> ReadPage(StoreReader reader, int limit, byte[]? after)
    {
        using var command = reader.CreateCommand("""
            SELECT w.workspace_id, w.name, w.root_path, w.created_at, w.last_used_at,
                   i.format_version, i.platform, i.native_identity, i.canonical_path, w.state
            FROM workspace AS w LEFT JOIN workspace_root_identity AS i
                 ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE w.kind = 1 AND w.removed_at IS NULL AND ($after IS NULL OR w.workspace_id > $after)
            ORDER BY w.workspace_id LIMIT $limit;
            """);
        command.Parameters.AddWithValue("$after", (object?)after ?? DBNull.Value);
        command.Parameters.AddWithValue("$limit", limit);
        using var rows = command.ExecuteReader();
        var result = new List<Stored>();
        while (rows.Read())
        {
            result.Add(ReadRow(rows));
        }

        return result;
    }

    private static Stored ReadRow(SqliteDataReader row) => new(
        (byte[])row.GetValue(0), row.GetString(1), row.GetString(2), row.GetInt64(3), row.GetInt64(4),
        row.IsDBNull(5) ? null : row.GetInt32(5), row.IsDBNull(6) ? null : row.GetInt32(6),
        row.IsDBNull(7) ? null : (byte[])row.GetValue(7), row.IsDBNull(8) ? null : row.GetString(8), row.GetInt32(9));

    private static WorkspacePath OpenVerified(Stored stored)
    {
        if (stored.Format != FormatVersion || stored.Platform is null || stored.Identity is null || stored.Canonical is null)
        {
            throw new RegisteredWorkspaceException("workspace_identity_missing");
        }

        if (stored.State != 2)
        {
            throw new RegisteredWorkspaceException("workspace_state_invalid");
        }

        if (!string.Equals(stored.Root, stored.Canonical, StringComparison.Ordinal))
        {
            throw new RegisteredWorkspaceException("workspace_identity_invalid");
        }

        RootIdentity.ValidateEncoding(stored.Platform.Value, stored.Identity);
        WorkspacePath root;
        try
        {
            root = WorkspacePath.OpenRoot(stored.Canonical);
        }
        catch (WorkspacePathException exception)
        {
            throw new RegisteredWorkspaceException("workspace_root_unavailable", exception);
        }

        try
        {
            var actual = RootIdentity.Encode(root.RootIdentity);
            if (stored.Platform != actual.Platform || !CryptographicOperations.FixedTimeEquals(stored.Identity, actual.Bytes))
            {
                throw new RegisteredWorkspaceException("workspace_root_changed");
            }

            return root;
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }

    private static WorkspacePath ReopenCandidate(string path, WorkspaceObjectIdentity expected, RootIdentity identity)
    {
        WorkspacePath root;
        try
        {
            root = WorkspacePath.OpenRoot(path, expected);
        }
        catch (WorkspacePathException exception)
        {
            throw new RegisteredWorkspaceException("workspace_root_changed", exception);
        }

        try
        {
            var actual = RootIdentity.Encode(root.RootIdentity);
            if (actual.Platform != identity.Platform || !CryptographicOperations.FixedTimeEquals(actual.Bytes, identity.Bytes))
            {
                throw new RegisteredWorkspaceException("workspace_root_changed");
            }

            return root;
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }

    private static byte[] CopyId(ReadOnlySpan<byte> id)
    {
        StoreIds.Validate(id, nameof(id));
        return id.ToArray();
    }

    private static string DefaultName(string path)
    {
        var leaf = Path.GetFileName(Path.TrimEndingDirectorySeparator(path));
        return leaf.Length == 0 ? path : leaf;
    }

    private static string ValidateName(string name)
    {
        try
        {
            StrictUtf8.GetByteCount(name);
            var count = 0;
            foreach (var rune in name.EnumerateRunes())
            {
                if (rune.Value == 0 || ++count > 100)
                {
                    throw new RegisteredWorkspaceException("workspace_name_invalid");
                }
            }

            return count == 0 ? throw new RegisteredWorkspaceException("workspace_name_invalid") : name;
        }
        catch (EncoderFallbackException exception)
        {
            throw new RegisteredWorkspaceException("workspace_name_invalid", exception);
        }
    }

    private static void ValidatePath(string path)
    {
        try
        {
            if (StrictUtf8.GetByteCount(path) is 0 or > 4096)
            {
                throw new RegisteredWorkspaceException("workspace_path_invalid");
            }
        }
        catch (EncoderFallbackException exception)
        {
            throw new RegisteredWorkspaceException("workspace_path_invalid", exception);
        }
    }

    private static SharedState GetSharedState(string databasePath)
    {
        // Aliased data-root paths must still share the same in-process use registry. SQLite has already opened this
        // node-owned database; this short read-only handle obtains its actual native identity, not its textual path.
        using var database = File.OpenHandle(databasePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var native = RootIdentity.Encode(WorkspacePath.Identity(database), directory: false);
        var key = native.Platform.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + Convert.ToHexString(native.Bytes);
        lock (SharedGate)
        {
            foreach (var obsolete in Shared.Where(static entry => !entry.Value.TryGetTarget(out _)).Select(static entry => entry.Key).ToArray())
            {
                Shared.Remove(obsolete);
            }

            if (!Shared.TryGetValue(key, out var weak) || !weak.TryGetTarget(out var state))
            {
                state = new SharedState();
                Shared[key] = new WeakReference<SharedState>(state);
            }

            return state;
        }
    }

    private sealed record Stored(byte[] Id, string Name, string Root, long Created, long LastUsed,
        int? Format, int? Platform, byte[]? Identity, string? Canonical, int State)
    {
        internal RegisteredWorkspace Public() => new(Id.ToArray(), Name, Root, Created, LastUsed);
    }

    internal sealed class SharedState
    {
        internal Lock Gate { get; } = new();
        internal Dictionary<string, int> Users { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>Version-1 identity includes the native volume and object instance; transient Linux mount IDs and path strings are excluded.</summary>
    private sealed record RootIdentity(int Platform, byte[] Bytes)
    {
        internal static RootIdentity Encode(WorkspaceObjectIdentity identity, bool directory = true)
        {
            if (directory ? !identity.IsDirectory || identity.Links == 0 : !identity.IsFile || identity.Links != 1)
            {
                throw new RegisteredWorkspaceException("workspace_identity_invalid");
            }

            if (OperatingSystem.IsLinux())
            {
                if (identity.InstanceToken.Length != 32 || identity.CreatedNanoseconds >= 1_000_000_000)
                {
                    throw new RegisteredWorkspaceException("workspace_identity_invalid");
                }

                var bytes = new byte[53];
                bytes[0] = 1;
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(1, 8), identity.Volume);
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(9, 8), identity.Created);
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(17, 4), identity.CreatedNanoseconds);
                identity.InstanceToken.Span.CopyTo(bytes.AsSpan(21));
                return new RootIdentity(2, bytes);
            }

            if (OperatingSystem.IsWindows() && identity.InstanceToken.IsEmpty && identity.CreatedNanoseconds == 0)
            {
                var bytes = new byte[33];
                bytes[0] = 1;
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(1, 8), identity.Volume);
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(9, 8), identity.Low);
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(17, 8), identity.High);
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(25, 8), identity.Created);
                return new RootIdentity(1, bytes);
            }

            throw new RegisteredWorkspaceException("workspace_identity_invalid");
        }

        internal static void ValidateEncoding(int platform, byte[] bytes)
        {
            if (platform != (OperatingSystem.IsWindows() ? 1 : OperatingSystem.IsLinux() ? 2 : 0) ||
                bytes.Length != (platform == 1 ? 33 : 53) || bytes[0] != 1)
            {
                throw new RegisteredWorkspaceException("workspace_identity_invalid");
            }
        }
    }
}

/// <summary>The root handle and the node-process lease, released together without changing workspace files.</summary>
internal sealed class RegisteredWorkspaceUse : IDisposable
{
    private readonly RegisteredWorkspaces.SharedState _state;
    private readonly string _key;
    private WorkspacePath? _root;

    internal RegisteredWorkspaceUse(RegisteredWorkspaces.SharedState state, string key, WorkspacePath root)
    {
        _state = state;
        _key = key;
        _root = root;
    }

    internal WorkspacePath Root => _root ?? throw new ObjectDisposedException(nameof(RegisteredWorkspaceUse));

    public void Dispose()
    {
        lock (_state.Gate)
        {
            if (_root is null)
            {
                return;
            }

            _root.Dispose();
            _root = null;
            var remaining = _state.Users[_key] - 1;
            if (remaining == 0)
            {
                _state.Users.Remove(_key);
            }
            else
            {
                _state.Users[_key] = remaining;
            }
        }
    }
}
