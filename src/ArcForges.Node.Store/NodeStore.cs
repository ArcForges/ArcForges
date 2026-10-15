// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using ArcForges.Node.Store.Policy;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

/// <summary>Where and as what node a store is opened.</summary>
public sealed class NodeStoreOptions
{
    /// <summary>The absolute node data root; the store is <c>&lt;data root&gt;/store/node.db</c>.</summary>
    public required string DataRoot { get; init; }

    /// <summary>
    /// The boot identity of the running machine (AD-0006 section 3: Windows last boot time with machine identity; Linux
    /// <c>/proc/sys/kernel/random/boot_id</c>), recorded in <c>store_meta</c> at every open.
    /// </summary>
    public required string BootIdentity { get; init; }

    /// <summary>The node's role, recorded when the store is created.</summary>
    public NodeRole Role { get; init; } = NodeRole.Host;

    /// <summary>The clock (the node's IClock; tests use a controllable one).</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;
}

/// <summary>The singleton <c>store_meta</c> row as read when the store was opened.</summary>
public sealed class StoreMetadata
{
    internal StoreMetadata(ReadOnlyMemory<byte> nodeId, NodeRole role, int schemaVersion, int minReaderVersion, long createdAt,
        string bootIdentity, string previousBootIdentity, bool previousShutdownClean, long journalGeneration)
    {
        NodeId = nodeId;
        Role = role;
        SchemaVersion = schemaVersion;
        MinReaderVersion = minReaderVersion;
        CreatedAt = createdAt;
        BootIdentity = bootIdentity;
        PreviousBootIdentity = previousBootIdentity;
        PreviousShutdownClean = previousShutdownClean;
        JournalGeneration = journalGeneration;
    }

    /// <summary>The node ID (16-byte UUIDv7), created with the store.</summary>
    public ReadOnlyMemory<byte> NodeId { get; }

    /// <summary>The node role.</summary>
    public NodeRole Role { get; }

    /// <summary><c>store_meta.schema_version</c>.</summary>
    public int SchemaVersion { get; }

    /// <summary><c>store_meta.min_reader_version</c>.</summary>
    public int MinReaderVersion { get; }

    /// <summary>When the store was created (microseconds since the Unix epoch).</summary>
    public long CreatedAt { get; }

    /// <summary>The boot identity recorded by this open.</summary>
    public string BootIdentity { get; }

    /// <summary>The boot identity the previous open recorded (equal to <see cref="BootIdentity"/> for a new store).</summary>
    public string PreviousBootIdentity { get; }

    /// <summary>Whether the previous node run closed the store cleanly (always true for a new store).</summary>
    public bool PreviousShutdownClean { get; }

    /// <summary><c>store_meta.journal_generation</c>.</summary>
    public long JournalGeneration { get; }
}

/// <summary>What opening did to the store file.</summary>
public sealed class StoreOpening
{
    internal StoreOpening(bool created, int? migratedFrom, int schemaVersion, string? backupPath)
    {
        Created = created;
        MigratedFrom = migratedFrom;
        SchemaVersion = schemaVersion;
        BackupPath = backupPath;
    }

    /// <summary>How many times opening was retried after a transient I/O error (another handle on the store's files).</summary>
    public int TransientRetries { get; internal set; }

    /// <summary>The extended SQLite code of the last transient I/O error, when opening was retried.</summary>
    public int? LastTransientCode { get; internal set; }

    /// <summary>The store did not exist and was created at the latest schema.</summary>
    public bool Created { get; }

    /// <summary>The schema version before migrating, when the store was migrated.</summary>
    public int? MigratedFrom { get; }

    /// <summary>The schema version after opening.</summary>
    public int SchemaVersion { get; }

    /// <summary>The pre-migration backup, when the store was migrated.</summary>
    public string? BackupPath { get; }
}

/// <summary>
/// The node store (ArcForges-Design docs/data/node-store.md): one SQLite file in WAL mode with a single writer connection
/// (the command processor) and short-lived read-only reader connections. Opening creates schema version 1 with the default
/// policy (revision 1), or checks <c>min_reader_version</c>, backs up and migrates forward an existing store.
/// </summary>
public sealed class NodeStore : IDisposable
{
    private const int BusyTimeoutMilliseconds = 5000;
    private readonly Lock _writerGate = new();
    private readonly SqliteConnection _writer;
    private readonly TimeProvider _clock;
    private bool _writing;
    private bool _disposed;

    private NodeStore(string dataRoot, string path, SqliteConnection writer, TimeProvider clock, StoreMetadata metadata, StoreOpening opening)
    {
        DataRoot = dataRoot;
        DatabasePath = path;
        _writer = writer;
        _clock = clock;
        Metadata = metadata;
        Opening = opening;
        Commands = new CommandDeduplication(this);
        Environments = new EnvSnapshots(this);
        Policies = new PolicyDocuments(this);
    }

    /// <summary>The node data root.</summary>
    public string DataRoot { get; }

    /// <summary><c>&lt;data root&gt;/store/node.db</c>.</summary>
    public string DatabasePath { get; }

    /// <summary>The store's identity and versions.</summary>
    public StoreMetadata Metadata { get; }

    /// <summary>What opening did.</summary>
    public StoreOpening Opening { get; }

    /// <summary>The store's clock.</summary>
    public TimeProvider Clock => _clock;

    /// <summary>Idempotency records (<c>command_dedup</c>).</summary>
    public CommandDeduplication Commands { get; }

    /// <summary>Content-addressed caller environments (<c>env_snapshot</c>).</summary>
    public EnvSnapshots Environments { get; }

    /// <summary>Revisioned policy documents (<c>policy_document</c>).</summary>
    public PolicyDocuments Policies { get; }

    /// <summary>Opens or creates the store with the released migrations.</summary>
    /// <exception cref="StoreIncompatibleException">The store needs a newer binary (<c>min_reader_version</c>), or it is not a node store.</exception>
    public static NodeStore Open(NodeStoreOptions options) => Open(options, StoreMigrations.Released);

    /// <summary>Opens or creates the store with an explicit migration plan (the released one, or a test's plan).</summary>
    internal static NodeStore Open(NodeStoreOptions options, MigrationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.BootIdentity);
        if (!Path.IsPathFullyQualified(options.DataRoot))
        {
            throw new ArgumentException("The node data root must be an absolute path.", nameof(options));
        }

        if (options.Role is not (NodeRole.Host or NodeRole.Guest))
        {
            throw new ArgumentException("The node role is HOST or GUEST.", nameof(options));
        }

        SQLitePCL.Batteries_V2.Init();
        var dataRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(options.DataRoot));
        var path = StorePaths.Database(dataRoot);
        StorePaths.CreatePrivateDirectory(dataRoot);
        StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(path)!);

        var (existing, writer, retries, lastCode) = OpenWriter(path, plan);
        try
        {
            Pragma(writer, "PRAGMA foreign_keys=ON;");
            Pragma(writer, "PRAGMA synchronous=NORMAL;");

            // Deleted and overwritten content (purged task secrets) is zeroed in the database pages.
            Pragma(writer, "PRAGMA secure_delete=ON;");

            StoreOpening opening;
            if (existing is null)
            {
                Create(writer, plan, options);
                opening = new StoreOpening(created: true, migratedFrom: null, plan.LatestVersion, backupPath: null);
            }
            else if (existing.SchemaVersion < plan.LatestVersion)
            {
                var backup = StoreBackups.Create(writer, dataRoot, existing.SchemaVersion, plan.LatestVersion, options.Clock);
                foreach (var step in plan.Steps.Where(step => step.Version > existing.SchemaVersion))
                {
                    InTransaction(writer, CommitDurability.Full, transaction =>
                    {
                        using (var command = writer.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = step.Sql;
                            command.ExecuteNonQuery();
                        }

                        using var meta = writer.CreateCommand();
                        meta.Transaction = transaction;
                        meta.CommandText = "UPDATE store_meta SET schema_version = $version, min_reader_version = max(min_reader_version, $minReader) WHERE singleton = 1;";
                        meta.Parameters.AddWithValue("$version", step.Version);
                        meta.Parameters.AddWithValue("$minReader", step.MinReaderVersion);
                        meta.ExecuteNonQuery();
                    });
                }

                opening = new StoreOpening(created: false, existing.SchemaVersion, plan.LatestVersion, backup);
            }
            else
            {
                // Same schema, or a newer schema that still admits this reader (expand-only): opened as it is.
                opening = new StoreOpening(created: false, migratedFrom: null, existing.SchemaVersion, backupPath: null);
            }

            opening.TransientRetries = retries;
            opening.LastTransientCode = lastCode;
            var metadata = Start(writer, options);
            return new NodeStore(dataRoot, path, writer, options.Clock, metadata, opening);
        }
        catch
        {
            writer.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Runs <paramref name="action"/> in one write transaction of the single writer and commits it. An exception rolls the
    /// transaction back. <see cref="CommitDurability.Full"/> commits with <c>synchronous=FULL</c>.
    /// </summary>
    public T Write<T>(Func<StoreTransaction, T> action, CommitDurability durability = CommitDurability.Normal)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (_writerGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_writing)
            {
                throw new InvalidOperationException("Store writes do not nest; use the transaction already open.");
            }

            _writing = true;
            try
            {
                T result = default!;
                InTransaction(_writer, durability, transaction => result = action(new StoreTransaction(_writer, transaction, _clock, durability)));
                return result;
            }
            finally
            {
                _writing = false;
            }
        }
    }

    /// <summary>Runs <paramref name="action"/> in one write transaction.</summary>
    public void Write(Action<StoreTransaction> action, CommitDurability durability = CommitDurability.Normal)
    {
        ArgumentNullException.ThrowIfNull(action);
        Write<int>(transaction =>
        {
            action(transaction);
            return 0;
        }, durability);
    }

    /// <summary>Runs <paramref name="action"/> on a separate read-only connection, in one snapshot transaction.</summary>
    public T Read<T>(Func<StoreReader, T> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var connection = new SqliteConnection(StorePaths.ConnectionString(DatabasePath, SqliteOpenMode.ReadOnly));
        connection.Open();
        Pragma(connection, string.Create(CultureInfo.InvariantCulture, $"PRAGMA busy_timeout={BusyTimeoutMilliseconds};"));
        Pragma(connection, "PRAGMA query_only=ON;");
        using var transaction = connection.BeginTransaction(deferred: true);
        var result = action(new StoreReader(connection, transaction, _clock));
        transaction.Commit();
        return result;
    }

    /// <summary>Copies the WAL into the database and truncates it (<c>wal_checkpoint(TRUNCATE)</c>); returns whether it completed.</summary>
    public bool Checkpoint()
    {
        lock (_writerGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var command = _writer.CreateCommand();
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            using var reader = command.ExecuteReader();
            return reader.Read() && reader.GetInt64(0) == 0;
        }
    }

    /// <summary>Records a clean shutdown in <c>store_meta</c> and closes the writer.</summary>
    public void Dispose()
    {
        lock (_writerGate)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                InTransaction(_writer, CommitDurability.Full, transaction =>
                {
                    using var command = _writer.CreateCommand();
                    command.Transaction = transaction;
                    command.CommandText = "UPDATE store_meta SET clean_shutdown_at = $now WHERE singleton = 1;";
                    command.Parameters.AddWithValue("$now", StoreTime.NowMicroseconds(_clock));
                    command.ExecuteNonQuery();
                });
            }
            finally
            {
                _disposed = true;
                _writer.Dispose();
            }
        }
    }

    internal void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private static void InTransaction(SqliteConnection connection, CommitDurability durability, Action<SqliteTransaction> action)
    {
        if (durability == CommitDurability.Full)
        {
            Pragma(connection, "PRAGMA synchronous=FULL;");
        }

        try
        {
            using var transaction = connection.BeginTransaction(deferred: false);
            action(transaction);
            transaction.Commit();
        }
        finally
        {
            if (durability == CommitDurability.Full)
            {
                Pragma(connection, "PRAGMA synchronous=NORMAL;");
            }
        }
    }

    /// <summary>
    /// Extended SQLite I/O codes that mean another handle holds the store's files, not a damaged store (sqlite3.h): on Windows a file
    /// cannot be truncated while any process has a mapped view of it, and the first connection after an unclean shutdown truncates the
    /// <c>-shm</c> file (SQLITE_IOERR_TRUNCATE 1546), so a predecessor still being torn down after its kill, or a scanner or indexer
    /// mapping the files it just released, fails the open briefly. Lock and shared-memory codes have the same cause.
    /// </summary>
    internal static readonly IReadOnlySet<int> TransientOpenErrors = new HashSet<int>
    {
        1546, // SQLITE_IOERR_TRUNCATE
        2058, // SQLITE_IOERR_UNLOCK
        2314, // SQLITE_IOERR_RDLOCK
        2570, // SQLITE_IOERR_DELETE
        3338, // SQLITE_IOERR_ACCESS
        3594, // SQLITE_IOERR_CHECKRESERVEDLOCK
        3850, // SQLITE_IOERR_LOCK
        4618, // SQLITE_IOERR_SHMOPEN
        4874, // SQLITE_IOERR_SHMSIZE
        5130, // SQLITE_IOERR_SHMLOCK
        5386, // SQLITE_IOERR_SHMMAP
    };

    /// <summary>How long opening retries a transient I/O error: the store's busy timeout (node-store.md: <c>busy_timeout=5000</c>).</summary>
    internal static readonly TimeSpan TransientOpenBound = TimeSpan.FromMilliseconds(BusyTimeoutMilliseconds);

    /// <summary>
    /// Inspects an existing store read-only (so a store this binary must not open is left untouched), then opens the writer in WAL mode.
    /// A transient I/O error (<see cref="TransientOpenErrors"/>) is retried with backoff for up to <see cref="TransientOpenBound"/>; the
    /// retries and the last code are reported in <see cref="StoreOpening"/>. Every other error, corruption included, fails at once.
    /// </summary>
    private static (ExistingStore? Existing, SqliteConnection Writer, int Retries, int? LastCode) OpenWriter(string path, MigrationPlan plan)
    {
        var started = TimeProvider.System.GetTimestamp();
        int? lastCode = null;
        for (var retries = 0; ; retries++)
        {
            SqliteConnection? writer = null;
            try
            {
                var existing = File.Exists(path) ? Inspect(path) : null;
                if (existing is { MinReaderVersion: var minReader } && minReader > plan.LatestVersion)
                {
                    throw new StoreIncompatibleException(string.Create(CultureInfo.InvariantCulture,
                        $"The node store needs a reader of schema version {minReader} or later; this binary reads up to version {plan.LatestVersion}. Install a newer ArcForges version (13-distribution-updates section 6)."));
                }

                writer = new SqliteConnection(StorePaths.ConnectionString(path, SqliteOpenMode.ReadWriteCreate));
                writer.Open();
                Pragma(writer, string.Create(CultureInfo.InvariantCulture, $"PRAGMA busy_timeout={BusyTimeoutMilliseconds};"));
                var journal = Convert.ToString(Scalar(writer, "PRAGMA journal_mode=WAL;"), CultureInfo.InvariantCulture);
                if (!string.Equals(journal, "wal", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"The node store could not enter WAL mode (journal_mode={journal}).");
                }

                return (existing, writer, retries, lastCode);
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 10 && TransientOpenErrors.Contains(exception.SqliteExtendedErrorCode)
                && TimeProvider.System.GetElapsedTime(started) < TransientOpenBound)
            {
                writer?.Dispose();
                lastCode = exception.SqliteExtendedErrorCode;
                Thread.Sleep(TimeSpan.FromMilliseconds(Math.Min(25 << Math.Min(retries, 4), 250)));
            }
            catch
            {
                writer?.Dispose();
                throw;
            }
        }
    }

    private static ExistingStore? Inspect(string path)
    {
        using var connection = new SqliteConnection(StorePaths.ConnectionString(path, SqliteOpenMode.ReadOnly));
        connection.Open();
        Pragma(connection, string.Create(CultureInfo.InvariantCulture, $"PRAGMA busy_timeout={BusyTimeoutMilliseconds};"));
        var objects = Convert.ToInt64(Scalar(connection, "SELECT count(*) FROM sqlite_schema;"), CultureInfo.InvariantCulture);
        if (objects == 0)
        {
            // An empty file: a creation that never committed. It is created again.
            return null;
        }

        if (Convert.ToInt64(Scalar(connection, "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'store_meta';"), CultureInfo.InvariantCulture) == 0)
        {
            throw new StoreIncompatibleException($"{path} is a SQLite database but not an ArcForges node store (no store_meta table); it was not changed.");
        }

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT schema_version, min_reader_version FROM store_meta WHERE singleton = 1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            throw new StoreIncompatibleException($"{path} has no store_meta row; it was not changed.");
        }

        return new ExistingStore(checked((int)reader.GetInt64(0)), checked((int)reader.GetInt64(1)));
    }

    private static void Create(SqliteConnection writer, MigrationPlan plan, NodeStoreOptions options)
    {
        InTransaction(writer, CommitDurability.Full, transaction =>
        {
            foreach (var step in plan.Steps)
            {
                using var command = writer.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = step.Sql;
                command.ExecuteNonQuery();
            }

            var now = StoreTime.NowMicroseconds(options.Clock);
            using (var meta = writer.CreateCommand())
            {
                meta.Transaction = transaction;
                meta.CommandText = """
                    INSERT INTO store_meta (singleton, schema_version, min_reader_version, node_id, node_role, created_at, boot_identity,
                                            clean_shutdown_at, journal_generation)
                    VALUES (1, $schema, $minReader, $nodeId, $role, $now, $boot, $now, 1);
                    """;
                meta.Parameters.AddWithValue("$schema", plan.LatestVersion);
                meta.Parameters.AddWithValue("$minReader", plan.Steps[^1].MinReaderVersion);
                meta.Parameters.AddWithValue("$nodeId", StoreIds.NewUuid7(options.Clock));
                meta.Parameters.AddWithValue("$role", (int)options.Role);
                meta.Parameters.AddWithValue("$now", now);
                meta.Parameters.AddWithValue("$boot", options.BootIdentity);
                meta.ExecuteNonQuery();
            }

            PolicyDocuments.InsertDefault(new StoreTransaction(writer, transaction, options.Clock, CommitDurability.Full));
        });
    }

    private static StoreMetadata Start(SqliteConnection writer, NodeStoreOptions options)
    {
        StoreMetadata? metadata = null;
        InTransaction(writer, CommitDurability.Normal, transaction =>
        {
            using (var read = writer.CreateCommand())
            {
                read.Transaction = transaction;
                read.CommandText = """
                    SELECT node_id, node_role, schema_version, min_reader_version, created_at, boot_identity, clean_shutdown_at, journal_generation
                    FROM store_meta WHERE singleton = 1;
                    """;
                using var reader = read.ExecuteReader();
                if (!reader.Read())
                {
                    throw new StoreIncompatibleException("The node store has no store_meta row.");
                }

                metadata = new StoreMetadata(
                    (byte[])reader.GetValue(0),
                    (NodeRole)reader.GetInt64(1),
                    checked((int)reader.GetInt64(2)),
                    checked((int)reader.GetInt64(3)),
                    reader.GetInt64(4),
                    options.BootIdentity,
                    reader.GetString(5),
                    !reader.IsDBNull(6),
                    reader.GetInt64(7));
            }

            using var update = writer.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = "UPDATE store_meta SET boot_identity = $boot, clean_shutdown_at = NULL WHERE singleton = 1;";
            update.Parameters.AddWithValue("$boot", options.BootIdentity);
            update.ExecuteNonQuery();
        });
        return metadata!;
    }

    private static void Pragma(SqliteConnection connection, string pragma)
    {
        using var command = connection.CreateCommand();
        command.CommandText = pragma;
        command.ExecuteNonQuery();
    }

    private static object? Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private sealed record ExistingStore(int SchemaVersion, int MinReaderVersion);
}

/// <summary>
/// The store cannot be opened by this binary: its <c>min_reader_version</c> is above the supported schema (a newer node
/// contracted it), or the file is not a node store. The file is left unchanged (13-distribution-updates section 6).
/// </summary>
public sealed class StoreIncompatibleException : InvalidOperationException
{
    /// <summary>Creates the exception.</summary>
    public StoreIncompatibleException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public StoreIncompatibleException()
    {
    }

    /// <summary>Creates the exception.</summary>
    public StoreIncompatibleException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
