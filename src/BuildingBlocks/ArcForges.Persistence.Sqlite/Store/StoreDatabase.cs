// SPDX-License-Identifier: AGPL-3.0-only
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace ArcForges.Persistence.Sqlite;

internal class SqliteReadContext(Guid storeId, SqliteConnection connection, SqliteTransaction transaction)
{
    public Guid StoreId { get; } = storeId;
    public SqliteConnection Connection { get; } = connection;
    public SqliteTransaction Transaction { get; } = transaction;
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Internal controlled SQL sink: mechanism callers use literal SQL with parameter-bound data; explicit owner-authored migration SQL executes only under the SQLite authorizer. No request or content values form SQL. Reviewed source scope: Design PR91 / Plan PR62.")]
    public SqliteCommand CreateCommand(string sql)
    {
        var command = Connection.CreateCommand();
        command.Transaction = Transaction;
        command.CommandText = sql;
        return command;
    }
}

internal sealed class SqliteCommitContext(Guid storeId, SqliteConnection connection, SqliteTransaction transaction)
    : SqliteReadContext(storeId, connection, transaction)
{
    private static readonly strdelegate_authorizer Authorizer = Authorize;
    private static int Authorize(object state, int action, string first, string second, string database, string source)
    {
        if (action is raw.SQLITE_TRANSACTION or raw.SQLITE_SAVEPOINT or raw.SQLITE_ATTACH or raw.SQLITE_DETACH or raw.SQLITE_PRAGMA)
            return raw.SQLITE_DENY;
        if (action is raw.SQLITE_CREATE_TEMP_TRIGGER or raw.SQLITE_DROP_TEMP_TRIGGER or raw.SQLITE_CREATE_TEMP_INDEX or raw.SQLITE_DROP_TEMP_INDEX)
            return raw.SQLITE_DENY;
        if (action is raw.SQLITE_INSERT or raw.SQLITE_UPDATE or raw.SQLITE_DELETE or raw.SQLITE_DROP_TABLE or raw.SQLITE_ALTER_TABLE or raw.SQLITE_CREATE_TRIGGER or raw.SQLITE_DROP_TRIGGER or raw.SQLITE_CREATE_INDEX or raw.SQLITE_DROP_INDEX)
        {
            var table = action is raw.SQLITE_ALTER_TABLE or raw.SQLITE_CREATE_TRIGGER or raw.SQLITE_DROP_TRIGGER or raw.SQLITE_CREATE_INDEX or raw.SQLITE_DROP_INDEX ? second : first;
            if (Protected(table)) return raw.SQLITE_DENY;
        }
        return raw.SQLITE_OK;
    }
    private static bool Protected(string table) => table.Equals("sys_meta", StringComparison.OrdinalIgnoreCase)
        || table.StartsWith("__arcforges_", StringComparison.OrdinalIgnoreCase)
        || table.StartsWith("store_", StringComparison.OrdinalIgnoreCase)
        || table.Equals("command_log", StringComparison.OrdinalIgnoreCase)
        || table.Equals("sync_outbox", StringComparison.OrdinalIgnoreCase)
        || table.Equals("journal", StringComparison.OrdinalIgnoreCase)
        || table.Equals("journal_state", StringComparison.OrdinalIgnoreCase);
    public void ExecuteSchemaStatement(string sql)
    {
        var handle = Connection.Handle!;
        raw.sqlite3_set_authorizer(handle, Authorizer, this);
        try { using var command = CreateCommand(sql); command.ExecuteNonQuery(); }
        finally { raw.sqlite3_set_authorizer(handle, (strdelegate_authorizer)null!, null!); }
    }
}

internal sealed class SqliteSchemaSession(Guid storeId, SqliteConnection connection)
{
    public T WithTransaction<T>(Func<SqliteCommitContext, T> action)
    {
        using var transaction = connection.BeginTransaction();
        var result = action(new(storeId, connection, transaction));
        transaction.Commit();
        return result;
    }
}

internal sealed class StoreDatabase : IDisposable
{
    private readonly string connectionString;
    private readonly SemaphoreSlim writer = new(1, 1);
    private readonly Guid storeId;
    public StoreDatabase(string databasePath, Guid storeId)
    {
        if (storeId == Guid.Empty) throw new ArgumentException("A store identity is required.", nameof(storeId));
        this.storeId = storeId;
        connectionString = new SqliteConnectionStringBuilder { DataSource = Path.GetFullPath(databasePath), Pooling = false, DefaultTimeout = 30 }.ToString();
        WithTransaction(context =>
        {
            using var command = context.CreateCommand("CREATE TABLE IF NOT EXISTS sys_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT OR IGNORE INTO sys_meta(key,value) VALUES ('storageSchemaVersion','0');");
            command.ExecuteNonQuery();
            return 0;
        });
    }
    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;";
        command.ExecuteNonQuery();
        return connection;
    }
    public T Read<T>(Func<SqliteReadContext, T> action)
    {
        using var connection = Open();
        using (var command = connection.CreateCommand()) { command.CommandText = "PRAGMA query_only=ON;"; command.ExecuteNonQuery(); }
        using var transaction = connection.BeginTransaction(deferred: true);
        return action(new(storeId, connection, transaction));
    }
    public T WithTransaction<T>(Func<SqliteCommitContext, T> action)
    {
        writer.Wait();
        try
        {
            using var connection = Open();
            return new SqliteSchemaSession(storeId, connection).WithTransaction(action);
        }
        finally { writer.Release(); }
    }
    public T RunSchemaExclusive<T>(Func<SqliteSchemaSession, T> action)
    {
        writer.Wait();
        try
        {
            using var connection = Open();
            using (var command = connection.CreateCommand()) { command.CommandText = "PRAGMA locking_mode=EXCLUSIVE;"; command.ExecuteNonQuery(); }
            // Obtain and retain the physical exclusive lock across individually committed migration steps.
            using (var transaction = connection.BeginTransaction()) { using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = "UPDATE sys_meta SET value=value WHERE key='storageSchemaVersion';"; command.ExecuteNonQuery(); transaction.Commit(); }
            return action(new(storeId, connection));
        }
        finally { writer.Release(); }
    }
    public void Dispose() => writer.Dispose();
}

