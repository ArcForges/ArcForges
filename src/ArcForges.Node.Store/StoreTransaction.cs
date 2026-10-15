// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

/// <summary>How a write transaction is committed (node-store.md section 1).</summary>
public enum CommitDurability
{
    /// <summary><c>synchronous=NORMAL</c> in WAL mode: durable across process crashes; the last commits may be lost on power loss.</summary>
    Normal = 0,

    /// <summary><c>synchronous=FULL</c>: the WAL is synced at commit, so the commit survives power loss (command_dedup commits).</summary>
    Full = 1,
}

/// <summary>
/// Read access to the store inside one SQLite transaction. Subsystems issue their own SQL through
/// <see cref="CreateCommand"/>; SQL text is trusted node code and every value is a bound parameter.
/// </summary>
public class StoreReader
{
    internal StoreReader(SqliteConnection connection, SqliteTransaction? transaction, TimeProvider clock)
    {
        Connection = connection;
        Transaction = transaction;
        Clock = clock;
    }

    /// <summary>The store's clock.</summary>
    public TimeProvider Clock { get; }

    /// <summary>The current instant in microseconds since the Unix epoch.</summary>
    public long NowMicroseconds => StoreTime.NowMicroseconds(Clock);

    internal SqliteConnection Connection { get; }

    internal SqliteTransaction? Transaction { get; }

    /// <summary>A command bound to this transaction. Values must be bound as parameters, never formatted into <paramref name="sql"/>.</summary>
    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Store SQL is literal node code; every value is a bound parameter (no request or user text forms SQL).")]
    public SqliteCommand CreateCommand(string sql)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sql);
        var command = Connection.CreateCommand();
        command.Transaction = Transaction;
        command.CommandText = sql;
        return command;
    }

    /// <summary>Runs <paramref name="sql"/> and returns the first column of the first row, or <see langword="null"/>.</summary>
    public object? Scalar(string sql, params ReadOnlySpan<(string Name, object? Value)> parameters)
    {
        using var command = CreateCommand(sql);
        Bind(command, parameters);
        var value = command.ExecuteScalar();
        return value is DBNull ? null : value;
    }

    /// <summary>Runs a statement and returns the number of changed rows.</summary>
    public int Execute(string sql, params ReadOnlySpan<(string Name, object? Value)> parameters)
    {
        using var command = CreateCommand(sql);
        Bind(command, parameters);
        return command.ExecuteNonQuery();
    }

    internal static void Bind(SqliteCommand command, ReadOnlySpan<(string Name, object? Value)> parameters)
    {
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
    }
}

/// <summary>One write transaction of the single writer (node-store.md section 1).</summary>
public sealed class StoreTransaction : StoreReader
{
    internal StoreTransaction(SqliteConnection connection, SqliteTransaction transaction, TimeProvider clock, CommitDurability durability)
        : base(connection, transaction, clock) => Durability = durability;

    /// <summary>How this transaction commits.</summary>
    public CommitDurability Durability { get; }
}
