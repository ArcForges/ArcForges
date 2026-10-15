// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Node.V1;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// Crash consistency (16-testing-strategy section 1, store layer; fault injection): a real process writing the store through
/// its submit path (arcforges-bench store-growth, JIT or the Native AOT binary of ARCFORGES_BENCH_PATH) is killed during
/// writes; the store then passes <c>PRAGMA integrity_check</c> and <c>foreign_key_check</c>, every acknowledged command is
/// present with its stored response, and the cross-table invariants hold.
/// </summary>
[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
public sealed class CrashConsistencyTests
{
    [Theory]
    [InlineData(25)]
    [InlineData(160)]
    [InlineData(420)]
    public async Task AStoreKilledDuringWritesReopensConsistent(int acknowledgedBeforeKill)
    {
        TestSecretStores.RequireRealSecretStore();
        using var root = new TemporaryDataRoot();
        var acknowledged = await RunAndKillAsync(root.Path, acknowledgedBeforeKill, TestContext.Current.CancellationToken);
        Assert.True(acknowledged.Count >= acknowledgedBeforeKill);

        // 1. SQLite's own checks on the file as the killed process left it (WAL included).
        var (integrity, foreignKeys) = await CheckAfterKillAsync(root.Database, TestContext.Current.CancellationToken);
        Assert.Equal(["ok"], integrity);
        Assert.Empty(foreignKeys);

        // 2. The store reopens (its previous run did not shut down cleanly) and the invariants hold.
        using var store = root.Open(new ManualClock(), boot: "after-kill");
        Assert.False(store.Metadata.PreviousShutdownClean);
        using var keys = new NodeDataKeyRing(store, TestSecretStores.Select(root.Path));
        try
        {
            store.Read(reader =>
            {
                // Every acknowledged submission is durable, with its response; no record lacks an outcome.
                foreach (var commandId in acknowledged)
                {
                    var outcome = reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", Convert.FromHexString(commandId)));
                    var response = TaskServiceSubmitTaskResponse.Parser.ParseFrom(Assert.IsType<byte[]>(outcome));
                    Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM task WHERE task_id = $id;", ("$id", response.Value.TaskId.Value.ToByteArray())));
                }

                Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE outcome IS NULL;"));

                // Each task's attempt count matches its attempts; snapshot references match the referencing tasks.
                Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM task t WHERE t.attempt_count <> (SELECT count(*) FROM attempt a WHERE a.task_id = t.task_id);"));
                Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM env_snapshot s WHERE s.ref_count <> (SELECT count(*) FROM task t WHERE t.env_digest = s.env_digest);"));
                Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM attempt WHERE state = 9 AND finished_at IS NULL;"));
                Assert.True((long)reader.Scalar("SELECT count(*) FROM task;")! >= acknowledged.Count);
                return 0;
            });

            // Sealed values written before the kill still open with the node data key.
            var sealedTasks = store.Read(reader =>
            {
                using var command = reader.CreateCommand("SELECT task_id FROM task_secret WHERE key_id <> 'purged' LIMIT 20;");
                using var row = command.ExecuteReader();
                var ids = new List<byte[]>();
                while (row.Read())
                {
                    ids.Add((byte[])row.GetValue(0));
                }

                return ids;
            });
            Assert.NotEmpty(sealedTasks);
            var sealer = new TaskSecrets(store, keys);
            Assert.All(sealedTasks, taskId => Assert.Equal(UnsealStatus.Available, sealer.Unseal(taskId).Status));

            // The store accepts writes again.
            store.Write(transaction => Rows.InsertTask(transaction));
        }
        finally
        {
            keys.DeleteKeys();
        }
    }

    /// <summary>
    /// The extended SQLite I/O codes that mean another handle holds the killed store's files (sqlite3.h), the same set the store's own
    /// open retries (<c>NodeStore.TransientOpenErrors</c>). SQLITE_IOERR_TRUNCATE (1546) is the first connection's truncation of the
    /// <c>-shm</c> file failing while another handle still has a mapped view of it (Windows refuses to truncate a mapped file;
    /// <c>StoreOpenTests.AnOpenWaitsOutAMappedSharedMemoryFile</c> reproduces it). A read, short-read, write or fsync error, and any
    /// other code, is never retried.
    /// </summary>
    private static readonly HashSet<int> LockClassIoErrors =
    [
        1546, // SQLITE_IOERR_TRUNCATE
        2058, // SQLITE_IOERR_UNLOCK
        2314, // SQLITE_IOERR_RDLOCK
        2570, // SQLITE_IOERR_DELETE (the WAL or journal still open elsewhere)
        3338, // SQLITE_IOERR_ACCESS
        3594, // SQLITE_IOERR_CHECKRESERVEDLOCK
        3850, // SQLITE_IOERR_LOCK
        4618, // SQLITE_IOERR_SHMOPEN
        4874, // SQLITE_IOERR_SHMSIZE
        5130, // SQLITE_IOERR_SHMLOCK
        5386, // SQLITE_IOERR_SHMMAP
    ];

    /// <summary>
    /// Opens the killed store and runs <c>integrity_check</c> and <c>foreign_key_check</c>. A lock-class I/O error (another handle on the
    /// files, for example a scanner reading the files the killed process just released) is retried for up to 10 s and each one is
    /// written to the test output with its extended code; the hosted Windows run that saw "SQLite Error 10: disk I/O error" once did
    /// not report which call failed, and 285 local runs (JIT and Native AOT writers, idle and under CPU load) did not reproduce it.
    /// Every other error fails at once with its extended code.
    /// </summary>
    private static async Task<(List<string> Integrity, List<string> ForeignKeys)> CheckAfterKillAsync(string database, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, Pooling = false }.ToString());
                connection.Open();
                return (StoreCreationTests.Query(connection, "PRAGMA integrity_check;"), StoreCreationTests.Query(connection, "PRAGMA foreign_key_check;"));
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 10)
            {
                var code = exception.SqliteExtendedErrorCode;
                TestContext.Current.TestOutputHelper?.WriteLine($"attempt {attempt} after {watch.ElapsedMilliseconds} ms: SQLITE_IOERR extended code {code} ({exception.Message})");
                Assert.True(LockClassIoErrors.Contains(code), $"SQLite I/O error with extended code {code} on the killed store: {exception.Message}");
                Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"The lock-class I/O error {code} persisted for 10 s: another handle keeps the store's files.");
                await Task.Delay(250, cancellationToken);
            }
        }
    }

    private static async Task<List<string>> RunAndKillAsync(string dataRoot, int killAfter, CancellationToken cancellationToken)
    {
        using var process = Process.Start(BenchExecutable.StartInfo(
            "store-growth", "--attempts", "1000000", "--acks", "true", "--data-root", dataRoot, "--seed", killAfter.ToString(System.Globalization.CultureInfo.InvariantCulture)))!;
        var acknowledged = new List<string>();
        var errors = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(3));
        try
        {
            while (acknowledged.Count < killAfter)
            {
                var line = await process.StandardOutput.ReadLineAsync(timeout.Token)
                    ?? throw new InvalidOperationException($"arcforges-bench ended before {killAfter} acknowledgements: {await errors}");
                if (line.StartsWith("ack ", StringComparison.Ordinal))
                {
                    acknowledged.Add(line[4..]);
                }
            }
        }
        finally
        {
            // Kill during writes: the process is mid-way through its next submissions and attempt records.
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None);
        }

        return acknowledged;
    }
}
