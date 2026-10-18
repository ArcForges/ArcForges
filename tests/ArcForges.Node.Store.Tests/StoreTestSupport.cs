// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>A controllable clock (16-testing-strategy section 4: deterministic time).</summary>
internal sealed class ManualClock(DateTimeOffset start) : TimeProvider
{
    public ManualClock()
        : this(new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero))
    {
    }

    public DateTimeOffset Now { get; private set; } = start;

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>A temporary node data root, deleted with everything in it.</summary>
internal sealed class TemporaryDataRoot : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcforges-store-tests-" + Guid.NewGuid().ToString("N"));

    public string Database => StorePaths.Database(Path);

    public NodeStore Open(TimeProvider clock, MigrationPlan? plan = null, string boot = "boot-1") =>
        NodeStore.Open(new NodeStoreOptions { DataRoot = Path, BootIdentity = boot, Clock = clock }, plan ?? StoreMigrations.Released);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}

/// <summary>
/// The secret stores of the store tests: always isolated backends (16-testing-strategy section 2), never a real OS secret store (the
/// user's decisions of 2026-10-17; the OS secret-store tier alone reaches one).
/// </summary>
internal static class TestSecretStores
{
    /// <summary>
    /// After a test deleted its keys: every key the store recorded must read back absent from <paramref name="secrets"/>, and nothing
    /// else may be left in it. Fails with the names (test verification; never a production read-back).
    /// </summary>
    public static void AssertNoLeaks(NodeStore store, ArcForges.Tests.IsolatedSecretStore secrets)
    {
        var recorded = KeyNames(store);
        var remaining = secrets.Remaining(recorded);
        var leaks = secrets.TakeLeaks(remaining);
        Assert.True(remaining.Count == 0 && leaks.Count == 0,
            "The isolated secret store still holds entries after the test's deletes: " + string.Join(", ", remaining.Concat(leaks)));
    }

    /// <summary>As <see cref="AssertNoLeaks(NodeStore, ArcForges.Tests.IsolatedSecretStore)"/> for the file-backed store of a data root.</summary>
    public static void AssertNoLeaks(NodeStore store, string dataRoot)
    {
        var files = new TestDataRootSecretStore(dataRoot);
        var remaining = KeyNames(store).Where(name => files.Read(name) is not null).ToList();
        var left = files.Names().Except(remaining, StringComparer.Ordinal).ToList();
        Assert.True(remaining.Count == 0 && left.Count == 0,
            "The data root's isolated secret store still holds entries after the test's deletes: " + string.Join(", ", remaining.Concat(left)));
    }

    /// <summary>The target names of every key version <paramref name="store"/> records.</summary>
    public static List<string> KeyNames(NodeStore store)
    {
        using var keys = new NodeDataKeyRing(store, new ArcForges.Tests.IsolatedSecretStore().Selection);
        return [.. keys.Keys().Select(key => NodeDataKeyRing.TargetName(store.Metadata.NodeId.Span, key.KeyId))];
    }
}

/// <summary>Minimal rows of later subsystems that the store's foreign keys need.</summary>
internal static class Rows
{
    public static byte[] InsertTask(StoreTransaction transaction, byte[]? envDigest = null, TaskSpec? spec = null)
    {
        var taskId = StoreIds.NewUuid7(transaction.Clock);
        var bytes = (spec ?? new TaskSpec { Title = "test" }).ToByteArray();
        transaction.Execute(
            """
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, env_digest, spec_digest, owner, owner_origin, pool,
                              priority, effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at, rev)
            VALUES ($id, 1, 1, 'test', 'test', $spec, $env, zeroblob(32), $owner, 1, 'default', 3, 3, 4, 1, 'test', zeroblob(32), $now, 0);
            """,
            ("$id", taskId),
            ("$spec", bytes),
            ("$env", envDigest),
            ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()),
            ("$now", transaction.NowMicroseconds));
        return taskId;
    }
}

/// <summary>The repository checkout above the test output (for checked-in files such as schema-history.json).</summary>
internal static class Repository
{
    public static string Root { get; } = Find();

    public static string PathOf(string relative) => Path.Combine(Root, relative);

    private static string Find()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ArcForges.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException("The repository root (ArcForges.slnx) was not found above the test output.");
    }
}

/// <summary>The real arcforges-bench executable: the JIT build next to the tests, or ARCFORGES_BENCH_PATH (a Native AOT publish).</summary>
internal static class BenchExecutable
{
    public static string Path
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("ARCFORGES_BENCH_PATH");
            if (!string.IsNullOrEmpty(configured))
            {
                return System.IO.Path.IsPathFullyQualified(configured) && File.Exists(configured)
                    ? configured
                    : throw new FileNotFoundException("ARCFORGES_BENCH_PATH must be the absolute path of an existing arcforges-bench executable.", configured);
            }

            var local = System.IO.Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "arcforges-bench.exe" : "arcforges-bench");
            return File.Exists(local) ? local : throw new FileNotFoundException("arcforges-bench is missing next to the tests.", local);
        }
    }

    public static IReadOnlyList<string> Environments { get; } =
    [
        .. Directory.EnumerateFiles(System.IO.Path.Combine(AppContext.BaseDirectory, "Fixtures", "environments"), "*.json").Order(StringComparer.Ordinal),
    ];

    public static ProcessStartInfo StartInfo(params IEnumerable<string> arguments)
    {
        var start = new ProcessStartInfo(Path)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        foreach (var environment in Environments)
        {
            start.ArgumentList.Add("--environment");
            start.ArgumentList.Add(environment);
        }

        return start;
    }
}
