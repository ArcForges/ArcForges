// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Node.Store;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Fault injection with real processes and OS mechanisms (16-testing-strategy section 1; no fault framework): IPC peers that die
/// mid-stream, permission failures on the data root and the store, and (Windows) a supervisor that is killed. Each test names the
/// contract it checks; the fixture fails a test that leaves a node, supervisor or attempt of its environment running.
/// </summary>
/// <remarks>
/// The former V1 attached-output peer and live Task checks remain at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// The installed V2 terminal and recovery fixtures exercise Run output and per-Run supervisor loss.
/// </remarks>
[Trait("loop", "local")]
public sealed class FaultInjectionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A killed event-stream client releases its subscription and local session, and the same Node still serves.</summary>
    [Fact(Timeout = 180_000)]
    public async Task AClientKilledMidEventStreamIsReleasedAndTheNodeKeepsServing()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        var pid = node.NodePid();
        var before = await HealthAsync(node);

        using var events = node.StartProduct(["events", "--topic", "node", NodeLocations.TestModeOption]);
        Assert.NotNull(await events.StandardOutput.ReadLineAsync(Ct).AsTask().WaitAsync(Bound, Ct));
        var streaming = await HealthAsync(node);
        TestContext.Current.TestOutputHelper?.WriteLine($"before {before}, while streaming {streaming}");
        Assert.True(streaming.Subscribers > before.Subscribers && streaming.Sessions >= before.Sessions + 1, $"Not streaming: {streaming}.");

        events.Kill(entireProcessTree: true);
        await events.WaitForExitAsync(Ct);

        await TestNode.WaitAsync(async () => await HealthAsync(node) == before, Bound, "the Node to release the killed event client");
        await node.WaitReadyAsync();
        Assert.Equal(pid, node.NodePid());
    }

    /// <summary>
    /// Permission failures (16 section 1; 02 section 2 step 1: the data root is created owner-only): a data root the user may not create
    /// fails the start with exit 1 and a clear message, creates nothing, and leaves no process; once access returns the node starts.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task ADataRootTheUserCannotCreateFailsTheStartCleanly()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        var run = await WithoutWriteAccessAsync(node.Root, async () =>
        {
            using var process = node.Start(TestNode.Host, ["node", "run", NodeLocations.TestModeOption]);
            return await TestNode.CompleteAsync(process, Bound);
        });

        TestContext.Current.TestOutputHelper?.WriteLine(run.ToString());
        Assert.Equal(1, run.ExitCode);
        Assert.StartsWith("arcforges: the node cannot start: ", run.Error, StringComparison.Ordinal);
        Assert.False(Directory.Exists(node.DataRoot), "A data root was created although the start failed.");
        Assert.Empty(node.LiveProcesses());

        await node.StartNodeAsync();
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
    }

    /// <summary>
    /// Permission failures and store integrity (16 section 1; 02 section 2 step 3): a store the user may no longer write fails the start
    /// with exit 1 and a clear message, and its files stay exactly as they were; once access returns the node starts on the same store.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task AStoreTheUserCannotWriteFailsTheStartAndStaysIntact()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        var id = RetainedClosedLoopTask.Seed(node, exitCode: 0);
        await node.StartNodeAsync();
        var before = await node.CliAsync("tasks", "show", id, "--json");
        Assert.Equal(0, before.ExitCode);
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
        await TestNode.WaitAsync(() => node.LiveProcesses().Count == 0, Bound, "the node to exit");

        var store = Path.GetDirectoryName(StorePaths.Database(node.DataRoot))!;
        var digest = Digest(store);
        var run = await WithoutWriteAccessAsync(store, async () =>
        {
            using var process = node.Start(TestNode.Host, ["node", "run", NodeLocations.TestModeOption]);
            return await TestNode.CompleteAsync(process, Bound);
        });

        TestContext.Current.TestOutputHelper?.WriteLine(run.ToString());
        Assert.Equal(1, run.ExitCode);
        Assert.StartsWith("arcforges: the node store cannot be opened: ", run.Error, StringComparison.Ordinal);
        Assert.Equal(digest, Digest(store));
        Assert.Empty(node.LiveProcesses());

        await node.StartNodeAsync();
        var after = await node.CliAsync("tasks", "show", id, "--json");
        Assert.Equal(0, after.ExitCode);
        using var beforeJson = JsonDocument.Parse(before.Output);
        using var afterJson = JsonDocument.Parse(after.Output);
        var restored = afterJson.RootElement.GetProperty("task");
        Assert.Equal("TASK_STATE_SUCCEEDED", restored.GetProperty("state").GetString());
        Assert.True(JsonElement.DeepEquals(beforeJson.RootElement.GetProperty("task"), restored));
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
    }

    /// <summary>Killing the Windows auto-start supervisor leaves the same Node serving and stoppable.</summary>
    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public async Task AKilledSupervisorLeavesItsNodeServing()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows supervisor.");
        await using var node = TestNode.Create();
        using var supervisor = node.Start(Path.Combine(Path.GetDirectoryName(TestNode.Host)!, "arcforges-supervisor.exe"), [NodeLocations.TestModeOption]);
        await node.WaitReadyAsync();
        var nodePid = node.NodePid();

        supervisor.Kill();
        await supervisor.WaitForExitAsync(Ct);

        await node.WaitReadyAsync();
        Assert.Equal(nodePid, node.NodePid());
        await node.StopNodeAsync();
    }

    private sealed record Health(double Subscribers, double Sessions);

    /// <summary>The node's stream subscribers and client sessions (<c>arcforges node health --json</c>; this call is one session).</summary>
    private static async Task<Health> HealthAsync(TestNode node)
    {
        var run = await node.CliAsync("node", "health", "--json");
        Assert.True(run.ExitCode == 0, run.ToString());
        var metrics = run.Json().GetProperty("metrics").EnumerateArray().ToList();
        double Value(string name) => metrics.Single(metric => metric.GetProperty("name").GetString() == name).GetProperty("value").GetDouble();
        return new Health(Value("node.stream_subscribers"), Value("node.client_sessions"));
    }

    /// <summary>Runs <paramref name="action"/> while this user may read but not create or write anything in <paramref name="directory"/>.</summary>
    private static async Task<T> WithoutWriteAccessAsync<T>(string directory, Func<Task<T>> action)
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows() && Environment.UserName == "root", "root is not bound by file modes, so a permission failure cannot be injected.");
        if (OperatingSystem.IsWindows())
        {
            var info = new DirectoryInfo(directory);
            var user = WindowsIdentity.GetCurrent().User!;
            var deny = new FileSystemAccessRule(user, FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Deny);
            var security = info.GetAccessControl();
            security.AddAccessRule(deny);
            info.SetAccessControl(security);
            try
            {
                return await action();
            }
            finally
            {
                security = info.GetAccessControl();
                security.RemoveAccessRuleSpecific(deny);
                info.SetAccessControl(security);
            }
        }

        var modes = Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.AllDirectories).Prepend(directory)
            .ToDictionary(path => path, File.GetUnixFileMode);
        foreach (var (path, mode) in modes)
        {
            File.SetUnixFileMode(path, mode & ~(UnixFileMode.UserWrite | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite));
        }

        try
        {
            return await action();
        }
        finally
        {
            foreach (var (path, mode) in modes)
            {
                File.SetUnixFileMode(path, mode);
            }
        }
    }

    /// <summary>The SHA-256 of every file under <paramref name="directory"/> by relative path.</summary>
    private static string Digest(string directory) => string.Join("\n", Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
        .Select(path => Path.GetRelativePath(directory, path) + " " + Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)))));
}
