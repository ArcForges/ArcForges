// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Node.Store;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Fault injection with real processes and OS mechanisms (16-testing-strategy section 1; no fault framework): IPC peers that die
/// mid-stream, permission failures on the data root and the store, and (Windows) a supervisor that is killed. Each test names the
/// contract it checks; the fixture fails a test that leaves a node, supervisor or attempt of its environment running.
/// </summary>
[Trait("loop", "local")]
public sealed class FaultInjectionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// IPC failures (16 section 1: a pipe or socket peer gone mid-call): clients killed while they stream events and attempt output are
    /// released by the node, which keeps serving: its stream subscriptions and client sessions return to what they were, and the task
    /// they watched keeps running (watching never binds a task to its watcher).
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task ClientsKilledMidStreamAreReleasedAndTheNodeKeepsServing()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        var before = await HealthAsync(node);
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "output", "--bytes", "1073741824", "--rate", "1000000");
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();

        using var events = node.Start(TestNode.Host, ["events", "--topic", "tasks", "--topic", "node", NodeLocations.TestModeOption]);
        using var attach = node.Start(TestNode.Host, [NodeLocations.TestModeOption, "tasks", "attach", id]);
        var buffer = new byte[4096];
        Assert.NotNull(await events.StandardOutput.ReadLineAsync(Ct).AsTask().WaitAsync(Bound, Ct));
        Assert.True(await attach.StandardOutput.BaseStream.ReadAsync(buffer, Ct).AsTask().WaitAsync(Bound, Ct) > 0, "The attach printed no output.");
        var streaming = await HealthAsync(node);
        TestContext.Current.TestOutputHelper?.WriteLine($"before {before}, while streaming {streaming}");
        Assert.True(streaming.Subscribers > before.Subscribers && streaming.Sessions >= before.Sessions + 2, $"Not streaming: {streaming}.");

        events.Kill(entireProcessTree: true);
        attach.Kill(entireProcessTree: true);
        await events.WaitForExitAsync(Ct);
        await attach.WaitForExitAsync(Ct);

        // The node notices the dead peers and drops their streams and sessions (the health call itself is one session in both counts).
        var after = before;
        await TestNode.WaitAsync(async () => (after = await HealthAsync(node)) == before, Bound, $"the node to release the killed clients' streams and sessions ({before})");
        var shown = JsonDocument.Parse((await node.CliAsync("tasks", "show", id, "--json")).Output).RootElement.GetProperty("task");
        Assert.Equal("TASK_STATE_RUNNING", shown.GetProperty("state").GetString());
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", id)).ExitCode);
        Assert.Equal("TASK_STATE_CANCELLED", JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement.GetProperty("state").GetString());
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
        await node.StartNodeAsync();
        var id = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "args", "recorded")).Stdout).Trim();
        await node.CliAsync("tasks", "wait", id);
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
        Assert.Contains("TASK_STATE_SUCCEEDED", (await node.CliAsync("tasks", "show", id, "--json")).Output, StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
    }

    /// <summary>
    /// Supervisor and node lifecycle failures (02 section 2: no in-memory state is authoritative; F-W03: executions outlive their
    /// supervisors): a supervisor that is killed leaves the node it started serving and the node's attempt running; the node still stops
    /// cleanly and cancels the attempt.
    /// </summary>
    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public async Task AKilledSupervisorLeavesItsNodeAndTheAttemptsRunning()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows supervisor.");
        await using var node = TestNode.Create();
        using var supervisor = node.Start(Path.Combine(Path.GetDirectoryName(TestNode.Host)!, "arcforges-supervisor.exe"), [NodeLocations.TestModeOption]);
        await node.WaitReadyAsync();
        var nodePid = node.NodePid();
        var marker = Path.Combine(node.Root, "m.txt");
        var id = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "signal", "--hold-ms", "120000", "--marker", marker)).Stdout).Trim();
        await TestNode.WaitAsync(() => TestNode.ReadShared(marker).Length > 0, Bound, "the attempt to run");

        supervisor.Kill();
        await supervisor.WaitForExitAsync(Ct);

        Assert.Equal(nodePid, node.NodePid());
        Assert.Equal(0, (await node.CliAsync("status")).ExitCode);
        Assert.Contains("TASK_STATE_RUNNING", (await node.CliAsync("tasks", "show", id, "--json")).Output, StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", id)).ExitCode);
        Assert.Contains("TASK_STATE_CANCELLED", (await node.CliAsync("tasks", "wait", id, "--json")).Output, StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
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
