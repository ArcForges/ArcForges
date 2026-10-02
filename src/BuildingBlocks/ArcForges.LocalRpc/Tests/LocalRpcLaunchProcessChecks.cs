// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Explicit local opt-in checks with real operating-system processes (set ARCFORGES_LOCALRPC_OS_STREAMS=1; skipped by default and
/// never run in hosted CI): concurrent launches from several processes, a parent killed without cleanup, a bound child that exits,
/// and a launch-authorized server over a real Named Pipe or Unix socket. A pass names only the operating system it ran on.
/// </summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcLaunchProcessChecks
{
    private const string OptIn = "Explicit local process checks only (ARCFORGES_LOCALRPC_OS_STREAMS=1).";
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(60);

    public static bool Enabled => LocalRpcOsStreamChecks.Enabled;

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task ConcurrentLaunchesFromSeveralRealProcessesNeverCollideOrRemoveEachOther()
    {
        var ct = TestContext.Current.CancellationToken;
        using var world = new LaunchWorld();
        const int processes = 4;
        const int perProcess = 24;

        var runs = await Task.WhenAll(Enumerable.Range(0, processes).Select(_ => RunToExitAsync("burst|" + world.Root + "|" + perProcess, ct)));

        Assert.All(runs, run => Assert.Equal(0, run.ExitCode));
        var launches = runs.SelectMany(run => run.Lines.Where(line => line.StartsWith("L ", StringComparison.Ordinal)))
            .Select(line => line.Split(' ', 3)).ToArray();
        Assert.Equal(processes * perProcess, launches.Length);
        Assert.Equal(processes * perProcess, launches.Select(parts => parts[1]).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(processes * perProcess, launches.Select(parts => parts[2]).Distinct(StringComparer.Ordinal).Count());
        Assert.All(runs, run => Assert.Contains("INTACT " + perProcess, run.Lines));
        Assert.Empty(Directory.EnumerateFileSystemEntries(world.Root));
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task AParentKilledWithoutCleanupLeavesAnOrphanThatTheNextParentSweepsAndItsDescriptorNeverAuthorizes()
    {
        var ct = TestContext.Current.CancellationToken;
        using var world = new LaunchWorld();
        using var parent = StartHelper("orphan|" + world.Root);
        var ready = await ReadLineAsync(parent, ct);
        var parts = ready.Split(' ', 3);
        Assert.Equal("READY", parts[0]);
        var descriptor = LocalRpcLaunchDescriptor.Decode(Convert.FromBase64String(parts[1]));
        var directory = parts[2];
        var parentIdentity = LocalRpcProcessIdentity.FromProcess(parent);
        Assert.Equal(parentIdentity, descriptor.Parent);
        Assert.True(Directory.Exists(directory));
        Assert.True(File.Exists(descriptor.Endpoint!.Address), "The helper's server should be listening on its launch socket.");

        parent.Kill(entireProcessTree: true);
        await parent.WaitForExitAsync(ct);

        Assert.Equal(ProcessLiveness.Dead, ProcessProbe.Probe(parentIdentity));
        Assert.True(Directory.Exists(directory), "A killed parent runs no cleanup, so its launch directory is still there.");
        await using var next = LocalRpcLaunchAuthority.Create(world.Root);
        Assert.False(Directory.Exists(directory));
        Assert.Empty(Directory.EnumerateFileSystemEntries(world.Root));
        Assert.Equal(LocalRpcLaunchRefusal.UnknownSlot, next.Verify(descriptor.ToClaim()));
        await using var stale = new LocalRpcLaunch(descriptor, null, new LaunchEnvironment());
        Assert.Equal(LocalRpcLaunchRefusal.ParentMismatch, stale.Status());
        Assert.Equal(LocalRpcLaunchRefusal.ParentMismatch, stale.Verify(descriptor.ToClaim()));
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task ALaunchAuthorizedServerOverARealEndpointStopsAdmittingWhenTheBoundChildExitsAndWhenTheLaunchIsRevoked()
    {
        var ct = TestContext.Current.CancellationToken;
        using var world = new LaunchWorld();
        await using var authority = LocalRpcLaunchAuthority.Create(world.Root);
        var launch = authority.Launch("slot-a", Launches.Identity());
        using var child = StartHelper("sleep");
        Assert.Equal("READY", await ReadLineAsync(child, ct));
        launch.BindChild(LocalRpcProcessIdentity.FromProcess(child));
        var info = new List<LocalRpcConnectionInfo>();
        await using var server = LocalRpcServer.CreateBuilder(launch.Endpoint!)
            .AddService(new RecordingBootstrapService())
            .AuthorizeConnectionsAsync((connection, token) =>
            {
                lock (info)
                {
                    info.Add(connection);
                }

                return launch.AuthorizeConnectionAsync(connection, token);
            })
            .Build();
        await server.StartAsync(ct);

        async Task<StatusCode> CallAsync()
        {
            await using var channel = LocalRpcClientChannel.Create(launch.Endpoint!, new LocalRpcLimits { ConnectTimeout = TimeSpan.FromSeconds(5) });
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            try
            {
                _ = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + TimeSpan.FromSeconds(10), cancellationToken: ct);
                return StatusCode.OK;
            }
            catch (RpcException exception)
            {
                return exception.StatusCode;
            }
        }

        Assert.Equal(StatusCode.OK, await CallAsync());
        lock (info)
        {
            Assert.Same(launch.Endpoint, info[0].Endpoint);
        }

        child.Kill(entireProcessTree: true);
        await child.WaitForExitAsync(ct);
        Assert.NotEqual(StatusCode.OK, await CallAsync());
        Assert.Equal(LocalRpcLaunchRefusal.ChildGone, launch.Status());

        var second = authority.Launch("slot-a", Launches.Identity());
        Assert.True(launch.Revoked.IsCancellationRequested);
        Assert.Equal(2UL, second.Descriptor.Epoch);
    }

    private static Process StartHelper(string mode)
    {
        var host = Environment.ProcessPath ?? throw new InvalidOperationException("The test executable path is unknown.");
        var start = new ProcessStartInfo(host)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.Environment["DOTNET_STARTUP_HOOKS"] = Path.Combine(AppContext.BaseDirectory, "ArcForges.LocalRpc.Tests.dll");
        if (string.Equals(Path.GetFileNameWithoutExtension(host), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            // Started through the shared host: run this test assembly in helper mode.
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "ArcForges.LocalRpc.Tests.dll"));
        }

        start.Environment[LaunchHelperProcess.Variable] = mode;
        return Process.Start(start) ?? throw new InvalidOperationException("The helper process did not start.");
    }

    private static async Task<string> ReadLineAsync(Process process, CancellationToken ct)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bounded.CancelAfter(Patience);
        try
        {
            return await process.StandardOutput.ReadLineAsync(bounded.Token) ?? throw new InvalidOperationException("The helper closed its output: " + await process.StandardError.ReadToEndAsync(ct));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("The helper printed no line in time.");
        }
    }

    private static async Task<(int ExitCode, List<string> Lines)> RunToExitAsync(string mode, CancellationToken ct)
    {
        using var process = StartHelper(mode);
        var lines = new List<string>();
        var error = process.StandardError.ReadToEndAsync(ct);
        string? line;
        while ((line = await process.StandardOutput.ReadLineAsync(ct)) is not null)
        {
            lines.Add(line);
        }

        await process.WaitForExitAsync(ct);
        var diagnostics = await error;
        Assert.True(process.ExitCode == 0, diagnostics);
        return (process.ExitCode, lines);
    }
}
