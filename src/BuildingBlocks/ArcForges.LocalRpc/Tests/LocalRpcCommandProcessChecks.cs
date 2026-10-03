// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Explicit local opt-in checks with a real helper process (set ARCFORGES_LOCALRPC_OS_STREAMS=1; skipped by default and never run in hosted
/// CI): the helper is killed before and after its commit point while a command is in flight over a real Named Pipe (Windows) or Unix socket,
/// and a second helper is started. A pass names only the operating system it ran on. The owner store is a directory of files, which the parent
/// and every helper process see, standing in for the durable record an owner reconciles against.
/// </summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCommandProcessChecks
{
    private const string OptIn = "Explicit local process checks only (ARCFORGES_LOCALRPC_OS_STREAMS=1).";
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(60);

    public static bool Enabled => LocalRpcOsStreamChecks.Enabled;

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task AHelperProcessKilledBeforeItsCommitPointLeavesAnUnknownEffectThatReconcilesToDidNotHappenAndRunsOnceOnTheNextHelper()
    {
        var ct = TestContext.Current.CancellationToken;
        using var world = new ProcessWorld();
        var executor = new LocalRpcCommandExecutor();
        var id = Guid.NewGuid();
        var command = CommandClient.CompleteCommand(id);
        var firstGeneration = new LocalRpcPeerGeneration(Guid.NewGuid(), 1);
        var first = world.Endpoint("a");
        using var helper = StartHelper(first, world.Root, "before");
        await ReadAsync(helper, "READY", ct);
        await using var channel = LocalRpcClientChannel.Create(first.Endpoint);
        var running = CommandClient.CompleteAsync(executor, channel, firstGeneration, command, cancellationToken: ct);
        Assert.Equal("before", (await ReadAsync(helper, "REACHED", ct)).Split(' ')[1]);

        helper.Kill(entireProcessTree: true);
        await helper.WaitForExitAsync(ct);
        var outcome = await running.WaitAsync(Patience, ct);

        Assert.Equal(LocalRpcOutcomeKind.Failure, outcome.Kind);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);
        Assert.Equal(0, world.Store.Commits(id));

        var second = world.Endpoint("b");
        var secondGeneration = new LocalRpcPeerGeneration(Guid.NewGuid(), 2);
        using var next = StartHelper(second, world.Root, "run");
        await ReadAsync(next, "READY", ct);
        await using var secondChannel = LocalRpcClientChannel.Create(second.Endpoint);
        var refused = await CommandClient.CompleteAsync(executor, secondChannel, secondGeneration, command, cancellationToken: ct);
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, refused.Reason);
        Assert.Equal(0, world.Store.Commits(id));

        var reconciled = await executor.ReconcileAsync(id, (_, _) => ValueTask.FromResult(world.Store.Commits(id) > 0 ? LocalRpcEffect.Happened : LocalRpcEffect.DidNotHappen), ct);
        Assert.Equal(LocalRpcEffect.DidNotHappen, reconciled!.Effect);
        var rerun = await CommandClient.CompleteAsync(executor, secondChannel, secondGeneration, command, cancellationToken: ct);
        Assert.Equal(LocalRpcOutcomeKind.Success, rerun.Kind);
        Assert.Equal(1, world.Store.Commits(id));
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task AHelperProcessKilledAfterItsCommitPointIsNeverReplayedAndReconcilesToHappened()
    {
        var ct = TestContext.Current.CancellationToken;
        using var world = new ProcessWorld();
        var executor = new LocalRpcCommandExecutor();
        var id = Guid.NewGuid();
        var command = CommandClient.CompleteCommand(id);
        var first = world.Endpoint("a");
        using var helper = StartHelper(first, world.Root, "after");
        await ReadAsync(helper, "READY", ct);
        await using var channel = LocalRpcClientChannel.Create(first.Endpoint);
        var running = CommandClient.CompleteAsync(executor, channel, new LocalRpcPeerGeneration(Guid.NewGuid(), 1), command, cancellationToken: ct);
        Assert.Equal("after", (await ReadAsync(helper, "REACHED", ct)).Split(' ')[1]);
        Assert.Equal(1, world.Store.Commits(id));

        helper.Kill(entireProcessTree: true);
        await helper.WaitForExitAsync(ct);
        var outcome = await running.WaitAsync(Patience, ct);
        Assert.Equal(LocalRpcEffect.Unknown, outcome.Effect);

        var second = world.Endpoint("b");
        var secondGeneration = new LocalRpcPeerGeneration(Guid.NewGuid(), 2);
        using var next = StartHelper(second, world.Root, "run");
        await ReadAsync(next, "READY", ct);
        await using var secondChannel = LocalRpcClientChannel.Create(second.Endpoint);
        var refused = await CommandClient.CompleteAsync(executor, secondChannel, secondGeneration, command, cancellationToken: ct);
        Assert.Equal(LocalRpcFailureReason.ReplayNotAllowed, refused.Reason);
        Assert.Equal(1, world.Store.Commits(id));

        var reconciled = await executor.ReconcileAsync(id, (_, _) => ValueTask.FromResult(world.Store.Commits(id) > 0 ? LocalRpcEffect.Happened : LocalRpcEffect.DidNotHappen), ct);
        Assert.Equal(LocalRpcEffect.Happened, reconciled!.Effect);
        Assert.Equal(LocalRpcCommandState.Resolved, reconciled.State);
        Assert.Equal(1, world.Store.Commits(id));
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task ACancelGoesThroughAReservedControlSlotOfARealHelperWhileItsDataLaneIsSaturated()
    {
        var ct = TestContext.Current.CancellationToken;
        using var world = new ProcessWorld();
        var executor = new LocalRpcCommandExecutor();
        var first = world.Endpoint("a");
        using var helper = StartHelper(first, world.Root, "before");
        await ReadAsync(helper, "READY", ct);
        await using var channel = LocalRpcClientChannel.Create(first.Endpoint);
        var generation = new LocalRpcPeerGeneration(Guid.NewGuid(), 1);
        var ids = Enumerable.Range(0, LocalRpcLimits.DefaultMaxActiveCalls + LocalRpcLimits.DefaultMaxQueuedCalls).Select(_ => Guid.NewGuid()).ToArray();
        var calls = ids.Select(id => CommandClient.CompleteAsync(executor, channel, generation, CommandClient.CompleteCommand(id), cancellationToken: ct)).ToArray();

        // 16 run (and park before their commit point); the rest wait in the helper's queue of 64.
        var reached = new List<string>();
        for (var index = 0; index < LocalRpcLimits.DefaultMaxActiveCalls; index++)
        {
            reached.Add((await ReadAsync(helper, "REACHED", ct)).Split(' ')[2]);
        }

        var victim = Guid.ParseExact(reached[0], "N");
        var started = Stopwatch.GetTimestamp();
        var result = await executor.CancelAsync(victim, (_, token) => CommandClient.CancelThroughProbeAsync(channel, victim, token), ct);
        var elapsed = Stopwatch.GetElapsedTime(started);

        Assert.Equal(LocalRpcCancelDisposition.Cancelled, result.Disposition);
        Assert.True(result.Delivered);
        Assert.Equal(LocalRpcEffect.DidNotHappen, result.Record!.Effect);
        Assert.True(elapsed < TimeSpan.FromSeconds(10), "The cancel was served without waiting for the saturated data lane: " + elapsed);
        Assert.Equal(0, world.Store.Commits(victim));
        _ = await calls[Array.IndexOf(ids, victim)].WaitAsync(Patience, ct);

        helper.Kill(entireProcessTree: true);
        await helper.WaitForExitAsync(ct);
        _ = await Task.WhenAll(calls).WaitAsync(Patience, ct);
    }

    private static Process StartHelper((LocalRpcEndpoint Endpoint, string Kind, string Address) endpoint, string store, string mode)
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
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "ArcForges.LocalRpc.Tests.dll"));
        }

        start.Environment[LaunchHelperProcess.Variable] = string.Join('|', "command", endpoint.Kind, endpoint.Address, store, mode);
        return Process.Start(start) ?? throw new InvalidOperationException("The helper process did not start.");
    }

    /// <summary>Reads helper output lines until one starts with <paramref name="prefix"/> and returns it.</summary>
    private static async Task<string> ReadAsync(Process process, string prefix, CancellationToken ct)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bounded.CancelAfter(Patience);
        try
        {
            while (true)
            {
                var line = await process.StandardOutput.ReadLineAsync(bounded.Token) ?? throw new InvalidOperationException("The helper closed its output: " + await process.StandardError.ReadToEndAsync(ct));
                if (line.StartsWith(prefix, StringComparison.Ordinal))
                {
                    return line;
                }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("The helper printed no " + prefix + " line in time.");
        }
    }

    private sealed class ProcessWorld : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("afcmd-");

        internal ProcessWorld()
        {
            Store = new OwnerStore(_directory.FullName);
        }

        internal OwnerStore Store { get; }

        internal string Root => _directory.FullName;

        internal (LocalRpcEndpoint Endpoint, string Kind, string Address) Endpoint(string name)
        {
            if (OperatingSystem.IsWindows())
            {
                var pipe = "af-cmd-" + name + "-" + Guid.NewGuid().ToString("N");
                return (LocalRpcEndpoint.NamedPipe(pipe), "pipe", pipe);
            }

            var path = Path.Combine(_directory.FullName, name + ".sock");
            return (LocalRpcEndpoint.UnixDomainSocket(path), "unix", path);
        }

        public void Dispose()
        {
            try
            {
                _directory.Delete(recursive: true);
            }
            catch (IOException)
            {
                // A helper that was just killed can still hold a file; the directory is disposable.
            }
            catch (UnauthorizedAccessException)
            {
                // Same: disposable temporary state.
            }
        }
    }
}
