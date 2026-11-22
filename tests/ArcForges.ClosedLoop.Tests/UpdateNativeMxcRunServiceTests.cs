// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Store;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 240_000, DisableParallelization = true)]
    public async Task InstalledUpdateFenceSurvivesNodeRestartWhileTheOriginalNativeRunDrains()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = await RecoveryNativeFixture.StartAsync();
        var original = fixture.Original;
        var running = fixture.Running;
        var native = fixture.Native;
        var binding = ReadRecoveryBinding(fixture.Node.DataRoot, running);
        Assert.False(native.IsEmpty());

        const string marker = "update-reopened.txt";
        var fresh = original.Clone();
        fresh.Meta = Mutation(original.Meta.ExpectedRev);
        fresh.Argv.Clear();
        string[] successorArguments = OperatingSystem.IsWindows()
            ? [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "echo update reopened>" + marker]
            : ["/usr/bin/dash", "-c", "printf 'update reopened\\n' > '" + marker + "'"];
        fresh.Argv.Add(successorArguments);
        fresh.TerminalMode = TerminalMode.Pipes;
        fresh.TerminalSize = null;

        string reopenedMarker;
        var operationId = Guid.NewGuid();
        var installation = Path.GetDirectoryName(fixture.Node.NodeExecutable)!;
        using var buildInfo = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(installation, "build-info.json")));
        var actualCommit = Assert.IsType<string>(buildInfo.RootElement.GetProperty("commit").GetString());
        // This test exercises the durable fence and native ownership. The fixture identities
        // stand in for verified package metadata, and no candidate binary is installed or started.
        var previous = new NativeUpdateCohort(actualCommit, new string('1', 40), new string('2', 64), installation);
        var candidate = new NativeUpdateCohort(new string('3', 40), new string('4', 40), new string('5', 64),
            Path.Combine(fixture.Node.Root, "unused-candidate"));
        var fence = NativeUpdateGate.Begin(fixture.Node.DataRoot, operationId, previous, candidate);
        Assert.Equal(NativeUpdatePhase.Fenced, fence.Phase);
        await using (var channel = OpenChannel(fixture.Node))
        {
            var node = new NodeService.NodeServiceClient(channel.CallInvoker);
            var runs = new RunService.RunServiceClient(channel.CallInvoker);
            var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
            var inspected = await sandboxes.InspectAsync(new SandboxServiceInspectRequest
            {
                Meta = Query(),
                SandboxId = original.SandboxId,
            }, deadline: Deadline, cancellationToken: token);
            var sandbox = Value(inspected.Value, inspected.Error).Sandbox;
            reopenedMarker = Path.Combine(sandbox.DataLocation, RelativeWorkdir, marker);
            await RequireUpdateStartRefusalAsync(node, runs, fresh, token);
            Assert.Equal(running.RunId, Assert.Single(await ListAsync(runs, running.SandboxId)).RunId);
        }

        await fixture.CrashNodeAsync(token);
        Assert.True(native.Supervisor.IsRunning());
        Assert.True(native.Payload.IsRunning());
        Assert.Equal(fence, NativeUpdateGate.Read(fixture.Node.DataRoot));
        await fixture.RestartNodeAsync();

        await using var recoveredChannel = OpenChannel(fixture.Node);
        var recoveredNode = new NodeService.NodeServiceClient(recoveredChannel.CallInvoker);
        var recoveredRuns = new RunService.RunServiceClient(recoveredChannel.CallInvoker);
        var hello = await HandshakeAsync(recoveredNode);
        Assert.NotEqual(fixture.FirstNodeEpoch, hello.NodeEpoch);
        Assert.Equal(original.OwnerEpoch, hello.OwnerEpoch);
        Assert.Equal(fence, NativeUpdateGate.Read(fixture.Node.DataRoot));

        var continued = await WaitForStateAsync(fixture.Node, recoveredRuns, running.RunId, RunState.Running, token);
        Assert.Equal(running.Epoch, continued.Epoch);
        Assert.Equal(running.LaunchSha256, continued.LaunchSha256);
        Assert.Equal(running.StartedAt, continued.StartedAt);
        var rebound = ReadRecoveryBinding(fixture.Node.DataRoot, continued);
        Assert.Equal(binding, rebound with { Generation = binding.Generation });
        Assert.True(rebound.Generation > binding.Generation);
        Assert.True(native.Supervisor.IsRunning());
        Assert.True(native.Payload.IsRunning());

        await RequireUpdateStartRefusalAsync(recoveredNode, recoveredRuns, fresh, token);
        var replayed = await recoveredRuns.StartAsync(original, deadline: Deadline, cancellationToken: token);
        Assert.Equal(running.RunId, Value(replayed.Value, replayed.Error).Run.RunId);
        await RequireKnownRecoveryStartAsync(recoveredNode, original, running.RunId, compacted: false);
        Assert.Equal(running.RunId, Assert.Single(await ListAsync(recoveredRuns, running.SandboxId)).RunId);
        fixture.RequireOneEntry();
        Assert.False(File.Exists(reopenedMarker));

        var stop = BuildStop(original.OwnerEpoch, continued);
        await StopAsync(recoveredRuns, stop, token);
        var settled = await WaitForStateAsync(fixture.Node, recoveredRuns, running.RunId, RunState.Exited, token);
        Assert.True(settled.Exit.GroupEmptyVerified);
        Assert.True(ReadProtectedDrain(fixture.Node.DataRoot, running).GroupEmptyVerified);
        Assert.True(native.IsEmpty());
        AssertStopReceipt(await OperationAsync(recoveredNode, stop.OwnerEpoch, stop.Meta.CommandId), stop,
            settled.Revision, EffectCertainty.Happened);
        await RequireUpdateStartRefusalAsync(recoveredNode, recoveredRuns, fresh, token);
        Assert.False(File.Exists(reopenedMarker));

        var rolledBack = NativeUpdateGate.MarkRolledBack(fixture.Node.DataRoot, operationId);
        Assert.Equal(NativeUpdatePhase.RolledBack, rolledBack.Phase);
        Assert.Null(rolledBack.Checkpoint);
        Assert.Equal(rolledBack, NativeUpdateGate.Read(fixture.Node.DataRoot));

        var accepted = await recoveredRuns.StartAsync(fresh, deadline: Deadline, cancellationToken: token);
        var successor = Value(accepted.Value, accepted.Error).Run;
        Assert.NotEqual(running.RunId, successor.RunId);
        var successorExit = await WaitForStateAsync(fixture.Node, recoveredRuns, successor.RunId, RunState.Exited, token);
        Assert.True(successorExit.Exit.GroupEmptyVerified);
        Assert.Equal("update reopened", Assert.Single(ReadLines(reopenedMarker)));
        await RequireKnownRecoveryStartAsync(recoveredNode, fresh, successor.RunId, compacted: false);
        Assert.Equal(2, (await ListAsync(recoveredRuns, running.SandboxId)).Length);
        fixture.RequireOneEntry();
        TestContext.Current.TestOutputHelper?.WriteLine("The original native supervisor remained bound after Node restart. Fresh Start left no receipt while fenced. The same command entered a new native Run after the pre-effect rollback.");
    }

    private static async Task RequireUpdateStartRefusalAsync(NodeService.NodeServiceClient node,
        RunService.RunServiceClient runs, RunServiceStartRequest fresh, CancellationToken token)
    {
        var refused = await runs.StartAsync(fresh, deadline: Deadline, cancellationToken: token);
        Assert.Null(refused.Value);
        var error = Assert.IsType<ArcError>(refused.Error);
        Assert.Equal(ErrorCategory.State, error.Category);
        Assert.Equal("busy", error.Code);
        Assert.Equal("node_update", error.Details?.State?.State);
        Assert.Equal("node_update_in_progress", error.Details?.State?.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        Assert.Equal(RetryMode.AfterTime, error.Retry?.Mode);
        Assert.NotNull(error.Retry?.RetryAt);

        var receipt = await node.GetOperationAsync(new NodeServiceGetOperationRequest
        {
            Meta = Query(),
            OwnerEpoch = fresh.OwnerEpoch,
            CommandId = fresh.Meta.CommandId,
        }, deadline: Deadline, cancellationToken: token);
        Assert.Null(receipt.Value);
        Assert.Equal("not_found", receipt.Error?.Code);
    }
}
