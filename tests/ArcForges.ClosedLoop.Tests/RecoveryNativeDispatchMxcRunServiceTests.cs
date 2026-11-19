// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Execution;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const string ReleaseDispatch = "hold-run-after-release-dispatch";
    private const string BeforeStopSignal = "hold-run-before-stop-signal";
    private const string ForceDispatch = "hold-run-after-force-dispatch";
    private const string BeforeExitCommit = "hold-run-before-exit-commit";

    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [InlineData(ReleaseDispatch)]
    [InlineData(BeforeStopSignal)]
    [InlineData(ForceDispatch)]
    public async Task InstalledRecoveryPreservesNativeDispatchAndOriginalReceipts(string checkpoint)
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        bool duringRelease = checkpoint == ReleaseDispatch;
        bool afterForce = checkpoint == ForceDispatch;
        string[] faults = afterForce ? [checkpoint, BeforeExitCommit] : [checkpoint];

        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        fixture.Environment[ExecutionFaults.Variable] = string.Join(',', faults.Select(fault => fault + "=60"));
        var process = await fixture.StartNodeAsync();
        TestDispatchEvidence? evidence = null;
        Id? ownerEpoch = null;
        Id? admittedRun = null;
        try
        {
            await using (var channel = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                var hello = await HandshakeAsync(node);
                ownerEpoch = hello.OwnerEpoch;
                var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch);
                string working = CreateFinalRecoveryWorkingDirectory(sandbox);
                string marker = Path.Combine(working, MarkerName);
                string childMarker = Path.Combine(working, ChildMarkerName);
                var start = FinalRecoveryStart(sandbox, ownerEpoch, PreparePayload(working));
                var response = await runs.StartAsync(start, deadline: Deadline, cancellationToken: cancellation);
                var run = Value(response.Value, response.Error).Run;
                admittedRun = run.RunId;
                if (duringRelease)
                {
                    await WaitDispatchCheckpointAsync(fixture, checkpoint);
                }
                else
                {
                    run = await WaitForStateAsync(fixture, runs, run.RunId, RunState.Running, cancellation);
                }

                await TestNode.WaitAsync(() => ChildIsReady(childMarker), NativeBound,
                    "the original foreground payload and its child after native release");
                var binding = ReadRecoveryBinding(fixture.DataRoot, run);
                var native = await ObserveNativeBoundaryAsync(fixture, run, childMarker, duringRelease ? null : runs);
                evidence = new(start, run, binding, native, marker, hello.NodeEpoch);
                Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(marker)));
                Assert.True(native.Supervisor.IsRunning() && native.Payload.IsRunning());
                Assert.NotEqual(process.Id, native.Payload.Pid);
                if (duringRelease)
                {
                    var committed = await InspectAsync(runs, run.RunId, cancellation);
                    Assert.Equal(RunState.Starting, committed.State);
                    Assert.Null(committed.StartedAt);
                    var pending = await OperationAsync(node, ownerEpoch, start.Meta.CommandId);
                    Assert.Equal(run.RunId, pending.AggregateId);
                    Assert.Equal(start.Meta.CommandId, pending.CommandId);
                    Assert.Equal(ownerEpoch, pending.OwnerEpoch);
                    Assert.Equal(OperationState.Accepted, pending.State);
                    Assert.Equal(EffectCertainty.Unknown, pending.Effect);
                }
                else
                {
                    await RequireKnownRecoveryStartAsync(node, start, run.RunId, compacted: false);
                    var stop = BuildStop(ownerEpoch, run);
                    stop.GraceMs = afterForce ? 0U : 8000U;
                    var accepted = await StopAsync(runs, stop, cancellation);
                    Assert.Equal(OperationState.Accepted, accepted.Operation.State);
                    Assert.Equal(stop.Meta.CommandId, accepted.Operation.CommandId);
                    await WaitDispatchCheckpointAsync(fixture, checkpoint);
                    if (afterForce)
                    {
                        await WaitDispatchCheckpointAsync(fixture, BeforeExitCommit);
                        await TestNode.WaitAsync(native.IsEmpty, NativeBound,
                            "the original owner and exact native boundary to drain after force");
                        AssertFinalWindowsEvidence(fixture, run, binding);
                    }
                    else
                    {
                        Assert.True(native.Supervisor.IsRunning() && native.Payload.IsRunning());
                    }

                    var intent = ReadRecoveryStopIntent(fixture.DataRoot, start, stop, run.Epoch);
                    Assert.Equal("ACCEPTED", intent.ReceiptState);
                    Assert.Equal(TimeSpan.FromMilliseconds(stop.GraceMs), intent.Deadline - intent.AcceptedAt);
                    evidence = evidence with { Stop = stop, StopIntent = intent };
                }
            }

            await CrashFinalRecoveryNodeAsync(process, evidence.Native.Supervisor, cancellation);
            if (!afterForce)
            {
                Assert.True(evidence.Native.Supervisor.IsRunning() && evidence.Native.Payload.IsRunning(),
                    "Both original native identities must survive loss of the Node at this boundary.");
            }

            if (evidence.Stop is { } interruptedStop)
            {
                Assert.Equal(evidence.StopIntent, ReadRecoveryStopIntent(fixture.DataRoot,
                    evidence.Start, interruptedStop, evidence.Run.Epoch));
            }

            fixture.Environment.Remove(ExecutionFaults.Variable);
            process = await fixture.StartNodeAsync();
            var recovered = await RequireRecoveredDispatchAsync(fixture, evidence, afterForce, cancellation);
            Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(evidence.Marker)));
            if (afterForce)
            {
                // Read the worker's original signed record after the actual cold restart so
                // opening a separate Store reader cannot change the crashed Node boot evidence.
                await StopNodeAsync(fixture, process);
                var (_, final) = ReadAuthenticatedFinalRecoveryObservation(fixture.DataRoot, evidence.Run, evidence.Binding);
                Assert.Equal(RunOwnerState.Exited, final.State);
                Assert.True(final.GroupEmptyVerified);
                Assert.True(final.TerminationReason is "user_stop" or "stopped");
                Assert.True(evidence.Native.IsEmpty());
            }

            TestContext.Current.TestOutputHelper?.WriteLine(
                $"The installed Node was killed at {checkpoint}. The original payload entered once and the original identities and receipts were preserved. Recovered Run state {recovered.State}.");
        }
        finally
        {
            if (!process.HasExited)
            {
                foreach (string fault in faults)
                {
                    string done = DispatchCheckpointPath(fixture, fault);
                    if (File.Exists(done)) File.WriteAllText(Path.ChangeExtension(done, ".release"), string.Empty);
                }
            }

            try
            {
                try
                {
                    if (evidence is null && !process.HasExited && ownerEpoch is not null && admittedRun is not null)
                    {
                        await StopUnobservedDispatchAsync(fixture, ownerEpoch, admittedRun);
                    }
                }
                finally
                {
                    await StopNodeAsync(fixture, process);
                }
            }
            finally
            {
                if (evidence is not null)
                {
                    using var native = evidence.Native;
                    if (native.Supervisor.IsRunning())
                    {
                        KillExactTerminalSupervisor(native.Supervisor, evidence.Binding.Creation);
                    }

                    await TestNode.WaitAsync(native.IsEmpty, NativeBound, "the test-owned original native scope to drain");
                }

                if (ownerEpoch is not null) RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
            }
        }
    }

    private static async Task StopUnobservedDispatchAsync(TestNode fixture, Id ownerEpoch, Id runId)
    {
        await using var channel = OpenChannel(fixture);
        var runs = new RunService.RunServiceClient(channel.CallInvoker);
        var run = await InspectAsync(runs, runId, CancellationToken.None);
        if (run.State is RunState.Starting or RunState.Running)
        {
            await StopAsync(runs, BuildStop(ownerEpoch, run), CancellationToken.None);
            await WaitForStateAsync(fixture, runs, runId, RunState.Exited, CancellationToken.None);
        }
    }

    private static async Task<Run> RequireRecoveredDispatchAsync(TestNode fixture, TestDispatchEvidence evidence,
        bool afterForce, CancellationToken cancellation)
    {
        await using var channel = OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var runs = new RunService.RunServiceClient(channel.CallInvoker);
        var hello = await HandshakeAsync(node);
        Assert.Equal(evidence.Start.OwnerEpoch, hello.OwnerEpoch);
        Assert.NotEqual(evidence.FirstNodeEpoch, hello.NodeEpoch);
        var run = evidence.Stop is null
            ? await WaitForStateAsync(fixture, runs, evidence.Run.RunId, RunState.Running, cancellation)
            : afterForce
                ? await InspectAsync(runs, evidence.Run.RunId, cancellation)
                : await WaitForStateAsync(fixture, runs, evidence.Run.RunId, RunState.Exited, cancellation);
        Assert.Equal(evidence.Run.Epoch, run.Epoch);
        Assert.Equal(evidence.Run.LaunchSha256, run.LaunchSha256);
        var binding = ReadRecoveryBinding(fixture.DataRoot, run);
        Assert.Equal(evidence.Binding, binding with { Generation = evidence.Binding.Generation });
        Assert.True(binding.Generation > evidence.Binding.Generation);
        await RequireKnownRecoveryStartAsync(node, evidence.Start, run.RunId, compacted: false);
        var replay = await runs.StartAsync(evidence.Start, deadline: Deadline, cancellationToken: cancellation);
        Assert.Equal(run.RunId, Value(replay.Value, replay.Error).Run.RunId);
        Assert.Equal(run.RunId, Assert.Single(await ListAsync(runs, run.SandboxId)).RunId);

        if (evidence.Stop is null)
        {
            Assert.True(evidence.Native.Supervisor.IsRunning() && evidence.Native.Payload.IsRunning());
            using var observed = await ObserveNativeBoundaryAsync(fixture, run,
                Path.Combine(Path.GetDirectoryName(evidence.Marker)!, ChildMarkerName), recoveryReadback: runs);
            Assert.Equal(evidence.Native.Supervisor, observed.Supervisor);
            Assert.Equal(evidence.Native.Payload, observed.Payload);
            var cleanup = BuildStop(evidence.Start.OwnerEpoch, run);
            await StopAsync(runs, cleanup, cancellation);
            run = await WaitForStateAsync(fixture, runs, run.RunId, RunState.Exited, cancellation);
            Assert.True(run.Exit.GroupEmptyVerified);
            AssertStopReceipt(await OperationAsync(node, evidence.Start.OwnerEpoch, cleanup.Meta.CommandId),
                cleanup, run.Revision, EffectCertainty.Happened);
        }
        else if (evidence.Stop is { } originalStop)
        {
            var operation = await OperationAsync(node, originalStop.OwnerEpoch, originalStop.Meta.CommandId);
            var stopReplay = await runs.StopAsync(originalStop, deadline: Deadline, cancellationToken: cancellation);
            if (run.State == RunState.Exited)
            {
                Assert.True(run.Exit.GroupEmptyVerified);
                AssertStopReceipt(operation, originalStop, run.Revision, EffectCertainty.Happened);
                AssertStopReceipt(Value(stopReplay.Value, stopReplay.Error).Operation, originalStop, run.Revision, EffectCertainty.Happened);
                Assert.Equal(evidence.StopIntent! with { ReceiptState = "SUCCEEDED" },
                    ReadRecoveryStopIntent(fixture.DataRoot, evidence.Start, originalStop, run.Epoch));
            }
            else
            {
                Assert.True(afterForce);
                Assert.Equal(RunState.RecoveryRequired, run.State);
                Assert.Null(run.Exit);
                Assert.Equal(originalStop.Meta.CommandId, operation.CommandId);
                Assert.Equal(originalStop.OwnerEpoch, operation.OwnerEpoch);
                Assert.Equal(run.RunId, operation.AggregateId);
                Assert.Equal(OperationState.Unknown, operation.State);
                Assert.Equal(EffectCertainty.Unknown, operation.Effect);
                Assert.False(operation.ResponseCompacted);
                Assert.Null(stopReplay.Value);
                Assert.Equal("outcome_unknown", stopReplay.Error?.Code);
                Assert.Equal(EffectCertainty.Unknown, stopReplay.Error!.Effect);
                Assert.Equal(evidence.StopIntent! with { ReceiptState = "UNKNOWN" },
                    ReadRecoveryStopIntent(fixture.DataRoot, evidence.Start, originalStop, run.Epoch));
            }
        }

        await TestNode.WaitAsync(evidence.Native.IsEmpty, NativeBound, "the exact original native scope to stay drained");
        return run;
    }

    private static Task WaitDispatchCheckpointAsync(TestNode fixture, string checkpoint) =>
        TestNode.WaitAsync(() => File.Exists(DispatchCheckpointPath(fixture, checkpoint)), NativeBound,
            "the private recovery checkpoint " + checkpoint);

    private static string DispatchCheckpointPath(TestNode fixture, string checkpoint) =>
        Path.Combine(fixture.DataRoot, "run", "fault-" + checkpoint + ".done");

    private sealed record TestDispatchEvidence(RunServiceStartRequest Start, Run Run, RecoveryBinding Binding,
        NativeBoundary Native, string Marker, string FirstNodeEpoch, RunServiceStopRequest? Stop = null,
        RecoveryStopIntent? StopIntent = null);
}
