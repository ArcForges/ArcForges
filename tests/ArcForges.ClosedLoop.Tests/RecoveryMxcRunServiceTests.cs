// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Microsoft.Data.Sqlite;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 240_000, DisableParallelization = true)]
    public async Task InstalledRecoveryRebindsTheSameOwnerAndCannotReplayACompactedStart()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = await RecoveryNativeFixture.StartAsync(checkWindowsBreakaway: OperatingSystem.IsWindows());
        var original = fixture.Original;
        var run = fixture.Running;
        var native = fixture.Native;
        await using (var channel = OpenChannel(fixture.Node))
        {
            var node = new NodeService.NodeServiceClient(channel.CallInvoker);
            await RequireKnownRecoveryStartAsync(node, original, run.RunId, compacted: false);
        }

        var binding = ReadRecoveryBinding(fixture.Node.DataRoot, run);
        await fixture.CrashNodeAsync(cancellationToken);
        Assert.True(native.Supervisor.IsRunning());
        Assert.True(native.Payload.IsRunning());
        CompactActualResponse(fixture.Node.DataRoot, original, run.RunId);
        Assert.True(native.Supervisor.IsRunning());
        Assert.True(native.Payload.IsRunning());

        await fixture.RestartNodeAsync();
        await using var recovered = OpenChannel(fixture.Node);
        var recoveredNode = new NodeService.NodeServiceClient(recovered.CallInvoker);
        var runs = new RunService.RunServiceClient(recovered.CallInvoker);
        var hello = await HandshakeAsync(recoveredNode);
        Assert.NotEqual(fixture.FirstNodeEpoch, hello.NodeEpoch);
        Assert.Equal(original.OwnerEpoch, hello.OwnerEpoch);
        var continued = await WaitForStateAsync(fixture.Node, runs, run.RunId, RunState.Running, cancellationToken);
        Assert.Equal(run.Epoch, continued.Epoch);
        Assert.Equal(run.LaunchSha256, continued.LaunchSha256);
        Assert.Equal(run.StartedAt, continued.StartedAt);
        var rebound = ReadRecoveryBinding(fixture.Node.DataRoot, continued);
        Assert.Equal(binding, rebound with { Generation = binding.Generation });
        Assert.True(rebound.Generation > binding.Generation, "The rebind must advance the authenticated control generation.");
        Assert.True(native.Supervisor.IsRunning());
        Assert.True(native.Payload.IsRunning());
        using (var observed = await fixture.ObserveBoundaryAsync(continued, runs))
        {
            Assert.Equal(native.Supervisor, observed.Supervisor);
            Assert.Equal(native.Payload, observed.Payload);
        }

        if (OperatingSystem.IsWindows())
        {
            var resources = new ResourceService.ResourceServiceClient(recovered.CallInvoker);
            var readback = await ReadEffectiveRunBudgetAsync(resources, continued, CpuMillicores, (int)(MemoryBytes >> 20));
            var scope = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(binding.Boundary)));
            foreach (var limit in readback.Limits.Where(limit => limit.Dimension is "cpu" or "memory" or "pids"))
            {
                Assert.Equal(scope, limit.Scope);
            }
        }

        var replay = await runs.StartAsync(original, deadline: Deadline, cancellationToken: cancellationToken);
        Assert.Equal("receipt_compacted", replay.Error?.Code);
        Assert.Equal(EffectCertainty.Happened, replay.Error!.Effect);
        Assert.Equal("SUCCEEDED", replay.Error.Details.State.State);
        Assert.Equal(run.RunId, replay.Error.Details.State.Resource.Id);
        await RequireKnownRecoveryStartAsync(recoveredNode, original, run.RunId, compacted: true);
        Assert.Equal(run.RunId, Assert.Single(await ListAsync(runs, run.SandboxId)).RunId);
        fixture.RequireOneEntry();

        var stop = BuildStop(original.OwnerEpoch, await InspectAsync(runs, continued.RunId, cancellationToken));
        await StopAsync(runs, stop, cancellationToken);
        var settled = await WaitForStateAsync(fixture.Node, runs, run.RunId, RunState.Exited, cancellationToken);
        Assert.True(settled.Exit.GroupEmptyVerified);
        Assert.True(native.IsEmpty(), "The recovered Stop must drain the exact original native boundary.");
        var protectedDrain = ReadProtectedDrain(fixture.Node.DataRoot, run);
        Assert.True(protectedDrain.GroupEmptyVerified);
        if (OperatingSystem.IsWindows())
        {
            var drained = ReadWindowsJobResource(fixture.Node.DataRoot, run,
                (binding.Pid, binding.Creation, binding.Boundary), "windows-drained.json");
            Assert.Equal(binding.Pid, Assert.Single(drained.ProcessIds));
            Assert.Empty(drained.PayloadProcessIds);
            Assert.True(drained.OutputDrainCompleted);
            fixture.RequireWindowsBreakawayRefusal(native.Payload, live: false);
        }

        AssertStopReceipt(await OperationAsync(recoveredNode, original.OwnerEpoch, stop.Meta.CommandId), stop,
            settled.Revision, EffectCertainty.Happened);
        fixture.RequireOneEntry();
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"The original owner and payload remained alive across Node loss and Start receipt compaction. Recovery advanced generation {binding.Generation} to {rebound.Generation}; Stop then drained the original scope."));
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledRecoveryDrainsTheOriginalScopeAfterSupervisorLoss()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = await RecoveryNativeFixture.StartAsync();
        var run = fixture.Running;
        var native = fixture.Native;
        var binding = ReadRecoveryBinding(fixture.Node.DataRoot, run);
        await using var channel = OpenChannel(fixture.Node);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var runs = new RunService.RunServiceClient(channel.CallInvoker);
        await RequireKnownRecoveryStartAsync(node, fixture.Original, run.RunId, compacted: false);
        Assert.True(native.Payload.IsRunning());

        KillExactTerminalSupervisor(native.Supervisor, binding.Creation);
        await TestNode.WaitAsync(() => !native.Supervisor.IsRunning(), NativeBound, "the original supervisor to die");
        var settled = await WaitForStateAsync(fixture.Node, runs, run.RunId, RunState.Exited, cancellationToken);
        Assert.True(settled.Exit.GroupEmptyVerified);
        Assert.False(settled.Exit.HasRawCode);
        Assert.Equal("owner_failure", settled.Exit.TerminationReason);
        Assert.True(native.IsEmpty());
        Assert.False(fixture.Process.HasExited, "The independent Node must still retain its exact original boundary lease.");
        await RequireKnownRecoveryStartAsync(node, fixture.Original, run.RunId, compacted: false);
        fixture.RequireOneEntry();
        TestContext.Current.TestOutputHelper?.WriteLine("After the exact supervisor died, the still-live Node verified the original scope empty without a raw payload exit code.");
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledRecoverySettlesTheOriginalStopAfterNodeLossDuringNativeGrace()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = await RecoveryNativeFixture.StartAsync(TerminalMode.Pipes);
        var running = fixture.Running;
        var native = fixture.Native;
        var start = fixture.Original;
        var binding = ReadRecoveryBinding(fixture.Node.DataRoot, running);
        var stop = BuildStop(start.OwnerEpoch, running);
        stop.GraceMs = 12_000;
        var clock = Stopwatch.StartNew();
        RecoveryStopIntent intent;
        await using (var channel = OpenChannel(fixture.Node))
        {
            var node = new NodeService.NodeServiceClient(channel.CallInvoker);
            var runs = new RunService.RunServiceClient(channel.CallInvoker);
            await RequireKnownRecoveryStartAsync(node, start, running.RunId, compacted: false);
            var accepted = await StopAsync(runs, stop, cancellationToken);
            Assert.Equal(RunState.Stopping, accepted.Run.State);
            Assert.Equal(OperationState.Accepted, accepted.Operation.State);
            Assert.Equal(stop.Meta.CommandId, accepted.Operation.CommandId);
            Assert.Equal(start.OwnerEpoch, accepted.Operation.OwnerEpoch);
            intent = ReadRecoveryStopIntent(fixture.Node.DataRoot, start, stop, running.Epoch);
            Assert.Equal(TimeSpan.FromMilliseconds(stop.GraceMs), intent.Deadline - intent.AcceptedAt);
            Assert.Equal("ACCEPTED", intent.ReceiptState);
            Assert.True(native.Supervisor.IsRunning() && native.Payload.IsRunning(),
                $"The real original scope drained before the Node interruption (elapsed {clock.Elapsed.TotalMilliseconds:F0} ms). {ReadRunDiagnostics(fixture.Node, running.RunId)}");
        }

        await fixture.CrashNodeAsync(cancellationToken);
        Assert.True(native.Supervisor.IsRunning() && native.Payload.IsRunning(),
            $"The real original scope did not survive the exact Node death during grace (elapsed {clock.Elapsed.TotalMilliseconds:F0} ms). {ReadRunDiagnostics(fixture.Node, running.RunId)}");
        Assert.Equal(intent, ReadRecoveryStopIntent(fixture.Node.DataRoot, start, stop, running.Epoch));
        await fixture.RestartNodeAsync();
        await using var recovered = OpenChannel(fixture.Node);
        var recoveredNode = new NodeService.NodeServiceClient(recovered.CallInvoker);
        var recoveredRuns = new RunService.RunServiceClient(recovered.CallInvoker);
        var hello = await HandshakeAsync(recoveredNode);
        Assert.NotEqual(fixture.FirstNodeEpoch, hello.NodeEpoch);
        Assert.Equal(start.OwnerEpoch, hello.OwnerEpoch);
        var settled = await WaitForStateAsync(fixture.Node, recoveredRuns, running.RunId, RunState.Exited, cancellationToken);
        Assert.Equal(running.Epoch, settled.Epoch);
        Assert.Equal(running.LaunchSha256, settled.LaunchSha256);
        Assert.True(settled.Exit.GroupEmptyVerified);
        Assert.True(native.IsEmpty(), "Reconciliation must drain the same held native scope before settling the Stop.");
        var rebound = ReadRecoveryBinding(fixture.Node.DataRoot, settled);
        Assert.Equal(binding, rebound with { Generation = binding.Generation });
        Assert.True(rebound.Generation > binding.Generation);
        var completed = ReadRecoveryStopIntent(fixture.Node.DataRoot, start, stop, running.Epoch);
        Assert.Equal(intent with { ReceiptState = "SUCCEEDED" }, completed);
        var receipt = await OperationAsync(recoveredNode, start.OwnerEpoch, stop.Meta.CommandId);
        AssertStopReceipt(receipt, stop, settled.Revision, EffectCertainty.Happened);
        var replay = await StopAsync(recoveredRuns, stop, cancellationToken);
        Assert.Equal(settled, replay.Run);
        AssertStopReceipt(replay.Operation, stop, settled.Revision, EffectCertainty.Happened);
        fixture.RequireOneEntry();
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"Original owner and payload outlived Node loss during a {stop.GraceMs} ms persisted Stop grace. The same receipt settled after exact native drain."));
    }

    [Theory(Timeout = 240_000, DisableParallelization = true)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InstalledRecoveryNeverSignalsAnUnrelatedProcessWhenStoredOwnerEvidenceIsStale(bool previousBoot)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = await RecoveryNativeFixture.StartAsync();
        var run = fixture.Running;
        var binding = ReadRecoveryBinding(fixture.Node.DataRoot, run);
        await fixture.CrashNodeAsync(cancellationToken);
        KillExactTerminalSupervisor(fixture.Native.Supervisor, binding.Creation);
        await TestNode.WaitAsync(fixture.Native.IsEmpty, NativeBound, "the original test-owned supervisor and scope to drain");

        var marker = Path.Combine(fixture.Node.Root, "unrelated-marker.log");
        var sentinel = fixture.Node.Start(TestNode.TestLoad, ["hold", "--hold-ms", "120000", "--marker", marker]);
        try
        {
            await TestNode.WaitAsync(() => ReadLines(marker).Any(line => line.StartsWith("ready ", StringComparison.Ordinal)),
                NativeBound, "the unrelated native process ready marker");
            var unrelated = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(sentinel.Id));
            Assert.NotEqual(fixture.Native.Supervisor.StartKey, unrelated.StartKey);
            Assert.True(unrelated.IsRunning());
            var storeBoot = previousBoot ? OtherRecoveryBoot(binding.StoreBoot) : binding.StoreBoot;
            var ownerBoot = OperatingSystem.IsLinux() ? storeBoot.Split(':')[1] : storeBoot;
            WriteStaleRecoveryOwnerFixture(fixture.Node.DataRoot, run, binding, unrelated.Pid, ownerBoot, storeBoot);

            await fixture.RestartNodeAsync();
            RunServiceStopRequest? unresolved = null;
            await using (var channel = OpenChannel(fixture.Node))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                var hello = await HandshakeAsync(node);
                Assert.Equal(fixture.Original.OwnerEpoch, hello.OwnerEpoch);
                Assert.NotEqual(fixture.FirstNodeEpoch, hello.NodeEpoch);
                var recovered = await WaitForStateAsync(fixture.Node, runs, run.RunId,
                    previousBoot ? RunState.Exited : RunState.RecoveryRequired, cancellationToken);
                Assert.Equal(run.Epoch, recovered.Epoch);
                Assert.Equal(run.LaunchSha256, recovered.LaunchSha256);
                if (previousBoot)
                {
                    Assert.True(recovered.Exit.GroupEmptyVerified);
                    Assert.Equal("host_reboot", recovered.Exit.TerminationReason);
                    Assert.Equal(ExitSource.Unknown, recovered.Exit.Source);
                    Assert.False(recovered.Exit.HasRawCode);
                }
                else
                {
                    Assert.Null(recovered.Exit);
                    Assert.Null(recovered.EndedAt);
                    unresolved = BuildStop(hello.OwnerEpoch, recovered);
                    await RequireUncertainRecoveryStopAsync(node, runs, unresolved, cancellationToken);
                }

                await RequireKnownRecoveryStartAsync(node, fixture.Original, run.RunId, compacted: false);
                var replay = await runs.StartAsync(fixture.Original, deadline: Deadline, cancellationToken: cancellationToken);
                Assert.Equal(run.RunId, Value(replay.Value, replay.Error).Run.RunId);
                Assert.Equal(run.RunId, Assert.Single(await ListAsync(runs, run.SandboxId)).RunId);
                Assert.True(unrelated.IsRunning());
                fixture.RequireOneEntry();
            }

            if (unresolved is not null)
            {
                await fixture.CrashNodeAsync(cancellationToken);
                CompactRecoveryAroundUnknownStop(fixture.Node.DataRoot, unresolved);
                await fixture.RestartNodeAsync();
                await using var channel = OpenChannel(fixture.Node);
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                await WaitForStateAsync(fixture.Node, runs, run.RunId, RunState.RecoveryRequired, cancellationToken);
                await RequireUncertainRecoveryStopAsync(node, runs, unresolved, cancellationToken);
                Assert.True(unrelated.IsRunning());
                fixture.RequireOneEntry();
            }

            TestContext.Current.TestOutputHelper?.WriteLine(previousBoot
                ? "The prior-boot fixture recovered without a numeric exit or action on the unrelated native process."
                : "The stored PID with a different real birth left recovery unresolved. Stop kept its original unknown effect through compaction and restart.");
        }
        finally
        {
            if (!sentinel.HasExited)
            {
                sentinel.Kill();
                await sentinel.WaitForExitAsync(CancellationToken.None).WaitAsync(NativeBound, CancellationToken.None);
            }
        }
    }

    [Fact(Timeout = 150_000, DisableParallelization = true)]
    public async Task InstalledRecoveryUsesOnlyTheOriginalNativeBoundaryWhenItDisappears()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = await RecoveryNativeFixture.StartAsync();
        var run = fixture.Running;
        var binding = ReadRecoveryBinding(fixture.Node.DataRoot, run);
        if (OperatingSystem.IsLinux())
        {
            var identity = binding.Boundary.Split('|');
            Assert.Equal(5, identity.Length);
            Assert.Matches("^arcforges-run-[0-9a-f]{32}\\.service$", identity[0]);
            Assert.Equal(binding.Instance, identity[1]);
            using var group = LinuxRunCgroup.Open(identity[2]);
            Assert.Equal(identity[3], group.MountId.ToString(CultureInfo.InvariantCulture));
            Assert.Equal(identity[4], group.Inode.ToString(CultureInfo.InvariantCulture));
            Assert.True(LinuxRunCgroup.MatchesProcess(fixture.Native.Supervisor.Pid, fixture.Native.Supervisor.StartKey, group.Path));
            Assert.Equal(binding.Instance, SystemdTestEnvironment.Property(identity[0], "InvocationID"));
            Assert.Equal(group.Path, SystemdTestEnvironment.Property(identity[0], "ControlGroup"));
            Assert.Equal(binding.Pid.ToString(CultureInfo.InvariantCulture), SystemdTestEnvironment.Property(identity[0], "MainPID"));
            var stop = SystemdTestEnvironment.Systemctl("--no-pager", "--no-block", "stop", "--", identity[0]);
            Assert.Equal(0, stop.ExitCode);
            await TestNode.WaitAsync(group.IsEmpty, NativeBound, "the exact original transient unit scope to empty");
        }
        else
        {
            // No extra Job handle may keep the boundary alive for this last-handle loss case.
            await fixture.CrashNodeAsync(cancellationToken);
            KillExactTerminalSupervisor(fixture.Native.Supervisor, binding.Creation);
            await TestNode.WaitAsync(fixture.Native.IsEmpty, NativeBound, "the original Windows Job members to exit");
            await fixture.RestartNodeAsync();
        }

        await using var channel = OpenChannel(fixture.Node);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var runs = new RunService.RunServiceClient(channel.CallInvoker);
        var state = OperatingSystem.IsLinux() ? RunState.Exited : RunState.RecoveryRequired;
        var recovered = await WaitForStateAsync(fixture.Node, runs, run.RunId, state, cancellationToken);
        if (OperatingSystem.IsLinux())
        {
            Assert.True(recovered.Exit.GroupEmptyVerified);
            Assert.False(recovered.Exit.HasRawCode);
            Assert.Equal("owner_failure", recovered.Exit.TerminationReason);
        }
        else
        {
            Assert.Null(recovered.Exit);
            Assert.Null(recovered.EndedAt);
        }

        Assert.True(fixture.Native.IsEmpty());
        await RequireKnownRecoveryStartAsync(node, fixture.Original, run.RunId, compacted: false);
        fixture.RequireOneEntry();
        TestContext.Current.TestOutputHelper?.WriteLine(OperatingSystem.IsLinux()
            ? "The held original native unit reported its exact cgroup empty after the unit stopped."
            : "The original known Job members exited after both owners died. Recovery retained an unresolved result without an independently provable Job handle.");
    }

    private static async Task RequireUncertainRecoveryStopAsync(NodeService.NodeServiceClient node,
        RunService.RunServiceClient runs, RunServiceStopRequest request, CancellationToken cancellationToken)
    {
        var reply = await runs.StopAsync(request, deadline: Deadline, cancellationToken: cancellationToken);
        Assert.Equal("outcome_unknown", reply.Error?.Code);
        Assert.Equal(EffectCertainty.Unknown, reply.Error!.Effect);
        var receipt = await OperationAsync(node, request.OwnerEpoch, request.Meta.CommandId);
        Assert.Equal(request.OwnerEpoch, receipt.OwnerEpoch);
        Assert.Equal(request.Meta.CommandId, receipt.CommandId);
        Assert.Equal(request.RunId, receipt.AggregateId);
        Assert.Equal("RunService.Stop", receipt.Method);
        Assert.Equal(OperationState.Unknown, receipt.State);
        Assert.Equal(EffectCertainty.Unknown, receipt.Effect);
        Assert.False(receipt.ResponseCompacted);
    }

    private static void CompactRecoveryAroundUnknownStop(string dataRoot, RunServiceStopRequest original)
    {
        var owner = SandboxLocalOwner.Current();
        Assert.NotNull(owner);
        using var store = NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = dataRoot,
            BootIdentity = BootIdentity.Read(),
            Clock = new PostRetentionClock(),
        });
        using var durable = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(dataRoot));
        Assert.True(durable.OwnerEpoch.Span.SequenceEqual(original.OwnerEpoch.Value.Span));
        var before = durable.Inspect(original.Meta.CommandId.Value.Span);
        Assert.NotNull(before);
        Assert.Equal(Hex(original.RunId), before.AggregateId);
        Assert.Equal("UNKNOWN", before.State);
        Assert.Equal((int)EffectCertainty.Unknown, before.Effect);
        Assert.NotNull(before.ResponseJson);
        Assert.False(before.Compacted);
        Assert.True(durable.CompactKnownResponses() > 0);
        Assert.Equal(before, durable.Inspect(original.Meta.CommandId.Value.Span));
    }

    private static string OtherRecoveryBoot(string current)
    {
        var separator = current.LastIndexOf(':');
        if (OperatingSystem.IsLinux())
        {
            return "linux:" + Guid.NewGuid().ToString("D") + current[separator..];
        }

        var currentSeconds = long.Parse(current.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture);
        return current[..(separator + 1)] + (currentSeconds - 1).ToString(CultureInfo.InvariantCulture);
    }

    private static void WriteStaleRecoveryOwnerFixture(string root, Run run, RecoveryBinding original,
        int unrelatedPid, string ownerBoot, string storeBoot)
    {
        // Only this stopped test Node's inputs are adjusted. Its Run and command effects remain the real prior journal.
        using var database = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(root),
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString());
        database.Open();
        using var transaction = database.BeginTransaction();
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE supervisor_identity SET process_id = $alias, boot_id = $ownerBoot
             WHERE run_id = $id AND process_id = $originalPid AND creation_identity = $creation AND control_epoch = $epoch;
            """;
        command.Parameters.AddWithValue("$alias", unrelatedPid);
        command.Parameters.AddWithValue("$ownerBoot", ownerBoot);
        command.Parameters.AddWithValue("$id", Hex(run.RunId));
        command.Parameters.AddWithValue("$originalPid", original.Pid);
        command.Parameters.AddWithValue("$creation", original.Creation);
        command.Parameters.AddWithValue("$epoch", run.Epoch);
        Assert.Equal(1, command.ExecuteNonQuery());
        command.CommandText = "UPDATE run_recovery SET boot_id = $storeBoot WHERE run_id = $id AND run_epoch = $epoch AND boot_id = $originalBoot;";
        command.Parameters.AddWithValue("$storeBoot", storeBoot);
        command.Parameters.AddWithValue("$originalBoot", original.StoreBoot);
        Assert.Equal(1, command.ExecuteNonQuery());
        transaction.Commit();
    }

    private static async Task RequireKnownRecoveryStartAsync(NodeService.NodeServiceClient node,
        RunServiceStartRequest original, Id runId, bool compacted)
    {
        var operation = await OperationAsync(node, original.OwnerEpoch, original.Meta.CommandId);
        Assert.Equal(original.Meta.CommandId, operation.CommandId);
        Assert.Equal(original.OwnerEpoch, operation.OwnerEpoch);
        Assert.Equal(runId, operation.AggregateId);
        Assert.Equal(OperationState.Succeeded, operation.State);
        Assert.Equal(EffectCertainty.Happened, operation.Effect);
        Assert.Equal(compacted, operation.ResponseCompacted);
    }

    private sealed record RecoveryBinding(string Instance, string Boot, int Pid, string Creation, string Endpoint,
        string Boundary, string Backend, string Cohort, string RunEpoch, string StoreBoot, long Generation);

    private sealed record RecoveryStopIntent(DateTimeOffset AcceptedAt, DateTimeOffset Deadline, string ReceiptState);

    private static RecoveryStopIntent ReadRecoveryStopIntent(string root, RunServiceStartRequest start,
        RunServiceStopRequest stop, string epoch)
    {
        using var database = ReadDatabase(root);
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT i.accepted_utc, i.deadline_utc, c.state
              FROM run_stop_intent AS i
              JOIN command_receipt AS c ON (c.owner_id, c.owner_epoch, c.command_id) = (i.owner_id, i.owner_epoch, i.command_id)
             WHERE i.run_id = $run AND i.run_epoch = $epoch AND i.owner_epoch = $ownerEpoch AND i.command_id = $stop
               AND i.pressure = 0 AND c.aggregate_kind = 'run' AND c.aggregate_id = $run AND c.safety_parent_command_id = $start;
            """;
        command.Parameters.AddWithValue("$run", Hex(stop.RunId));
        command.Parameters.AddWithValue("$epoch", epoch);
        command.Parameters.AddWithValue("$ownerEpoch", stop.OwnerEpoch.Value.ToByteArray());
        command.Parameters.AddWithValue("$stop", Hex(stop.Meta.CommandId));
        command.Parameters.AddWithValue("$start", Hex(start.Meta.CommandId));
        using var row = command.ExecuteReader();
        Assert.True(row.Read(), "The exact original Stop and Start must remain linked across recovery.");
        var result = new RecoveryStopIntent(DateTimeOffset.Parse(row.GetString(0), CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(row.GetString(1), CultureInfo.InvariantCulture), row.GetString(2));
        Assert.False(row.Read());
        return result;
    }

    private static RecoveryBinding ReadRecoveryBinding(string dataRoot, Run run)
    {
        using var database = ReadDatabase(dataRoot);
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT o.instance_id, o.boot_id, o.process_id, o.creation_identity, o.endpoint, o.boundary_identity,
                   o.backend_id, o.cohort, o.control_epoch, r.boot_id, r.control_generation
              FROM supervisor_identity AS o JOIN run_recovery AS r ON r.run_id = o.run_id
             WHERE o.run_id = $id AND r.run_epoch = o.control_epoch;
            """;
        command.Parameters.AddWithValue("$id", Hex(run.RunId));
        using var row = command.ExecuteReader();
        Assert.True(row.Read(), "The authenticated owner and durable recovery intent must agree on Run and boot identity.");
        var binding = new RecoveryBinding(row.GetString(0), row.GetString(1), row.GetInt32(2), row.GetString(3),
            row.GetString(4), row.GetString(5), row.GetString(6), row.GetString(7), row.GetString(8), row.GetString(9), row.GetInt64(10));
        Assert.Equal(run.Epoch, binding.RunEpoch);
        var currentBoot = BootIdentity.Read();
        if (OperatingSystem.IsLinux())
        {
            var machine = Guid.ParseExact(File.ReadAllText("/etc/machine-id").TrimEnd('\n'), "N");
            Assert.NotEqual(Guid.Empty, machine);
            var machineHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(machine.ToString("N"))));
            Assert.Equal(currentBoot + ":" + machineHash, binding.StoreBoot);
            Assert.Equal(currentBoot["linux:".Length..], binding.Boot);
        }
        else
        {
            Assert.Equal(currentBoot, binding.StoreBoot);
            Assert.Equal(currentBoot, binding.Boot);
        }

        Assert.False(row.Read());
        return binding;
    }

    private sealed class RecoveryNativeFixture(TestNode node) : IAsyncDisposable
    {
        private RunServiceStartRequest? _original;
        private NativeBoundary? _native;
        private Run? _running;
        private Process? _process;
        private Id? _ownerEpoch;
        private Id? _runId;
        private string? _marker;
        private string? _childMarker;
        private string? _windowsBreakawayImage;
        private string? _firstNodeEpoch;

        public TestNode Node { get; } = node;
        public RunServiceStartRequest Original => _original!;
        public Run Running => _running!;
        public NativeBoundary Native => _native!;
        public Process Process => _process!;
        public string FirstNodeEpoch => _firstNodeEpoch!;

        public static async Task<RecoveryNativeFixture> StartAsync(TerminalMode mode = TerminalMode.Interactive,
            bool checkWindowsBreakaway = false)
        {
            var fixture = new RecoveryNativeFixture(TestNode.Create());
            try
            {
                await fixture.StartRunAsync(mode, checkWindowsBreakaway);
                return fixture;
            }
            catch
            {
                await fixture.DisposeAsync();
                throw;
            }
        }

        private async Task StartRunAsync(TerminalMode mode, bool checkWindowsBreakaway)
        {
            PrepareDataRoot(Node.DataRoot);
            _process = await Node.StartNodeAsync();
            await using var channel = OpenChannel(Node);
            var nodeClient = new NodeService.NodeServiceClient(channel.CallInvoker);
            var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
            var runs = new RunService.RunServiceClient(channel.CallInvoker);
            var hello = await HandshakeAsync(nodeClient);
            _ownerEpoch = hello.OwnerEpoch;
            _firstNodeEpoch = hello.NodeEpoch;
            var sandbox = await CreateSandboxAsync(sandboxes, _ownerEpoch);
            var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
            Directory.CreateDirectory(working);
            _marker = Path.Combine(working, MarkerName);
            _childMarker = Path.Combine(working, ChildMarkerName);
            var argv = OperatingSystem.IsWindows() && checkWindowsBreakaway
                ? PrepareWindowsBreakaway(working) : PreparePayload(working);
            _original = BuildStart(sandbox, _ownerEpoch, argv);
            if (mode == TerminalMode.Pipes)
            {
                _original.TerminalMode = mode;
                _original.TerminalSize = null;
            }

            var reply = await runs.StartAsync(_original, deadline: Deadline, cancellationToken: Ct);
            _runId = Value(reply.Value, reply.Error).Run.RunId;
            _running = await WaitForStateAsync(Node, runs, _runId, RunState.Running);
            await TestNode.WaitAsync(() => ChildIsReady(_childMarker), NativeBound, "the original recovery payload to start");
            RequireOneEntry();
            _native = await ObserveBoundaryAsync(_running, runs);
        }

        public async Task<NativeBoundary> ObserveBoundaryAsync(Run run, RunService.RunServiceClient runs)
        {
            if (!OperatingSystem.IsWindows() || _windowsBreakawayImage is null)
            {
                return await ObserveNativeBoundaryAsync(Node, run, _childMarker!, recoveryReadback: runs);
            }

            var binding = ReadRecoveryBinding(Node.DataRoot, run);
            var owner = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(binding.Pid));
            Assert.Equal(binding.Creation, new DateTime(owner.StartKey, DateTimeKind.Utc).ToFileTimeUtc().ToString(CultureInfo.InvariantCulture));
            var payload = Assert.Single(WindowsBreakawayProcesses());
            RequireWindowsBreakawayRefusal(payload, live: true);
            return new NativeBoundary(owner, payload, null);
        }

        [SupportedOSPlatform("windows")]
        private string[] PrepareWindowsBreakaway(string working)
        {
            InstallWindowsTestLoad(working);
            var imageName = "arcforges-recovery-" + Guid.NewGuid().ToString("N") + ".exe";
            _windowsBreakawayImage = Path.Combine(working, imageName);
            File.Move(Path.Combine(working, "arcforges-testload.exe"), _windowsBreakawayImage);
            const string script = """
                @echo off
                >>entered.log echo %~1,%CORE02_PAYLOAD_MARKER%
                ".\%~2" signal --child breakaway --on-break ignore --hold-ms 120000 --child-hold-ms 30000 --marker child.log
                """;
            File.WriteAllText(Path.Combine(working, "fixture.cmd"), script.ReplaceLineEndings("\r\n") + "\r\n");
            return [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "fixture.cmd", FixtureArgument, imageName];
        }

        [SupportedOSPlatform("windows")]
        public void RequireWindowsBreakawayRefusal(ProcessIdentity payload, bool live)
        {
            var lines = ReadLines(_childMarker!);
            Assert.DoesNotContain(lines, line => line.StartsWith("breakaway-allowed ", StringComparison.Ordinal));
            foreach (var milestone in new[] { "breakaway-refused", "ready" })
            {
                var observed = Assert.Single(lines, line => line.StartsWith(milestone + " ", StringComparison.Ordinal)).Split(' ');
                Assert.Equal(payload.Pid.ToString(CultureInfo.InvariantCulture), observed[1]);
            }

            var sameImage = WindowsBreakawayProcesses();
            if (live)
            {
                Assert.Equal(payload, Assert.Single(sameImage));
            }
            else
            {
                Assert.Empty(sameImage);
            }
        }

        [SupportedOSPlatform("windows")]
        private List<ProcessIdentity> WindowsBreakawayProcesses()
        {
            var matches = new List<ProcessIdentity>();
            foreach (var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(_windowsBreakawayImage!)))
            {
                using (process)
                {
                    if (process.HasExited || ProcessIdentity.Capture(process.Id) is not { } identity) continue;
                    Assert.Equal(_windowsBreakawayImage, process.MainModule?.FileName, ignoreCase: true);
                    matches.Add(identity);
                }
            }

            return matches;
        }

        public void RequireOneEntry() => Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(_marker!)));

        public async Task CrashNodeAsync(CancellationToken cancellationToken)
        {
            Assert.False(Process.HasExited);
            Assert.NotEqual(Process.Id, Native.Supervisor.Pid);
            Assert.NotEqual(Process.Id, Native.Payload.Pid);
            Process.Kill();
            await Process.WaitForExitAsync(cancellationToken).WaitAsync(NativeBound, cancellationToken);
        }

        public async Task RestartNodeAsync()
        {
            Assert.True(Process.HasExited);
            _process = await Node.StartNodeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (_process is { HasExited: false } && _ownerEpoch is not null && _runId is not null)
                {
                    await using var channel = OpenChannel(Node);
                    var runs = new RunService.RunServiceClient(channel.CallInvoker);
                    var run = await InspectAsync(runs, _runId, CancellationToken.None);
                    if (run.State is RunState.Running or RunState.Starting)
                    {
                        await StopAsync(runs, BuildStop(_ownerEpoch, run), CancellationToken.None);
                        await WaitForStateAsync(Node, runs, _runId, RunState.Exited, CancellationToken.None);
                    }
                }
            }
            finally
            {
                try
                {
                    if (_process is not null) await StopNodeAsync(Node, _process);
                    if (_native is not null)
                    {
                        using (_native)
                        {
                            if (_native.Supervisor.IsRunning())
                            {
                                var birth = OperatingSystem.IsWindows()
                                    ? new DateTime(_native.Supervisor.StartKey, DateTimeKind.Utc).ToFileTimeUtc()
                                    : _native.Supervisor.StartKey;
                                KillExactTerminalSupervisor(_native.Supervisor, birth.ToString(CultureInfo.InvariantCulture));
                            }

                            await TestNode.WaitAsync(_native.IsEmpty, NativeBound, "the test-owned native recovery workload to drain");
                        }
                    }

                    if (_ownerEpoch is not null) RemoveFixtureOwnerKey(Node.DataRoot, _ownerEpoch);
                }
                finally
                {
                    await Node.DisposeAsync();
                }
            }
        }
    }
}
