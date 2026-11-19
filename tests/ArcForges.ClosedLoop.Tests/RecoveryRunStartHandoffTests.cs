// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.RunSupervisor.Protocol;
using ArcForges.Tests;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [InlineData("hold-run-before-start-receipt")]
    [InlineData("hold-run-before-prepare")]
    [InlineData("hold-run-before-activate")]
    public async Task InstalledRecoveryNeverReleasesAnInterruptedStartHandoff(string checkpoint)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        bool beforeReceipt = checkpoint == "hold-run-before-start-receipt";
        bool beforeActivate = checkpoint == "hold-run-before-activate";

        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        fixture.Environment[ExecutionFaults.Variable] = checkpoint + "=60";
        var interrupted = await fixture.StartNodeAsync();
        Process? restarted = null;
        Process? originalOwner = null;
        LinuxRunCgroup? originalScope = null;
        Id? ownerEpoch = null;
        var faultMarker = Path.Combine(fixture.DataRoot, "run", "fault-" + checkpoint + ".done");
        var unrelatedMarker = Path.Combine(fixture.Root, "start-handoff-unrelated.log");
        using var unrelated = fixture.Start(TestNode.TestLoad, ["hold", "--hold-ms", "120000", "--marker", unrelatedMarker]);
        try
        {
            await TestNode.WaitAsync(() => ReadLines(unrelatedMarker).Any(line => line.StartsWith("ready ", StringComparison.Ordinal)),
                NativeBound, "the unrelated native process outside the Run");
            var sentinel = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(unrelated.Id));
            RunServiceStartRequest request;
            string payloadMarker;
            string initialNodeEpoch;
            Run? admitted;
            await using (var channel = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                var hello = await HandshakeAsync(node);
                ownerEpoch = hello.OwnerEpoch;
                initialNodeEpoch = hello.NodeEpoch;
                var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch);
                var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
                Directory.CreateDirectory(working);
                payloadMarker = Path.Combine(working, MarkerName);
                request = BuildStart(sandbox, ownerEpoch, PrepareStartHandoffPayload(working, payloadMarker));
                request.TerminalMode = TerminalMode.Pipes;
                request.TerminalSize = null;

                using var submission = runs.StartAsync(request, deadline: Deadline, cancellationToken: cancellationToken);
                await TestNode.WaitAsync(() => File.Exists(faultMarker), NativeBound, "the durable Start checkpoint " + checkpoint);
                var captured = ReadStartHandoff(fixture.DataRoot, request);
                admitted = captured.Run;
                if (beforeReceipt)
                {
                    Assert.Null(captured.Receipt);
                    Assert.Null(admitted);
                    Assert.Null(captured.PrepareStarted);
                    Assert.Equal(0, captured.ReservedLimits);
                }
                else
                {
                    Assert.Equal("ACCEPTED", captured.Receipt);
                    Assert.NotNull(admitted);
                    Assert.Equal(beforeActivate, captured.PrepareStarted);
                    Assert.Equal(beforeActivate ? 0 : 3, captured.ReservedLimits);
                }

                if (beforeActivate)
                {
                    Assert.Equal(3, captured.VerifiedNativeLimits);
                    var binding = ReadRecoveryBinding(fixture.DataRoot, admitted!);
                    Assert.Equal(sandbox.Config.ProfileId, binding.Backend);
                    Assert.Equal(sandbox.Config.ProfileVersion, binding.Cohort);
                    Assert.Equal(0, binding.Generation);
                    Assert.NotEqual(interrupted.Id, binding.Pid);
                    var identity = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(binding.Pid));
                    originalOwner = Process.GetProcessById(identity.Pid);
                    var birth = OperatingSystem.IsWindows() ? originalOwner.StartTime.ToUniversalTime().ToFileTimeUtc() : identity.StartKey;
                    Assert.Equal(binding.Creation, birth.ToString(CultureInfo.InvariantCulture));
                    if (OperatingSystem.IsWindows()) RequirePreparedSupervisorInJob(originalOwner);
                    if (OperatingSystem.IsLinux())
                    {
                        var owner = new RunOwnerIdentity(binding.Instance, binding.Boot, binding.Pid, binding.Creation,
                            binding.Endpoint, binding.Boundary, binding.Backend, binding.Cohort, binding.RunEpoch);
                        originalScope = HoldPreparedLinuxScope(owner, identity);
                    }

                    var control = Path.Combine(fixture.DataRoot, "control", "run-" + Hex(admitted!.RunId));
                    Assert.True(File.Exists(Path.Combine(control, "launch.json")));
                    Assert.False(File.Exists(Path.Combine(control, "windows-prepared.json")));
                }
                else
                {
                    Assert.Null(captured.OwnerPid);
                    Assert.Equal(0, captured.VerifiedNativeLimits);
                    Assert.Empty(Directory.EnumerateDirectories(Path.Combine(fixture.DataRoot, "control"), "run-*"));
                }

                Assert.False(File.Exists(payloadMarker));
                interrupted.Kill();
                await interrupted.WaitForExitAsync(cancellationToken).WaitAsync(NativeBound, cancellationToken);
                try
                {
                    var accepted = await submission.ResponseAsync.WaitAsync(NativeBound, cancellationToken);
                    Assert.False(beforeReceipt);
                    Assert.Equal(admitted!.RunId, Value(accepted.Value, accepted.Error).Run.RunId);
                }
                catch (RpcException error) when (error.StatusCode is StatusCode.Unavailable or StatusCode.Cancelled)
                {
                    // Killing the Node can close the RPC on either side of sending the accepted receipt.
                }
            }

            if (originalOwner is not null)
            {
                await originalOwner.WaitForExitAsync(cancellationToken).WaitAsync(NativeBound, cancellationToken);
                if (OperatingSystem.IsLinux() && originalScope is not null)
                {
                    await TestNode.WaitAsync(originalScope.IsEmpty, NativeBound, "the held prepared cgroup to empty");
                }
            }

            fixture.Environment.Remove(ExecutionFaults.Variable);
            restarted = await fixture.StartNodeAsync();
            await using var recovered = OpenChannel(fixture);
            var recoveredNode = new NodeService.NodeServiceClient(recovered.CallInvoker);
            var recoveredRuns = new RunService.RunServiceClient(recovered.CallInvoker);
            var recoveredHello = await HandshakeAsync(recoveredNode);
            Assert.Equal(ownerEpoch, recoveredHello.OwnerEpoch);
            Assert.NotEqual(initialNodeEpoch, recoveredHello.NodeEpoch);
            if (beforeReceipt)
            {
                var absent = await recoveredNode.GetOperationAsync(new NodeServiceGetOperationRequest
                {
                    Meta = Query(),
                    OwnerEpoch = ownerEpoch,
                    CommandId = request.Meta.CommandId,
                }, deadline: Deadline, cancellationToken: cancellationToken);
                Assert.Equal("not_found", absent.Error?.Code);
                Assert.Empty(await ListAsync(recoveredRuns, request.SandboxId));
            }
            else
            {
                await RequireInterruptedStartReplayAsync(recoveredNode, recoveredRuns, request, admitted!, beforeActivate,
                    cancellationToken);
            }

            Assert.True(sentinel.IsRunning());
            Assert.False(File.Exists(payloadMarker));
            TestContext.Current.TestOutputHelper?.WriteLine("The installed Node was killed at " + checkpoint
                + ". Recovery preserved its actual command and native-scope evidence without releasing the payload.");
        }
        finally
        {
            if (OperatingSystem.IsLinux()) originalScope?.Dispose();
            originalOwner?.Dispose();
            if (!interrupted.HasExited && File.Exists(faultMarker))
            {
                File.WriteAllText(Path.ChangeExtension(faultMarker, ".release"), string.Empty);
            }

            await StopNodeAsync(fixture, interrupted);
            if (restarted is not null) await StopNodeAsync(fixture, restarted);
            if (!unrelated.HasExited)
            {
                unrelated.Kill();
                await unrelated.WaitForExitAsync(cancellationToken).WaitAsync(NativeBound, cancellationToken);
            }

            if (ownerEpoch is not null) RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
        }
    }

    private static string[] PrepareStartHandoffPayload(string working, string marker)
    {
        if (!OperatingSystem.IsWindows()) return ["/usr/bin/dash", "-c", "printf 'entered\\n' >> entered.log"];

        InstallWindowsTestLoad(working);
        return [Path.Combine(working, "arcforges-testload.exe"), "hold", "--hold-ms", "300", "--marker", marker];
    }

    private static StartHandoff ReadStartHandoff(string dataRoot, RunServiceStartRequest request)
    {
        using var database = ReadDatabase(dataRoot);
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT c.state, r.run_id, r.epoch, r.launch_sha256, d.prepare_started, o.process_id, c.aggregate_id,
                   (SELECT count(*) FROM limit_application AS l
                    WHERE l.run_id = r.run_id AND l.dimension IN ('cpu', 'memory', 'pids')
                      AND l.state = 'pending' AND l.boundary_identity = ''),
                   (SELECT count(*) FROM limit_application AS l
                    WHERE l.run_id = r.run_id AND l.boundary_identity = o.boundary_identity
                      AND l.dimension IN ('cpu', 'memory', 'pids') AND l.state = 'effective'
                      AND l.applied_value = l.readback_value AND l.readback_utc IS NOT NULL
                      AND CAST(l.readback_value AS INTEGER) > 0)
              FROM sandbox AS s
              LEFT JOIN command_receipt AS c ON c.owner_id = s.owner_id AND c.owner_epoch = $epoch AND c.command_id = $command
              LEFT JOIN run AS r ON r.sandbox_id = s.sandbox_id
              LEFT JOIN run_recovery AS d ON d.run_id = r.run_id AND d.run_epoch = r.epoch
              LEFT JOIN supervisor_identity AS o ON o.run_id = r.run_id AND o.control_epoch = r.epoch
             WHERE s.sandbox_id = $sandbox;
            """;
        command.Parameters.AddWithValue("$sandbox", Hex(request.SandboxId));
        command.Parameters.AddWithValue("$epoch", request.OwnerEpoch.Value.ToByteArray());
        command.Parameters.AddWithValue("$command", Hex(request.Meta.CommandId));
        using var row = command.ExecuteReader();
        Assert.True(row.Read());
        var run = row.IsDBNull(1) ? null : new Run
        {
            RunId = new Id { Value = ByteString.CopyFrom(Convert.FromHexString(row.GetString(1))) },
            Epoch = row.GetString(2),
            LaunchSha256 = row.GetString(3),
        };
        if (run is not null) Assert.Equal(Hex(run.RunId), row.GetString(6));
        var result = new StartHandoff(row.IsDBNull(0) ? null : row.GetString(0), run,
            row.IsDBNull(4) ? null : row.GetBoolean(4), row.IsDBNull(5) ? null : row.GetInt32(5), row.GetInt32(7), row.GetInt32(8));
        Assert.False(row.Read());
        return result;
    }

    private static async Task RequireInterruptedStartReplayAsync(NodeService.NodeServiceClient node, RunService.RunServiceClient runs,
        RunServiceStartRequest request, Run original, bool afterOwnerBinding, CancellationToken cancellationToken)
    {
        var run = Assert.Single(await ListAsync(runs, request.SandboxId));
        Assert.Equal(original.RunId, run.RunId);
        Assert.Equal(original.Epoch, run.Epoch);
        Assert.Equal(original.LaunchSha256, run.LaunchSha256);
        Assert.Null(run.StartedAt);
        if (afterOwnerBinding) Assert.True(run.State is RunState.Failed or RunState.Exited or RunState.RecoveryRequired);
        else Assert.Equal(RunState.Failed, run.State);

        if (run.State == RunState.RecoveryRequired)
        {
            Assert.Null(run.Exit);
        }
        else
        {
            Assert.True(run.Exit.GroupEmptyVerified);
            Assert.False(run.Exit.HasRawCode);
            if (!afterOwnerBinding) Assert.Equal("recovered_before_owner_prepare", run.Exit.TerminationReason);
        }

        var command = await OperationAsync(node, request.OwnerEpoch, request.Meta.CommandId);
        Assert.Equal(original.RunId, command.AggregateId);
        Assert.Equal(request.OwnerEpoch, command.OwnerEpoch);
        Assert.Equal(request.Meta.CommandId, command.CommandId);
        Assert.Equal("RunService.Start", command.Method);
        bool failed = run.State == RunState.Failed;
        Assert.Equal(failed ? OperationState.Failed : OperationState.Unknown, command.State);
        Assert.Equal(failed ? EffectCertainty.DidNotHappen : EffectCertainty.Unknown, command.Effect);

        var replay = await runs.StartAsync(request, deadline: Deadline, cancellationToken: cancellationToken);
        Assert.Null(replay.Value);
        Assert.Equal(failed ? "launch_failed" : "outcome_unknown", replay.Error?.Code);
        Assert.Equal(command, await OperationAsync(node, request.OwnerEpoch, request.Meta.CommandId));
        Assert.Equal(run, Assert.Single(await ListAsync(runs, request.SandboxId)));
    }

    [SupportedOSPlatform("windows")]
    private static void RequirePreparedSupervisorInJob(Process supervisor)
    {
        Assert.True(IsPreparedProcessInJob(supervisor.SafeHandle, 0, out var contained));
        Assert.True(contained);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "IsProcessInJob", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsPreparedProcessInJob(SafeProcessHandle process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);

    private sealed record StartHandoff(string? Receipt, Run? Run, bool? PrepareStarted, int? OwnerPid, int ReservedLimits,
        int VerifiedNativeLimits);
}
