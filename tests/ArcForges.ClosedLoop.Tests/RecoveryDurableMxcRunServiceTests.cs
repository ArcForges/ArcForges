// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const int RecoveryReceiptLimit = 10;
    private static readonly string[] RecoveryGrantMethods =
    [
        "/arcforges.sandbox.v2.NodeService/GetOperation",
        "/arcforges.sandbox.v2.NodeService/RevokeRemoteGrant",
        "/arcforges.sandbox.v2.RunService/Start",
    ];

    [Fact(Timeout = 240_000, DisableParallelization = true)]
    public async Task InstalledRecoveryKeepsReservedNativeStopAndGrantRevocationWhenOrdinaryAdmissionIsFull()
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        if (OperatingSystem.IsWindows() && !Path.GetFileName(WindowsMxcProcess.CurrentImagePath()).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            await RunFixtureFromTrustedRuntimeAsync(nameof(InstalledRecoveryKeepsReservedNativeStopAndGrantRevocationWhenOrdinaryAdmissionIsFull),
                TimeSpan.FromSeconds(210));
            return;
        }

        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        string owner = Assert.IsType<string>(SandboxLocalOwner.Current());
        var secrets = NodeSecretStores.ForTestDataRoot(fixture.DataRoot);
        var earlier = Path.Combine(fixture.Root, "earlier-backup");
        var latest = Path.Combine(fixture.Root, "latest-backup");
        var restoreParent = Path.Combine(fixture.Root, "restore-work");
        PrepareDataRoot(restoreParent);
        var restored = Path.Combine(restoreParent, "verified-restore");
        var refused = Path.Combine(fixture.Root, "refused-restore");
        Id ownerEpoch;
        using (var store = OpenRecoveryStore(fixture.DataRoot))
        using (var commands = new DurableCommandStore(store, owner, secrets,
            new DurableCapacity(MaximumReceipts: RecoveryReceiptLimit, SafetyReceipts: 3)))
        {
            ownerEpoch = new Id { Value = ByteString.CopyFrom(commands.OwnerEpoch.Span) };
        }

        try
        {
            Sandbox primary;
            Sandbox unused;
            var installed = await fixture.StartNodeAsync();
            try
            {
                await using var channel = OpenChannel(fixture);
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                Assert.Equal(ownerEpoch, (await HandshakeAsync(node)).OwnerEpoch);
                primary = await CreateSandboxAsync(sandboxes, ownerEpoch);
                var other = await sandboxes.CreateAsync(new SandboxServiceCreateRequest
                {
                    Meta = Mutation(),
                    OwnerEpoch = ownerEpoch,
                    DisplayName = "Unused native recovery fixture",
                    Config = primary.Config.Clone(),
                }, deadline: Deadline, cancellationToken: cancellation);
                unused = Value(other.Value, other.Error).Sandbox;
                Assert.NotEqual(primary.SandboxId, unused.SandboxId);
            }
            finally
            {
                await StopNodeAsync(fixture, installed);
            }

            CreateRecoveryBackup(fixture.DataRoot, owner, secrets, earlier);
            var effects = await ExerciseReservedRecoveryAsync(fixture, owner, ownerEpoch, primary, unused, cancellation);

            var fencePath = DurableEpochFence.PathFor(fixture.DataRoot, owner);
            var latestFence = await File.ReadAllBytesAsync(fencePath, cancellation);
            Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(earlier,
                NodeSecretStores.ForTestDataRoot(earlier), fixture.DataRoot, secrets, refused,
                NodeSecretStores.ForTestDataRoot(refused)));
            Assert.False(File.Exists(StorePaths.Database(refused)));
            Assert.Equal(latestFence, await File.ReadAllBytesAsync(fencePath, cancellation));

            CreateRecoveryBackup(fixture.DataRoot, owner, secrets, latest);
            DurableCommandStore.RestoreBackup(latest, NodeSecretStores.ForTestDataRoot(latest), fixture.DataRoot,
                secrets, restored, NodeSecretStores.ForTestDataRoot(restored));
            RequireRestoredRecoveryReceipts(restored, owner, ownerEpoch, effects);
            await RequireInstalledMaintenanceOnStaleDatabaseAsync(fixture, earlier, restored, owner, effects, cancellation);
            await RequireFreshAuthorityRejectsSavedRequestsAsync(ownerEpoch, effects, cancellation);

            Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(effects.Marker)));
            Assert.Equal(latestFence, await File.ReadAllBytesAsync(fencePath, cancellation));
            TestContext.Current.TestOutputHelper?.WriteLine("Live native Run and active grant exhausted ordinary admission. Their reserved Stop and revocation completed. A coherent backup restored the original receipts. The installed Node refused stale history and a fresh owner epoch rejected the saved original requests.");
        }
        finally
        {
            RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
        }
    }

    private static async Task<ReservedRecoveryEffects> ExerciseReservedRecoveryAsync(TestNode fixture, string owner,
        Id ownerEpoch, Sandbox primary, Sandbox unused, CancellationToken cancellation)
    {
        // Use the existing in-process enrollment input with the real Node host, LocalRpc,
        // platform, archive worker and Store. No remote connection is needed to set a local grant.
        var enrollmentId = CommandIds.New();
        const string fixtureAudience = "https://recovery-fixture.example.invalid";
        var enrollment = new ActiveRemoteEnrollment(owner, Hex(enrollmentId), Hex(CommandIds.New()),
            fixtureAudience, fixtureAudience, Hex(CommandIds.New()));
        using var stop = new CancellationTokenSource();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new NodeHostOptions
        {
            ConfigPath = Path.Combine(fixture.ConfigDirectory, "node.json"),
            Endpoint = OperatingSystem.IsWindows() ? LocalRpcEndpoint.NamedPipe(fixture.Endpoint)
                : LocalRpcEndpoint.UnixDomainSocket(fixture.Endpoint),
            TestMode = true,
            SecretStore = NodeSecretStores.ForTestDataRoot,
            NodeKeys = NodeKeyStores.ForTestDataRoot,
            SandboxMxcInstallationRoot = Path.Combine(Path.GetDirectoryName(TestNode.Host)!, "mxc"),
            BeforeReady = runtime =>
            {
                var manager = Assert.IsType<SandboxManager>(runtime.Sandboxes);
                manager.UpdateRemoteEnrollment(enrollment);
                return Task.CompletedTask;
            },
            Ready = _ => ready.TrySetResult(),
            Output = TextWriter.Null,
            Error = TextWriter.Null,
        };
        var serving = Task.Run(() => NodeHost.RunAsync(options, stop.Token), cancellation);
        try
        {
            var first = await Task.WhenAny(ready.Task, serving).WaitAsync(NativeBound, cancellation);
            if (first == serving)
            {
                Assert.Fail($"The recovery fixture Node exited before readiness with status {await serving}.");
            }

            await using var channel = OpenChannel(fixture);
            return await FillOrdinaryRecoveryCapacityAsync(fixture, channel, ownerEpoch, enrollmentId, primary, unused,
                cancellation);
        }
        finally
        {
            await stop.CancelAsync();
            Assert.Equal(NodeExitCodes.Success, await serving.WaitAsync(NativeBound, CancellationToken.None));
        }
    }

    private static async Task<ReservedRecoveryEffects> FillOrdinaryRecoveryCapacityAsync(TestNode fixture, NodeChannel channel,
        Id ownerEpoch, Id enrollmentId, Sandbox primary, Sandbox unused, CancellationToken cancellation)
    {
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var runs = new RunService.RunServiceClient(channel.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
        Assert.Equal(ownerEpoch, (await HandshakeAsync(node)).OwnerEpoch);
        var set = new NodeServiceSetRemoteGrantRequest
        {
            Meta = Mutation(),
            OwnerEpoch = ownerEpoch,
            Grant = new RemoteGrant
            {
                GrantId = CommandIds.New(),
                EnrollmentId = enrollmentId,
                ScopeKind = "sandbox",
                SandboxId = primary.SandboxId,
                Methods = { RecoveryGrantMethods },
            },
        };
        var granted = await node.SetRemoteGrantAsync(set, deadline: Deadline, cancellationToken: cancellation);
        var grant = Value(granted.Value, granted.Error).Grant;
        Assert.Equal(GrantState.Active, grant.State);

        var working = Directory.CreateDirectory(Path.Combine(primary.DataLocation, "work", "quoted directory")).FullName;
        var start = BuildStart(primary, ownerEpoch, PreparePayload(working));
        start.TerminalMode = TerminalMode.Pipes;
        start.TerminalSize = null;
        var started = await runs.StartAsync(start, deadline: Deadline, cancellationToken: cancellation);
        var runId = Value(started.Value, started.Error).Run.RunId;
        var marker = Path.Combine(working, MarkerName);
        var childMarker = Path.Combine(working, ChildMarkerName);
        var drained = false;
        try
        {
            var running = await WaitForStateAsync(fixture, runs, runId, RunState.Running, cancellation);
            await TestNode.WaitAsync(() => ChildIsReady(childMarker), NativeBound, "the native recovery capacity fixture's child");
            using var native = await ObserveNativeBoundaryAsync(fixture, running, childMarker, runs);
            Assert.False(native.IsEmpty());
            Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(marker)));

            var saturated = await ExhaustOrdinaryRecoveryCapacityAsync(sandboxes, ownerEpoch, unused, cancellation);
            Assert.Equal(RecoveryReceiptLimit - 2, RecoveryReceiptCount(fixture.DataRoot));
            var unusedWork = Directory.CreateDirectory(Path.Combine(saturated.DataLocation, "work", "quoted directory")).FullName;
            var blocked = BuildStart(saturated, ownerEpoch, PreparePayload(unusedWork));
            blocked.TerminalMode = TerminalMode.Pipes;
            blocked.TerminalSize = null;
            var refusal = await runs.StartAsync(blocked, deadline: Deadline, cancellationToken: cancellation);
            Assert.Null(refusal.Value);
            var refusalError = Assert.IsType<ArcError>(refusal.Error);
            Assert.Equal(ErrorCategory.Resource, refusalError.Category);
            Assert.Equal("budget_unavailable", refusalError.Code);
            Assert.Equal("operation_capacity", refusalError.Details?.State?.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, refusalError.Effect);
            Assert.False(File.Exists(Path.Combine(unusedWork, MarkerName)));
            Assert.False(File.Exists(Path.Combine(unusedWork, ChildMarkerName)));
            Assert.Empty(await ListAsync(runs, saturated.SandboxId));
            var missing = await node.GetOperationAsync(new NodeServiceGetOperationRequest
            {
                Meta = Query(),
                OwnerEpoch = ownerEpoch,
                CommandId = blocked.Meta.CommandId,
            }, deadline: Deadline, cancellationToken: cancellation);
            Assert.Equal("not_found", missing.Error?.Code);
            Assert.Null(missing.Value);
            var original = await OperationAsync(node, ownerEpoch, start.Meta.CommandId);
            Assert.Equal(runId, original.AggregateId);
            Assert.Equal(ownerEpoch, original.OwnerEpoch);
            Assert.Equal(start.Meta.CommandId, original.CommandId);
            Assert.False(original.ResponseCompacted);

            var stop = BuildStop(ownerEpoch, await InspectAsync(runs, runId, cancellation));
            // A pipe-only workload keeps running during the grace period. This makes the
            // actual unresolved Stop observable while both reserved admissions compete.
            stop.GraceMs = 10_000;
            var pending = await StopAsync(runs, stop, cancellation);
            Assert.Equal(OperationState.Accepted, pending.Operation.State);
            Assert.Equal(EffectCertainty.Unknown, pending.Operation.Effect);
            Assert.Equal(runId, pending.Operation.AggregateId);
            Assert.Equal(stop.Meta.CommandId, pending.Operation.CommandId);
            var observed = await OperationAsync(node, ownerEpoch, stop.Meta.CommandId);
            Assert.Equal(runId, observed.AggregateId);
            Assert.Equal(pending.Operation.CommandId, observed.CommandId);
            Assert.Equal(ownerEpoch, observed.OwnerEpoch);
            Assert.Equal(OperationState.Accepted, observed.State);
            Assert.Equal(EffectCertainty.Unknown, observed.Effect);
            Assert.False(observed.ResponseCompacted);
            Assert.True(native.Payload.IsRunning());

            var revoke = new NodeServiceRevokeRemoteGrantRequest
            {
                Meta = Mutation(grant.Revision),
                OwnerEpoch = ownerEpoch,
                GrantId = set.Grant.GrantId,
            };
            var revoked = await node.RevokeRemoteGrantAsync(revoke, deadline: Deadline, cancellationToken: cancellation);
            var revokedGrant = Value(revoked.Value, revoked.Error).Grant;
            Assert.Equal(GrantState.Revoked, revokedGrant.State);
            Assert.Equal(grant.Revision.Value + 1, revokedGrant.Revision.Value);
            Assert.True(native.Supervisor.IsRunning());
            Assert.True(native.Payload.IsRunning());
            Assert.Equal(RecoveryReceiptLimit, RecoveryReceiptCount(fixture.DataRoot));
            var replay = await node.RevokeRemoteGrantAsync(revoke, deadline: Deadline, cancellationToken: cancellation);
            Assert.Equal(revokedGrant, Value(replay.Value, replay.Error).Grant);

            var settled = await WaitForStateAsync(fixture, runs, runId, RunState.Exited, cancellation);
            Assert.True(settled.Exit.GroupEmptyVerified);
            Assert.True(native.IsEmpty());
            drained = true;
            var replayStop = await StopAsync(runs, stop, cancellation);
            Assert.Equal(settled, replayStop.Run);
            AssertStopReceipt(await OperationAsync(node, ownerEpoch, stop.Meta.CommandId), stop,
                settled.Revision, EffectCertainty.Happened);
            var revokeReceipt = await OperationAsync(node, ownerEpoch, revoke.Meta.CommandId);
            Assert.Equal(grant.GrantId, revokeReceipt.AggregateId);
            Assert.Equal(ownerEpoch, revokeReceipt.OwnerEpoch);
            Assert.Equal(revoke.Meta.CommandId, revokeReceipt.CommandId);
            Assert.Equal(OperationState.Succeeded, revokeReceipt.State);
            Assert.Equal(EffectCertainty.Happened, revokeReceipt.Effect);
            Assert.False(revokeReceipt.ResponseCompacted);

            Assert.False(File.Exists(Path.Combine(unusedWork, MarkerName)));
            Assert.False(File.Exists(Path.Combine(unusedWork, ChildMarkerName)));
            Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(marker)));
            return new(start, stop, set, revoke, marker, blocked.Meta.CommandId);
        }
        finally
        {
            if (!drained)
            {
                var remaining = await InspectAsync(runs, runId, CancellationToken.None);
                if (remaining.State is RunState.Starting or RunState.Running)
                {
                    await StopAsync(runs, BuildStop(ownerEpoch, remaining), CancellationToken.None);
                }

                if (remaining.State is RunState.Starting or RunState.Running or RunState.Stopping or RunState.Draining)
                {
                    await WaitForStateAsync(fixture, runs, runId, RunState.Exited, CancellationToken.None);
                }
            }
        }
    }

    private static async Task<Sandbox> ExhaustOrdinaryRecoveryCapacityAsync(SandboxService.SandboxServiceClient sandboxes,
        Id ownerEpoch, Sandbox unused, CancellationToken cancellation)
    {
        int committed = 0;
        for (int i = 0; i < RecoveryReceiptLimit; i++)
        {
            var response = await sandboxes.ConfigureAsync(new SandboxServiceConfigureRequest
            {
                Meta = Mutation(unused.Revision),
                OwnerEpoch = ownerEpoch,
                SandboxId = unused.SandboxId,
                Config = unused.Config.Clone(),
                DisplayName = "Recovery ordinary receipt " + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
            }, deadline: Deadline, cancellationToken: cancellation);
            if (response.Error is { } error)
            {
                Assert.Equal(ErrorCategory.Resource, error.Category);
                Assert.Equal("disk_space", error.Code);
                Assert.Equal("durable_receipt_capacity", error.Details?.State?.Reason);
                Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
                Assert.True(committed > 0);
                return unused;
            }

            var configured = Value(response.Value, response.Error).Sandbox;
            Assert.Equal(unused.SandboxId, configured.SandboxId);
            Assert.Equal(unused.Revision.Value + 1, configured.Revision.Value);
            unused = configured;
            committed++;
        }

        throw new InvalidOperationException("The fixture reached its configured ordinary receipt count without an admission refusal.");
    }

    private static NodeStore OpenRecoveryStore(string dataRoot) =>
        NodeStore.Open(new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = BootIdentity.Read() });

    private static long RecoveryReceiptCount(string dataRoot)
    {
        using var database = ReadDatabase(dataRoot);
        using var command = database.CreateCommand();
        command.CommandText = "SELECT count(*) FROM command_receipt;";
        return Assert.IsType<long>(command.ExecuteScalar());
    }

    private static void CreateRecoveryBackup(string dataRoot, string owner, NodeSecretStore secrets, string backupRoot)
    {
        using var store = OpenRecoveryStore(dataRoot);
        using var commands = new DurableCommandStore(store, owner, secrets);
        commands.CreateBackup(backupRoot, NodeSecretStores.ForTestDataRoot(backupRoot));
        Assert.True(store.Checkpoint());
    }

    private static void RequireRestoredRecoveryReceipts(string dataRoot, string owner, Id ownerEpoch, ReservedRecoveryEffects effects)
    {
        using var store = OpenRecoveryStore(dataRoot);
        using var commands = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(dataRoot));
        Assert.False(commands.MaintenanceRequired);
        Assert.True(commands.OwnerEpoch.Span.SequenceEqual(ownerEpoch.Value.Span));
        var start = Assert.IsType<DurableReceipt>(commands.Inspect(effects.Start.Meta.CommandId.Value.Span));
        var stop = Assert.IsType<DurableReceipt>(commands.Inspect(effects.Stop.Meta.CommandId.Value.Span));
        var set = Assert.IsType<DurableReceipt>(commands.Inspect(effects.Set.Meta.CommandId.Value.Span));
        var revoke = Assert.IsType<DurableReceipt>(commands.Inspect(effects.Revoke.Meta.CommandId.Value.Span));
        Assert.Equal(Hex(effects.Stop.RunId), start.AggregateId);
        Assert.Equal(start.AggregateId, stop.AggregateId);
        Assert.Equal(start.CommandId, stop.SafetyParentCommandId);
        Assert.Equal(Hex(effects.Revoke.GrantId), set.AggregateId);
        Assert.Equal(set.AggregateId, revoke.AggregateId);
        Assert.All(new[] { start, stop, set, revoke }, receipt =>
        {
            Assert.Equal("SUCCEEDED", receipt.State);
            Assert.Equal((int)EffectCertainty.Happened, receipt.Effect);
            Assert.False(receipt.Compacted);
        });
        Assert.Null(commands.Inspect(effects.RefusedCommand.Value.Span));
        Assert.True(store.Checkpoint());
    }

    private static async Task RequireInstalledMaintenanceOnStaleDatabaseAsync(TestNode fixture, string earlier,
        string restored, string owner, ReservedRecoveryEffects effects, CancellationToken cancellation)
    {
        // Stage old database bytes only in the disposable verified restore, leaving its newer
        // protected fence, key and the fixture's original running-state history untouched.
        string database = StorePaths.Database(restored);
        Assert.False(File.Exists(database + "-wal"));
        Assert.False(File.Exists(database + "-shm"));
        string fence = DurableEpochFence.PathFor(restored, owner);
        byte[] authority = await File.ReadAllBytesAsync(fence, cancellation);
        File.Copy(StorePaths.Database(earlier), database, overwrite: true);

        string config = Path.Combine(fixture.ConfigDirectory, "node.json");
        string originalConfig = await File.ReadAllTextAsync(config, cancellation);
        try
        {
            await File.WriteAllTextAsync(config, "{ \"dataRoot\": " + JsonSerializer.Serialize(restored) + " }", cancellation);
            using var node = fixture.Start(TestNode.Host, ["node", "run", NodeLocations.TestModeOption]);
            var refused = await TestNode.CompleteAsync(node, NativeBound);
            Assert.Equal(NodeExitCodes.Failure, refused.ExitCode);
            Assert.Contains("owner_authority_reconciliation_required", refused.Error, StringComparison.Ordinal);
            Assert.Null(EndpointDescriptor.TryRead(NodeLocations.EndpointDescriptorFile(restored)));
        }
        finally
        {
            await File.WriteAllTextAsync(config, originalConfig, CancellationToken.None);
        }

        Assert.Equal(authority, await File.ReadAllBytesAsync(fence, cancellation));
        using var staleStore = OpenRecoveryStore(restored);
        using var commands = new DurableCommandStore(staleStore, owner, NodeSecretStores.ForTestDataRoot(restored));
        Assert.True(commands.MaintenanceRequired);
        Assert.Null(commands.Inspect(effects.Start.Meta.CommandId.Value.Span));
        Assert.Null(commands.Inspect(effects.Stop.Meta.CommandId.Value.Span));
        Assert.Null(commands.Inspect(effects.Revoke.Meta.CommandId.Value.Span));
    }

    private static async Task RequireFreshAuthorityRejectsSavedRequestsAsync(Id originalEpoch,
        ReservedRecoveryEffects effects, CancellationToken cancellation)
    {
        await using var fresh = TestNode.Create();
        PrepareDataRoot(fresh.DataRoot);
        var process = await fresh.StartNodeAsync();
        Id? currentEpoch = null;
        try
        {
            await using var channel = OpenChannel(fresh);
            var node = new NodeService.NodeServiceClient(channel.CallInvoker);
            var runs = new RunService.RunServiceClient(channel.CallInvoker);
            currentEpoch = (await HandshakeAsync(node)).OwnerEpoch;
            Assert.NotEqual(originalEpoch, currentEpoch);
            Assert.Equal(originalEpoch, effects.Start.OwnerEpoch);
            Assert.Equal(originalEpoch, effects.Stop.OwnerEpoch);

            var start = await runs.StartAsync(effects.Start, deadline: Deadline, cancellationToken: cancellation);
            var stop = await runs.StopAsync(effects.Stop, deadline: Deadline, cancellationToken: cancellation);
            Assert.Null(start.Value);
            Assert.Null(stop.Value);
            Assert.All(new[] { start.Error, stop.Error }, error =>
            {
                Assert.Equal("owner_epoch_retired", error?.Code);
                Assert.Equal(EffectCertainty.DidNotHappen, error?.Effect);
            });

            var old = await node.GetOperationAsync(new NodeServiceGetOperationRequest
            {
                Meta = Query(),
                OwnerEpoch = originalEpoch,
                CommandId = effects.Start.Meta.CommandId,
            }, deadline: Deadline, cancellationToken: cancellation);
            Assert.Null(old.Value);
            Assert.Equal("not_found", old.Error?.Code);
            Assert.Equal(0L, RecoveryReceiptCount(fresh.DataRoot));
        }
        finally
        {
            await StopNodeAsync(fresh, process);
            if (currentEpoch is not null) RemoveFixtureOwnerKey(fresh.DataRoot, currentEpoch);
        }
    }

    private sealed record ReservedRecoveryEffects(RunServiceStartRequest Start, RunServiceStopRequest Stop,
        NodeServiceSetRemoteGrantRequest Set, NodeServiceRevokeRemoteGrantRequest Revoke, string Marker, Id RefusedCommand);
}
