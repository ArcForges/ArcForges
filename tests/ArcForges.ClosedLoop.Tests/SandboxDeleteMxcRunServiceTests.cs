// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Store;
using Grpc.Core;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const string DeleteAfterLock = "hold-delete-after-lock";
    private const string DeleteBeforeAcceptedReply = "hold-delete-before-accepted-reply";
    private const string DeleteAfterQuarantine = "hold-delete-after-quarantine";
    internal const string DeleteDuringRemoval = "hold-delete-during-removal";
    private const string DeleteBeforeRemovalProof = "hold-delete-before-removal-proof";
    private const string DeleteBeforeTombstone = "hold-delete-before-tombstone";
    private const string LinuxDeleteGuardUnavailable = "linux_exact_directory_mutation_unavailable";
    private static readonly string[] DeleteRecoveryCheckpoints = [DeleteAfterLock, DeleteAfterQuarantine,
        DeleteDuringRemoval, DeleteBeforeRemovalProof, DeleteBeforeTombstone];

    [Fact(Timeout = 145_000, DisableParallelization = true)]
    public Task InstalledSandboxDeletePreservesSiblingAndHostGrantAfterManagedUseClears() =>
        VerifyInstalledDeleteAfterManagedUseAsync(provisionedDataRoot: null, TestContext.Current.CancellationToken);

    internal static async Task VerifyInstalledDeleteAfterManagedUseAsync(string? provisionedDataRoot, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create(provisionedDataRoot: provisionedDataRoot);
        PrepareInstalledCliFixture(fixture);
        var process = await fixture.StartNodeAsync();
        Id? cleanupEpoch = null;
        Id? heldRun = null;
        try
        {
            await using var connection = OpenChannel(fixture);
            var node = new NodeService.NodeServiceClient(connection.CallInvoker);
            var sandboxes = new SandboxService.SandboxServiceClient(connection.CallInvoker);
            var runs = new RunService.RunServiceClient(connection.CallInvoker);
            var data = new DataService.DataServiceClient(connection.CallInvoker);
            var epoch = (await HandshakeAsync(node)).OwnerEpoch;
            cleanupEpoch = epoch;
            if (provisionedDataRoot is not null)
            {
                await RequireProtectedLinuxLocalRegistrationsAsync(connection, token);
                await PrepareInstalledDeleteCustodyQuarantineAsync(node, sandboxes, epoch, token);
            }

            var sibling = await CreateSandboxAsync(sandboxes, epoch);
            var externalRoot = Directory.CreateDirectory(Path.Combine(fixture.Root, "delete external fixture")).FullName;
            var sandbox = await CreateDeleteSandboxAsync(sandboxes, epoch, sibling.Config, externalRoot, token);
            Assert.NotEqual(sibling.SandboxId, sandbox.SandboxId);
            var boundGrant = Assert.Single(sandbox.Config.HostGrants);
            Assert.False(string.IsNullOrWhiteSpace(boundGrant.NativeIdentity));
            var previousConfig = ReadInstalledDeleteConfigBytes(fixture, sandbox);
            var id = IdText.Format(sandbox.SandboxId);
            var siblingFile = Path.Combine(sibling.DataLocation, "data", "sibling-sentinel.bin");
            var externalFile = Path.Combine(externalRoot, "external-sentinel.bin");
            var ownedParent = Directory.CreateDirectory(Path.Combine(sandbox.DataLocation, "data", "owned subtree")).FullName;
            const string ownedRelative = "data/owned subtree/owned.bin";
            var ownedFile = Path.Combine(ownedParent, "owned.bin");
            byte[] owned = BuildFileBytes(13_017, 79);
            byte[] siblingBytes = BuildFileBytes(1_032, 43);
            byte[] externalBytes = BuildFileBytes(2_059, 211);
            await File.WriteAllBytesAsync(ownedFile, owned, token);
            await File.WriteAllBytesAsync(siblingFile, siblingBytes, token);
            await File.WriteAllBytesAsync(externalFile, externalBytes, token);
            if (OperatingSystem.IsLinux() && provisionedDataRoot is not null)
            {
                Directory.CreateSymbolicLink(Path.Combine(ownedParent, "external link"), externalRoot);
            }

            var abandoned = (await InstalledCliSuccessAsync(fixture, "sandbox", "delete", id, "--plan-only")).GetProperty("plan");
            Assert.Equal(sandbox.SandboxId, InstalledCliId(abandoned, "sandboxId"));
            var abandonedId = InstalledCliId(abandoned, "planId");
            var rootDigest = abandoned.GetProperty("rootIdentityDigest").GetString();
            Assert.False(string.IsNullOrWhiteSpace(rootDigest));
            Assert.Equal(boundGrant.HostPath, Assert.Single(abandoned.GetProperty("excludedHostGrants").EnumerateArray()).GetString());
            await InstalledCliRefusalAsync(fixture, 2, "invalid_argument", "sandbox", "delete", id, "--plan",
                IdText.Format(abandonedId), "--expected-revision", CliRevision(sandbox.Revision));
            await RequireDeleteSandboxReadyAsync(sandboxes, sandbox, token);
            Assert.Equal(owned, await File.ReadAllBytesAsync(ownedFile, token));

            var export = await data.BeginExportAsync(new DataServiceBeginExportRequest
            {
                Meta = Mutation(sandbox.Revision),
                OwnerEpoch = epoch,
                SandboxId = sandbox.SandboxId,
                RelativePath = ownedRelative,
            }, deadline: Deadline, cancellationToken: token);
            var exportId = Value(export.Value, export.Error).Transfer.TransferId;
            var snapshot = await AwaitMaterializedExportAsync(data, exportId, token);
            var retained = Value(snapshot.Value, snapshot.Error).Transfer;
            RequireCompleteFileTransfer(retained, sandbox, ownedRelative, "export", owned);
            Assert.Null(retained.ClosedAt);
            var exportPlan = await RequireBlockedDeletePlanAsync(sandboxes, epoch, sandbox, expectedRun: null, exportId, token);
            Assert.Equal(rootDigest, exportPlan.RootIdentityDigest);
            var close = await data.CloseTransferAsync(new DataServiceCloseTransferRequest
            {
                Meta = Mutation(TransferRevision(snapshot.Meta)),
                OwnerEpoch = epoch,
                TransferId = exportId,
            }, deadline: Deadline, cancellationToken: token);
            var closed = Value(close.Value, close.Error).Transfer;
            RequireCompleteFileTransfer(closed, sandbox, ownedRelative, "export", owned);
            Assert.NotNull(closed.ClosedAt);

            var working = Directory.CreateDirectory(Path.Combine(sandbox.DataLocation, "work", "quoted directory")).FullName;
            var image = CopySecurityTestLoad(working);
            var release = Path.Combine(working, "delete-run-release");
            var marker = Path.Combine(working, "delete-run-ready.log");
            var custodyMarker = Path.Combine(working, "delete-run-custody.log");
            string[] arguments = [image, "hold", "--hold-ms", "60000", "--until-file", release, "--marker", marker];
            if (provisionedDataRoot is not null)
            {
                arguments = await ObserveLinuxCustodyFromRunAsync(fixture, siblingFile, custodyMarker, arguments);
            }

            var start = BuildStart(sandbox, epoch, arguments);
            start.TerminalMode = TerminalMode.Pipes;
            start.TerminalSize = null;
            var started = await runs.StartAsync(start, deadline: Deadline, cancellationToken: token);
            heldRun = Value(started.Value, started.Error).Run.RunId;
            await WaitForStateAsync(fixture, runs, heldRun, RunState.Running, token);
            await TestNode.WaitAsync(() => ReadLines(marker).Any(line => line.StartsWith("ready ", StringComparison.Ordinal)),
                NativeBound, "the native Run marker in the installed Delete fixture");
            if (provisionedDataRoot is not null)
            {
                Assert.Equal(["source denied", "control denied", "quarantine denied", "sibling denied"], ReadLines(custodyMarker));
            }

            var runPlan = await RequireBlockedDeletePlanAsync(sandboxes, epoch, sandbox, heldRun, expectedTransfer: null, token);
            Assert.Equal(rootDigest, runPlan.RootIdentityDigest);
            Assert.Equal(RunState.Running, (await InspectAsync(runs, heldRun, token)).State);
            await File.WriteAllTextAsync(release, "release", token);
            var drained = await WaitForStateAsync(fixture, runs, heldRun, RunState.Exited, token);
            Assert.True(drained.Exit.HasRawCode);
            Assert.Equal(0, drained.Exit.RawCode);
            Assert.True(drained.Exit.GroupEmptyVerified);
            heldRun = null;

            var eligible = await WaitForUnblockedDeletePlanAsync(sandboxes, sandbox, drained.RunId, token);
            Assert.Equal(boundGrant.HostPath, Assert.Single(eligible.ExcludedHostGrants));
            Assert.Equal(rootDigest, eligible.RootIdentityDigest);
            Assert.Equal(owned, await File.ReadAllBytesAsync(ownedFile, token));
            var fresh = (await InstalledCliSuccessAsync(fixture, "sandbox", "delete", id, "--plan-only")).GetProperty("plan");
            var freshId = InstalledCliId(fresh, "planId");
            Assert.NotEqual(abandonedId, freshId);
            Assert.NotEqual(exportPlan.PlanId, freshId);
            Assert.NotEqual(runPlan.PlanId, freshId);
            Assert.Equal(rootDigest, fresh.GetProperty("rootIdentityDigest").GetString());
            Assert.Equal(boundGrant.HostPath, Assert.Single(fresh.GetProperty("excludedHostGrants").EnumerateArray()).GetString());
            string[] apply = ["sandbox", "delete", id, "--plan", IdText.Format(freshId),
                "--expected-revision", CliRevision(sandbox.Revision), "--yes"];
            if (OperatingSystem.IsLinux() && provisionedDataRoot is null)
            {
                var denied = await RequireLinuxDeleteRefusalAsync(fixture, node, sandboxes, sandbox, epoch, freshId, token);
                var refused = await InstalledCliRefusalAsync(fixture, 2, "path_rejected", [.. apply, "--command-id",
                    IdText.Format(denied), "--owner-epoch", IdText.Format(epoch)]);
                Assert.Equal(LinuxDeleteGuardUnavailable, refused.GetProperty("error").GetProperty("details").GetProperty("state")
                    .GetProperty("reason").GetString());
                await RequireMissingDeleteReceiptAsync(node, epoch, denied, token);
                Assert.Equal(owned, await File.ReadAllBytesAsync(ownedFile, token));
                Assert.Equal(siblingBytes, await File.ReadAllBytesAsync(siblingFile, token));
                Assert.Equal(externalBytes, await File.ReadAllBytesAsync(externalFile, token));
                await RequireDeleteSandboxReadyAsync(sandboxes, sandbox, token);
                await RequireDeleteSandboxReadyAsync(sandboxes, sibling, token);
                RequireInstalledDeleteConfigUnchanged(fixture, sandbox, previousConfig);
                return;
            }

            var accepted = await InstalledCliSuccessAsync(fixture, apply);
            var command = InstalledCliId(accepted, "commandId");
            Assert.Equal(epoch, InstalledCliId(accepted, "ownerEpoch"));
            Assert.Equal(command, InstalledCliId(accepted.GetProperty("operation"), "commandId"));
            Assert.Equal(sandbox.SandboxId, InstalledCliId(accepted.GetProperty("operation"), "aggregateId"));
            var afterAdmission = await InspectInstalledCliSandboxAsync(sandboxes, sandbox.SandboxId, token);
            Assert.Empty(afterAdmission.Config.HostGrants);
            RequireInstalledDeleteConfigUnchanged(fixture, sandbox, previousConfig);

            var original = await WaitForInstalledDeleteReceiptAsync(node, epoch, command, sandbox.SandboxId, token);
            var tombstone = await InspectInstalledCliSandboxAsync(sandboxes, sandbox.SandboxId, token);
            Assert.Equal(sandbox.SandboxId, tombstone.SandboxId);
            Assert.Equal(SandboxState.Deleted, tombstone.State);
            Assert.Empty(tombstone.Config.HostGrants);
            Assert.True(tombstone.Revision.Value > sandbox.Revision.Value);
            Assert.False(Directory.Exists(sandbox.DataLocation));
            Assert.False(File.Exists(ownedFile));
            Assert.Equal(siblingBytes, await File.ReadAllBytesAsync(siblingFile, token));
            Assert.Equal(externalBytes, await File.ReadAllBytesAsync(externalFile, token));
            await RequireDeleteSandboxReadyAsync(sandboxes, sibling, token);

            var reply = await InstalledCliSuccessAsync(fixture, [.. apply, "--command-id", IdText.Format(command),
                "--owner-epoch", IdText.Format(epoch)]);
            var replayed = reply.GetProperty("operation");
            Assert.Equal(command, InstalledCliId(replayed, "commandId"));
            Assert.Equal(sandbox.SandboxId, InstalledCliId(replayed, "aggregateId"));
            var identical = new SandboxServiceDeleteRequest
            {
                Meta = Mutation(sandbox.Revision),
                OwnerEpoch = epoch,
                SandboxId = sandbox.SandboxId,
                PlanId = freshId,
            };
            identical.Meta.CommandId = command;
            var typedReplay = await sandboxes.DeleteAsync(identical, deadline: Deadline, cancellationToken: token);
            Assert.Equal(original, Value(typedReplay.Value, typedReplay.Error).Operation);
            Assert.Equal(original, await OperationAsync(node, epoch, command));
            Assert.Equal(tombstone, await InspectInstalledCliSandboxAsync(sandboxes, sandbox.SandboxId, token));
            RequireInstalledDeleteConfigUnchanged(fixture, sandbox, previousConfig);
            Assert.False(Directory.Exists(sandbox.DataLocation));
            Assert.Equal(siblingBytes, await File.ReadAllBytesAsync(siblingFile, token));
            Assert.Equal(externalBytes, await File.ReadAllBytesAsync(externalFile, token));
        }
        finally
        {
            await CleanInstalledCliFixtureAsync(fixture, process, cleanupEpoch, heldRun);
        }
    }

    private static async Task RequireProtectedLinuxLocalRegistrationsAsync(NodeChannel connection, CancellationToken token)
    {
        var legacy = await Assert.ThrowsAsync<RpcException>(async () =>
        {
            var retired = new ArcForges.Contracts.Node.V1.TaskService.TaskServiceClient(connection.CallInvoker);
            await retired.ListTasksAsync(new() { Meta = Query() }, deadline: Deadline, cancellationToken: token);
        });
        Assert.Equal(StatusCode.Unimplemented, legacy.StatusCode);
        var control = new CenterControlService.CenterControlServiceClient(connection.CallInvoker);
        var center = await Assert.ThrowsAsync<RpcException>(async () =>
        {
            await control.GetStatusAsync(new() { Meta = Query() }, deadline: Deadline, cancellationToken: token);
        });
        Assert.Equal(StatusCode.Unimplemented, center.StatusCode);
    }

    private static async Task PrepareInstalledDeleteCustodyQuarantineAsync(NodeService.NodeServiceClient node,
        SandboxService.SandboxServiceClient sandboxes, Id epoch, CancellationToken token)
    {
        // The Node creates the actual quarantine through the qualified deletion path. The test never provisions it directly.
        var seed = await CreateSandboxAsync(sandboxes, epoch);
        var plan = await ReadDeletePlanAsync(sandboxes, seed, token);
        var request = new SandboxServiceDeleteRequest
        {
            Meta = Mutation(seed.Revision),
            OwnerEpoch = epoch,
            SandboxId = seed.SandboxId,
            PlanId = plan.PlanId,
        };
        var accepted = await sandboxes.DeleteAsync(request, deadline: Deadline, cancellationToken: token);
        Assert.Equal(request.Meta.CommandId, Value(accepted.Value, accepted.Error).Operation.CommandId);
        await WaitForInstalledDeleteReceiptAsync(node, epoch, request.Meta.CommandId, seed.SandboxId, token);
        RequireInstalledDeleteNameAbsent(seed.DataLocation);
    }

    private static async Task<string[]> ObserveLinuxCustodyFromRunAsync(TestNode fixture, string siblingFile,
        string custodyMarker, string[] payload)
    {
        var source = Path.Combine(fixture.DataRoot, "sandboxes");
        var control = Path.Combine(fixture.DataRoot, "control");
        var quarantine = Path.Combine(control, SandboxPrivateRoots.DeletionQuarantineName);
        using var host = fixture.Start("/usr/bin/stat", ["-Lc", "%d:%i", "--", source, control, quarantine]);
        var observed = await TestNode.CompleteAsync(host, NativeBound);
        Assert.True(observed.ExitCode == 0, observed.ToString());
        var identities = observed.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.Equal(3, identities.Length);

        // Bubblewrap can create synthetic parent directories for a Run's writable mounts. Compare native
        // identity to distinguish that view from a real protected parent, and directly check the sibling file.
        const string script = """
            marker=$1
            sibling=$2
            shift 2
            : > "$marker" || exit 74
            /usr/bin/stat -Lc '%d:%i' -- "$marker" >/dev/null || exit 74
            for label in source control quarantine; do
              if actual=$(/usr/bin/stat -Lc '%d:%i' -- "$1" 2>/dev/null) && [ "$actual" = "$2" ]; then
                printf '%s exposed\n' "$label" >> "$marker"
                exit 74
              fi
              printf '%s denied\n' "$label" >> "$marker"
              shift 2
            done
            if [ -e "$sibling" ] || [ -r "$sibling" ] || [ -w "$sibling" ]; then
              printf 'sibling exposed\n' >> "$marker"
              exit 74
            fi
            printf 'sibling denied\n' >> "$marker"
            exec "$@"
            """;
        return ["/usr/bin/dash", "-c", script, "custody-observation", custodyMarker, siblingFile,
            source, identities[0], control, identities[1], quarantine, identities[2], .. payload];
    }

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    public async Task InstalledSandboxDeleteReconcilesInterruptedOwnedBoundaries()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        if (OperatingSystem.IsLinux())
        {
            await VerifyLinuxDeleteRefusalBeforeArmedCheckpointAsync(token);
            return;
        }

        Assert.True(OperatingSystem.IsWindows());
        await VerifyInstalledDeleteRecoveryAsync(token);
    }

    internal static async Task VerifyInstalledDeleteRecoveryAsync(CancellationToken token, Func<string, string>? provisionedDataRoot = null)
    {
        RequireExtractedPackage();
        foreach (var checkpoint in DeleteRecoveryCheckpoints)
        {
            await VerifyInterruptedInstalledDeletionAsync(checkpoint, token, provisionedDataRoot?.Invoke(checkpoint));
        }
    }

    private static async Task VerifyLinuxDeleteRefusalBeforeArmedCheckpointAsync(CancellationToken token)
    {
        await using var fixture = TestNode.Create();
        PrepareInstalledCliFixture(fixture);
        fixture.Environment[ExecutionFaults.Variable] = DeleteAfterLock + "=60";
        var process = await fixture.StartNodeAsync();
        Id? cleanupEpoch = null;
        try
        {
            await using var connection = OpenChannel(fixture);
            var node = new NodeService.NodeServiceClient(connection.CallInvoker);
            var sandboxes = new SandboxService.SandboxServiceClient(connection.CallInvoker);
            var epoch = (await HandshakeAsync(node)).OwnerEpoch;
            cleanupEpoch = epoch;
            var sandbox = await CreateSandboxAsync(sandboxes, epoch);
            var sibling = await CreateDeleteSandboxAsync(sandboxes, epoch, sandbox.Config, externalRoot: null, token);
            var ownedFile = Path.Combine(sandbox.DataLocation, "data", "owned-sentinel.bin");
            var siblingFile = Path.Combine(sibling.DataLocation, "data", "sibling-sentinel.bin");
            byte[] bytes = BuildFileBytes(827, 31);
            await File.WriteAllBytesAsync(ownedFile, bytes, token);
            await File.WriteAllBytesAsync(siblingFile, bytes, token);
            var plan = await ReadDeletePlanAsync(sandboxes, sandbox, token);
            await RequireLinuxDeleteRefusalAsync(fixture, node, sandboxes, sandbox, epoch, plan.PlanId, token);
            Assert.False(File.Exists(DispatchCheckpointPath(fixture, DeleteAfterLock)));
            Assert.Equal(bytes, await File.ReadAllBytesAsync(ownedFile, token));
            Assert.Equal(bytes, await File.ReadAllBytesAsync(siblingFile, token));
            await RequireDeleteSandboxReadyAsync(sandboxes, sibling, token);
        }
        finally
        {
            ReleaseInstalledDeleteCheckpoint(fixture, process, DeleteAfterLock);
            await CleanInstalledCliFixtureAsync(fixture, process, cleanupEpoch, heldRun: null);
        }
    }

    private static async Task<Id> RequireLinuxDeleteRefusalAsync(TestNode fixture, NodeService.NodeServiceClient node,
        SandboxService.SandboxServiceClient sandboxes, Sandbox sandbox, Id epoch, Id plan, CancellationToken token)
    {
        var request = new SandboxServiceDeleteRequest
        {
            Meta = Mutation(sandbox.Revision),
            OwnerEpoch = epoch,
            SandboxId = sandbox.SandboxId,
            PlanId = plan,
        };
        var before = ReadInstalledDeletion(fixture, sandbox.SandboxId, epoch, request.Meta.CommandId);
        RequireUnacceptedDelete(before);
        var rejected = await sandboxes.DeleteAsync(request, deadline: Deadline, cancellationToken: token);
        Assert.Null(rejected.Value);
        RequireDataRefusal(rejected.Error, ErrorCategory.Validation, "path_rejected");
        Assert.Equal(LinuxDeleteGuardUnavailable, rejected.Error?.Details?.State?.Reason);
        await RequireMissingDeleteReceiptAsync(node, epoch, request.Meta.CommandId, token);
        var after = ReadInstalledDeletion(fixture, sandbox.SandboxId, epoch, request.Meta.CommandId);
        RequireUnacceptedDelete(after);
        Assert.Equal(before.Row, after.Row);
        Assert.False(Directory.Exists(InstalledDeleteQuarantinePath(fixture, plan)));
        await RequireDeleteSandboxReadyAsync(sandboxes, sandbox, token);
        return request.Meta.CommandId;
    }

    private static async Task VerifyInterruptedInstalledDeletionAsync(string checkpoint, CancellationToken token, string? provisionedDataRoot = null)
    {
        await using var fixture = TestNode.Create(provisionedDataRoot: provisionedDataRoot);
        PrepareInstalledCliFixture(fixture);
        bool cancelOriginalCall = checkpoint == DeleteAfterLock;
        fixture.Environment[ExecutionFaults.Variable] = checkpoint + "=60" +
            (cancelOriginalCall ? "," + DeleteBeforeAcceptedReply + "=60" : string.Empty);
        var interrupted = await fixture.StartNodeAsync();
        Process? restarted = null;
        Id? cleanupEpoch = null;
        try
        {
            Sandbox sandbox;
            Sandbox sibling;
            SandboxServiceDeleteRequest original;
            InstalledDeletionDisk observed;
            WorkspaceObjectIdentity originalRoot;
            string[] initialEntries;
            IReadOnlyDictionary<string, WorkspaceObjectIdentity>? windowsRundownDirectories = null;
            string siblingFile;
            var externalRoot = Directory.CreateDirectory(Path.Combine(fixture.Root, "delete checkpoint external fixture")).FullName;
            var externalFile = Path.Combine(externalRoot, "external-checkpoint.bin");
            string firstNodeEpoch;
            byte[] sentinel = BuildFileBytes(695, 57);
            byte[] externalSentinel = BuildFileBytes(163, 31);
            await File.WriteAllBytesAsync(externalFile, externalSentinel, token);
            await using (var channel = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var hello = await HandshakeAsync(node);
                cleanupEpoch = hello.OwnerEpoch;
                firstNodeEpoch = hello.NodeEpoch;
                sibling = await CreateSandboxAsync(sandboxes, hello.OwnerEpoch);
                sandbox = await CreateDeleteSandboxAsync(sandboxes, hello.OwnerEpoch, sibling.Config, externalRoot, token);
                var nested = Directory.CreateDirectory(Path.Combine(sandbox.DataLocation, "data", "owned checkpoint subtree")).FullName;
                _ = Directory.CreateDirectory(Path.Combine(sandbox.DataLocation, "work", "quoted directory"));
                await File.WriteAllBytesAsync(Path.Combine(nested, "first.bin"), sentinel, token);
                await File.WriteAllBytesAsync(Path.Combine(nested, "second.bin"), sentinel, token);
                siblingFile = Path.Combine(sibling.DataLocation, "data", "sibling-checkpoint.bin");
                await File.WriteAllBytesAsync(siblingFile, sentinel, token);
                using (var root = WorkspacePath.OpenRoot(sandbox.DataLocation)) originalRoot = root.RootIdentity;
                initialEntries = EnumerateOwnedDeleteEntries(sandbox.DataLocation);
                if (OperatingSystem.IsWindows() && checkpoint == DeleteDuringRemoval)
                {
                    windowsRundownDirectories = CaptureWindowsDeleteRundownDirectories(sandbox.DataLocation, token);
                }

                var preview = await ReadDeletePlanAsync(sandboxes, sandbox, token);
                original = new SandboxServiceDeleteRequest
                {
                    Meta = Mutation(preview.Revision),
                    OwnerEpoch = hello.OwnerEpoch,
                    SandboxId = sandbox.SandboxId,
                    PlanId = preview.PlanId,
                };
                RequireUnacceptedDelete(ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId));
                using var originalWait = CancellationTokenSource.CreateLinkedTokenSource(token);
                using var pendingCall = sandboxes.DeleteAsync(original, deadline: DateTime.UtcNow.AddSeconds(55),
                    cancellationToken: originalWait.Token);
                Operation operation;
                if (cancelOriginalCall)
                {
                    await WaitDispatchCheckpointAsync(fixture, DeleteBeforeAcceptedReply);
                    Assert.False(pendingCall.ResponseAsync.IsCompleted);
                    operation = await OperationAsync(node, original.OwnerEpoch, original.Meta.CommandId);
                }
                else
                {
                    var accepted = await pendingCall.ResponseAsync;
                    operation = Value(accepted.Value, accepted.Error).Operation;
                }

                Assert.Equal(original.Meta.CommandId, operation.CommandId);
                Assert.Equal(OperationState.Accepted, operation.State);
                Assert.Equal(EffectCertainty.Unknown, operation.Effect);
                await WaitDispatchCheckpointAsync(fixture, checkpoint);
                observed = ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId);
                RequireDeleteCheckpointJournal(checkpoint, sandbox, original, observed);
                if (checkpoint != DeleteAfterLock) RequireInstalledDeleteNameAbsent(sandbox.DataLocation);
                if (cancelOriginalCall)
                {
                    Assert.False(pendingCall.ResponseAsync.IsCompleted);
                    await originalWait.CancelAsync();
                    var cancelled = await Assert.ThrowsAsync<RpcException>(() => pendingCall.ResponseAsync.WaitAsync(NativeBound, token));
                    Assert.Equal(StatusCode.Cancelled, cancelled.StatusCode);
                    var runs = new RunService.RunServiceClient(channel.CallInvoker);
                    var start = BuildStart(sandbox, original.OwnerEpoch, OperatingSystem.IsWindows()
                        ? [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "exit 0"]
                        : ["/usr/bin/true"]);
                    start.Meta.ExpectedRev = new Revision { Value = observed.Row.Revision };
                    var fenced = await runs.StartAsync(start, deadline: Deadline, cancellationToken: token);
                    Assert.Null(fenced.Value);
                    RequireDataRefusal(fenced.Error, ErrorCategory.State, "busy");
                    Assert.Equal("sandbox_not_ready", fenced.Error?.Details?.State?.Reason);
                    Assert.Equal(operation, await OperationAsync(node, original.OwnerEpoch, original.Meta.CommandId));
                    Assert.Equal(observed, ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId));
                }

                interrupted.Kill();
                await interrupted.WaitForExitAsync(token).WaitAsync(NativeBound, token);
            }

            var quarantine = InstalledDeleteQuarantinePath(fixture, original.PlanId);
            Assert.True(interrupted.HasExited);
            var interruptedEntries = await RequireInterruptedDeleteTreeAsync(checkpoint, sandbox.DataLocation, quarantine,
                originalRoot, initialEntries, waitForClosedHandles: true, token, windowsRundownDirectories);
            Assert.Equal(sentinel, await File.ReadAllBytesAsync(siblingFile, token));
            Assert.Equal(externalSentinel, await File.ReadAllBytesAsync(externalFile, token));
            fixture.Environment.Remove(ExecutionFaults.Variable);
            string? alternateSentinel = null;
            if (checkpoint == DeleteAfterQuarantine)
            {
                alternateSentinel = await VerifyMismatchedInstalledQuarantineAsync(fixture, sandbox, original, quarantine,
                    originalRoot, sentinel, token);
                var restoredEntries = await RequireInterruptedDeleteTreeAsync(checkpoint, sandbox.DataLocation, quarantine,
                    originalRoot, initialEntries, waitForClosedHandles: false, token);
                Assert.Equal(interruptedEntries, restoredEntries);
            }

            restarted = await fixture.StartNodeAsync();
            interrupted.Dispose();
            await using var recovered = OpenChannel(fixture);
            var recoveredNode = new NodeService.NodeServiceClient(recovered.CallInvoker);
            var recoveredSandboxes = new SandboxService.SandboxServiceClient(recovered.CallInvoker);
            var current = await HandshakeAsync(recoveredNode);
            Assert.Equal(original.OwnerEpoch, current.OwnerEpoch);
            Assert.NotEqual(firstNodeEpoch, current.NodeEpoch);
            var after = await InspectInstalledCliSandboxAsync(recoveredSandboxes, sandbox.SandboxId, token);
            bool hasRemovalProof = checkpoint == DeleteBeforeTombstone;
            Assert.Equal(hasRemovalProof ? SandboxState.Deleting : SandboxState.RecoveryRequired, after.State);
            Assert.Equal(observed.Row.Revision + (hasRemovalProof ? 0 : 1), after.Revision.Value);
            var pending = ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId);
            Assert.Equal(hasRemovalProof ? "removing" : "recovery_required", pending.Phase);
            Assert.Equal("UNKNOWN", pending.ReceiptState);
            Assert.Equal(observed.DeletionId, pending.DeletionId);
            Assert.Equal(observed.Row.RootIdentity, pending.Row.RootIdentity);
            Assert.Equal(observed.QuarantineIdentity, pending.QuarantineIdentity);
            Assert.Equal(observed.RemovalProof, pending.RemovalProof);
            Assert.Null(pending.LatestSuccessor);

            var unknown = await OperationAsync(recoveredNode, original.OwnerEpoch, original.Meta.CommandId);
            Assert.Equal(OperationState.Unknown, unknown.State);
            Assert.Equal(EffectCertainty.Unknown, unknown.Effect);
            Assert.Equal("outcome_unknown", unknown.Error?.Code);
            var replay = await recoveredSandboxes.DeleteAsync(original, deadline: Deadline, cancellationToken: token);
            var replayedUnknown = Value(replay.Value, replay.Error).Operation;
            Assert.Equal(original.Meta.CorrelationId, replayedUnknown.Error?.CorrelationId);
            Assert.Equal(WithoutDeleteReceiptCorrelation(unknown), WithoutDeleteReceiptCorrelation(replayedUnknown));
            var replayedEntries = await RequireInterruptedDeleteTreeAsync(checkpoint, sandbox.DataLocation, quarantine,
                originalRoot, initialEntries, waitForClosedHandles: false, token);
            Assert.Equal(interruptedEntries, replayedEntries);
            if (checkpoint == DeleteAfterLock)
            {
                await RequireInvalidResumeAuthorityAsync(recoveredNode, recoveredSandboxes, original, after.Revision, token);
                Assert.Equal(pending, ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId));
            }

            var successor = Mutation(after.Revision).CommandId;
            string[] resume = ["sandbox", "delete", IdText.Format(sandbox.SandboxId), "--resume",
                IdText.Format(original.Meta.CommandId), "--expected-revision", CliRevision(after.Revision),
                "--command-id", IdText.Format(successor), "--owner-epoch", IdText.Format(original.OwnerEpoch)];
            if (checkpoint == DeleteBeforeRemovalProof)
            {
                await InstalledCliRefusalAsync(fixture, 3, "identity_changed", resume);
                await RequireMissingDeleteReceiptAsync(recoveredNode, original.OwnerEpoch, successor, token);
                var unchanged = ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId);
                Assert.Equal(pending, unchanged);
                var originalAfterRefusal = await OperationAsync(recoveredNode, original.OwnerEpoch, original.Meta.CommandId);
                Assert.Equal(WithoutDeleteReceiptCorrelation(unknown), WithoutDeleteReceiptCorrelation(originalAfterRefusal));
                Assert.Equal(after, await InspectInstalledCliSandboxAsync(recoveredSandboxes, sandbox.SandboxId, token));
            }
            else
            {
                var continued = await InstalledCliSuccessAsync(fixture, resume);
                Assert.Equal(successor, InstalledCliId(continued, "commandId"));
                Assert.NotEqual(original.Meta.CommandId, successor);
                var completed = await WaitForInstalledDeleteReceiptAsync(recoveredNode, original.OwnerEpoch, successor,
                    sandbox.SandboxId, token);
                await WaitForInstalledDeleteReceiptAsync(recoveredNode, original.OwnerEpoch, original.Meta.CommandId,
                    sandbox.SandboxId, token);
                var settled = ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId);
                Assert.Equal("complete", settled.Phase);
                Assert.Equal("SUCCEEDED", settled.ReceiptState);
                Assert.Equal(pending.DeletionId, settled.DeletionId);
                Assert.Equal(pending.Row.RootIdentity, settled.Row.RootIdentity);
                if (pending.QuarantineIdentity is not null) Assert.Equal(pending.QuarantineIdentity, settled.QuarantineIdentity);
                Assert.Equal(Hex(successor), settled.LatestSuccessor);
                Assert.Null(settled.Pending);
                Assert.Null(settled.RemovalProof);
                var tombstone = await InspectInstalledCliSandboxAsync(recoveredSandboxes, sandbox.SandboxId, token);
                Assert.Equal(SandboxState.Deleted, tombstone.State);
                Assert.True(tombstone.Revision.Value > after.Revision.Value);
                var repeated = await InstalledCliSuccessAsync(fixture, resume);
                Assert.Equal(successor, InstalledCliId(repeated, "commandId"));
                Assert.Equal(completed, await OperationAsync(recoveredNode, original.OwnerEpoch, successor));
                Assert.Equal(settled, ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId));
            }

            RequireInstalledDeleteNameAbsent(sandbox.DataLocation);
            RequireInstalledDeleteNameAbsent(quarantine);
            Assert.Equal(sentinel, await File.ReadAllBytesAsync(siblingFile, token));
            Assert.Equal(externalSentinel, await File.ReadAllBytesAsync(externalFile, token));
            if (alternateSentinel is not null) Assert.Equal(sentinel, await File.ReadAllBytesAsync(alternateSentinel, token));
            await RequireDeleteSandboxReadyAsync(recoveredSandboxes, sibling, token);
        }
        finally
        {
            if (restarted is null)
            {
                ReleaseInstalledDeleteCheckpoint(fixture, interrupted, checkpoint);
                if (cancelOriginalCall) ReleaseInstalledDeleteCheckpoint(fixture, interrupted, DeleteBeforeAcceptedReply);
            }

            await CleanInstalledCliFixtureAsync(fixture, restarted ?? interrupted, cleanupEpoch, heldRun: null);
        }
    }

    private static async Task<string> VerifyMismatchedInstalledQuarantineAsync(TestNode fixture, Sandbox sandbox,
        SandboxServiceDeleteRequest original, string quarantine, WorkspaceObjectIdentity originalRoot, byte[] sentinel,
        CancellationToken token)
    {
        var parent = Path.GetDirectoryName(quarantine)!;
        var retainedOriginal = Path.Combine(parent, "fixture-original-" + Guid.NewGuid().ToString("N"));
        var retainedAlternate = Path.Combine(parent, "fixture-alternate-" + Guid.NewGuid().ToString("N"));
        const string sentinelName = "alternate-sentinel.bin";
        var sentinelPath = Path.Combine(quarantine, sentinelName);
        RequireInstalledDeleteNameAbsent(retainedOriginal);
        RequireInstalledDeleteNameAbsent(retainedAlternate);
        Directory.Move(quarantine, retainedOriginal);
        Process? probe = null;
        bool startedProbe = false;
        try
        {
            using (var root = WorkspacePath.OpenRoot(parent))
            using (var alternate = root.CreateSandboxDirectory(Path.GetFileName(quarantine)))
            {
                Assert.False(originalRoot.SameObject(alternate.RootIdentity));
            }

            await File.WriteAllBytesAsync(sentinelPath, sentinel, token);
            startedProbe = true;
            probe = await fixture.StartNodeAsync();
            await using var connection = OpenChannel(fixture);
            var node = new NodeService.NodeServiceClient(connection.CallInvoker);
            var sandboxes = new SandboxService.SandboxServiceClient(connection.CallInvoker);
            var current = await InspectInstalledCliSandboxAsync(sandboxes, sandbox.SandboxId, token);
            Assert.Equal(SandboxState.RecoveryRequired, current.State);
            var before = ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId);
            Assert.Equal("UNKNOWN", before.ReceiptState);
            var successor = new SandboxServiceDeleteRequest
            {
                Meta = Mutation(current.Revision),
                OwnerEpoch = original.OwnerEpoch,
                SandboxId = sandbox.SandboxId,
                ResumeCommandId = original.Meta.CommandId,
            };
            var refused = await sandboxes.DeleteAsync(successor, deadline: Deadline, cancellationToken: token);
            Assert.Null(refused.Value);
            RequireDataRefusal(refused.Error, ErrorCategory.Conflict, "identity_changed");
            Assert.Equal("deletion_quarantine_identity_changed", refused.Error?.Details?.State?.Reason);
            await RequireMissingDeleteReceiptAsync(node, original.OwnerEpoch, successor.Meta.CommandId, token);
            Assert.Equal(before, ReadInstalledDeletion(fixture, sandbox.SandboxId, original.OwnerEpoch, original.Meta.CommandId));
            Assert.Equal(sentinel, await File.ReadAllBytesAsync(sentinelPath, token));
        }
        finally
        {
            if (probe is not null)
            {
                using (probe) await StopInstalledCliNodeAsync(fixture, probe);
            }

            // If startup threw before returning its process, the outer fixture owns cleanup. Never move these paths under a live Node.
            if (!startedProbe || probe is not null)
            {
                if (Directory.Exists(quarantine)) Directory.Move(quarantine, retainedAlternate);
                Directory.Move(retainedOriginal, quarantine);
            }
        }

        return Path.Combine(retainedAlternate, sentinelName);
    }

    private static async Task RequireInvalidResumeAuthorityAsync(NodeService.NodeServiceClient node,
        SandboxService.SandboxServiceClient sandboxes, SandboxServiceDeleteRequest original, Revision current, CancellationToken token)
    {
        var staleRevision = new SandboxServiceDeleteRequest
        {
            OwnerEpoch = original.OwnerEpoch,
            SandboxId = original.SandboxId,
            ResumeCommandId = original.Meta.CommandId,
            Meta = Mutation(new Revision { Value = current.Value - 1 }),
        };
        var rejectedRevision = await sandboxes.DeleteAsync(staleRevision, deadline: Deadline, cancellationToken: token);
        Assert.Null(rejectedRevision.Value);
        RequireDataRefusal(rejectedRevision.Error, ErrorCategory.Conflict, "revision_mismatch");
        Assert.Equal(staleRevision.Meta.ExpectedRev, rejectedRevision.Error?.Details?.Revision?.Expected);
        Assert.Equal(current, rejectedRevision.Error?.Details?.Revision?.Actual);
        await RequireMissingDeleteReceiptAsync(node, original.OwnerEpoch, staleRevision.Meta.CommandId, token);

        var retired = staleRevision.Clone();
        retired.Meta = Mutation(current);
        retired.OwnerEpoch = CommandIds.New();
        Assert.NotEqual(original.OwnerEpoch, retired.OwnerEpoch);
        var rejectedEpoch = await sandboxes.DeleteAsync(retired, deadline: Deadline, cancellationToken: token);
        Assert.Null(rejectedEpoch.Value);
        RequireDataRefusal(rejectedEpoch.Error, ErrorCategory.Conflict, "owner_epoch_retired");
        await RequireMissingDeleteReceiptAsync(node, original.OwnerEpoch, retired.Meta.CommandId, token);
    }

    private static Operation WithoutDeleteReceiptCorrelation(Operation operation)
    {
        var durable = operation.Clone();
        if (durable.Error is { } error) error.CorrelationId = null;
        return durable;
    }

    private static void ReleaseInstalledDeleteCheckpoint(TestNode fixture, Process process, string checkpoint)
    {
        var marker = DispatchCheckpointPath(fixture, checkpoint);
        if (!process.HasExited && File.Exists(marker)) File.WriteAllText(Path.ChangeExtension(marker, ".release"), string.Empty);
    }

    private static string InstalledDeleteQuarantinePath(TestNode fixture, Id plan) =>
        Path.Combine(fixture.DataRoot, "control", SandboxPrivateRoots.DeletionQuarantineName, Hex(plan));

    private static byte[] ReadInstalledDeleteConfigBytes(TestNode fixture, Sandbox sandbox)
    {
        using var database = ReadDatabase(fixture.DataRoot);
        var reader = new StoreReader(database, transaction: null, clock: TimeProvider.System);
        return Assert.IsType<byte[]>(reader.Scalar("""
            SELECT CAST(config_json AS BLOB) FROM sandbox_config WHERE sandbox_id=$id AND revision=$revision;
            """, ("$id", Hex(sandbox.SandboxId)), ("$revision", sandbox.Revision.Value)));
    }

    private static void RequireInstalledDeleteConfigUnchanged(TestNode fixture, Sandbox sandbox, byte[] previous) =>
        Assert.True(previous.AsSpan().SequenceEqual(ReadInstalledDeleteConfigBytes(fixture, sandbox)),
            "The historical Sandbox configuration revision changed.");

    private static InstalledDeletionDisk ReadInstalledDeletion(TestNode fixture, Id sandbox, Id epoch, Id command)
    {
        using var database = ReadDatabase(fixture.DataRoot);
        var reader = new StoreReader(database, transaction: null, clock: TimeProvider.System);
        var sandboxId = Hex(sandbox);
        var owner = Assert.IsType<string>(reader.Scalar("SELECT owner_id FROM sandbox WHERE sandbox_id=$id;", ("$id", sandboxId)));
        var current = Assert.IsType<StoredSandbox>(SandboxRecords.Get(reader, owner, sandboxId));
        var epochBytes = epoch.Value.ToByteArray();
        var commandId = Hex(command);
        var existing = SandboxDeletionRecords.ReadOriginal(reader, owner, epochBytes, sandboxId, commandId);
        var count = Assert.IsType<long>(reader.Scalar("SELECT COUNT(*) FROM deletion_journal WHERE sandbox_id=$id AND owner_id=$owner;",
            ("$id", sandboxId), ("$owner", owner)));
        using var receipt = reader.CreateCommand("""
            SELECT state,json_extract(response_json,'$._deletionRemovalVerified') FROM command_receipt
            WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$command
                AND method=$method AND aggregate_kind='sandbox' AND aggregate_id=$sandbox;
            """);
        StoreReader.Bind(receipt, [("$owner", owner), ("$epoch", epochBytes), ("$command", commandId),
            ("$method", SandboxDeletionRecords.Method), ("$sandbox", sandboxId)]);
        string? receiptState = null;
        string? removalProof = null;
        using (var response = receipt.ExecuteReader())
        {
            if (response.Read())
            {
                receiptState = response.GetString(0);
                if (!response.IsDBNull(1)) removalProof = response.GetString(1);
            }
        }

        using var journal = reader.CreateCommand("""
            SELECT deletion_id,phase,latest_resume_command_id,quarantine_identity FROM deletion_journal
            WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$command AND sandbox_id=$sandbox;
            """);
        StoreReader.Bind(journal, [("$owner", owner), ("$epoch", epochBytes), ("$command", commandId), ("$sandbox", sandboxId)]);
        using var row = journal.ExecuteReader();
        return row.Read()
            ? new(current, existing, count, receiptState, row.GetString(0), row.GetString(1), row.IsDBNull(2) ? null : row.GetString(2),
                row.IsDBNull(3) ? null : row.GetString(3), removalProof)
            : new(current, existing, count, receiptState, null, null, null, null, removalProof);
    }

    private static void RequireUnacceptedDelete(InstalledDeletionDisk disk)
    {
        Assert.Equal(StoredSandboxState.Ready, disk.Row.State);
        Assert.Equal(0L, disk.JournalCount);
        Assert.Null(disk.ReceiptState);
        Assert.Null(disk.Pending);
        Assert.Null(disk.DeletionId);
        Assert.Null(disk.RemovalProof);
    }

    private static async Task RequireMissingDeleteReceiptAsync(NodeService.NodeServiceClient node, Id epoch, Id command,
        CancellationToken token)
    {
        var missing = await node.GetOperationAsync(new NodeServiceGetOperationRequest
        {
            Meta = Query(),
            OwnerEpoch = epoch,
            CommandId = command,
        }, deadline: Deadline, cancellationToken: token);
        Assert.Null(missing.Value);
        RequireDataRefusal(missing.Error, ErrorCategory.State, "not_found");
    }

    private static void RequireDeleteCheckpointJournal(string checkpoint, Sandbox sandbox, SandboxServiceDeleteRequest original,
        InstalledDeletionDisk observed)
    {
        var journal = Assert.IsType<StoredSandboxDeletion>(observed.Pending);
        var phase = checkpoint switch
        {
            DeleteAfterLock => "locked",
            DeleteAfterQuarantine => "quarantined",
            _ => "removing",
        };
        Assert.Equal(1L, observed.JournalCount);
        Assert.Equal(StoredSandboxState.Deleting, observed.Row.State);
        Assert.Equal(sandbox.Revision.Value + 1, observed.Row.Revision);
        Assert.Equal("ACCEPTED", observed.ReceiptState);
        Assert.Equal(Hex(original.PlanId), journal.DeletionId);
        Assert.Equal(Hex(original.Meta.CommandId), journal.OriginalCommandId);
        Assert.Equal(sandbox.Revision.Value, journal.OriginalExpectedRevision);
        Assert.Equal(observed.Row.RootIdentity, journal.RootIdentity);
        Assert.Equal(phase, journal.Phase);
        Assert.Equal(phase == "locked", journal.QuarantineIdentity is null);
        Assert.Equal(journal.QuarantineIdentity, observed.QuarantineIdentity);
        if (checkpoint == DeleteBeforeTombstone)
        {
            Assert.NotNull(observed.RemovalProof);
            Assert.Matches("^[0-9a-f]{64}$", observed.RemovalProof);
        }
        else
        {
            Assert.Null(observed.RemovalProof);
        }

        Assert.Null(observed.LatestSuccessor);
    }

    private static string[] EnumerateOwnedDeleteEntries(string root) => Directory
        .EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
        .Select(path => Path.GetRelativePath(root, path)).Order(StringComparer.Ordinal).ToArray();

    internal static async Task<string[]> RequireInterruptedDeleteTreeAsync(string checkpoint, string original, string quarantine,
        WorkspaceObjectIdentity originalRoot, string[] initialEntries, bool waitForClosedHandles, CancellationToken token,
        IReadOnlyDictionary<string, WorkspaceObjectIdentity>? windowsRundownDirectories = null,
        Action<string>? beforeWindowsRundownDirectoryOpen = null)
    {
        if (checkpoint is DeleteBeforeRemovalProof or DeleteBeforeTombstone)
        {
            RequireInstalledDeleteNameAbsent(original);
            RequireInstalledDeleteNameAbsent(quarantine);
            return [];
        }

        bool locked = checkpoint == DeleteAfterLock;
        RequireInstalledDeleteNameAbsent(locked ? quarantine : original);
        var current = locked ? original : quarantine;
        var elapsed = Stopwatch.StartNew();
        string[]? remaining = null;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            bool rootOpened = false;
            try
            {
                using var opened = WorkspacePath.OpenRoot(current);
                rootOpened = true;
                Assert.True(originalRoot.SameObject(opened.RootIdentity), $"The native directory identity changed at {checkpoint}.");
                if (OperatingSystem.IsWindows() && waitForClosedHandles && checkpoint == DeleteDuringRemoval &&
                    windowsRundownDirectories is not null)
                {
                    remaining = EnumerateWindowsDeleteRundownEntries(opened, windowsRundownDirectories, token,
                        beforeWindowsRundownDirectoryOpen);
                }
                break;
            }
            catch (WorkspacePathException failure) when (!rootOpened && waitForClosedHandles && failure.Reason == "native_32")
            {
                Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(3),
                    $"The directory at {checkpoint} still reports native_32 after the original Node exited.");
            }
            catch (WindowsDeleteRundownRetryException retry)
            {
                TestContext.Current.TestOutputHelper?.WriteLine($"Owned directory {retry.Message} reported {retry.NativeReason} during post-exit rundown.");
                Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(3),
                    $"The owned directory {retry.Message} still reports {retry.NativeReason} at {checkpoint}.");
            }
            await Task.Delay(TimeSpan.FromMilliseconds(50), token);
        }

        remaining ??= EnumerateOwnedDeleteEntries(current);
        if (checkpoint == DeleteDuringRemoval)
        {
            Assert.InRange(remaining.Length, 1, initialEntries.Length - 1);
            Assert.All(remaining, entry => Assert.Contains(entry, initialEntries));
        }
        else
        {
            Assert.Equal(initialEntries, remaining);
        }

        return remaining;
    }

    private static void RequireInstalledDeleteNameAbsent(string path)
    {
        var parent = Path.GetDirectoryName(path)!;
        if (Directory.Exists(parent))
        {
            using var root = WorkspacePath.OpenRoot(parent);
            Assert.True(root.InspectRemovalAbsent(Path.GetFileName(path)));
        }

        Assert.False(Directory.Exists(path));
        Assert.False(File.Exists(path));
    }

    private static async Task<Sandbox> CreateDeleteSandboxAsync(SandboxService.SandboxServiceClient sandboxes, Id epoch,
        SandboxConfig standard, string? externalRoot, CancellationToken token)
    {
        var config = standard.Clone();
        if (externalRoot is not null)
        {
            config.HostGrants.Add(new HostGrant { HostPath = externalRoot, SandboxPath = externalRoot, Writable = false });
        }

        var created = await sandboxes.CreateAsync(new SandboxServiceCreateRequest
        {
            Meta = Mutation(),
            OwnerEpoch = epoch,
            DisplayName = "Installed delete fixture",
            Config = config,
        }, deadline: Deadline, cancellationToken: token);
        var sandbox = Value(created.Value, created.Error).Sandbox;
        Assert.Equal(SandboxState.Ready, sandbox.State);
        return sandbox;
    }

    private static async Task RequireDeleteSandboxReadyAsync(SandboxService.SandboxServiceClient sandboxes, Sandbox sandbox,
        CancellationToken token)
    {
        var current = await InspectInstalledCliSandboxAsync(sandboxes, sandbox.SandboxId, token);
        Assert.Equal(SandboxState.Ready, current.State);
        Assert.Equal(sandbox.Revision, current.Revision);
        Assert.Equal(sandbox.DataLocation, current.DataLocation);
        Assert.True(sandbox.Config.HostGrants.Equals(current.Config.HostGrants), "Ready Sandbox host grants changed.");
        Assert.True(Directory.Exists(sandbox.DataLocation));
    }

    private static async Task<DeletePlan> ReadDeletePlanAsync(SandboxService.SandboxServiceClient sandboxes, Sandbox sandbox,
        CancellationToken token)
    {
        var preview = await sandboxes.PlanDeleteAsync(new SandboxServicePlanDeleteRequest
        {
            Meta = Query(),
            SandboxId = sandbox.SandboxId,
        }, deadline: Deadline, cancellationToken: token);
        var plan = Value(preview.Value, preview.Error).Plan;
        Assert.Equal(sandbox.SandboxId, plan.SandboxId);
        Assert.Equal(sandbox.Revision, plan.Revision);
        Assert.NotNull(plan.ExpiresAt);
        return plan;
    }

    private static async Task<DeletePlan> WaitForUnblockedDeletePlanAsync(SandboxService.SandboxServiceClient sandboxes,
        Sandbox sandbox, Id drainedRun, CancellationToken token)
    {
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            var plan = await ReadDeletePlanAsync(sandboxes, sandbox, token);
            Assert.Empty(plan.BlockingTransferIds);
            if (plan.BlockingRuns.Count == 0) return plan;
            Assert.Equal(drainedRun, Assert.Single(plan.BlockingRuns));
            Assert.True(elapsed.Elapsed < NativeBound, "The drained Run still holds its Sandbox deletion lease.");
            await Task.Delay(TimeSpan.FromSeconds(1), token);
        }
    }

    private static async Task<DeletePlan> RequireBlockedDeletePlanAsync(SandboxService.SandboxServiceClient sandboxes, Id epoch,
        Sandbox sandbox, Id? expectedRun, Id? expectedTransfer, CancellationToken token)
    {
        var plan = await ReadDeletePlanAsync(sandboxes, sandbox, token);
        Assert.Equal(sandbox.Config.HostGrants.Select(grant => grant.HostPath), plan.ExcludedHostGrants);
        if (expectedRun is null) Assert.Empty(plan.BlockingRuns);
        else Assert.Equal(expectedRun, Assert.Single(plan.BlockingRuns));
        if (expectedTransfer is null) Assert.Empty(plan.BlockingTransferIds);
        else Assert.Equal(expectedTransfer, Assert.Single(plan.BlockingTransferIds));
        var refused = await sandboxes.DeleteAsync(new SandboxServiceDeleteRequest
        {
            Meta = Mutation(plan.Revision),
            OwnerEpoch = epoch,
            SandboxId = sandbox.SandboxId,
            PlanId = plan.PlanId,
        }, deadline: Deadline, cancellationToken: token);
        Assert.Null(refused.Value);
        RequireDataRefusal(refused.Error, ErrorCategory.State, "managed_use");
        await RequireDeleteSandboxReadyAsync(sandboxes, sandbox, token);
        return plan;
    }

    private static async Task<Operation> WaitForInstalledDeleteReceiptAsync(NodeService.NodeServiceClient node, Id epoch, Id command,
        Id sandbox, CancellationToken token)
    {
        Operation? completed = null;
        await TestNode.WaitAsync(async () =>
        {
            token.ThrowIfCancellationRequested();
            var observed = await OperationAsync(node, epoch, command);
            Assert.Equal(command, observed.CommandId);
            Assert.Equal(epoch, observed.OwnerEpoch);
            Assert.Equal(sandbox, observed.AggregateId);
            if (observed.State == OperationState.Accepted) return false;
            var error = observed.Error;
            Assert.True(observed.State == OperationState.Succeeded,
                $"Delete reached {observed.State} with effect {observed.Effect}, error {error?.Category}/{SafeDeleteReason(error?.Code)} " +
                $"and reason {SafeDeleteReason(error?.Details?.State?.Reason)}.");
            Assert.Equal(EffectCertainty.Happened, observed.Effect);
            completed = observed;
            return true;
        }, NativeBound, "the original installed Delete receipt completing");
        return Assert.IsType<Operation>(completed);
    }

    private static string SafeDeleteReason(string? value) => value is { Length: > 0 and <= 128 }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or ':') ? value : "unavailable";

    private sealed record InstalledDeletionDisk(StoredSandbox Row, StoredSandboxDeletion? Pending, long JournalCount,
        string? ReceiptState, string? DeletionId, string? Phase, string? LatestSuccessor, string? QuarantineIdentity,
        string? RemovalProof);
}
