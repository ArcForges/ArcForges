// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const string FixtureDataPath = "data/round-trip.bin";
    private const int TransferChunkSize = 1024 * 1024;
    private const string BeforeFileCommitIntent = "hold-data-before-commit-intent";
    private const string AfterFileCommitIntent = "hold-data-after-commit-intent";
    private const string AfterFirstFilePublicationEffect = "hold-data-after-first-publication-effect";
    private const string AfterFilePublication = "hold-data-after-publication";
    private const string BeforeFileCommitReply = "hold-data-before-commit-reply";

    [Fact(Timeout = 145_000, DisableParallelization = true)]
    public async Task InstalledSandboxDataImportsPersistsAndExportsTheExactRetainedSnapshot()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        await using var installed = await TerminalCliFixture.StartAsync(retention: 2 * TransferChunkSize);
        await using var control = OpenChannel(installed.Node);
        var node = new NodeService.NodeServiceClient(control.CallInvoker);
        var data = new DataService.DataServiceClient(control.CallInvoker);
        var epoch = (await HandshakeAsync(node)).OwnerEpoch;
        var sandbox = installed.Sandbox;
        var clientFiles = Directory.CreateDirectory(Path.Combine(installed.Node.Root, "client data files")).FullName;
        var source = Path.Combine(clientFiles, "fixture input 四.bin");
        byte[] original = BuildFileBytes(TransferChunkSize + 89, 17);
        byte[] replacement = BuildFileBytes(1389, 91);
        await File.WriteAllBytesAsync(source, original, token);

        var firstUsage = await data.GetUsageAsync(new DataServiceGetUsageRequest { Meta = Query(), SandboxId = sandbox.SandboxId },
            deadline: Deadline, cancellationToken: token);
        var pendingScan = Value(firstUsage.Value, firstUsage.Error).Usage;
        Assert.True(pendingScan.HasPartial && pendingScan.Partial);
        Assert.False(pendingScan.HasOwnedBytes);
        Assert.False(pendingScan.HasFileCount);
        var baseline = await AwaitOwnedUsageAsync(data, sandbox.SandboxId, _ => true, token);
        await RequireOwnedRootListingAsync(data, sandbox.SandboxId, token);
        var imported = await InstalledCliSuccessAsync(installed.Node, "sandbox", "import", installed.SandboxText, source,
            "--to", FixtureDataPath);
        Assert.Equal(epoch, InstalledCliId(imported, "ownerEpoch"));
        var importId = InstalledCliId(imported.GetProperty("transfer"), "transferId");
        var importState = await InspectFileTransferAsync(data, importId, token);
        var importedTransfer = Value(importState.Value, importState.Error).Transfer;
        RequireCompleteFileTransfer(importedTransfer, sandbox, FixtureDataPath, "import", original);
        Assert.NotNull(importedTransfer.ClosedAt);
        var usage = await AwaitOwnedUsageAsync(data, sandbox.SandboxId,
            current => current.OwnedBytes == baseline.OwnedBytes + (ulong)original.Length && current.FileCount == baseline.FileCount + 1, token);
        var cliUsage = (await InstalledCliSuccessAsync(installed.Node, "sandbox", "usage", installed.SandboxText)).GetProperty("usage");
        Assert.Equal(usage.OwnedBytes.ToString(CultureInfo.InvariantCulture), CliScalar(cliUsage.GetProperty("ownedBytes")));
        Assert.Equal(usage.FileCount.ToString(CultureInfo.InvariantCulture), CliScalar(cliUsage.GetProperty("fileCount")));
        Assert.False(cliUsage.GetProperty("partial").GetBoolean());

        var entry = await ReadOwnedFileEntryAsync(data, sandbox, original.Length, token);
        var cliFiles = await InstalledCliSuccessAsync(installed.Node, "sandbox", "files", installed.SandboxText, "data");
        var entryJson = Assert.Single(cliFiles.GetProperty("entries").EnumerateArray(), e =>
            e.GetProperty("relativePath").GetString() == FixtureDataPath);
        Assert.Equal(entry.VersionToken, entryJson.GetProperty("versionToken").GetString());

        var firstRun = await ReadOriginalFromNativeRunAsync(installed, epoch, original, replacementFile: null, token);
        var begin = new DataServiceBeginExportRequest
        {
            Meta = Mutation(sandbox.Revision),
            OwnerEpoch = epoch,
            SandboxId = sandbox.SandboxId,
            RelativePath = FixtureDataPath,
            ExpectedFileVersion = entry.VersionToken,
        };
        var started = await data.BeginExportAsync(begin, deadline: Deadline, cancellationToken: token);
        var exportId = Value(started.Value, started.Error).Transfer.TransferId;
        var snapshot = await AwaitMaterializedExportAsync(data, exportId, token);
        var retained = Value(snapshot.Value, snapshot.Error).Transfer;
        RequireCompleteFileTransfer(retained, sandbox, FixtureDataPath, "export", original);
        Assert.Null(retained.ClosedAt);
        await RequireFileTransferCliInspectionAsync(installed.Node, retained, original);

        var replacementFile = Path.Combine(installed.Working, "replacement.bin");
        await File.WriteAllBytesAsync(replacementFile, replacement, token);
        var secondRun = await ReadOriginalFromNativeRunAsync(installed, epoch, original, replacementFile, token);
        Assert.NotEqual(firstRun.RunId, secondRun.RunId);
        var updated = await File.ReadAllBytesAsync(Path.Combine(sandbox.DataLocation, "data", "round-trip.bin"), token);
        Assert.True(replacement.AsSpan().SequenceEqual(updated));
        await VerifyRetainedExportReplayAsync(installed.Node, data, node, installed.Runs, epoch, sandbox, retained, original, token);

        var destination = Path.Combine(clientFiles, "fixture export 四.bin");
        var exported = await InstalledCliSuccessAsync(installed.Node, "sandbox", "export", installed.SandboxText, FixtureDataPath,
            "--to", destination);
        Assert.True(exported.GetProperty("localFilePublished").GetBoolean());
        var cliExport = InstalledCliId(exported.GetProperty("transfer"), "transferId");
        var cliClosed = await InspectFileTransferAsync(data, cliExport, token);
        var closed = Value(cliClosed.Value, cliClosed.Error).Transfer;
        RequireCompleteFileTransfer(closed, sandbox, FixtureDataPath, "export", replacement);
        Assert.NotNull(closed.ClosedAt);
        var written = await File.ReadAllBytesAsync(destination, token);
        var unchanged = await File.ReadAllBytesAsync(source, token);
        Assert.True(replacement.AsSpan().SequenceEqual(written));
        Assert.True(original.AsSpan().SequenceEqual(unchanged));
        await RequireLocalExportNoReplaceAsync(installed.Node, installed.SandboxText, destination, replacement, token);
    }

    [Fact(Timeout = 125_000, DisableParallelization = true)]
    public async Task InstalledSandboxDataRefusesOrdinaryUnsafePathsAndManagedUse()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        await using var installed = await TerminalCliFixture.StartAsync();
        await using var control = OpenChannel(installed.Node);
        var node = new NodeService.NodeServiceClient(control.CallInvoker);
        var data = new DataService.DataServiceClient(control.CallInvoker);
        var epoch = (await HandshakeAsync(node)).OwnerEpoch;
        var sandbox = installed.Sandbox;
        var owned = Path.Combine(sandbox.DataLocation, "data");
        var outside = Directory.CreateDirectory(Path.Combine(installed.Node.Root, "foreign file fixture")).FullName;
        var outsideFile = Path.Combine(outside, "sentinel.bin");
        var original = BuildFileBytes(3141, 82);
        var offered = BuildFileBytes(41_021, 183);
        await File.WriteAllBytesAsync(outsideFile, original, token);
        var existing = Path.Combine(owned, "CaseOwner.bin");
        await File.WriteAllBytesAsync(existing, original, token);

        string[] invalid = OperatingSystem.IsWindows()
            ? ["../sentinel.bin", outsideFile, "data/file.bin:stream"]
            : ["../sentinel.bin", outsideFile];
        foreach (var path in invalid)
        {
            var response = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, path, offered), deadline: Deadline,
                cancellationToken: token);
            Assert.Null(response.Value);
            Assert.NotNull(response.Error);
            Assert.Equal(ErrorCategory.Validation, response.Error.Category);
            Assert.Equal("invalid_argument", response.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        }

        var noReplace = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, "data/CaseOwner.bin", offered),
            deadline: Deadline, cancellationToken: token);
        Assert.Null(noReplace.Value);
        RequireDataRefusal(noReplace.Error, ErrorCategory.Conflict, "identity_changed");
        Assert.Equal("import_target_changed", noReplace.Error?.Details?.State?.Reason);
        var wrongCase = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, "data/caseowner.bin", offered),
            deadline: Deadline, cancellationToken: token);
        RequireFileDestinationRefused(wrongCase);
        Assert.Equal("CaseOwner.bin", Path.GetFileName(Assert.Single(Directory.EnumerateFiles(owned))));
        await RequireGuardedExistingFileRefusalsAsync(installed, data, epoch, existing, original, offered, token);
        await RequireDataLinkRefusalAsync(installed.Node, data, sandbox, epoch, owned, outside, token);
        await RequireApprovedHostGrantExclusionAsync(new SandboxService.SandboxServiceClient(control.CallInvoker), data,
            sandbox.Config, epoch, outside, token);
        await RequireActiveRunDataRefusalAsync(installed, data, epoch, offered, token);
        await RequireNewDestinationPreservedAsync(data, sandbox, epoch, offered, original, token);
        var retained = await File.ReadAllBytesAsync(existing, token);
        var sentinel = await File.ReadAllBytesAsync(outsideFile, token);
        Assert.True(original.AsSpan().SequenceEqual(retained));
        Assert.True(original.AsSpan().SequenceEqual(sentinel));
    }

    private static DataServiceBeginImportRequest BeginFixtureImport(Sandbox sandbox, Id epoch, string path, byte[] bytes) => new()
    {
        Meta = Mutation(sandbox.Revision),
        OwnerEpoch = epoch,
        SandboxId = sandbox.SandboxId,
        RelativePath = path,
        ByteLength = (ulong)bytes.Length,
        Sha256 = FileDigest(bytes),
        Overwrite = false,
    };

    [Theory(Timeout = 135_000, DisableParallelization = true)]
    [InlineData(BeforeFileCommitIntent)]
    [InlineData(AfterFileCommitIntent)]
    [InlineData(AfterFirstFilePublicationEffect)]
    [InlineData(AfterFilePublication)]
    [InlineData(BeforeFileCommitReply)]
    public async Task InstalledSandboxDataRecoversOriginalCommitAtEachDurableBoundary(string checkpoint)
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareInstalledCliFixture(fixture);
        fixture.Environment[ExecutionFaults.Variable] = checkpoint + "=60";
        var interrupted = await fixture.StartNodeAsync();
        Process? restarted = null;
        Id? cleanupEpoch = null;
        try
        {
            const string path = "data/checkpoint-import.bin";
            byte[] content = BuildFileBytes(27_031, 119);
            bool beforeIntent = checkpoint == BeforeFileCommitIntent;
            bool published = checkpoint is AfterFirstFilePublicationEffect or AfterFilePublication or BeforeFileCommitReply;
            bool bothNamesRemain = checkpoint == AfterFirstFilePublicationEffect && OperatingSystem.IsLinux();
            string? expectedReceipt = beforeIntent ? null : checkpoint == BeforeFileCommitReply ? "SUCCEEDED" : "ACCEPTED";
            DataServiceCommitImportRequest commit;
            Sandbox sandbox;
            string destination;
            string firstNodeEpoch;
            StoredTransfer atCheckpoint;
            await using (var connection = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(connection.CallInvoker);
                var data = new DataService.DataServiceClient(connection.CallInvoker);
                var hello = await HandshakeAsync(node);
                var epoch = hello.OwnerEpoch;
                cleanupEpoch = epoch;
                firstNodeEpoch = hello.NodeEpoch;
                sandbox = await CreateSandboxAsync(new SandboxService.SandboxServiceClient(connection.CallInvoker), epoch);
                destination = Path.Combine(sandbox.DataLocation, "data", "checkpoint-import.bin");
                var (_, staged) = await WriteFirstFileChunkAsync(data, sandbox, epoch, path, destination, content, content.Length, token);
                var ready = await InspectFileTransferAsync(data, staged.TransferId, token);
                Assert.Equal(staged, Value(ready.Value, ready.Error).Transfer);
                commit = new DataServiceCommitImportRequest
                {
                    Meta = Mutation(TransferRevision(ready.Meta)), OwnerEpoch = epoch, TransferId = staged.TransferId,
                };

                using var pending = data.CommitImportAsync(commit, deadline: DateTime.UtcNow.AddSeconds(55), cancellationToken: token);
                await WaitDispatchCheckpointAsync(fixture, checkpoint);
                Assert.False(pending.ResponseAsync.IsCompleted, "The original caller must lose its reply at the selected private boundary.");
                var observation = ReadFileCommitCheckpoint(fixture, sandbox.SandboxId, commit);
                atCheckpoint = observation.Transfer;
                Assert.Equal(expectedReceipt, observation.ReceiptState);
                Assert.Equal(published, File.Exists(destination));
                Assert.Equal((long)content.Length, atCheckpoint.VerifiedOffset);
                Assert.Equal(checkpoint == BeforeFileCommitReply ? StoredTransferState.Complete : StoredTransferState.Streaming,
                    atCheckpoint.State);
                Assert.Null(atCheckpoint.ClosedAt);
                if (beforeIntent || checkpoint == BeforeFileCommitReply)
                {
                    Assert.Null(atCheckpoint.Manifest.Pending);
                }
                else
                {
                    Assert.Equal(StoredTransferPhase.Publish, atCheckpoint.Manifest.Pending?.Phase);
                    Assert.Equal(Hex(commit.Meta.CommandId), atCheckpoint.Manifest.Pending?.CommandId);
                }

                interrupted.Kill();
                await interrupted.WaitForExitAsync(token).WaitAsync(NativeBound, token);
                await Assert.ThrowsAnyAsync<RpcException>(() => pending.ResponseAsync.WaitAsync(NativeBound, token));
            }

            var diskStamp = await RequireFileCommitDiskBoundaryAsync(fixture, commit, atCheckpoint, destination, published,
                bothNamesRemain, content, token);
            fixture.Environment.Remove(ExecutionFaults.Variable);
            restarted = await fixture.StartNodeAsync();
            await using var recovered = OpenChannel(fixture);
            var recoveredNode = new NodeService.NodeServiceClient(recovered.CallInvoker);
            var recoveredData = new DataService.DataServiceClient(recovered.CallInvoker);
            var current = await HandshakeAsync(recoveredNode);
            Assert.Equal(commit.OwnerEpoch, current.OwnerEpoch);
            Assert.NotEqual(firstNodeEpoch, current.NodeEpoch);
            await VerifyRecoveredFileCommitAsync(fixture, recoveredNode, recoveredData, sandbox, commit, atCheckpoint,
                destination, path, content, beforeIntent, published, bothNamesRemain ? diskStamp : null, token);
        }
        finally
        {
            string marker = DispatchCheckpointPath(fixture, checkpoint);
            if (!interrupted.HasExited && File.Exists(marker))
            {
                File.WriteAllText(Path.ChangeExtension(marker, ".release"), string.Empty);
            }

            if (restarted is not null) interrupted.Dispose();
            await CleanInstalledCliFixtureAsync(fixture, restarted ?? interrupted, cleanupEpoch, heldRun: null);
        }
    }

    private static (StoredTransfer Transfer, string? ReceiptState) ReadFileCommitCheckpoint(TestNode fixture, Id sandbox,
        DataServiceCommitImportRequest commit)
    {
        using var database = ReadDatabase(fixture.DataRoot);
        var reader = new StoreReader(database, transaction: null, clock: TimeProvider.System);
        var sandboxId = Hex(sandbox);
        var transferId = Hex(commit.TransferId);
        var owner = Assert.IsType<string>(reader.Scalar("SELECT owner_id FROM sandbox WHERE sandbox_id=$id;", ("$id", sandboxId)));
        var row = Assert.IsType<StoredTransfer>(TransferRecords.Get(reader, owner, transferId));
        Assert.Equal(sandboxId, row.SandboxId);
        Assert.Equal(StoredTransferDirection.Import, row.Direction);
        Assert.True(commit.OwnerEpoch.Value.Span.SequenceEqual(row.OwnerEpoch));
        var state = reader.Scalar("""
            SELECT state FROM command_receipt WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$command
                AND method=$method AND aggregate_kind='transfer' AND aggregate_id=$transfer;
            """, ("$owner", owner), ("$epoch", commit.OwnerEpoch.Value.ToByteArray()), ("$command", Hex(commit.Meta.CommandId)),
            ("$method", TransferRecords.CommitMethod), ("$transfer", transferId));
        return (row, state as string);
    }

    private static string FileCommitStageDirectory(TestNode fixture) => Path.Combine(fixture.DataRoot, "control", "sandbox-transfers");

    private static string FileCommitStagePath(TestNode fixture, Id transfer) =>
        Path.Combine(FileCommitStageDirectory(fixture), Hex(transfer));

    private static async Task<WorkspaceFileStamp> RequireFileCommitDiskBoundaryAsync(TestNode fixture, DataServiceCommitImportRequest commit,
        StoredTransfer observed, string destination, bool published, bool bothNamesRemain, byte[] expected, CancellationToken token)
    {
        var stagePath = FileCommitStagePath(fixture, commit.TransferId);
        Assert.Equal(published, File.Exists(destination));
        Assert.Equal(!published || bothNamesRemain, File.Exists(stagePath));
        if (bothNamesRemain)
        {
            // Linux has linked the exact fixture file to its final name and has yet to retire its original name.
            // The production reader requires single-link files, so observe only these known fixture paths directly.
            const FileAttributes nonRegular = FileAttributes.Directory | FileAttributes.ReparsePoint;
            Assert.Equal((FileAttributes)0, File.GetAttributes(stagePath) & nonRegular);
            Assert.Equal((FileAttributes)0, File.GetAttributes(destination) & nonRegular);
            using var stage = File.OpenHandle(stagePath, FileMode.Open, FileAccess.Read);
            using var target = File.OpenHandle(destination, FileMode.Open, FileAccess.Read);
            var stageIdentity = WorkspacePath.Identity(stage);
            var targetIdentity = WorkspacePath.Identity(target);
            Assert.True(stageIdentity.IsFile && targetIdentity.IsFile);
            Assert.Equal(2U, stageIdentity.Links);
            Assert.Equal(2U, targetIdentity.Links);
            Assert.True(stageIdentity.SameObject(targetIdentity));
            // The durable token excludes link count. The encoder accepts its original one-link shape only.
            Assert.Equal(observed.StagingIdentity, WorkspacePath.EncodeDataIdentity(stageIdentity with { Links = 1 }));
            var stamp = WorkspacePath.FileStamp(stage);
            Assert.Equal(stamp, WorkspacePath.FileStamp(target));
            await RequireFileCommitBytesAsync(stage, expected, token);
            await RequireFileCommitBytesAsync(target, expected, token);
            return stamp;
        }

        var parent = published ? Path.GetDirectoryName(destination)! : FileCommitStageDirectory(fixture);
        using var workspace = WorkspacePath.OpenRoot(parent);
        using var file = published ? workspace.OpenRead(Path.GetFileName(destination))
            : workspace.OpenSandboxDataStage(Hex(commit.TransferId), observed.StagingIdentity, writable: false);
        if (published)
        {
            Assert.Equal(observed.StagingIdentity, WorkspacePath.EncodeDataIdentity(WorkspacePath.Identity(file)));
        }

        var observedStamp = WorkspacePath.FileStamp(file);
        await RequireFileCommitBytesAsync(file, expected, token);
        return observedStamp;
    }

    private static async Task RequireFileCommitBytesAsync(SafeFileHandle file, byte[] expected, CancellationToken token)
    {
        using var input = new FileStream(file, FileAccess.Read);
        Assert.Equal(expected.LongLength, input.Length);
        var staged = new byte[expected.Length];
        await input.ReadExactlyAsync(staged, token);
        Assert.True(expected.AsSpan().SequenceEqual(staged));
    }

    private static async Task VerifyRecoveredFileCommitAsync(TestNode fixture, NodeService.NodeServiceClient node,
        DataService.DataServiceClient data, Sandbox sandbox, DataServiceCommitImportRequest commit, StoredTransfer original,
        string destination, string path, byte[] bytes, bool beforeIntent, bool published, WorkspaceFileStamp? linkedStamp,
        CancellationToken token)
    {
        if (beforeIntent)
        {
            var missing = await node.GetOperationAsync(new NodeServiceGetOperationRequest
            {
                Meta = Query(), OwnerEpoch = commit.OwnerEpoch, CommandId = commit.Meta.CommandId,
            }, deadline: Deadline, cancellationToken: token);
            Assert.Null(missing.Value);
            RequireDataRefusal(missing.Error, ErrorCategory.State, "not_found");
            var stillStaged = ReadFileCommitCheckpoint(fixture, sandbox.SandboxId, commit);
            Assert.Null(stillStaged.ReceiptState);
            Assert.Equal(original.StagingIdentity, stillStaged.Transfer.StagingIdentity);
            Assert.Null(stillStaged.Transfer.Manifest.Pending);
            var stage = await InspectFileTransferAsync(data, commit.TransferId, token);
            Assert.Equal(TransferState.Streaming, Value(stage.Value, stage.Error).Transfer.State);
            await RequireFileCommitDiskBoundaryAsync(fixture, commit, stillStaged.Transfer, destination, published: false,
                bothNamesRemain: false, bytes, token);
            await CloseFileCommitAsync(fixture, data, commit, stage.Meta, TransferState.Failed, token);
            Assert.False(File.Exists(destination));
            return;
        }

        bool recoveredPublication = published && linkedStamp is null;
        OperationState expectedState = recoveredPublication ? OperationState.Succeeded : OperationState.Unknown;
        EffectCertainty expectedEffect = recoveredPublication ? EffectCertainty.Happened : EffectCertainty.Unknown;
        await TestNode.WaitAsync(async () =>
        {
            var receipt = await OperationAsync(node, commit.OwnerEpoch, commit.Meta.CommandId);
            Assert.Equal(commit.Meta.CommandId, receipt.CommandId);
            Assert.Equal(commit.TransferId, receipt.AggregateId);
            Assert.Equal(commit.OwnerEpoch, receipt.OwnerEpoch);
            if (receipt.State == OperationState.Accepted) return false;
            Assert.Equal(expectedState, receipt.State);
            Assert.Equal(expectedEffect, receipt.Effect);
            return true;
        }, NativeBound, "reconciliation of the original commit receipt");

        var before = await InspectFileTransferAsync(data, commit.TransferId, token);
        var transfer = Value(before.Value, before.Error).Transfer;
        var stored = ReadFileCommitCheckpoint(fixture, sandbox.SandboxId, commit);
        Assert.Equal(original.StagingIdentity, stored.Transfer.StagingIdentity);
        if (recoveredPublication)
        {
            RequireCompleteFileTransfer(transfer, sandbox, path, "import", bytes);
            Assert.Null(stored.Transfer.Manifest.Pending);
        }
        else
        {
            Assert.Equal(TransferState.RecoveryRequired, transfer.State);
            Assert.Null(transfer.ClosedAt);
            Assert.Equal(StoredTransferPhase.Publish, stored.Transfer.Manifest.Pending?.Phase);
            Assert.Equal(Hex(commit.Meta.CommandId), stored.Transfer.Manifest.Pending?.CommandId);
        }

        var version = recoveredPublication ? (await ObserveFixtureRegularFileAsync(data, sandbox.SandboxId, path, token)).VersionToken : null;
        var replayed = await data.CommitImportAsync(commit, deadline: Deadline, cancellationToken: token);
        var replay = Value(replayed.Value, replayed.Error);
        Assert.Equal(commit.Meta.CommandId, replay.Operation.CommandId);
        Assert.Equal(expectedState, replay.Operation.State);
        Assert.Equal(expectedEffect, replay.Operation.Effect);
        Assert.Equal(transfer, replay.Transfer);
        var after = await InspectFileTransferAsync(data, commit.TransferId, token);
        Assert.Equal(transfer, Value(after.Value, after.Error).Transfer);
        Assert.Equal(TransferRevision(before.Meta), TransferRevision(after.Meta));
        var stampAfterReplay = await RequireFileCommitDiskBoundaryAsync(fixture, commit, stored.Transfer, destination, published,
            linkedStamp is not null, bytes, token);
        if (linkedStamp is { } originalStamp)
        {
            Assert.Equal(originalStamp, stampAfterReplay);
        }

        if (recoveredPublication)
        {
            Assert.Equal(version, (await ObserveFixtureRegularFileAsync(data, sandbox.SandboxId, path, token)).VersionToken);
            Assert.Equal(destination, Assert.Single(Directory.EnumerateFiles(Path.GetDirectoryName(destination)!)));
            await CloseFileCommitAsync(fixture, data, commit, after.Meta, TransferState.Complete, token);
        }
    }

    private static async Task CloseFileCommitAsync(TestNode fixture, DataService.DataServiceClient data,
        DataServiceCommitImportRequest commit, ResponseMeta observed, TransferState expected, CancellationToken token)
    {
        var reply = await data.CloseTransferAsync(new DataServiceCloseTransferRequest
        {
            Meta = Mutation(TransferRevision(observed)), OwnerEpoch = commit.OwnerEpoch, TransferId = commit.TransferId,
        }, deadline: Deadline, cancellationToken: token);
        var result = Value(reply.Value, reply.Error).Transfer;
        Assert.Equal(commit.TransferId, result.TransferId);
        Assert.Equal(expected, result.State);
        Assert.NotNull(result.ClosedAt);
        Assert.False(File.Exists(FileCommitStagePath(fixture, commit.TransferId)));
    }

    private static void RequireFileDestinationRefused(DataServiceBeginImportResponse response)
    {
        Assert.Null(response.Value);
        Assert.NotNull(response.Error);
        Assert.True(response.Error.Code is "identity_changed" or "path_rejected" or "invalid_argument");
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
    }

    private static async Task RequireGuardedExistingFileRefusalsAsync(TerminalCliFixture installed, DataService.DataServiceClient data,
        Id epoch, string destination, byte[] existing, byte[] offered, CancellationToken token)
    {
        const string path = "data/CaseOwner.bin";
        var sandbox = installed.Sandbox;
        var current = await ObserveFixtureRegularFileAsync(data, sandbox.SandboxId, path, token);
        Assert.Equal((ulong)existing.Length, current.ByteLength);
        var exact = BeginFixtureImport(sandbox, epoch, path, offered);
        exact.Overwrite = true;
        exact.ExpectedFileVersion = current.VersionToken;
        var unsupported = await data.BeginImportAsync(exact, deadline: Deadline, cancellationToken: token);
        Assert.Null(unsupported.Value);
        RequireDataRefusal(unsupported.Error, ErrorCategory.Execution, "unsupported_combination");
        Assert.Equal("guarded_existing_file_replace_unavailable", unsupported.Error?.Details?.State?.Reason);
        var afterExact = await File.ReadAllBytesAsync(destination, token);
        Assert.True(existing.AsSpan().SequenceEqual(afterExact));

        var different = await ObserveFixtureRegularFileAsync(data, sandbox.SandboxId,
            RelativeWorkdir + "/" + Path.GetFileName(installed.Payload), token);
        Assert.NotEqual(current.VersionToken, different.VersionToken);
        var wrong = BeginFixtureImport(sandbox, epoch, path, offered);
        wrong.Overwrite = true;
        wrong.ExpectedFileVersion = different.VersionToken;
        var conflict = await data.BeginImportAsync(wrong, deadline: Deadline, cancellationToken: token);
        Assert.Null(conflict.Value);
        RequireDataRefusal(conflict.Error, ErrorCategory.Conflict, "identity_changed");
        Assert.Equal("import_target_changed", conflict.Error?.Details?.State?.Reason);
        var afterWrong = await File.ReadAllBytesAsync(destination, token);
        Assert.True(existing.AsSpan().SequenceEqual(afterWrong));
        Assert.Equal(current.VersionToken, (await ObserveFixtureRegularFileAsync(data, sandbox.SandboxId, path, token)).VersionToken);
    }

    private static async Task RequireDataLinkRefusalAsync(TestNode fixture, DataService.DataServiceClient data, Sandbox sandbox,
        Id epoch, string owned, string outside, CancellationToken token)
    {
        var link = Path.Combine(owned, "linked-dir");
        if (OperatingSystem.IsWindows())
        {
            await CreateFileFixtureJunctionAsync(fixture.Root, link, outside, token);
        }
        else
        {
            Directory.CreateSymbolicLink(link, outside);
        }

        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0);
        try
        {
            var list = await data.ListEntriesAsync(new DataServiceListEntriesRequest
            {
                Meta = Query(), SandboxId = sandbox.SandboxId, RelativeDirectory = "data/linked-dir",
            }, deadline: Deadline, cancellationToken: token);
            Assert.Null(list.Value);
            RequireDataRefusal(list.Error, ErrorCategory.Validation, "path_rejected");
            var export = await data.BeginExportAsync(new DataServiceBeginExportRequest
            {
                Meta = Mutation(sandbox.Revision), OwnerEpoch = epoch, SandboxId = sandbox.SandboxId,
                RelativePath = "data/linked-dir/sentinel.bin",
            }, deadline: Deadline, cancellationToken: token);
            Assert.Null(export.Value);
            RequireDataRefusal(export.Error, ErrorCategory.Validation, "invalid_argument");
        }
        finally
        {
            Directory.Delete(link, recursive: false);
        }
    }

    private static async Task CreateFileFixtureJunctionAsync(string fixtureRoot, string link, string target, CancellationToken token)
    {
        Assert.True(Directory.Exists(Path.GetDirectoryName(link)));
        Assert.True(Directory.Exists(target));
        Assert.False(Path.Exists(link));
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
        {
            WorkingDirectory = fixtureRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // /s strips just the enclosing pair. Quote the expanded paths independently.
            Arguments = "/d /s /v:off /c \"mklink /J \"%ARCFORGES_FIXTURE_JUNCTION%\" \"%ARCFORGES_FIXTURE_JUNCTION_TARGET%\"\"",
        };
        start.Environment["ARCFORGES_FIXTURE_JUNCTION"] = link;
        start.Environment["ARCFORGES_FIXTURE_JUNCTION_TARGET"] = target;
        using var junction = Process.Start(start) ?? throw new InvalidOperationException("The owned junction fixture did not start.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(NativeBound);
        var errors = junction.StandardError.ReadToEndAsync(deadline.Token);
        var output = junction.StandardOutput.ReadToEndAsync(deadline.Token);
        try
        {
            await junction.WaitForExitAsync(deadline.Token);
            var stderr = await errors;
            var stdout = await output;
            Assert.True(junction.ExitCode == 0,
                $"Owned junction creation returned {junction.ExitCode}. stderr: {Bounded(stderr)}. stdout: {Bounded(stdout)}.");
        }
        finally
        {
            await KillOwnedCliAsync(junction);
        }

        static string Bounded(string value)
        {
            string line = value.Trim().ReplaceLineEndings(" ");
            return line[..Math.Min(line.Length, 512)];
        }
    }

    private static async Task RequireApprovedHostGrantExclusionAsync(SandboxService.SandboxServiceClient sandboxes,
        DataService.DataServiceClient data, SandboxConfig original, Id epoch, string outside, CancellationToken token)
    {
        var config = original.Clone();
        config.HostGrants.Add(new HostGrant { HostPath = outside, SandboxPath = outside, Writable = false });
        var created = await sandboxes.CreateAsync(new SandboxServiceCreateRequest
        {
            Meta = Mutation(), OwnerEpoch = epoch, DisplayName = "Installed file exclusion fixture", Config = config,
        }, deadline: Deadline, cancellationToken: token);
        var sandbox = Value(created.Value, created.Error).Sandbox;
        var bound = Assert.Single(sandbox.Config.HostGrants);
        Assert.False(string.IsNullOrEmpty(bound.NativeIdentity));
        var current = await AwaitOwnedUsageAsync(data, sandbox.SandboxId, _ => true, token);
        Assert.Equal(bound.HostPath, Assert.Single(current.ExcludedRoots));
        Assert.Equal(0UL, current.OwnedBytes);
        Assert.Equal(0UL, current.FileCount);
    }

    private static void RequireDataRefusal(ArcError? error, ErrorCategory category, string code)
    {
        Assert.NotNull(error);
        Assert.Equal(category, error.Category);
        Assert.Equal(code, error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
    }

    private static async Task RequireActiveRunDataRefusalAsync(TerminalCliFixture installed, DataService.DataServiceClient data,
        Id epoch, byte[] offered, CancellationToken token)
    {
        var release = Path.Combine(installed.Working, "live-file-run-release");
        var marker = Path.Combine(installed.Working, "live-file-run.log");
        var request = BuildStart(installed.Sandbox, epoch,
            [installed.Payload, "hold", "--hold-ms", "60000", "--until-file", release, "--marker", marker]);
        request.TerminalMode = TerminalMode.Pipes;
        request.TerminalSize = null;
        var reply = await installed.Runs.StartAsync(request, deadline: Deadline, cancellationToken: token);
        var run = Value(reply.Value, reply.Error).Run;
        await WaitForStateAsync(installed.Node, installed.Runs, run.RunId, RunState.Running, token);
        await TestNode.WaitAsync(() => ReadLines(marker).Any(line => line.StartsWith("ready ", StringComparison.Ordinal)),
            NativeBound, "a real active Run with its Sandbox private root");

        var sandbox = installed.Sandbox;
        var import = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, "data/live-refused.bin", offered),
            deadline: Deadline, cancellationToken: token);
        Assert.Null(import.Value);
        RequireDataRefusal(import.Error, ErrorCategory.State, "managed_use");
        var export = await data.BeginExportAsync(new DataServiceBeginExportRequest
        {
            Meta = Mutation(sandbox.Revision), OwnerEpoch = epoch, SandboxId = sandbox.SandboxId, RelativePath = "data/CaseOwner.bin",
        }, deadline: Deadline, cancellationToken: token);
        Assert.Null(export.Value);
        RequireDataRefusal(export.Error, ErrorCategory.State, "managed_use");
        Assert.False(File.Exists(Path.Combine(sandbox.DataLocation, "data", "live-refused.bin")));
        await File.WriteAllTextAsync(release, "release", token);
        var settled = await installed.WaitExitedAsync(run.RunId, token);
        Assert.True(settled.Exit.HasRawCode);
        Assert.Equal(0, settled.Exit.RawCode);
    }

    private static async Task RequireNewDestinationPreservedAsync(DataService.DataServiceClient data, Sandbox sandbox, Id epoch,
        byte[] offered, byte[] newOwnerFile, CancellationToken token)
    {
        const string path = "data/appeared-after-begin.bin";
        string destination = Path.Combine(sandbox.DataLocation, "data", "appeared-after-begin.bin");
        var opened = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, path, offered), deadline: Deadline,
            cancellationToken: token);
        var transfer = Value(opened.Value, opened.Error).Transfer;
        var written = await data.WriteImportAsync(new DataServiceWriteImportRequest
        {
            Meta = Mutation(TransferRevision(opened.Meta)), OwnerEpoch = epoch, TransferId = transfer.TransferId,
            Offset = 0, Chunk = ByteString.CopyFrom(offered),
        }, deadline: Deadline, cancellationToken: token);
        var staged = Value(written.Value, written.Error).Transfer;
        Assert.Equal((ulong)offered.Length, staged.VerifiedOffset);
        Assert.False(File.Exists(destination));

        // An ordinary owner action creates this single regular file after staging has completed.
        await File.WriteAllBytesAsync(destination, newOwnerFile, token);
        var declined = await data.CommitImportAsync(new DataServiceCommitImportRequest
        {
            Meta = Mutation(TransferRevision(written.Meta)), OwnerEpoch = epoch, TransferId = transfer.TransferId,
        }, deadline: Deadline, cancellationToken: token);
        Assert.Null(declined.Value);
        RequireDataRefusal(declined.Error, ErrorCategory.Conflict, "identity_changed");
        Assert.Equal("import_target_changed", declined.Error?.Details?.State?.Reason);
        var actual = await File.ReadAllBytesAsync(destination, token);
        Assert.True(newOwnerFile.AsSpan().SequenceEqual(actual));

        var current = await InspectFileTransferAsync(data, transfer.TransferId, token);
        Assert.Equal(staged, Value(current.Value, current.Error).Transfer);
        var close = await data.CloseTransferAsync(new DataServiceCloseTransferRequest
        {
            Meta = Mutation(TransferRevision(current.Meta)), OwnerEpoch = epoch, TransferId = transfer.TransferId,
        }, deadline: Deadline, cancellationToken: token);
        var canceled = Value(close.Value, close.Error).Transfer;
        Assert.Equal(TransferState.Failed, canceled.State);
        Assert.NotNull(canceled.ClosedAt);
        actual = await File.ReadAllBytesAsync(destination, token);
        Assert.True(newOwnerFile.AsSpan().SequenceEqual(actual));
    }

    [Fact(Timeout = 125_000, DisableParallelization = true)]
    public async Task InstalledSandboxDataResumesTheSameStagedImportAfterOrderlyNodeRestart()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareInstalledCliFixture(fixture);
        var process = await fixture.StartNodeAsync();
        Id? epoch = null;
        try
        {
            const string path = "data/staged-import.bin";
            const int initialBytes = 16 * 1024;
            byte[] original = BuildFileBytes(41_021, 183);
            string destination;
            Sandbox sandbox;
            string originalNode;
            Id ownerEpoch;
            DataServiceWriteImportRequest first;
            Transfer partial;
            await using (var originalConnection = OpenChannel(fixture))
            {
                var hello = await HandshakeAsync(new NodeService.NodeServiceClient(originalConnection.CallInvoker));
                ownerEpoch = hello.OwnerEpoch;
                epoch = ownerEpoch;
                originalNode = hello.NodeEpoch;
                sandbox = await CreateSandboxAsync(new SandboxService.SandboxServiceClient(originalConnection.CallInvoker), ownerEpoch);
                destination = Path.Combine(sandbox.DataLocation, "data", "staged-import.bin");
                var data = new DataService.DataServiceClient(originalConnection.CallInvoker);
                (first, partial) = await WriteFirstFileChunkAsync(data, sandbox, ownerEpoch, path, destination, original, initialBytes, token);
            }

            await StopInstalledCliNodeAsync(fixture, process);
            Assert.True(process.HasExited);
            var originalProcess = process;
            process = await fixture.StartNodeAsync();
            originalProcess.Dispose();
            await using var recovered = OpenChannel(fixture);
            var node = new NodeService.NodeServiceClient(recovered.CallInvoker);
            var current = await HandshakeAsync(node);
            Assert.Equal(ownerEpoch, current.OwnerEpoch);
            Assert.NotEqual(originalNode, current.NodeEpoch);
            var resumed = new DataService.DataServiceClient(recovered.CallInvoker);
            var checkpoint = await InspectFileTransferAsync(resumed, partial.TransferId, token);
            Assert.Equal(partial, Value(checkpoint.Value, checkpoint.Error).Transfer);
            Assert.False(File.Exists(destination));
            var originalReceipt = await OperationAsync(node, ownerEpoch, first.Meta.CommandId);
            Assert.Equal(first.Meta.CommandId, originalReceipt.CommandId);
            Assert.Equal(partial.TransferId, originalReceipt.AggregateId);
            Assert.Equal(OperationState.Succeeded, originalReceipt.State);
            Assert.Equal(EffectCertainty.Happened, originalReceipt.Effect);

            var replay = await resumed.WriteImportAsync(first, deadline: Deadline, cancellationToken: token);
            Assert.Equal(partial, Value(replay.Value, replay.Error).Transfer);
            var afterReplay = await InspectFileTransferAsync(resumed, partial.TransferId, token);
            Assert.Equal(partial, Value(afterReplay.Value, afterReplay.Error).Transfer);
            Assert.Equal(TransferRevision(checkpoint.Meta), TransferRevision(afterReplay.Meta));
            await RequireFileTransferCliInspectionAsync(fixture, partial, original);
            await FinishResumedFileImportAsync(resumed, node, ownerEpoch, sandbox, path, destination, original, afterReplay, token);
        }
        finally
        {
            await CleanInstalledCliFixtureAsync(fixture, process, epoch, heldRun: null);
        }
    }

    private static async Task<(DataServiceWriteImportRequest First, Transfer Partial)> WriteFirstFileChunkAsync(
        DataService.DataServiceClient data, Sandbox sandbox, Id epoch, string path, string destination, byte[] original,
        int initialBytes, CancellationToken token)
    {
        var opened = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, path, original), deadline: Deadline,
            cancellationToken: token);
        var stage = Value(opened.Value, opened.Error).Transfer;
        Assert.Equal("import", stage.Direction);
        Assert.Equal(0UL, stage.VerifiedOffset);
        Assert.Null(stage.ClosedAt);
        Assert.False(File.Exists(destination));
        var first = new DataServiceWriteImportRequest
        {
            Meta = Mutation(TransferRevision(opened.Meta)), OwnerEpoch = epoch, TransferId = stage.TransferId,
            Offset = 0, Chunk = ByteString.CopyFrom(original.AsSpan(0, initialBytes)),
        };
        var written = await data.WriteImportAsync(first, deadline: Deadline, cancellationToken: token);
        var partial = Value(written.Value, written.Error).Transfer;
        Assert.Equal(stage.TransferId, partial.TransferId);
        Assert.Equal((ulong)initialBytes, partial.VerifiedOffset);
        Assert.Null(partial.ClosedAt);
        Assert.False(File.Exists(destination));
        return (first, partial);
    }

    private static async Task FinishResumedFileImportAsync(DataService.DataServiceClient resumed, NodeService.NodeServiceClient node,
        Id epoch, Sandbox sandbox, string path, string destination, byte[] original, DataServiceInspectTransferResponse checkpoint,
        CancellationToken token)
    {
        var progress = Value(checkpoint.Value, checkpoint.Error).Transfer;
        var id = progress.TransferId;
        Assert.InRange(progress.VerifiedOffset, 1UL, (ulong)original.Length - 1);
        var final = new DataServiceWriteImportRequest
        {
            Meta = Mutation(TransferRevision(checkpoint.Meta)), OwnerEpoch = epoch, TransferId = id,
            Offset = progress.VerifiedOffset, Chunk = ByteString.CopyFrom(original.AsSpan(checked((int)progress.VerifiedOffset))),
        };
        var written = await resumed.WriteImportAsync(final, deadline: Deadline, cancellationToken: token);
        var verified = Value(written.Value, written.Error).Transfer;
        Assert.Equal((ulong)original.Length, verified.VerifiedOffset);
        var replay = await resumed.WriteImportAsync(final, deadline: Deadline, cancellationToken: token);
        Assert.Equal(verified, Value(replay.Value, replay.Error).Transfer);
        var changed = final.Clone();
        changed.Chunk = ByteString.CopyFrom(new byte[final.Chunk.Length]);
        var conflict = await resumed.WriteImportAsync(changed, deadline: Deadline, cancellationToken: token);
        Assert.Null(conflict.Value);
        RequireDataRefusal(conflict.Error, ErrorCategory.Conflict, "command_id_reused");
        Assert.False(File.Exists(destination));

        var commit = new DataServiceCommitImportRequest
        {
            Meta = Mutation(TransferRevision(written.Meta)), OwnerEpoch = epoch, TransferId = id,
        };
        var committed = await resumed.CommitImportAsync(commit, deadline: Deadline, cancellationToken: token);
        var receipt = Value(committed.Value, committed.Error).Operation;
        Assert.Equal(commit.Meta.CommandId, receipt.CommandId);
        Assert.Equal(id, receipt.AggregateId);
        Assert.True(receipt.State is OperationState.Accepted or OperationState.Succeeded);
        DataServiceInspectTransferResponse? finalState = null;
        await TestNode.WaitAsync(async () =>
        {
            var observed = await InspectFileTransferAsync(resumed, id, token);
            if (Value(observed.Value, observed.Error).Transfer.State != TransferState.Complete) return false;
            finalState = observed;
            return true;
        }, NativeBound, "the original staged import commit");
        var finished = Assert.IsType<DataServiceInspectTransferResponse>(finalState);
        var committedTransfer = Value(finished.Value, finished.Error).Transfer;
        RequireCompleteFileTransfer(committedTransfer, sandbox, path, "import", original);
        var operation = await OperationAsync(node, epoch, commit.Meta.CommandId);
        Assert.Equal(OperationState.Succeeded, operation.State);
        Assert.Equal(EffectCertainty.Happened, operation.Effect);
        var actual = await File.ReadAllBytesAsync(destination, token);
        Assert.True(original.AsSpan().SequenceEqual(actual));
        var closeRequest = new DataServiceCloseTransferRequest
        {
            Meta = Mutation(TransferRevision(finished.Meta)), OwnerEpoch = epoch, TransferId = id,
        };
        var close = await resumed.CloseTransferAsync(closeRequest, deadline: Deadline, cancellationToken: token);
        var closed = Value(close.Value, close.Error).Transfer;
        RequireCompleteFileTransfer(closed, sandbox, path, "import", original);
        Assert.NotNull(closed.ClosedAt);

        var reused = new DataServiceCommitImportRequest
        {
            Meta = Mutation(TransferRevision(close.Meta)), OwnerEpoch = epoch, TransferId = id,
        };
        reused.Meta.CommandId = closeRequest.Meta.CommandId;
        var wrongMethod = await resumed.CommitImportAsync(reused, deadline: Deadline, cancellationToken: token);
        Assert.Null(wrongMethod.Value);
        RequireDataRefusal(wrongMethod.Error, ErrorCategory.Conflict, "command_id_reused");
        var afterConflict = await InspectFileTransferAsync(resumed, id, token);
        Assert.Equal(closed, Value(afterConflict.Value, afterConflict.Error).Transfer);
        Assert.Equal(TransferRevision(close.Meta), TransferRevision(afterConflict.Meta));
        var unchanged = await File.ReadAllBytesAsync(destination, token);
        Assert.True(original.AsSpan().SequenceEqual(unchanged));
    }

    private static Revision TransferRevision(ResponseMeta meta)
    {
        Assert.NotNull(meta.ResultRev);
        Assert.True(meta.ResultRev.Value > 0);
        return meta.ResultRev;
    }

    private static byte[] BuildFileBytes(int length, int salt)
    {
        var bytes = new byte[length];
        for (int index = 0; index < length; index++) bytes[index] = (byte)((index * 31) ^ (index >> 9) ^ salt);
        return bytes;
    }

    private static string FileDigest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static async Task<Usage> AwaitOwnedUsageAsync(DataService.DataServiceClient data, Id sandbox,
        Func<Usage, bool> expected, CancellationToken token)
    {
        Usage? completed = null;
        await TestNode.WaitAsync(async () =>
        {
            var response = await data.GetUsageAsync(new DataServiceGetUsageRequest { Meta = Query(), SandboxId = sandbox },
                deadline: Deadline, cancellationToken: token);
            var usage = Value(response.Value, response.Error).Usage;
            if (!(usage.HasPartial && !usage.Partial && usage.HasOwnedBytes && usage.HasFileCount && expected(usage))) return false;
            Assert.NotNull(usage.ObservedAt);
            completed = usage;
            return true;
        }, NativeBound, "the completed private ownership scan");
        return Assert.IsType<Usage>(completed);
    }

    private static async Task RequireOwnedRootListingAsync(DataService.DataServiceClient data, Id sandbox, CancellationToken token)
    {
        var request = new DataServiceListEntriesRequest { Meta = Query(), SandboxId = sandbox, Limit = 2 };
        var first = await data.ListEntriesAsync(request, deadline: Deadline, cancellationToken: token);
        var page = Value(first.Value, first.Error);
        Assert.Equal(["cache", "config"], page.Entries.Select(entry => entry.RelativePath));
        Assert.False(string.IsNullOrEmpty(page.Page.NextCursor));
        var otherDirectory = request.Clone();
        otherDirectory.RelativeDirectory = "data";
        otherDirectory.Cursor = page.Page.NextCursor;
        var refused = await data.ListEntriesAsync(otherDirectory, deadline: Deadline, cancellationToken: token);
        Assert.Null(refused.Value);
        RequireDataRefusal(refused.Error, ErrorCategory.Validation, "invalid_cursor");

        var rest = request.Clone();
        rest.Cursor = page.Page.NextCursor;
        rest.Limit = 4;
        var reply = await data.ListEntriesAsync(rest, deadline: Deadline, cancellationToken: token);
        var terminal = Value(reply.Value, reply.Error);
        Assert.Equal(["data", "home", "tmp", "work"], terminal.Entries.Select(entry => entry.RelativePath));
        Assert.Empty(terminal.Page.NextCursor);
    }

    private static async Task<FileEntry> ReadOwnedFileEntryAsync(DataService.DataServiceClient data, Sandbox sandbox, int length,
        CancellationToken token)
    {
        var entry = await ObserveFixtureRegularFileAsync(data, sandbox.SandboxId, FixtureDataPath, token);
        Assert.Equal((ulong)length, entry.ByteLength);
        return entry;
    }

    private static async Task<FileEntry> ObserveFixtureRegularFileAsync(DataService.DataServiceClient data, Id sandbox, string path,
        CancellationToken token)
    {
        var listed = await data.ListEntriesAsync(new DataServiceListEntriesRequest
        {
            Meta = Query(), SandboxId = sandbox, RelativeDirectory = path[..path.LastIndexOf('/')], Limit = 20,
        }, deadline: Deadline, cancellationToken: token);
        var entry = Assert.Single(Value(listed.Value, listed.Error).Entries, row => row.RelativePath == path);
        Assert.Equal("regular_file", entry.Kind);
        Assert.True(entry.HasByteLength);
        Assert.False(string.IsNullOrEmpty(entry.VersionToken));
        return entry;
    }

    private static async Task<Run> ReadOriginalFromNativeRunAsync(TerminalCliFixture installed, Id epoch, byte[] expected,
        string? replacementFile, CancellationToken token)
    {
        var owned = Path.Combine(installed.Sandbox.DataLocation, "data", "round-trip.bin");
        var readbackName = "data-readback-" + Guid.NewGuid().ToString("N") + ".bin";
        var readback = Path.Combine(installed.Working, readbackName);
        Assert.False(File.Exists(readback));
        string[] argv;
        if (OperatingSystem.IsLinux())
        {
            const string capture = "/usr/bin/cat -- \"$1\" > \"$2\"";
            argv = replacementFile is null
                ? ["/usr/bin/dash", "-c", capture, "arcforges-file-fixture", owned, readback]
                : ["/usr/bin/dash", "-c", capture + " && /usr/bin/cat -- \"$3\" > \"$1\"", "arcforges-file-fixture", owned, readback, replacementFile];
        }
        else
        {
            var read = $"""
                @echo off
                copy /b /y "..\..\data\round-trip.bin" "{readbackName}" >nul
                if not "%errorlevel%"=="0" exit /b %errorlevel%
                """;
            const string replace = """
                copy /b /y "replacement.bin" "..\..\data\round-trip.bin" >nul
                exit /b %errorlevel%
                """;
            string batch = replacementFile is null ? read + "\nexit /b 0\n" : read + "\n" + replace;
            await File.WriteAllTextAsync(Path.Combine(installed.Working, "data-round-trip.cmd"), batch.ReplaceLineEndings("\r\n"), token);
            argv = [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "data-round-trip.cmd"];
        }

        var request = BuildStart(installed.Sandbox, epoch, argv);
        request.TerminalMode = TerminalMode.Pipes;
        request.TerminalSize = null;
        var started = await installed.Runs.StartAsync(request, deadline: Deadline, cancellationToken: token);
        var run = Value(started.Value, started.Error).Run;
        var final = await installed.WaitExitedAsync(run.RunId, token);
        Assert.True(final.Exit.HasRawCode);
        Assert.Equal(0, final.Exit.RawCode);
        Assert.True(File.Exists(readback), "The native Run did not create its private readback file.");
        var actual = await File.ReadAllBytesAsync(readback, token);
        Assert.Equal(expected.Length, actual.Length);
        Assert.True(expected.AsSpan().SequenceEqual(actual), "The native Run did not read the exact imported file bytes.");
        return final;
    }

    private static Task<DataServiceInspectTransferResponse> InspectFileTransferAsync(DataService.DataServiceClient data, Id transfer,
        CancellationToken token) => data.InspectTransferAsync(new DataServiceInspectTransferRequest { Meta = Query(), TransferId = transfer },
        deadline: Deadline, cancellationToken: token).ResponseAsync;

    private static async Task<DataServiceInspectTransferResponse> AwaitMaterializedExportAsync(DataService.DataServiceClient data,
        Id transferId, CancellationToken token)
    {
        DataServiceInspectTransferResponse? complete = null;
        await TestNode.WaitAsync(async () =>
        {
            var response = await InspectFileTransferAsync(data, transferId, token);
            var transfer = Value(response.Value, response.Error).Transfer;
            Assert.Equal(transferId, transfer.TransferId);
            Assert.Equal("export", transfer.Direction);
            Assert.Null(transfer.ClosedAt);
            Assert.True(transfer.State is TransferState.Open or TransferState.Streaming or TransferState.Complete);
            if (transfer.State != TransferState.Complete) return false;
            complete = response;
            return true;
        }, NativeBound, "the same verified private export snapshot");
        return Assert.IsType<DataServiceInspectTransferResponse>(complete);
    }

    private static void RequireCompleteFileTransfer(Transfer transfer, Sandbox sandbox, string path, string direction, byte[] bytes)
    {
        Assert.Equal(sandbox.SandboxId, transfer.SandboxId);
        Assert.Equal(path, transfer.RelativePath);
        Assert.Equal(direction, transfer.Direction);
        Assert.Equal(TransferState.Complete, transfer.State);
        Assert.True(transfer.HasByteLength && transfer.HasVerifiedOffset && transfer.HasSha256);
        Assert.Equal((ulong)bytes.Length, transfer.ByteLength);
        Assert.Equal(transfer.ByteLength, transfer.VerifiedOffset);
        Assert.Equal(FileDigest(bytes), transfer.Sha256);
        Assert.NotNull(transfer.ExpiresAt);
    }

    private static async Task RequireFileTransferCliInspectionAsync(TestNode fixture, Transfer transfer, byte[] expected)
    {
        var inspected = await InstalledCliSuccessAsync(fixture, "sandbox", "transfer", "inspect", IdText.Format(transfer.TransferId));
        var result = inspected.GetProperty("transfer");
        Assert.Equal(transfer.TransferId, InstalledCliId(result, "transferId"));
        Assert.Equal(transfer.Direction, result.GetProperty("direction").GetString());
        Assert.Equal(FileDigest(expected), result.GetProperty("sha256").GetString());
        Assert.Equal(transfer.ByteLength.ToString(CultureInfo.InvariantCulture), CliScalar(result.GetProperty("byteLength")));
        Assert.Equal(transfer.VerifiedOffset.ToString(CultureInfo.InvariantCulture), CliScalar(result.GetProperty("verifiedOffset")));
        Assert.Equal(transfer.ClosedAt is not null, result.TryGetProperty("closedAt", out _));
    }

    private static async Task VerifyRetainedExportReplayAsync(TestNode fixture, DataService.DataServiceClient data,
        NodeService.NodeServiceClient node, RunService.RunServiceClient runs, Id epoch, Sandbox sandbox, Transfer retained,
        byte[] original, CancellationToken token)
    {
        var initial = new DataServiceReadExportRequest
        {
            Meta = Query(), TransferId = retained.TransferId, Offset = 0, MaxBytes = TransferChunkSize,
        };
        var first = await data.ReadExportAsync(initial, deadline: Deadline, cancellationToken: token);
        var firstChunk = Value(first.Value, first.Error).Chunk;
        Assert.Equal(0UL, firstChunk.Offset);
        Assert.False(firstChunk.Eof);
        Assert.Equal(TransferChunkSize, firstChunk.Data.Length);
        Assert.True(original.AsSpan(0, firstChunk.Data.Length).SequenceEqual(firstChunk.Data.Span));

        var final = new DataServiceReadExportRequest
        {
            Meta = Query(), TransferId = retained.TransferId, Offset = (ulong)firstChunk.Data.Length, MaxBytes = TransferChunkSize,
        };
        await using (var abandoned = OpenChannel(fixture))
        {
            var reader = new DataService.DataServiceClient(abandoned.CallInvoker);
            var discarded = await reader.ReadExportAsync(final, deadline: Deadline, cancellationToken: token);
            // Leave the real response body unconsumed by the fixture, then reconnect without another BeginExport.
            Assert.Null(discarded.Error);
        }

        var repeated = await data.ReadExportAsync(final, deadline: Deadline, cancellationToken: token);
        var replay = Value(repeated.Value, repeated.Error).Chunk;
        Assert.Equal(final.Offset, replay.Offset);
        Assert.True(replay.Eof);
        Assert.Equal((ulong)original.Length, replay.Offset + (ulong)replay.Data.Length);
        Assert.True(original.AsSpan(TransferChunkSize).SequenceEqual(replay.Data.Span));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(firstChunk.Data.Span);
        hash.AppendData(replay.Data.Span);
        Assert.Equal(retained.Sha256, Convert.ToHexStringLower(hash.GetHashAndReset()));

        var inspected = await InspectFileTransferAsync(data, retained.TransferId, token);
        Assert.Equal(retained, Value(inspected.Value, inspected.Error).Transfer);
        Assert.NotNull(inspected.Meta.ResultRev);
        Assert.True(inspected.Meta.ResultRev.Value > 0);
        var close = new DataServiceCloseTransferRequest
        {
            Meta = Mutation(inspected.Meta.ResultRev), TransferId = retained.TransferId, OwnerEpoch = epoch,
        };
        var settledRuns = await ListAsync(runs, sandbox.SandboxId);
        Assert.Equal(2, settledRuns.Length);
        Assert.All(settledRuns, run =>
        {
            Assert.Equal(RunState.Exited, run.State);
            Assert.True(run.Exit.GroupEmptyVerified);
        });
        RequireStoredExportManagedUse(fixture, sandbox.SandboxId, epoch, retained.TransferId, held: true);
        var response = await data.CloseTransferAsync(close, deadline: Deadline, cancellationToken: token);
        var closed = Value(response.Value, response.Error).Transfer;
        RequireCompleteFileTransfer(closed, sandbox, FixtureDataPath, "export", original);
        Assert.Equal(retained.TransferId, closed.TransferId);
        Assert.NotNull(closed.ClosedAt);
        RequireStoredExportManagedUse(fixture, sandbox.SandboxId, epoch, closed.TransferId, held: false);
        var again = await data.CloseTransferAsync(close, deadline: Deadline, cancellationToken: token);
        Assert.Equal(closed, Value(again.Value, again.Error).Transfer);
        var operation = await OperationAsync(node, epoch, close.Meta.CommandId);
        Assert.Equal(OperationState.Succeeded, operation.State);
        Assert.Equal(EffectCertainty.Happened, operation.Effect);
        Assert.Equal(closed.TransferId, operation.AggregateId);
        await RequireFileTransferCliInspectionAsync(fixture, closed, original);
        var after = await data.ReadExportAsync(final, deadline: Deadline, cancellationToken: token);
        Assert.Null(after.Value);
        RequireDataRefusal(after.Error, ErrorCategory.State, "managed_use");
        Assert.Equal("transfer_closed", after.Error?.Details?.State?.Reason);
    }

    private static void RequireStoredExportManagedUse(TestNode fixture, Id sandbox, Id epoch, Id transfer, bool held)
    {
        using var database = ReadDatabase(fixture.DataRoot);
        var reader = new StoreReader(database, transaction: null, clock: TimeProvider.System);
        var sandboxId = Hex(sandbox);
        var owner = Assert.IsType<string>(reader.Scalar("SELECT owner_id FROM sandbox WHERE sandbox_id=$id;", ("$id", sandboxId)));
        var stored = Assert.IsType<StoredTransfer>(TransferRecords.Get(reader, owner, Hex(transfer)));
        Assert.Equal(sandboxId, stored.SandboxId);
        Assert.Equal(StoredTransferDirection.Export, stored.Direction);
        Assert.Equal(StoredTransferState.Complete, stored.State);
        Assert.Equal(held, stored.ClosedAt is null);
        Assert.Equal(held, SandboxRecords.HasUnresolvedUse(reader, owner, sandboxId, epoch.Value.ToByteArray()));
    }

    private static async Task RequireLocalExportNoReplaceAsync(TestNode fixture, string sandbox, string destination, byte[] content,
        CancellationToken token)
    {
        var existing = Path.Combine(Path.GetDirectoryName(destination)!, "leave existing intact.bin");
        var sentinel = BuildFileBytes(79, 202);
        await File.WriteAllBytesAsync(existing, sentinel, token);
        var refusal = await InstalledCliRefusalAsync(fixture, 3, "identity_changed", "sandbox", "export", sandbox,
            FixtureDataPath, "--to", existing);
        var reason = refusal.GetProperty("error").GetProperty("details").GetProperty("state").GetProperty("reason");
        Assert.Equal("local_destination_exists", reason.GetString());
        var transfer = refusal.GetProperty("value");
        var retained = InstalledCliId(transfer, "transferId");
        Assert.Equal(FileDigest(content), transfer.GetProperty("sha256").GetString());
        Assert.False(transfer.TryGetProperty("closedAt", out _));
        var unchanged = await File.ReadAllBytesAsync(existing, token);
        Assert.True(sentinel.AsSpan().SequenceEqual(unchanged));
        var released = await InstalledCliSuccessAsync(fixture, "sandbox", "transfer", "close", IdText.Format(retained));
        var closed = released.GetProperty("transfer");
        Assert.Equal(retained, InstalledCliId(closed, "transferId"));
        Assert.True(closed.TryGetProperty("closedAt", out _));
    }
}
