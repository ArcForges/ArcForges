// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real SQLite, native stages and synthetic HUMAN decision for approved journal adoption; no target effect.</summary>
public sealed class FileApprovedJournalTests
{
    [Fact(Timeout = 120_000)]
    public async Task ApprovedExactBindingAdoptsCommandOnceAndAcknowledgmentReleasesWorkspaceHold()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "approved-journal")).FullName;
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("owned-approved-stage-body-e3308");
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var raw = request.ToByteArray();
        var hash = SHA256.HashData(body);
        var spec = new PrivateStageSpec(2, Path.Combine(rootPath, "stage"), body.Length, hash);
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            new FileStageBudget(), FileOperationKind.Write, request.Meta.CommandId.Value.Span, registered.Id,
            request.Meta.CorrelationId.Value.Span, caller, raw, [spec]), CommitDurability.Full));
        using var root = WorkspacePath.OpenRoot(rootPath);
        RegisteredWorkspaces.RootIdentity stageIdentity;
        using (var empty = root.CreateEmptyPrivateNamedStage("stage", ct))
        {
            stageIdentity = empty.Identity;
            node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
                2, root, root, "stage", empty.Guard, ct), CommitDurability.Full);
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, request.Meta.CommandId.Value.Span, 2, caller, raw, empty, body, ct);
        }
        var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var intent = new FileJournalIntent(FileOperationKind.Write, request.Meta.CommandId.Value.ToByteArray(),
            request.Meta.CorrelationId.Value.ToByteArray(), caller, registered.Id, "target", identity.Platform, identity.Bytes,
            identity.Bytes, null, null, null, null, body.Length, hash, stageIdentity.Bytes);
        var requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId.Clone() };
        var raised = await node.Runtime.Processor.ExecuteAsync(command => PrivateStageApproval.Raise(command, intent, raw,
            requester, root, target: null, TimeSpan.FromHours(1), ct), CommitDurability.Full);
        Assert.True(raised.Created);
        var id = raised.Approval!.Id;
        Assert.Null(node.Runtime.Store.Read(r => PrivateStageApprovedPlans.Read(r, id)));

        // Direct synthetic HUMAN decision exercises actual approval storage; this is not an authenticated local RPC test.
        var human = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
        await node.Runtime.Processor.ExecuteAsync(command => Approvals.Decide(command, id, approve: true, human, comment: null),
            CommitDurability.Full);
        var plan = node.Runtime.Store.Read(r => PrivateStageApprovedPlans.Read(r, id));
        Assert.NotNull(plan);
        Assert.Equal(SHA256.HashData(raw), plan.RequestSha256);
        Assert.Equal(intent.CommandId, plan.Intent.CommandId);
        Assert.Equal(intent.IntendedStageIdentity, plan.Intent.IntendedStageIdentity);

        // Negative expiry is test-owned metadata only; the positive below uses the actual native clock.
        var originalExpiry = plan.ApprovalExpiresAt;
        node.Runtime.Store.Write(t => t.Execute("UPDATE approval SET expires_at = $expired WHERE approval_id = $id;",
            ("$expired", t.NowMicroseconds - 1), ("$id", id)), CommitDurability.Full);
        using (var source = node.Runtime.Store.Read(r => PrivateStageRegistry.ReopenReadyStage(r, intent.CommandId, 2,
            caller, SHA256.HashData(raw), ct)))
        {
            var expired = node.Runtime.Store.Write(t => FileMutationJournal.PrepareApproved(t, id, root, target: null,
                original: null, source, ct), CommitDurability.Full);
            Assert.Equal(ApprovedFilePreparation.Expired, expired.Status);
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
            node.Runtime.Store.Write(t => t.Execute("UPDATE approval SET expires_at = $expiry WHERE approval_id = $id;",
                ("$expiry", originalExpiry), ("$id", id)), CommitDurability.Full);
            var prepared = node.Runtime.Store.Write(t => FileMutationJournal.PrepareApproved(t, id, root, target: null,
                original: null, source, ct), CommitDurability.Full);
            Assert.Equal(ApprovedFilePreparation.Prepared, prepared.Status);
            var duplicate = node.Runtime.Store.Write(t => FileMutationJournal.PrepareApproved(t, id, root, target: null,
                original: null, source, ct), CommitDurability.Full);
            Assert.Equal(ApprovedFilePreparation.Existing, duplicate.Status);
        }

        Assert.False(File.Exists(Path.Combine(rootPath, "target")));
        Assert.Equal(1, node.Runtime.Store.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
        var operation = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, intent.CommandId, caller))!;
        Assert.Equal(FileOperationState.Unknown, operation.State);
        Assert.True(operation.Held);
        Assert.Equal(SHA256.HashData(raw), operation.RequestSha256.ToByteArray());

        // The real local endpoint checks the peer's HUMAN classification; no stage location enters the routed reply.
        var query = new FileServiceGetFileOperationRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            OperationCommandId = request.Meta.CommandId.Clone(),
        };
        await using var humanClient = await node.ChannelAsync(helloAsHuman: true);
        await using var scriptClient = await node.ChannelAsync();
        var local = await humanClient.Files.GetFileOperationAsync(query, cancellationToken: ct);
        Assert.True(NodeShapes.IsValid(local)); // Real published 450.1 validator, including warning metadata.
        Assert.Null(local.Error);
        var warning = Assert.Single(local.Meta.Warnings);
        var parts = warning.Split(':', 4);
        Assert.Equal("arcforges.file-stage.v1", parts[0]);
        Assert.Equal("2", parts[1]);
        Assert.Equal("confirmed", parts[2]);
        Assert.Equal(Path.Combine(rootPath, "stage"), Encoding.UTF8.GetString(Convert.FromBase64String(parts[3])));
        // Contract check only: the maximal synthetic absolute path need not exist on the host filesystem.
        var pathRoot = Path.GetPathRoot(rootPath)!;
        var maximumPath = pathRoot + new string('x', 4096 - Encoding.UTF8.GetByteCount(pathRoot));
        Assert.Equal(4096, Encoding.UTF8.GetByteCount(maximumPath));
        var edge = local.Clone();
        edge.Meta.Warnings.Clear();
        edge.Meta.Warnings.Add(PrivateStageLocations.ToWarning(new PrivateStageLocation(1, maximumPath, true, true)));
        edge.Meta.Warnings.Add(PrivateStageLocations.ToWarning(new PrivateStageLocation(2, maximumPath, false, false)));
        Assert.True(NodeShapes.IsValid(edge));
        var denied = await scriptClient.Files.GetFileOperationAsync(query, cancellationToken: ct);
        Assert.Equal("permission_denied", denied.Error.Code);
        Assert.Empty(denied.Meta.Warnings);
        var remote = await routed.CallAsync(caller, RoutedMethod.GetNodeFileOperation, query.ToByteArray());
        var remoteResponse = FileServiceGetFileOperationResponse.Parser.ParseFrom(remote.Answer!.Response);
        Assert.True(NodeShapes.IsValid(remoteResponse));
        Assert.Null(remoteResponse.Error);
        Assert.Empty(remoteResponse.Meta.Warnings);

        var stagePath = Path.Combine(rootPath, "stage");
        var moved = Path.Combine(rootPath, "moved-stage");
        File.Move(stagePath, moved);
        File.WriteAllText(stagePath, "owned replacement");
        var replaced = await humanClient.Files.GetFileOperationAsync(query, cancellationToken: ct);
        Assert.True(NodeShapes.IsValid(replaced));
        Assert.Contains(":last-known:", Assert.Single(replaced.Meta.Warnings), StringComparison.Ordinal);
        Assert.Equal("owned replacement", File.ReadAllText(stagePath));
        File.Delete(stagePath); // This exact replacement is a test-owned fixture.
        File.Move(moved, stagePath);

        Assert.Equal(FileJournalAcknowledgment.DigestMismatch, node.Runtime.Store.Write(t =>
            FileMutationJournal.AcknowledgeFromVerifiedHuman(t, intent.CommandId, new byte[32], human), CommitDurability.Full));
        Assert.True(node.Runtime.Store.Read(r => PrivateStageRegistry.HasWorkspaceHold(r, registered.Id)));
        Assert.Throws<ArgumentException>(() => node.Runtime.Store.Write(t => FileMutationJournal.AcknowledgeFromVerifiedHuman(
            t, intent.CommandId, SHA256.HashData(raw), new ActorRef { Origin = Origin.Script }), CommitDurability.Full));
        Assert.True(node.Runtime.Store.Read(r => PrivateStageRegistry.HasWorkspaceHold(r, registered.Id)));
        Assert.Equal(FileJournalAcknowledgment.Acknowledged, node.Runtime.Store.Write(t =>
            FileMutationJournal.AcknowledgeFromVerifiedHuman(t, intent.CommandId, SHA256.HashData(raw), human), CommitDurability.Full));
        Assert.False(node.Runtime.Store.Read(r => PrivateStageRegistry.HasWorkspaceHold(r, registered.Id)));
        new RegisteredWorkspaces(node.Runtime.Store).UnregisterFromVerifiedHuman(registered.Id, ct);
        var retained = node.Runtime.Store.Read(r => FileMutationJournal.GetForVerifiedHuman(r, intent.CommandId))!;
        Assert.Equal(FileOperationState.Unknown, retained.State);
        Assert.True(retained.Acknowledged);
        Assert.False(retained.Held);
        Assert.Equal(SHA256.HashData(raw), retained.RequestSha256.ToByteArray());
        Assert.Equal("target", retained.WorkspacePath.Path);
        Assert.Equal(body, File.ReadAllBytes(Path.Combine(rootPath, "stage")));
        Assert.Single(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
        Assert.Equal((0, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.False(File.Exists(Path.Combine(rootPath, "target")));
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task ApprovedJournalCanSettleTheActualGuardedWindowsEffectAndReplayItsMetadata()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows guarded target effect."); return; }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var caller = new RoutedCalls(node).Relay(Origin.Script);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "approved-effect")).FullName;
        var targetPath = Path.Combine(rootPath, "target");
        var oldBytes = Encoding.UTF8.GetBytes("prior-approved-target");
        var newBytes = Encoding.UTF8.GetBytes("verified-approved-result-42dd");
        File.WriteAllBytes(targetPath, oldBytes);
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(oldBytes)),
            Data = ByteString.CopyFrom(newBytes),
        };
        var raw = request.ToByteArray();
        var oldHash = SHA256.HashData(oldBytes);
        var newHash = SHA256.HashData(newBytes);
        var beforeSpec = new PrivateStageSpec(1, Path.Combine(rootPath, "before"), oldBytes.Length, oldHash);
        var afterSpec = new PrivateStageSpec(2, Path.Combine(rootPath, "after"), newBytes.Length, newHash);
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            new FileStageBudget(), FileOperationKind.Write, request.Meta.CommandId.Value.Span, workspace.Id,
            request.Meta.CorrelationId.Value.Span, caller, raw, [beforeSpec, afterSpec]), CommitDurability.Full));
        using var root = WorkspacePath.OpenRoot(rootPath);
        RegisteredWorkspaces.RootIdentity originalId, intendedId;
        using (var before = root.CreateEmptyPrivateNamedStage("before", ct))
        {
            originalId = before.Identity;
            node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
                1, root, root, "before", before.Guard, ct), CommitDurability.Full);
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, request.Meta.CommandId.Value.Span, 1, caller, raw, before, oldBytes, ct);
        }
        using (var after = root.CreateEmptyPrivateNamedStage("after", ct))
        {
            intendedId = after.Identity;
            node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
                2, root, root, "after", after.Guard, ct), CommitDurability.Full);
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, request.Meta.CommandId.Value.Span, 2, caller, raw, after, newBytes, ct);
        }
        var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        byte[] approvalId;
        using (var target = root.OpenExistingWriteGuard("target"))
        {
            var targetId = RegisteredWorkspaces.RootIdentity.Encode(target.ObjectIdentity, directory: false);
            var intent = new FileJournalIntent(FileOperationKind.Write, request.Meta.CommandId.Value.ToByteArray(),
                request.Meta.CorrelationId.Value.ToByteArray(), caller, workspace.Id, "target", rootId.Platform,
                rootId.Bytes, rootId.Bytes, targetId.Bytes, oldBytes.Length, oldHash, originalId.Bytes,
                newBytes.Length, newHash, intendedId.Bytes);
            var requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId.Clone() };
            var raised = await node.Runtime.Processor.ExecuteAsync(command => PrivateStageApproval.Raise(command, intent, raw,
                requester, root, target, TimeSpan.FromHours(1), ct), CommitDurability.Full);
            approvalId = raised.Approval!.Id;
        }
        // Synthetic direct decision exercises the real approval record; authenticated local execution is tested separately.
        await node.Runtime.Processor.ExecuteAsync(command => Approvals.Decide(command, approvalId, approve: true,
            new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli }, comment: null), CommitDurability.Full);
        byte[] outcome;
        using (var before = node.Runtime.Store.Read(r => PrivateStageRegistry.ReopenReadyStage(r, request.Meta.CommandId.Value.Span,
            1, caller, SHA256.HashData(raw), ct)))
        using (var after = node.Runtime.Store.Read(r => PrivateStageRegistry.ReopenReadyStage(r, request.Meta.CommandId.Value.Span,
            2, caller, SHA256.HashData(raw), ct)))
        using (var target = root.OpenExistingWriteGuard("target"))
        {
            var prepared = node.Runtime.Store.Write(t => FileMutationJournal.PrepareApproved(t, approvalId, root, target,
                before, after, ct), CommitDurability.Full);
            Assert.Equal(ApprovedFilePreparation.Prepared, prepared.Status);
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(t => FileMutationJournal.CompleteApprovedVerifiedEffect(
                t, approvalId, newBytes.Length, new byte[32], replacements: null), CommitDurability.Full));
            var observed = root.ApplyExistingGuardedStage("target", target, after, oldHash, ct);
            outcome = node.Runtime.Store.Write(t => FileMutationJournal.CompleteApprovedVerifiedEffect(t, approvalId,
                observed.Size, observed.Sha256, replacements: null), CommitDurability.Full);
        }
        Assert.Equal(newBytes, File.ReadAllBytes(targetPath));
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(outcome);
        Assert.Null(response.Error);
        Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
        Assert.Equal(newHash, response.Value.Result.Sha256.ToByteArray());
        Assert.Equal(outcome, node.Runtime.Store.Read(r => FileMutationJournal.ReplayApproved(r, approvalId)));
        Assert.Equal(outcome, node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Write,
            request.Meta.CommandId.Value.Span, caller, raw)));
        var changed = request.Clone();
        changed.Meta.CorrelationId = CommandIds.New();
        Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Write,
            request.Meta.CommandId.Value.Span, caller, changed.ToByteArray())));
        var status = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, request.Meta.CommandId.Value.Span, caller))!;
        Assert.Equal(FileOperationState.Completed, status.State);
        Assert.False(status.Held);
        Assert.False(node.Runtime.Store.Read(r => PrivateStageRegistry.HasWorkspaceHold(r, workspace.Id)));
        new RegisteredWorkspaces(node.Runtime.Store).UnregisterFromVerifiedHuman(workspace.Id, ct);
        Assert.Equal(newBytes, File.ReadAllBytes(targetPath));
        Assert.Equal(newBytes, File.ReadAllBytes(Path.Combine(rootPath, "after")));
        Assert.Equal(oldBytes, File.ReadAllBytes(Path.Combine(rootPath, "before")));
    }
}
