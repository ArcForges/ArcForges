// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>A synthetic routed requester, actual native stages, SQLite and authenticated local RPC HUMAN decision.</summary>
public sealed class FileApprovedExecutionTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(false, 1)]
    [InlineData(false, 2)]
    [InlineData(false, 3)]
    [InlineData(false, 4)]
    public async Task HumanDecisionUsesCapturedCallerAndGuardedNativeEffect(bool edit, int scenario)
    {
        if (!OperatingSystem.IsWindows() && scenario is 1 or 2)
        {
            Assert.Skip("The supported approved target effect and stage-tamper checks require Windows.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var foreign = calls.Relay(Origin.Agent);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "approved-local-rpc")).FullName;
        var targetPath = Path.Combine(directory, "target");
        var original = Encoding.UTF8.GetBytes("alpha-private-cb89 alpha-private-cb89");
        var intended = Encoding.UTF8.GetBytes("beta-private-cb89 beta-private-cb89");
        File.WriteAllBytes(targetPath, original);
        if (OperatingSystem.IsWindows())
            File.SetAttributes(targetPath, File.GetAttributes(targetPath) | FileAttributes.Archive);
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
        var path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" };
        var oldHash = SHA256.HashData(original);
        var newHash = SHA256.HashData(intended);
        byte[] raw;
        if (edit)
            raw = new FileServiceEditFileRequest
            {
                Meta = meta,
                Path = path,
                ExpectedSha256 = ByteString.CopyFrom(oldHash),
                OldText = "alpha",
                NewText = "beta",
                ExpectedOccurrences = 2,
            }.ToByteArray();
        else
            raw = new FileServiceWriteFileRequest
            {
                Meta = meta,
                Path = path,
                ExpectedSha256 = ByteString.CopyFrom(oldHash),
                Data = ByteString.CopyFrom(intended),
            }.ToByteArray();
        var kind = edit ? FileOperationKind.Edit : FileOperationKind.Write;
        var id = meta.CommandId.Value.ToByteArray();
        var beforeSpec = new PrivateStageSpec(1, Path.Combine(directory, "before"), original.Length, oldHash);
        var afterSpec = new PrivateStageSpec(2, Path.Combine(directory, "after"), intended.Length, newHash);
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            node.Runtime.FileStages, kind, id, workspace.Id, meta.CorrelationId.Value.Span, caller, raw, [beforeSpec, afterSpec]),
            CommitDurability.Full));
        byte[] approvalId;
        byte[] reference;
        using (var root = WorkspacePath.OpenRoot(directory))
        {
            RegisteredWorkspaces.RootIdentity beforeId, afterId;
            using (var before = await PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 1, root, root, "before", ct))
            {
                beforeId = before.Identity;
                PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 1, caller, raw, before, original, ct);
            }
            using (var after = await PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, "after", ct))
            {
                afterId = after.Identity;
                PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2, caller, raw, after, intended, ct);
            }
            using var target = root.OpenExistingWriteGuard("target");
            var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            var targetId = RegisteredWorkspaces.RootIdentity.Encode(target.ObjectIdentity, directory: false);
            var intent = new FileJournalIntent(kind, id, meta.CorrelationId.Value.ToByteArray(), caller, workspace.Id, "target",
                rootId.Platform, rootId.Bytes, rootId.Bytes, targetId.Bytes, original.Length, oldHash, beforeId.Bytes,
                intended.Length, newHash, afterId.Bytes);
            var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = meta.CommandId.Clone() };
            var raised = await node.Runtime.Processor.ExecuteAsync(command => PrivateStageApproval.Raise(command, intent, raw,
                actor, root, target, TimeSpan.FromHours(1), ct), CommitDurability.Full);
            Assert.True(raised.Created);
            approvalId = raised.Approval!.Id;
            reference = raised.Approval.Request;
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        await using var script = await node.ChannelAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var changedTarget = Encoding.UTF8.GetBytes("changed-target-kept-70fd");
        if (scenario == 1)
        {
            var changedStage = intended.ToArray();
            changedStage[0] ^= 1;
            File.WriteAllBytes(Path.Combine(directory, "after"), changedStage);
        }
        if (scenario == 2) File.WriteAllBytes(targetPath, changedTarget);
        if (scenario == 3)
        {
            var policy = await Sched.ChangePolicyAsync(human, document => document.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Script,
                Decision = PermissionDecision.Deny,
            }));
            Assert.Null(policy.Error);
        }
        ApprovalState approvedState;
        if (scenario == 4)
        {
            // Synthetic decision intentionally tests the executor after APPROVED, unlike a forgery against PENDING.
            await node.Runtime.Processor.ExecuteAsync(command => Approvals.Decide(command, approvalId, approve: true,
                new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli }, comment: null), CommitDurability.Full);
            var fake = new ActorRef { Origin = Origin.Remote, CenterCaller = foreign, RemoteCommandId = meta.CommandId.Clone() };
            var forged = Caller.OfApproval(fake, approvalId, node.Runtime.NodeId.Span, reference);
            Assert.Null(await calls.Dispatcher.FileHandlerForTests!.ExecuteApprovedReferenceAsync(reference, forged));
            Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller)));
            Assert.Equal(original, File.ReadAllBytes(targetPath));
            var actual = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = meta.CommandId.Clone() };
            var valid = Caller.OfApproval(actual, approvalId, node.Runtime.NodeId.Span, reference);
            Assert.NotNull(await calls.Dispatcher.FileHandlerForTests.ExecuteApprovedReferenceAsync(reference, valid));
            // A deferred approval settlement must replay the stored result and never write the target again.
            await node.Runtime.ResumeApprovals!();
            approvedState = node.Runtime.Store.Read(r => Approvals.Get(r, approvalId))!.State;
        }
        else
        {
            var decision = new ApprovalServiceDecideApprovalRequest
            {
                Meta = InProcessNode.Command(),
                ApprovalId = new Id { Value = ByteString.CopyFrom(approvalId) },
                Decision = ApprovalDecisionKind.Approve,
            };
            var denied = await script.Approvals.DecideApprovalAsync(decision, cancellationToken: ct);
            Assert.Equal("permission_denied", denied.Error.Code);
            Assert.Equal(scenario == 2 ? changedTarget : original, File.ReadAllBytes(targetPath));
            var approved = await human.Approvals.DecideApprovalAsync(decision, cancellationToken: ct);
            Assert.Null(approved.Error);
            approvedState = approved.Value.Approval.State;
        }
        var receipt = node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, kind, id, caller, raw));
        Assert.NotNull(receipt);
        var state = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!;
        Assert.Equal(FileOperationState.Completed, state.State);
        Assert.False(state.Held);
        Assert.Equal(SHA256.HashData(raw), state.RequestSha256.ToByteArray());
        Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, kind, id, foreign, raw)));
        if (OperatingSystem.IsWindows() && scenario is 0 or 4)
        {
            Assert.Equal(ApprovalState.Executed, approvedState);
            Assert.Equal(intended, File.ReadAllBytes(targetPath));
            if (edit)
            {
                var result = FileServiceEditFileResponse.Parser.ParseFrom(receipt);
                Assert.True(NodeShapes.IsValid(result));
                Assert.Null(result.Error);
                Assert.Equal(2U, result.Value.Result.Replacements);
                Assert.Equal(newHash, result.Value.Result.Sha256.ToByteArray());
                Assert.Equal(meta.CorrelationId, result.Meta.CorrelationId);
            }
            else
            {
                var result = FileServiceWriteFileResponse.Parser.ParseFrom(receipt);
                Assert.True(NodeShapes.IsValid(result));
                Assert.Null(result.Error);
                Assert.Equal(newHash, result.Value.Result.Sha256.ToByteArray());
                Assert.Equal(meta.CorrelationId, result.Meta.CorrelationId);
            }
        }
        else
        {
            Assert.Equal(ApprovalState.Failed, approvedState);
            Assert.Equal(scenario == 2 ? changedTarget : original, File.ReadAllBytes(targetPath));
            var error = edit ? FileServiceEditFileResponse.Parser.ParseFrom(receipt).Error :
                FileServiceWriteFileResponse.Parser.ParseFrom(receipt).Error;
            Assert.Equal(scenario == 3 ? "permission_denied" :
                OperatingSystem.IsWindows() && scenario is 1 or 2 ? "file_changed" : "enforcement_unavailable", error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
            Assert.Equal(meta.CorrelationId, error.CorrelationId);
        }
        Assert.Equal((0, (long)original.Length + intended.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Equal(2, node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities).Count);
        foreach (var db in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(db)) continue;
            using var stream = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(original));
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(intended));
        }
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        Assert.Equal(receipt, node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, kind, id, caller, raw)));
        Assert.Equal(OperatingSystem.IsWindows() && scenario is 0 or 4 ? intended : scenario == 2 ? changedTarget : original,
            File.ReadAllBytes(targetPath));
    }
}
