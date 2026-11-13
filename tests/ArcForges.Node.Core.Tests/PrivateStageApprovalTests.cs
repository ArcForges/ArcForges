// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real Node approval and SQLite metadata for a staged synthetic caller; no approved effect or real center.</summary>
public sealed class PrivateStageApprovalTests
{
    [Fact(Timeout = 120_000)]
    public async Task OnlyBoundStageRaisesBodyFreeApprovalAndOnlyLocalHumanCanDeny()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var other = calls.Relay(Origin.Agent);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "approval-stage")).FullName;
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("private-approval-file-body-a70bd3");
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var raw = request.ToByteArray();
        var hash = SHA256.HashData(body);
        var budget = new FileStageBudget();
        var spec = new PrivateStageSpec(2, Path.Combine(rootPath, "stage"), body.Length, hash);
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            budget, FileOperationKind.Write, request.Meta.CommandId.Value.Span, registered.Id,
            request.Meta.CorrelationId.Value.Span, caller, raw, [spec]), CommitDurability.Full));
        using var root = WorkspacePath.OpenRoot(rootPath);
        RegisteredWorkspaces.RootIdentity stageIdentity;
        using (var stage = root.CreateEmptyPrivateNamedStage("stage", ct))
        {
            stageIdentity = stage.Identity;
            node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
                2, root, root, "stage", stage.Guard, ct), CommitDurability.Full);
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, request.Meta.CommandId.Value.Span, 2, caller, raw, stage, body, ct);
        }

        var rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var intent = new FileJournalIntent(FileOperationKind.Write, request.Meta.CommandId.Value.ToByteArray(),
            request.Meta.CorrelationId.Value.ToByteArray(), caller, registered.Id, "target", rootIdentity.Platform, rootIdentity.Bytes,
            rootIdentity.Bytes, null, null, null, null, body.Length, hash, stageIdentity.Bytes);
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId.Clone() };
        Task<(StoredApproval? Approval, bool Created, ArcError? Error)> Raise(ActorRef requester, byte[] bytes) =>
            node.Runtime.Processor.ExecuteAsync(command => PrivateStageApproval.Raise(command, intent, bytes, requester,
                root, target: null, TimeSpan.FromHours(1), ct), CommitDurability.Full);

        var foreign = actor.Clone();
        foreign.CenterCaller = other;
        await Assert.ThrowsAsync<ArgumentException>(async () => await Raise(foreign, raw));
        var changed = request.Clone();
        changed.Data = ByteString.CopyFromUtf8("different");
        await Assert.ThrowsAsync<ArgumentException>(async () => await Raise(actor, changed.ToByteArray()));
        File.WriteAllText(Path.Combine(rootPath, "target"), "owned collision");
        await Assert.ThrowsAsync<WorkspacePathException>(async () => await Raise(actor, raw));
        Assert.Equal("owned collision", File.ReadAllText(Path.Combine(rootPath, "target")));
        File.Delete(Path.Combine(rootPath, "target")); // This test owns the exact collision fixture.
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM approval;")));

        var longPath = new string('x', 199) + "/" + new string('y', 199) + "😀" + "/" +
            string.Join('/', Enumerable.Repeat(new string('z', 190), 8));
        var pieces = PrivateStageApproval.Describe(intent with { RelativePath = longPath }, SHA256.HashData(raw))
            .Where(item => item.Name.StartsWith("target_path_", StringComparison.Ordinal)).ToArray();
        Assert.Equal(longPath, string.Concat(pieces.Select(item => item.Value)));
        Assert.All(pieces, item =>
        {
            Assert.InRange(item.Value.Length, 1, 400);
            Assert.False(char.IsHighSurrogate(item.Value[^1]));
        });

        var first = await Raise(actor, raw);
        Assert.True(first.Created);
        Assert.Null(first.Error);
        Assert.NotNull(first.Approval);
        Assert.Equal(ApprovalState.Pending, first.Approval.State);
        Assert.Equal(17, first.Approval.Request.Length);
        Assert.Equal(1, first.Approval.Request[0]);
        Assert.Equal(request.Meta.CommandId.Value.ToByteArray(), first.Approval.Request[1..]);
        Assert.Equal(SHA256.HashData(raw), first.Approval.RequestDigest);
        Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_approval_binding;")));
        var again = await Raise(actor, raw);
        Assert.False(again.Created);
        Assert.Equal(first.Approval.Id, again.Approval!.Id);
        Assert.Null(again.Error);
        Assert.False(File.Exists(Path.Combine(rootPath, "target")));

        foreach (var path in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(path)) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(body));
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var persisted = node.Runtime.Store.Read(r => Approvals.ByCommand(r, request.Meta.CommandId.Value.Span));
        Assert.NotNull(persisted);
        Assert.Equal(ApprovalState.Pending, persisted.State);
        Assert.Equal(first.Approval.Id, persisted.Id);
        await using var script = await node.ChannelAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var decision = new ApprovalServiceDecideApprovalRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            ApprovalId = persisted.View.ApprovalId.Clone(),
            Decision = ApprovalDecisionKind.Deny,
        };
        var refused = await script.Approvals.DecideApprovalAsync(decision, cancellationToken: ct);
        Assert.NotNull(refused.Error);
        Assert.Equal("permission_denied", refused.Error.Code);
        Assert.Equal(ApprovalState.Pending, node.Runtime.Store.Read(r => Approvals.Get(r, persisted.Id))!.State);
        var denied = await human.Approvals.DecideApprovalAsync(decision, cancellationToken: ct);
        Assert.Null(denied.Error);
        Assert.Equal(ApprovalState.Denied, denied.Value.Approval.State);
        Assert.False(File.Exists(Path.Combine(rootPath, "target")));
    }

    [Fact(Timeout = 120_000)]
    public async Task EditApprovalRecomputesActualReplacementAndRejectsDifferentIntendedStage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "edit-approval-stage")).FullName;
        var targetPath = Path.Combine(rootPath, "target");
        var original = Encoding.UTF8.GetBytes("copper-private-b0b3 copper-private-b0b3");
        File.WriteAllBytes(targetPath, original);
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        using var root = WorkspacePath.OpenRoot(rootPath);
        var originalHash = SHA256.HashData(original);
        var budget = new FileStageBudget();

        async Task<(StoredApproval? Approval, bool Created, ArcError? Error)> Raise(string tag, byte[] proposed)
        {
            var request = new FileServiceEditFileRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
                ExpectedSha256 = ByteString.CopyFrom(originalHash),
                OldText = "copper",
                NewText = "silver",
                ExpectedOccurrences = 2,
            };
            var raw = request.ToByteArray();
            var intendedHash = SHA256.HashData(proposed);
            var beforeSpec = new PrivateStageSpec(1, Path.Combine(rootPath, tag + "-before"), original.Length, originalHash);
            var afterSpec = new PrivateStageSpec(2, Path.Combine(rootPath, tag + "-after"), proposed.Length, intendedHash);
            Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
                budget, FileOperationKind.Edit, request.Meta.CommandId.Value.Span, workspace.Id,
                request.Meta.CorrelationId.Value.Span, caller, raw, [beforeSpec, afterSpec]), CommitDurability.Full));
            RegisteredWorkspaces.RootIdentity beforeIdentity, afterIdentity;
            using (var before = root.CreateEmptyPrivateNamedStage(tag + "-before", ct))
            {
                beforeIdentity = before.Identity;
                node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
                    1, root, root, tag + "-before", before.Guard, ct), CommitDurability.Full);
                PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, request.Meta.CommandId.Value.Span, 1, caller, raw, before, original, ct);
            }
            using (var after = root.CreateEmptyPrivateNamedStage(tag + "-after", ct))
            {
                afterIdentity = after.Identity;
                node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
                    2, root, root, tag + "-after", after.Guard, ct), CommitDurability.Full);
                PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, request.Meta.CommandId.Value.Span, 2, caller, raw, after, proposed, ct);
            }
            using var target = root.OpenExistingWriteGuard("target");
            var rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            var targetIdentity = RegisteredWorkspaces.RootIdentity.Encode(target.ObjectIdentity, directory: false);
            var intent = new FileJournalIntent(FileOperationKind.Edit, request.Meta.CommandId.Value.ToByteArray(),
                request.Meta.CorrelationId.Value.ToByteArray(), caller, workspace.Id, "target", rootIdentity.Platform,
                rootIdentity.Bytes, rootIdentity.Bytes, targetIdentity.Bytes, original.Length, originalHash, beforeIdentity.Bytes,
                proposed.Length, intendedHash, afterIdentity.Bytes);
            var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId.Clone() };
            return await node.Runtime.Processor.ExecuteAsync(command => PrivateStageApproval.Raise(command, intent, raw, actor,
                root, target, TimeSpan.FromHours(1), ct), CommitDurability.Full);
        }

        var wrong = Encoding.UTF8.GetBytes("bronze-private-b0b3 bronze-private-b0b3");
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await Raise("wrong", wrong));
        Assert.Equal(original, File.ReadAllBytes(targetPath));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM approval;")));
        var expected = Encoding.UTF8.GetBytes("silver-private-b0b3 silver-private-b0b3");
        var correct = await Raise("correct", expected);
        Assert.True(correct.Created);
        Assert.Null(correct.Error);
        Assert.Equal(ApprovalState.Pending, correct.Approval!.State);
        Assert.Equal(original, File.ReadAllBytes(targetPath));
        foreach (var path in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(path)) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(original));
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(expected));
        }
    }
}
