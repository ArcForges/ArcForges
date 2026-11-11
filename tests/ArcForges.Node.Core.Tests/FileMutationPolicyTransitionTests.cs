// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual policy changes between PREPARED and effect on owned Windows fixtures; caller is synthetic.</summary>
public sealed class FileMutationPolicyTransitionTests
{
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task PolicyNarrowingAfterPrepareSettlesAReplayableRefusalWithoutEffect()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native guarded-effect boundary."); return; }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var humanActor = calls.Relay(Origin.Human);
        var scriptActor = calls.Relay(Origin.Script);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "policy-boundary")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var original = Encoding.UTF8.GetBytes("policy-before-original");
        var body = Encoding.UTF8.GetBytes("policy-after-intended");
        var path = Path.Combine(root, "existing.txt");
        File.WriteAllBytes(path, original);
        File.SetAttributes(path, FileAttributes.Archive);

        FileServiceWriteFileRequest Request(string name) => new()
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = name },
            Data = ByteString.CopyFrom(body),
        };
        async Task<byte[]> Invoke(FileServiceWriteFileRequest request, CenterCaller actor)
        {
            var raw = request.ToByteArray();
            var routed = new RoutedContext(calls.Link, node.Runtime.Lifecycle, node.Runtime.Clock.GetUtcNow().AddSeconds(30),
                TimeSpan.FromSeconds(15), node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
            var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
            {
                CellsOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span),
                RemoteCommandId = request.Meta.CommandId.Clone(),
                RawRequest = raw,
                Routed = routed,
            };
            return (await handler.WriteExistingCandidateAsync(caller, ct))!;
        }

        var create = Request("new.txt");
        create.ExpectedAbsent = true;
        handler.AfterPreparationForTests = async () =>
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Remote,
                Decision = PermissionDecision.Deny,
            }))).Error);
        };
        var deniedBytes = await Invoke(create, humanActor);
        handler.AfterPreparationForTests = null;
        var denied = FileServiceWriteFileResponse.Parser.ParseFrom(deniedBytes);
        Assert.Equal("permission_denied", denied.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, denied.Error.Effect);
        Assert.False(File.Exists(Path.Combine(root, "new.txt")));
        var deniedStatus = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, create.Meta.CommandId.Value.Span, humanActor));
        Assert.Equal(FileOperationState.Completed, deniedStatus!.State);
        Assert.False(deniedStatus.Held);
        Assert.Equal(denied.Error, deniedStatus.Error);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Clear())).Error);
        Assert.Equal(deniedBytes, await Invoke(create, humanActor)); // exact original command, bytes and caller
        Assert.False(File.Exists(Path.Combine(root, "new.txt")));

        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.FileWrite,
            Origin = Origin.Script,
            Decision = PermissionDecision.Allow,
        }))).Error);
        var edit = Request("existing.txt");
        edit.ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original));
        handler.AfterPreparationForTests = async () =>
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Clear())).Error);
        };
        var approvalBytes = await Invoke(edit, scriptActor);
        handler.AfterPreparationForTests = null;
        var refusal = FileServiceWriteFileResponse.Parser.ParseFrom(approvalBytes);
        Assert.Equal(ErrorCategory.Resource, refusal.Error.Category);
        Assert.Equal("enforcement_unavailable", refusal.Error.Code);
        Assert.Equal("file_approval_unavailable", refusal.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
        Assert.Equal(original, File.ReadAllBytes(path));
        var approvalStatus = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, edit.Meta.CommandId.Value.Span, scriptActor));
        Assert.Equal(FileOperationState.Completed, approvalStatus!.State);
        Assert.False(approvalStatus.Held);
        Assert.Equal(refusal.Error, approvalStatus.Error);
        Assert.Equal(approvalBytes, await Invoke(edit, scriptActor));
        Assert.Equal(original, File.ReadAllBytes(path));

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var afterDenied = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, create.Meta.CommandId.Value.Span, humanActor));
        var afterApproval = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, edit.Meta.CommandId.Value.Span, scriptActor));
        Assert.Equal(FileOperationState.Completed, afterDenied!.State);
        Assert.Equal(denied.Error, afterDenied.Error);
        Assert.False(afterDenied.Held);
        Assert.Equal(FileOperationState.Completed, afterApproval!.State);
        Assert.Equal(refusal.Error, afterApproval.Error);
        Assert.False(afterApproval.Held);
        Assert.False(File.Exists(Path.Combine(root, "new.txt")));
        Assert.Equal(original, File.ReadAllBytes(path));
    }
}
