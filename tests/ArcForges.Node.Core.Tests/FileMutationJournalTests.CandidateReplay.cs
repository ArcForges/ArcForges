// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed partial class FileMutationJournalTests
{
    [Fact(Timeout = 120_000)]
    public async Task CandidateReplaysOnlyBoundUnknownAfterPolicyNarrowingAndWorkspaceUnregistration()
    {
        // This deliberately creates a test-owned PREPARED journal with real native fixture identities; it does not
        // claim a routed file write happened. Node startup must recover it before this replay-only scenario.
        using var fixture = new Fixture();
        await using var node = await InProcessNode.Create().StartAsync();
        var token = TestContext.Current.CancellationToken;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(fixture.Workspace,
            "candidate-replay", cancellationToken: token);
        var marker = Encoding.UTF8.GetBytes("candidate-replay-body-a6bd4");
        var (intent, raw) = fixture.WriteIntent(workspace.Id, marker);
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(
            transaction => FileMutationJournal.Prepare(transaction, intent, raw), CommitDurability.Full));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var original = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
        var unknown = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, intent.CommandId, intent.Caller));
        Assert.Equal(FileOperationState.Unknown, unknown!.State);
        var saved = node.Runtime.Store.Read(reader =>
            FileMutationJournal.Replay(reader, intent.Kind, intent.CommandId, intent.Caller, raw));
        Assert.NotNull(saved);
        Assert.Equal("file_outcome_unknown", FileServiceWriteFileResponse.Parser.ParseFrom(saved).Error.Details.State.Reason);

        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            var changed = await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Remote,
                Decision = PermissionDecision.Deny,
            }));
            Assert.Null(changed.Error);
        }

        var humanActor = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
        Assert.Equal(FileJournalAcknowledgment.Acknowledged, node.Runtime.Store.Write(transaction =>
            FileMutationJournal.AcknowledgeFromVerifiedHuman(transaction, intent.CommandId, SHA256.HashData(raw), humanActor),
            CommitDurability.Full));
        new RegisteredWorkspaces(node.Runtime.Store).UnregisterFromVerifiedHuman(workspace.Id, token);
        File.Delete(fixture.Target);

        var calls = new RoutedCalls(node);
        async Task<byte[]?> Invoke(byte[] payload, CenterCaller source)
        {
            var request = FileServiceWriteFileRequest.Parser.ParseFrom(payload);
            var now = node.Runtime.Clock.GetUtcNow();
            var routed = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
                node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
            var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: source.Clone())
            {
                CellsOrigin = CenterRouting.CellsOrigin(source, node.Runtime.NodeId.Span),
                RemoteCommandId = request.Meta.CommandId.Clone(),
                RawRequest = payload,
                Routed = routed,
            };
            return await calls.Dispatcher.FileHandlerForTests!.WriteExistingCandidateAsync(caller, token);
        }

        var newSession = intent.Caller.Clone();
        newSession.SessionId = CommandIds.New();
        var replayed = await Invoke(raw, newSession);
        Assert.Equal("operation_failed", FileServiceWriteFileResponse.Parser.ParseFrom(replayed).Error.Code);
        Assert.Equal(saved, replayed);
        var foreign = intent.Caller.Clone();
        foreign.AccountId = CommandIds.New();
        var foreignResult = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(raw, foreign));
        Assert.Equal("command_id_reused", foreignResult.Error.Code);
        var altered = original.Clone();
        altered.Meta.CorrelationId = CommandIds.New();
        var alteredResult = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(altered.ToByteArray(), intent.Caller));
        Assert.Equal("command_id_reused", alteredResult.Error.Code);
        var fresh = original.Clone();
        fresh.Meta.CommandId = CommandIds.New();
        var freshResult = FileServiceWriteFileResponse.Parser.ParseFrom(await Invoke(fresh.ToByteArray(), intent.Caller));
        Assert.Equal("permission_denied", freshResult.Error.Code);
        calls.Link.Reset(usableFor: 0);
        await Assert.ThrowsAsync<RoutedAbortException>(async () => await Invoke(raw, intent.Caller));
        calls.Link.Reset();
        Assert.Equal(saved, await Invoke(raw, intent.Caller));
        Assert.False(File.Exists(fixture.Target));
        AssertNoContent(node.Runtime.Store.DatabasePath, marker);
    }
}
