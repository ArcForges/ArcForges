// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>In-process routing cannot impersonate the real Host's bounded stage worker.
/// Successful native approval/create/restart is covered by FileStageProducerHostTests.</summary>
public sealed class RoutedApprovedFileCreateTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task InProcessApprovalCannotReachCreateHooksWithoutARealHostWorker(int scenario)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "approved-create")).FullName;
        var target = Path.Combine(root, "new.txt");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "new.txt" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(Encoding.UTF8.GetBytes("approved-created-file-49ca")),
        };
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var reachedCreate = false;
        if (scenario == 1) handler.BeforeCreateForTests = () => { reachedCreate = true; File.WriteAllText(target, "owned rival"); };
        if (scenario == 2) handler.AfterCreateForTests = () => { reachedCreate = true; throw new IOException("owned post-create fault"); };
        try
        {
            var dispatched = await calls.CallAsync(actor, RoutedMethod.WriteNodeFile, request.ToByteArray(), request.Meta.CommandId);
            Assert.NotNull(dispatched.Answer);
            Assert.Equal(RoutedOutcome.Executed, dispatched.Answer.Outcome);
            var failure = FileServiceWriteFileResponse.Parser.ParseFrom(dispatched.Answer.Response);
            Assert.Equal("enforcement_unavailable", failure.Error.Code);
            Assert.Equal("file_guard_unavailable", failure.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, failure.Error.Effect);
            Assert.Equal(request.Meta.CorrelationId, failure.Error.CorrelationId);
            Assert.False(reachedCreate);
            Assert.False(File.Exists(target));
            Assert.Empty(Directory.EnumerateFileSystemEntries(root));
            Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, request.Meta.CommandId.Value.Span, actor)));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM approval;")));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_creation_ownership;")));
            Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("""
                SELECT count(*) FROM audit_log WHERE remote_command_id = $id AND decision = $deny
                  AND outcome_summary = 'refused: enforcement_unavailable';
                """, ("$id", request.Meta.CommandId.Value.ToByteArray()), ("$deny", (int)PermissionDecision.Deny))));
        }
        finally { handler.BeforeCreateForTests = null; handler.AfterCreateForTests = null; }
    }
}
