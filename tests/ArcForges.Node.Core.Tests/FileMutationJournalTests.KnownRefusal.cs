// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

public sealed partial class FileMutationJournalTests
{
    [Fact(Timeout = 120_000)]
    public async Task RealOversizedGuardedTargetAfterPreparationSettlesKnownRefusalAndReplaysIt()
    {
        using var fixture = new Fixture();
        await using var node = await InProcessNode.Create().StartAsync();
        var token = TestContext.Current.CancellationToken;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(fixture.Workspace, "known-refusal", cancellationToken: token);
        var marker = Encoding.UTF8.GetBytes("KNOWN_REFUSAL_PRIVATE_BODY_12c197");
        var (baseIntent, raw) = fixture.WriteIntent(workspace.Id, marker);
        var caller = RoutedCalls.Session();
        var intent = baseIntent with { Caller = caller };
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(
            transaction => FileMutationJournal.Prepare(transaction, intent, raw), CommitDurability.Full));

        // PREPARED exists before this independent real file change; this is not a fabricated preflight journal.
        using (var root = WorkspacePath.OpenRoot(fixture.Workspace))
        using (var originalGuard = root.OpenExistingWriteGuard("target.txt"))
        {
            Assert.True(originalGuard.ObserveLength(token) < 4_194_304);
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(transaction =>
                FileMutationJournal.CompleteKnownExistingFileTooLarge(transaction, intent.Kind, intent.CommandId, caller, raw,
                    originalGuard, token), CommitDurability.Full));
        }

        using (var changed = new FileStream(fixture.Target, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            changed.SetLength(4_194_305);
            changed.Flush(flushToDisk: true);
        }

        byte[] outcome;
        using (var root = WorkspacePath.OpenRoot(fixture.Workspace))
        using (var guarded = root.OpenExistingWriteGuard("target.txt"))
        {
            Assert.Equal(4_194_305, guarded.ObserveLength(token));
            var foreign = caller.Clone();
            foreign.AccountId = CommandIds.New();
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(transaction =>
                FileMutationJournal.CompleteKnownExistingFileTooLarge(transaction, intent.Kind, intent.CommandId, foreign, raw,
                    guarded, token), CommitDurability.Full));
            var altered = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
            altered.Meta.CorrelationId = CommandIds.New();
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(transaction =>
                FileMutationJournal.CompleteKnownExistingFileTooLarge(transaction, intent.Kind, intent.CommandId, caller, altered.ToByteArray(),
                    guarded, token), CommitDurability.Full));
            outcome = node.Runtime.Store.Write(transaction =>
                FileMutationJournal.CompleteKnownExistingFileTooLarge(transaction, intent.Kind, intent.CommandId, caller, raw,
                    guarded, token), CommitDurability.Full);
            Assert.Equal(4_194_305, guarded.ObserveLength(token));
        }

        var reply = FileServiceWriteFileResponse.Parser.ParseFrom(outcome);
        Assert.True(NodeShapes.IsValid(reply));
        Assert.Equal("too_large", reply.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, reply.Error.Effect);
        Assert.Equal(RetryMode.Never, reply.Error.Retry.Mode);
        Assert.Equal("file_existing_bytes", reply.Error.Details.Limit.LimitName);
        Assert.Equal("4194304", reply.Error.Details.Limit.Maximum.Value);
        Assert.Equal(intent.CorrelationId, reply.Meta.CorrelationId.Value.ToByteArray());
        Assert.Equal(intent.CorrelationId, reply.Error.CorrelationId.Value.ToByteArray());
        Assert.Equal(outcome, node.Runtime.Store.Read(reader =>
            FileMutationJournal.Replay(reader, intent.Kind, intent.CommandId, caller, raw)));
        Assert.False(node.Runtime.Store.Read(reader => FileMutationJournal.HasWorkspaceHold(reader, workspace.Id)));
        AssertNoContent(node.Runtime.Store.DatabasePath, marker);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var calls = new RoutedCalls(node);
        var statusRequest = new FileServiceGetFileOperationRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            OperationCommandId = new Id { Value = ByteString.CopyFrom(intent.CommandId) },
        };
        var returned = await calls.CallAsync(caller, RoutedMethod.GetNodeFileOperation, statusRequest.ToByteArray());
        Assert.Equal(RoutedOutcome.Executed, returned.Answer!.Outcome);
        var status = FileServiceGetFileOperationResponse.Parser.ParseFrom(returned.Answer.Response);
        Assert.True(NodeShapes.IsValid(status));
        Assert.Equal(FileOperationState.Completed, status.Value.Operation.State);
        Assert.False(status.Value.Operation.Held);
        Assert.False(status.Value.Operation.Acknowledged);
        Assert.Equal(SHA256.HashData(raw), status.Value.Operation.RequestSha256.ToByteArray());
        Assert.Equal("too_large", status.Value.Operation.Error.Code);
        Assert.Equal(intent.CorrelationId, status.Value.Operation.Error.CorrelationId.Value.ToByteArray());
        var target = new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) };
        var wrapped = new FleetServiceGetNodeFileOperationResponse
        {
            Meta = new ResponseMeta { CorrelationId = statusRequest.Meta.CorrelationId.Clone() },
            Value = new FleetServiceGetNodeFileOperationValue { NodeId = target, Response = status.ToByteString() },
        };
        Assert.True(RoutedFileResponseValidation.GetFileOperation(wrapped, target, statusRequest));
        Assert.Equal(4_194_305, new FileInfo(fixture.Target).Length);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a JOIN audit_log l ON l.seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'target.txt' AND l.operation = 'file.write FileService.WriteFile'
              AND l.decision = 3;
            """, ("$workspace", workspace.Id))));

        // Deliberately corrupt only the test-owned persisted response to prove 450.1's permissive Decimal validator is not enough.
        var corrupt = reply.Clone();
        corrupt.Error.Details.Limit.Maximum.Value = "4194304.00";
        Assert.True(NodeShapes.IsValid(corrupt));
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE command_dedup SET outcome = $outcome WHERE command_id = $id;",
            ("$outcome", corrupt.ToByteArray()), ("$id", intent.CommandId)), CommitDurability.Full);
        Assert.Throws<InvalidDataException>(() => node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, intent.CommandId, caller)));
        Assert.Throws<InvalidDataException>(() => node.Runtime.Store.Read(reader =>
            FileMutationJournal.Replay(reader, intent.Kind, intent.CommandId, caller, raw)));
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE command_dedup SET outcome = $outcome WHERE command_id = $id;",
            ("$outcome", outcome), ("$id", intent.CommandId)), CommitDurability.Full);
        Assert.Equal(outcome, node.Runtime.Store.Read(reader =>
            FileMutationJournal.Replay(reader, intent.Kind, intent.CommandId, caller, raw)));
    }
}
