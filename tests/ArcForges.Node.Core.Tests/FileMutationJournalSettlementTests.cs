// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Exercises real SQLite settlement and restart with test-owned fixture files. The named fixture staging and manual
/// fixture write do not establish the required guarded production effect, approval or routed service.
/// </summary>
public sealed partial class FileMutationJournalTests
{
    [Fact]
    public void CompletionPersistsOnlyBoundMetadataAndReplaysAfterRestart()
    {
        using var fixture = new Fixture();
        var marker = Encoding.UTF8.GetBytes("actual-settlement-body-682bcf80");
        FileJournalIntent intent;
        byte[] raw;
        byte[] outcome;
        using (var store = fixture.Open())
        {
            var registered = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(fixture.Workspace, "settlement-test",
                cancellationToken: TestContext.Current.CancellationToken);
            (intent, raw) = fixture.WriteIntent(registered.Id, marker);
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
            Assert.Null(store.Read(r => FileMutationJournal.Replay(r, intent.Kind, intent.CommandId, intent.Caller, raw)));
            Assert.Throws<InvalidOperationException>(() => store.Write(t => FileMutationJournal.CompleteVerifiedEffect(
                t, intent.CommandId, raw, marker.Length, new byte[32], null), CommitDurability.Full));
            var changed = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
            changed.Meta.CorrelationId = CommandIds.New();
            Assert.Throws<InvalidOperationException>(() => store.Write(t => FileMutationJournal.CompleteVerifiedEffect(
                t, intent.CommandId, changed.ToByteArray(), marker.Length, SHA256.HashData(marker), null), CommitDurability.Full));
            Assert.Equal(FileOperationState.Prepared,
                store.Read(r => FileMutationJournal.GetForVerifiedHuman(r, intent.CommandId))!.State);

            // This is a real fixture write, not a production guard or native file-effect acceptance test.
            File.WriteAllBytes(fixture.Target, marker);
            var actual = File.ReadAllBytes(fixture.Target);
            outcome = store.Write(t => FileMutationJournal.CompleteVerifiedEffect(
                t, intent.CommandId, raw, actual.Length, SHA256.HashData(actual), null), CommitDurability.Full);
            var response = FileServiceWriteFileResponse.Parser.ParseFrom(outcome);
            Assert.True(NodeShapes.IsValid(response));
            Assert.Equal(intent.CorrelationId, response.Meta.CorrelationId.Value.ToByteArray());
            Assert.Equal(intent.CommandId, response.Value.Result.CommandId.Value.ToByteArray());
            Assert.Equal((ulong)marker.Length, response.Value.Result.SizeBytes);
            Assert.Equal(SHA256.HashData(marker), response.Value.Result.Sha256.ToByteArray());
            Assert.False(response.Value.Result.HasReplacements);
            Assert.Equal(FileAuditKind.WrittenBytes, Assert.Single(response.Audit.Observations).Kind);
            Assert.Equal(1L, store.Read(r => r.Scalar(
                "SELECT count(*) FROM file_workspace_audit_observation WHERE kind = 3 AND size_bytes = $size AND sha256 = $hash;",
                ("$size", marker.Length), ("$hash", SHA256.HashData(marker)))));
            Assert.False(store.Read(r => FileMutationJournal.HasWorkspaceHold(r, intent.WorkspaceId)));
            AssertNoContent(store.DatabasePath, marker);
        }

        using (var restarted = fixture.Open())
        {
            Assert.Equal(0, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
            Assert.Equal(outcome, restarted.Read(r => FileMutationJournal.Replay(r, intent.Kind, intent.CommandId, intent.Caller, raw)));
            var operation = restarted.Read(r => FileMutationJournal.GetForCaller(r, intent.CommandId, intent.Caller))!;
            Assert.True(NodeShapes.IsValid(operation));
            Assert.Equal(FileOperationState.Completed, operation.State);
            Assert.False(operation.Held);
            Assert.False(operation.Acknowledged);
            Assert.Equal(SHA256.HashData(raw), operation.RequestSha256.ToByteArray());
            Assert.Equal(SHA256.HashData(marker), operation.Mutation.Sha256.ToByteArray());
            Assert.Equal("target.txt", operation.WorkspacePath.Path);
            var foreign = intent.Caller.Clone();
            foreign.AccountId = CommandIds.New();
            Assert.Null(restarted.Read(r => FileMutationJournal.Replay(r, intent.Kind, intent.CommandId, foreign, raw)));
            var changed = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
            changed.Meta.CorrelationId = CommandIds.New();
            Assert.Null(restarted.Read(r => FileMutationJournal.Replay(r, intent.Kind, intent.CommandId, intent.Caller, changed.ToByteArray())));
            Assert.Null(restarted.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Edit, intent.CommandId, intent.Caller, raw)));
            Assert.Throws<InvalidOperationException>(() => restarted.Write(t => FileMutationJournal.CompleteVerifiedEffect(
                t, intent.CommandId, raw, marker.Length, SHA256.HashData(marker), null), CommitDurability.Full));
            AssertNoContent(restarted.DatabasePath, marker);
        }
    }

    [Fact]
    public void EditSettlementBindsActualCountToTheOriginalRawRequest()
    {
        using var fixture = new Fixture();
        using var store = fixture.Open();
        var registered = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(fixture.Workspace, "edit-settlement",
            cancellationToken: TestContext.Current.CancellationToken);
        var content = Encoding.UTF8.GetBytes("new test bytes");
        var (writeIntent, writeRaw) = fixture.WriteIntent(registered.Id, content);
        var write = FileServiceWriteFileRequest.Parser.ParseFrom(writeRaw);
        var edit = new FileServiceEditFileRequest
        {
            Meta = write.Meta,
            Path = write.Path,
            OldText = "original",
            NewText = "new",
            ExpectedOccurrences = 1,
            ExpectedSha256 = write.ExpectedSha256,
        };
        var raw = edit.ToByteArray();
        var intent = writeIntent with { Kind = FileOperationKind.Edit };
        Assert.Equal(FileJournalPreparation.Prepared, store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
        Assert.Throws<ArgumentException>(() => store.Write(t => FileMutationJournal.CompleteVerifiedEffect(
            t, intent.CommandId, raw, content.Length, SHA256.HashData(content), 2), CommitDurability.Full));
        Assert.Equal(FileOperationState.Prepared, store.Read(r => FileMutationJournal.GetForVerifiedHuman(r, intent.CommandId))!.State);
        File.WriteAllBytes(fixture.Target, content); // real test-owned fixture only; not the production effect path
        var actual = File.ReadAllBytes(fixture.Target);
        var outcome = store.Write(t => FileMutationJournal.CompleteVerifiedEffect(
            t, intent.CommandId, raw, actual.Length, SHA256.HashData(actual), 1), CommitDurability.Full);
        var response = FileServiceEditFileResponse.Parser.ParseFrom(outcome);
        Assert.True(NodeShapes.IsValid(response));
        Assert.True(response.Value.Result.HasReplacements);
        Assert.Equal(1u, response.Value.Result.Replacements);
        var operation = store.Read(r => FileMutationJournal.GetForVerifiedHuman(r, intent.CommandId))!;
        Assert.True(NodeShapes.IsValid(operation));
        Assert.Equal(1u, operation.Mutation.Replacements);
        AssertNoContent(store.DatabasePath, content);
    }

    [Fact]
    public void UncertainOutcomePersistsOriginalCorrelationAndNeverReexecutes()
    {
        using var fixture = new Fixture();
        FileJournalIntent intent;
        byte[] raw;
        byte[] response;
        using (var store = fixture.Open())
        {
            var registered = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(fixture.Workspace, "unknown-settlement",
                cancellationToken: TestContext.Current.CancellationToken);
            (intent, raw) = fixture.WriteIntent(registered.Id, Encoding.UTF8.GetBytes("uncertain-body-7f781c0e"));
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
            response = store.Write(t => FileMutationJournal.MarkUnknown(t, intent.CommandId), CommitDurability.Full);
        }
        using (var restarted = fixture.Open())
        {
            Assert.Equal(0, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
            Assert.Equal(response, restarted.Read(r => FileMutationJournal.Replay(r, intent.Kind, intent.CommandId, intent.Caller, raw)));
            var reply = FileServiceWriteFileResponse.Parser.ParseFrom(response);
            Assert.True(NodeShapes.IsValid(reply));
            Assert.Equal(intent.CorrelationId, reply.Meta.CorrelationId.Value.ToByteArray());
            Assert.Equal(intent.CorrelationId, reply.Error.CorrelationId.Value.ToByteArray());
            Assert.Equal(EffectCertainty.Unknown, reply.Error.Effect);
            Assert.Equal(RetryMode.Never, reply.Error.Retry.Mode);
            Assert.Equal("file_outcome_unknown", reply.Error.Details.State.Reason);
            Assert.Equal(FileOperationState.Unknown, restarted.Read(r => FileMutationJournal.GetForVerifiedHuman(r, intent.CommandId))!.State);
            Assert.True(restarted.Read(r => FileMutationJournal.HasWorkspaceHold(r, intent.WorkspaceId)));
            Assert.Throws<InvalidOperationException>(() => restarted.Write(
                t => FileMutationJournal.MarkUnknown(t, intent.CommandId), CommitDurability.Full));
            Assert.Equal("original test bytes", File.ReadAllText(fixture.Target));
            AssertNoContent(restarted.DatabasePath, Encoding.UTF8.GetBytes("uncertain-body-7f781c0e"));
        }
    }
}
