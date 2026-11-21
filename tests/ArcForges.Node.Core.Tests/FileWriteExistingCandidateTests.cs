// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

public sealed class FileWriteExistingCandidateTests
{
    // The fresh native guarded Write/Edit cases remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task RetainedWindowsWriteAndEditReplaysPreserveTheirAuthorityAndCurrentFile()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("The Windows fixture verifies alternate streams and security metadata.");
            return;
        }
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "existing-write-history")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: token);
        var path = Path.Combine(rootPath, "target.txt");
        var streamPath = path + ":af-test";
        var original = "REAL_CANDIDATE_ORIGINAL_54cc"u8.ToArray();
        var intended = "REAL_CANDIDATE_RESULT_709a"u8.ToArray();
        var edited = "REAL_CANDIDATE_REVISED_709a"u8.ToArray();
        var alternate = "REAL_CANDIDATE_ALTERNATE_26a2"u8.ToArray();
        var current = "independent later change"u8.ToArray();
        File.WriteAllBytes(path, current);
        File.WriteAllBytes(streamPath, alternate);
        File.SetAttributes(path, FileAttributes.Archive);
        var attributes = File.GetAttributes(path);
        var created = File.GetCreationTimeUtc(path);
        const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
        var security = new FileInfo(path).GetAccessControl(sections).GetSecurityDescriptorBinaryForm();
        using var verifiedRoot = WorkspacePath.OpenRoot(rootPath);
        var identity = verifiedRoot.InspectEntry("target.txt").Identity;

        var write = RetainedExistingFileFixture.Write(workspace, "target.txt", original, intended);
        var edit = new FileServiceEditFileRequest
        {
            Meta = InProcessNode.Command(),
            Path = write.Path.Clone(),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(intended)),
            OldText = "RESULT",
            NewText = "REVISED",
            ExpectedOccurrences = 1,
        };
        var rawWrite = write.ToByteArray();
        var rawEdit = edit.ToByteArray();
        var (writeReceipt, editReceipt) = node.Runtime.Store.Write(tx =>
        {
            var first = RetainedExistingFileFixture.Prepare(tx, workspace, actor, FileOperationKind.Write,
                write.Meta, write.Path.Path, rawWrite, original, intended);
            var writeBytes = FileMutationJournal.CompleteVerifiedEffect(tx, first.CommandId, rawWrite, intended.Length, SHA256.HashData(intended), null);
            var second = RetainedExistingFileFixture.Prepare(tx, workspace, actor, FileOperationKind.Edit,
                edit.Meta, edit.Path.Path, rawEdit, intended, edited);
            var editBytes = FileMutationJournal.CompleteVerifiedEffect(tx, second.CommandId, rawEdit, edited.Length, SHA256.HashData(edited), 1);
            return (writeBytes, editBytes);
        }, CommitDurability.Full);

        async Task AssertHistoryAsync()
        {
            var writeBytes = await RetainedExistingFileFixture.ReplyAsync(calls, actor, RoutedMethod.WriteNodeFile,
                rawWrite, write.Meta.CommandId, token);
            var editBytes = await RetainedExistingFileFixture.ReplyAsync(calls, actor, RoutedMethod.EditNodeFile,
                rawEdit, edit.Meta.CommandId, token);
            Assert.Equal(writeReceipt, writeBytes);
            Assert.Equal(editReceipt, editBytes);
            var writeReply = FileServiceWriteFileResponse.Parser.ParseFrom(writeBytes);
            var editReply = FileServiceEditFileResponse.Parser.ParseFrom(editBytes);
            Assert.True(NodeShapes.IsValid(writeReply));
            Assert.True(NodeShapes.IsValid(editReply));
            Assert.Equal(write.Meta.CommandId, writeReply.Value.Result.CommandId);
            Assert.Equal(write.Meta.CorrelationId, writeReply.Meta.CorrelationId);
            Assert.Equal(SHA256.HashData(intended), writeReply.Value.Result.Sha256.ToByteArray());
            Assert.Equal((ulong)intended.Length, writeReply.Value.Result.SizeBytes);
            Assert.Equal(edit.Meta.CommandId, editReply.Value.Result.CommandId);
            Assert.Equal(edit.Meta.CorrelationId, editReply.Meta.CorrelationId);
            Assert.Equal(1U, editReply.Value.Result.Replacements);
            Assert.Equal(SHA256.HashData(edited), editReply.Value.Result.Sha256.ToByteArray());
            foreach (var (meta, raw) in new[] { (write.Meta, rawWrite), (edit.Meta, rawEdit) })
            {
                var operation = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, meta.CommandId.Value.Span, actor));
                Assert.NotNull(operation);
                Assert.Equal(FileOperationState.Completed, operation.State);
                Assert.False(operation.Held);
                Assert.Equal(SHA256.HashData(raw), operation.RequestSha256.ToByteArray());
            }
            Assert.Equal(current, File.ReadAllBytes(path));
            Assert.Equal(alternate, File.ReadAllBytes(streamPath));
            Assert.Equal(attributes, File.GetAttributes(path));
            Assert.Equal(created, File.GetCreationTimeUtc(path));
            Assert.Equal(security, new FileInfo(path).GetAccessControl(sections).GetSecurityDescriptorBinaryForm());
            Assert.True(identity.SameObject(verifiedRoot.InspectEntry("target.txt").Identity));
        }

        await AssertHistoryAsync();
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Remote,
                Decision = PermissionDecision.Deny,
            }))).Error);
            await AssertHistoryAsync();

            var changed = write.Clone();
            changed.Meta.CorrelationId = CommandIds.New();
            var conflict = await RetainedExistingFileFixture.ReplyAsync(calls, actor, RoutedMethod.WriteNodeFile,
                changed.ToByteArray(), changed.Meta.CommandId, token);
            Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(conflict).Error.Code);
            var foreign = actor.Clone();
            foreign.LocalSessionId = CommandIds.New();
            var withheld = await RetainedExistingFileFixture.ReplyAsync(calls, foreign, RoutedMethod.EditNodeFile, rawEdit, edit.Meta.CommandId, token);
            Assert.Equal("command_id_reused", FileServiceEditFileResponse.Parser.ParseFrom(withheld).Error.Code);

            var denied = RetainedExistingFileFixture.Write(workspace, "target.txt", current, intended);
            var deniedAnswer = (await calls.CallAsync(actor, RoutedMethod.WriteNodeFile,
                denied.ToByteArray(), denied.Meta.CommandId, cancellationToken: token)).Answer;
            Assert.NotNull(deniedAnswer);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, deniedAnswer.Outcome);
            Assert.Equal("permission_denied", deniedAnswer.Error?.Code);
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Clear())).Error);
        }

        var neverStaged = RetainedExistingFileFixture.Write(workspace, "target.txt", current, intended);
        var refused = await RetainedExistingFileFixture.ReplyAsync(calls, calls.Relay(Origin.Script), RoutedMethod.WriteNodeFile,
            neverStaged.ToByteArray(), neverStaged.Meta.CommandId, token);
        RetainedExistingFileFixture.AssertUnknown(FileServiceWriteFileResponse.Parser.ParseFrom(refused).Error);
        var agentDenied = (await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.WriteNodeFile, neverStaged.ToByteArray(),
            neverStaged.Meta.CommandId, cancellationToken: token)).Answer;
        Assert.NotNull(agentDenied);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, agentDenied.Outcome);
        Assert.Equal("permission_denied", agentDenied.Error?.Code);
        Assert.Equal(2L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
        Assert.Equal((0, 0L), node.Runtime.Store.Read(PrivateStageRegistry.Usage));

        // Model prior bytes laid down independently, then abort only the actual SQLite settlement transaction.
        var fail = RetainedExistingFileFixture.Write(workspace, "fail.txt", original, intended);
        var failingPath = Path.Combine(rootPath, "fail.txt");
        File.WriteAllBytes(failingPath, intended);
        var rawFailed = fail.ToByteArray();
        var failedId = node.Runtime.Store.Write(tx =>
        {
            var intent = RetainedExistingFileFixture.Prepare(tx, workspace, actor, FileOperationKind.Write,
                fail.Meta, fail.Path.Path, rawFailed, original, intended);
            tx.Execute("""
                CREATE TRIGGER test_fail_write_audit BEFORE INSERT ON file_workspace_audit
                WHEN NEW.path = 'fail.txt' BEGIN SELECT RAISE(ABORT, 'test_write_audit_failure'); END;
                """);
            return intent.CommandId;
        }, CommitDurability.Full);
        Assert.Throws<SqliteException>(() => node.Runtime.Store.Write(tx =>
            FileMutationJournal.CompleteVerifiedEffect(tx, failedId, rawFailed, intended.Length, SHA256.HashData(intended), null),
            CommitDurability.Full));
        Assert.Null(node.Runtime.Store.Read(reader => reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", failedId))) as byte[]);
        Assert.Equal(FileOperationState.Prepared,
            node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, failedId, actor))?.State);
        node.Runtime.Store.Write(tx => tx.Execute("DROP TRIGGER test_fail_write_audit;"), CommitDurability.Full);

        Assert.Equal(0, await node.StopAsync().WaitAsync(token));
        await node.StartAsync();
        calls = new RoutedCalls(node);
        await AssertHistoryAsync();
        var failedReplay = await RetainedExistingFileFixture.ReplyAsync(calls, actor, RoutedMethod.WriteNodeFile, rawFailed, fail.Meta.CommandId, token);
        var failedResponse = FileServiceWriteFileResponse.Parser.ParseFrom(failedReplay);
        RetainedExistingFileFixture.AssertUnknown(failedResponse.Error);
        Assert.Equal(fail.Meta.CorrelationId, failedResponse.Error.CorrelationId);
        var recovered = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, failedId, actor));
        Assert.NotNull(recovered);
        Assert.True(recovered.Held);
        Assert.Equal(FileOperationState.Unknown, recovered.State);
        Assert.Equal(intended, File.ReadAllBytes(failingPath));

        foreach (var db in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(db)) continue;
            using var file = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            var data = copy.ToArray();
            foreach (var payload in new[] { original, intended, edited })
                Assert.Equal(-1, data.AsSpan().IndexOf(payload));
        }
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "linux-real")]
    public async Task ANewLinuxWriteHasNoRetainedOutcomeAndCreatesNoEffectOrStage()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The retired Linux route checks a Linux fixture root.");
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "linux-write-history")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: token);
        var path = Path.Combine(rootPath, "target.txt");
        var original = "linux-existing-unchanged"u8.ToArray();
        File.WriteAllBytes(path, original);
        var request = RetainedExistingFileFixture.Write(workspace, "target.txt", original, "new-content"u8.ToArray());
        var raw = await RetainedExistingFileFixture.ReplyAsync(calls, calls.Relay(Origin.Human), RoutedMethod.WriteNodeFile,
            request.ToByteArray(), request.Meta.CommandId, token);
        var reply = FileServiceWriteFileResponse.Parser.ParseFrom(raw);
        Assert.True(NodeShapes.IsValid(reply));
        RetainedExistingFileFixture.AssertUnknown(reply.Error);
        Assert.Equal(request.Meta.CorrelationId, reply.Meta.CorrelationId);
        Assert.Equal(original, File.ReadAllBytes(path));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_effect_worker;")));
    }
}

internal static class RetainedExistingFileFixture
{
    internal static FileServiceWriteFileRequest Write(RegisteredWorkspace workspace, string name, byte[] before, byte[] after) => new()
    {
        Meta = InProcessNode.Command(),
        Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = name },
        ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(before)),
        Data = ByteString.CopyFrom(after),
    };

    internal static FileJournalIntent Prepare(StoreTransaction tx, RegisteredWorkspace workspace, CenterCaller caller,
        FileOperationKind kind, RequestMeta meta, string name, byte[] raw, byte[] before, byte[] after)
    {
        using var root = WorkspacePath.OpenRoot(workspace.RootPath);
        var parent = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var target = RegisteredWorkspaces.RootIdentity.Encode(root.InspectEntry(name).Identity, directory: false);
        // Historical anonymous stage identities are represented in SQLite only.
        byte[] ReleasedStage(byte tag)
        {
            var encoded = new byte[parent.Bytes.Length];
            encoded[0] = 1;
            encoded[1] = tag;
            return encoded;
        }

        var intent = new FileJournalIntent(kind, meta.CommandId.Value.ToByteArray(), meta.CorrelationId.Value.ToByteArray(), caller,
            workspace.Id, name, parent.Platform, parent.Bytes, parent.Bytes, target.Bytes,
            before.Length, SHA256.HashData(before), ReleasedStage(2), after.Length, SHA256.HashData(after), ReleasedStage(3));
        Assert.Equal(FileJournalPreparation.Prepared, FileMutationJournal.Prepare(tx, intent, raw));
        return intent;
    }

    internal static async Task<byte[]> ReplyAsync(RoutedCalls calls, CenterCaller caller, RoutedMethod method, byte[] raw, Id? id,
        CancellationToken token)
    {
        var (answer, _) = await calls.CallAsync(caller, method, raw, id, cancellationToken: token);
        Assert.NotNull(answer);
        Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
        return Assert.IsType<ByteString>(answer.Response).ToByteArray();
    }

    internal static void AssertUnknown(ArcError error) =>
        Assert.Equal(("operation_failed", "file_outcome_unknown", EffectCertainty.Unknown, RetryMode.Never),
            (error.Code, error.Details.State.Reason, error.Effect, error.Retry.Mode));
}
