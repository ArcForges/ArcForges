// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Synthetic routed seam, native staged objects and real local HUMAN RPC; no actual center or channel signature.</summary>
public sealed class RoutedFileApprovalProducerTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RoutedScriptStagesAndHumanApprovesAnExistingFile(bool edit)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var foreign = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "routed-approval")).FullName;
        var target = Path.Combine(root, "target.txt");
        var before = Encoding.UTF8.GetBytes("alpha-seed-4d79 alpha-seed-4d79");
        var after = Encoding.UTF8.GetBytes("beta-seed-4d79 beta-seed-4d79");
        File.WriteAllBytes(target, before);
        if (OperatingSystem.IsWindows()) File.SetAttributes(target, File.GetAttributes(target) | FileAttributes.Archive);
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
        var path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target.txt" };
        var hash = SHA256.HashData(before);
        var write = new FileServiceWriteFileRequest
        {
            Meta = meta.Clone(),
            Path = path.Clone(),
            ExpectedSha256 = ByteString.CopyFrom(hash),
            Data = ByteString.CopyFrom(after),
        };
        var change = new FileServiceEditFileRequest
        {
            Meta = meta.Clone(),
            Path = path.Clone(),
            ExpectedSha256 = ByteString.CopyFrom(hash),
            OldText = "alpha",
            NewText = "beta",
            ExpectedOccurrences = 2,
        };
        var raw = edit ? change.ToByteArray() : write.ToByteArray();
        var method = edit ? RoutedMethod.EditNodeFile : RoutedMethod.WriteNodeFile;
        var result = await calls.CallAsync(actor, method, raw, meta.CommandId);
        Assert.NotNull(result.Answer);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(RoutedOutcome.Executed, result.Answer.Outcome);
            var error = edit ? FileServiceEditFileResponse.Parser.ParseFrom(result.Answer.Response).Error :
                FileServiceWriteFileResponse.Parser.ParseFrom(result.Answer.Response).Error;
            Assert.Equal("enforcement_unavailable", error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
            Assert.Equal(before, File.ReadAllBytes(target));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
            return;
        }

        Assert.Equal(RoutedOutcome.RefusedByPolicy, result.Answer.Outcome);
        var approvalError = Assert.IsType<ArcError>(result.Answer.Error);
        Assert.Equal("approval_required", approvalError.Code);
        var approvalId = approvalError.Details.State.Resource.Id;
        Assert.NotNull(approvalId);
        Assert.Equal(before, File.ReadAllBytes(target));
        var captured = node.Runtime.Store.Read(r => Approvals.ByCommand(r, meta.CommandId.Value.Span))!;
        Assert.Equal(ApprovalState.Pending, captured.State);
        Assert.Equal(SHA256.HashData(raw), captured.RequestDigest);
        Assert.Equal(17, captured.Request.Length);
        Assert.Equal(meta.CommandId.Value.ToByteArray(), captured.Request[1..]);
        Assert.Equal(2L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_object WHERE phase = 3;")));

        var duplicate = await calls.CallAsync(actor, method, raw, meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, duplicate.Answer!.Outcome);
        var duplicateError = Assert.IsType<ArcError>(duplicate.Answer.Error);
        Assert.Equal(approvalId, duplicateError.Details.State.Resource.Id);
        var cross = await calls.CallAsync(foreign, method, raw, meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, cross.Answer!.Outcome);
        var crossError = edit ? FileServiceEditFileResponse.Parser.ParseFrom(cross.Answer.Response).Error :
            FileServiceWriteFileResponse.Parser.ParseFrom(cross.Answer.Response).Error;
        Assert.Equal("command_id_reused", crossError.Code);
        var otherRaw = edit ? change.Clone() : null;
        byte[] different;
        if (edit)
        {
            otherRaw!.NewText = "gamma";
            different = otherRaw.ToByteArray();
        }
        else
        {
            var changedWrite = write.Clone();
            changedWrite.Data = ByteString.CopyFromUtf8("different-body");
            different = changedWrite.ToByteArray();
        }
        var conflict = await calls.CallAsync(actor, method, different, meta.CommandId);
        var conflictError = edit ? FileServiceEditFileResponse.Parser.ParseFrom(conflict.Answer!.Response).Error :
            FileServiceWriteFileResponse.Parser.ParseFrom(conflict.Answer!.Response).Error;
        Assert.Equal("command_id_reused", conflictError.Code);
        Assert.Equal(before, File.ReadAllBytes(target));

        var stagePath = node.Runtime.Store.Read(r =>
        {
            using var q = r.CreateCommand("SELECT stage_path FROM file_private_stage_object WHERE command_id=$id AND slot=2;");
            q.Parameters.AddWithValue("$id", meta.CommandId.Value.ToByteArray());
            return (string)q.ExecuteScalar()!;
        });
        Assert.Equal(after, File.ReadAllBytes(stagePath));
        var stageRead = new FileServiceReadFileRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = path.WorkspaceId.Clone(), Path = Path.GetRelativePath(root, stagePath).Replace('\\', '/') },
            Offset = 0,
            Length = 128,
        };
        var stageReply = await calls.CallAsync(actor, RoutedMethod.ReadNodeFile, stageRead.ToByteArray());
        var protectedRead = FileServiceReadFileResponse.Parser.ParseFrom(stageReply.Answer!.Response);
        Assert.Equal("file_access_denied", protectedRead.Error.Code);
        Assert.Equal(-1, stageReply.Answer.Response!.Span.IndexOf(after));

        foreach (var db in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(db)) continue;
            using var stream = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(before));
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(after));
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            var approved = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
            {
                Meta = InProcessNode.Command(),
                ApprovalId = approvalId.Clone(),
                Decision = ApprovalDecisionKind.Approve,
            }, cancellationToken: ct);
            Assert.Null(approved.Error);
            Assert.Equal(ApprovalState.Executed, approved.Value.Approval.State);
        }
        Assert.Equal(after, File.ReadAllBytes(target));
        calls = new RoutedCalls(node);
        var replay = await calls.CallAsync(actor, method, raw, meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, replay.Answer!.Outcome);
        if (edit)
        {
            var response = FileServiceEditFileResponse.Parser.ParseFrom(replay.Answer.Response);
            Assert.Null(response.Error);
            Assert.Equal(2U, response.Value.Result.Replacements);
            Assert.Equal(meta.CorrelationId, response.Meta.CorrelationId);
        }
        else
        {
            var response = FileServiceWriteFileResponse.Parser.ParseFrom(replay.Answer.Response);
            Assert.Null(response.Error);
            Assert.Equal(meta.CorrelationId, response.Meta.CorrelationId);
        }
        var status = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, meta.CommandId.Value.Span, actor))!;
        Assert.Equal(FileOperationState.Completed, status.State);
        Assert.Equal(SHA256.HashData(raw), status.RequestSha256.ToByteArray());
        Assert.False(status.Held);
    }
}
