// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
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

/// <summary>Retired routed writes and edits preserve existing bytes and audit refusal without staging content.</summary>
public sealed class RoutedFileApprovalProducerTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetiredRouteCannotStageAnExistingFileForWriteOrEdit(bool edit)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
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
        var result = await calls.CallAsync(actor, method, raw, meta.CommandId, cancellationToken: ct);
        Assert.NotNull(result.Answer);
        Assert.Equal(RoutedOutcome.Executed, result.Answer.Outcome);
        var error = edit ? FileServiceEditFileResponse.Parser.ParseFrom(result.Answer.Response).Error :
            FileServiceWriteFileResponse.Parser.ParseFrom(result.Answer.Response).Error;
        Assert.Equal((ErrorCategory.Execution, "operation_failed", "file", "file_outcome_unknown", EffectCertainty.Unknown, RetryMode.Never),
            (error.Category, error.Code, error.Details.State.State, error.Details.State.Reason, error.Effect, error.Retry.Mode));
        Assert.Equal(meta.CorrelationId, error.CorrelationId);
        Assert.Equal(before, File.ReadAllBytes(target));
        Assert.Equal(["target.txt"], Directory.GetFileSystemEntries(root).Select(Path.GetFileName).ToArray());
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM approval;")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_stage_worker;")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_effect_worker;")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;",
            ("$id", meta.CommandId.Value.ToByteArray()))));
        Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, meta.CommandId.Value.Span, actor)));
        var duplicate = await calls.CallAsync(actor, method, raw, meta.CommandId, cancellationToken: ct);
        Assert.Equal(RoutedOutcome.Executed, duplicate.Answer!.Outcome);
        var repeated = edit ? FileServiceEditFileResponse.Parser.ParseFrom(duplicate.Answer.Response).Error :
            FileServiceWriteFileResponse.Parser.ParseFrom(duplicate.Answer.Response).Error;
        Assert.Equal(error, repeated);
        Assert.Equal(2L, node.Runtime.Store.Read(r => r.Scalar("""
            SELECT count(*) FROM audit_log WHERE remote_command_id = $id AND decision = $deny
              AND outcome_summary = 'refused: operation_failed';
            """, ("$id", meta.CommandId.Value.ToByteArray()), ("$deny", (int)PermissionDecision.Deny))));
        foreach (var db in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(db)) continue;
            using var stream = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(before));
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(after));
        }
    }
}
