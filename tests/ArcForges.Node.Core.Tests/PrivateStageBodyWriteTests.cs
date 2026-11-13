// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native named staging and SQLite; isolated callers, no approval or actual center.</summary>
public sealed class PrivateStageBodyWriteTests
{
    [Fact(Timeout = 120_000)]
    public async Task OnlyCommittedExactBindingCanWriteAndPartialOrCommitFailureRetainsIdentity()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var foreign = calls.Relay(Origin.Agent);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "private-stage-body")).FullName;
        var workspaces = new RegisteredWorkspaces(node.Runtime.Store);
        var workspace = workspaces.RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        using var root = WorkspacePath.OpenRoot(rootPath);
        var budget = new FileStageBudget();

        (FileServiceWriteFileRequest Request, byte[] Raw, WorkspaceEmptyNamedStage Stage, string Path)
            Prepare(string name, byte[] bytes)
        {
            var request = new FileServiceWriteFileRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target-" + name },
                ExpectedAbsent = true,
                Data = ByteString.CopyFrom(bytes),
            };
            var raw = request.ToByteArray();
            var path = Path.Combine(rootPath, name);
            var spec = new PrivateStageSpec(2, path, bytes.Length, SHA256.HashData(bytes));
            Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t =>
                PrivateStageRegistry.Reserve(t, budget, FileOperationKind.Write, request.Meta.CommandId.Value.Span,
                    workspace.Id, request.Meta.CorrelationId.Value.Span, actor, raw, [spec]), CommitDurability.Full));
            var stage = root.CreateEmptyPrivateNamedStage(name, ct);
            node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
                2, root, root, name, stage.Guard, ct), CommitDurability.Full);
            return (request, raw, stage, path);
        }

        long Phase(FileServiceWriteFileRequest request) => (long)node.Runtime.Store.Read(r => r.Scalar(
            "SELECT phase FROM file_private_stage_object WHERE command_id = $id AND slot = 2;",
            ("$id", request.Meta.CommandId.Value.ToByteArray()))!);

        var body = RandomNumberGenerator.GetBytes(100_000);
        var first = Prepare("partial", body);
        using (first.Stage)
        using (var other = root.CreateEmptyPrivateNamedStage("other", ct))
        {
            var id = first.Request.Meta.CommandId.Value.ToByteArray();
            var wrongRaw = first.Raw.Concat(new byte[] { 0 }).ToArray();
            var wrongBody = body.ToArray();
            wrongBody[0] ^= 1;
            Assert.Throws<InvalidOperationException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2,
                foreign, first.Raw, first.Stage, body, ct));
            Assert.Throws<InvalidOperationException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2,
                actor, wrongRaw, first.Stage, body, ct));
            Assert.Throws<InvalidOperationException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2,
                actor, first.Raw, first.Stage, wrongBody, ct));
            Assert.Throws<InvalidOperationException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 1,
                actor, first.Raw, first.Stage, body, ct));
            Assert.Throws<InvalidOperationException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2,
                actor, first.Raw, other, body, ct));
            Assert.Equal(0, first.Stage.Guard.ObserveLength(ct));
            Assert.Equal(0, other.Guard.ObserveLength(ct));
            Assert.Equal(2, Phase(first.Request));

            Assert.Throws<IOException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2, actor,
                first.Raw, first.Stage, body, ct, () => throw new IOException("owned fault after first write")));
            Assert.Equal(65_536, first.Stage.Guard.ObserveLength(ct));
            Assert.Equal(2, Phase(first.Request));
            Assert.Throws<InvalidOperationException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2,
                actor, first.Raw, first.Stage, body, ct));
        }
        Assert.Equal(body.AsSpan(0, 65_536).ToArray(), File.ReadAllBytes(first.Path));

        var secondBody = RandomNumberGenerator.GetBytes(2_048);
        var second = Prepare("failed-commit", secondBody);
        node.Runtime.Store.Write(t => t.Execute("""
            CREATE TRIGGER owned_test_reject_stage_ready BEFORE UPDATE OF phase ON file_private_stage_object
            WHEN NEW.phase = 3 BEGIN SELECT RAISE(ABORT, 'owned test failure'); END;
            """), CommitDurability.Full);
        using (second.Stage)
        {
            var id = second.Request.Meta.CommandId.Value.ToByteArray();
            Assert.Throws<SqliteException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2, actor,
                second.Raw, second.Stage, secondBody, ct));
            Assert.Equal(secondBody.Length, second.Stage.Guard.ObserveLength(ct));
            Assert.Equal(2, Phase(second.Request));
        }
        Assert.Equal(secondBody, File.ReadAllBytes(second.Path));
        node.Runtime.Store.Write(t => t.Execute("DROP TRIGGER owned_test_reject_stage_ready;"), CommitDurability.Full);

        foreach (var file in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(file)) continue;
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(body.AsSpan(0, 256)));
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(secondBody));
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var read = new FileServiceReadFileRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "partial" },
            Offset = 0,
            Length = 128,
        };
        var answer = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.ReadNodeFile, read.ToByteArray());
        var refusal = FileServiceReadFileResponse.Parser.ParseFrom(answer.Answer!.Response);
        Assert.Null(refusal.Value);
        Assert.NotNull(refusal.Error);
        Assert.Equal(2, Phase(first.Request));
        Assert.Equal(2, Phase(second.Request));
    }
}
