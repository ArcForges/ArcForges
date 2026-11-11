// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real rollback, restart and local endpoint for a reserved stage whose identity was not committed.</summary>
public sealed class PrivateStageProducerRecoveryTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedCreateOrBindTransactionNeverAdoptsTheLeftoverName(bool afterBinding)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var path = Directory.CreateDirectory(Path.Combine(node.Root, "stage-rollback")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(path, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("not-written-private-stage-6b892");
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var stagePath = Path.Combine(path, "stage");
        var spec = new PrivateStageSpec(2, stagePath, body.Length, SHA256.HashData(body));
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            new FileStageBudget(), FileOperationKind.Write, id, workspace.Id, request.Meta.CorrelationId.Value.Span,
            caller, raw, [spec]), CommitDurability.Full));
        using (var root = WorkspacePath.OpenRoot(path))
        {
            Action fail = () => throw new InvalidOperationException("Test-owned interruption within stage transaction.");
            var failed = await Assert.ThrowsAsync<InvalidOperationException>(() => PrivateStageProducer.CreateBoundAsync(
                node.Runtime.Processor, id, 2, root, root, "stage", ct,
                afterCreateForTests: afterBinding ? null : fail, afterBindForTests: afterBinding ? fail : null));
            Assert.Contains("Test-owned interruption", failed.Message, StringComparison.Ordinal);
        }
        Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("""
            SELECT count(*) FROM file_private_stage_object WHERE phase = 1 AND native_identity IS NULL AND parent_identity IS NULL;
            """)));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal((1, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.True(File.Exists(stagePath));
        Assert.Empty(File.ReadAllBytes(stagePath));
        Assert.False(File.Exists(Path.Combine(path, "target")));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        Assert.Empty(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
        Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("""
            SELECT count(*) FROM file_private_stage_object WHERE phase = 1 AND native_identity IS NULL AND parent_identity IS NULL;
            """)));
        using (var root = WorkspacePath.OpenRoot(path))
        {
            // FILE_CREATE/O_EXCL must refuse this unidentifiable name, not open it as the stage or delete it.
            await Assert.ThrowsAsync<WorkspacePathException>(() => PrivateStageProducer.CreateBoundAsync(
                node.Runtime.Processor, id, 2, root, root, "stage", ct));
        }
        Assert.Empty(File.ReadAllBytes(stagePath));
        var query = new FileServiceGetFileOperationRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            OperationCommandId = request.Meta.CommandId.Clone(),
        };
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        var local = await human.Files.GetFileOperationAsync(query, cancellationToken: ct);
        Assert.True(NodeShapes.IsValid(local));
        Assert.Equal("not_found", local.Error.Code);
        Assert.Null(local.Value);
        var warning = Assert.Single(local.Meta.Warnings).Split(':', 4);
        Assert.Equal("arcforges.file-stage.v1", warning[0]);
        Assert.Equal("2", warning[1]);
        Assert.Equal("unbound", warning[2]);
        Assert.Equal(stagePath, Encoding.UTF8.GetString(Convert.FromBase64String(warning[3])));
        var denied = await script.Files.GetFileOperationAsync(query, cancellationToken: ct);
        Assert.Equal("permission_denied", denied.Error.Code);
        Assert.Empty(denied.Meta.Warnings);
        var remote = await new RoutedCalls(node).CallAsync(caller, RoutedMethod.GetNodeFileOperation, query.ToByteArray());
        var remoteBytes = Assert.IsType<ByteString>(remote.Answer?.Response);
        var remoteResponse = FileServiceGetFileOperationResponse.Parser.ParseFrom(remoteBytes);
        Assert.True(NodeShapes.IsValid(remoteResponse));
        Assert.NotNull(remoteResponse.Error);
        Assert.Null(remoteResponse.Value);
        Assert.Empty(remoteResponse.Meta.Warnings);
        Assert.Equal(-1, remoteBytes.Span.IndexOf(Encoding.UTF8.GetBytes(stagePath)));
        Assert.Empty(File.ReadAllBytes(stagePath));
        Assert.False(File.Exists(Path.Combine(path, "target")));
    }
}
