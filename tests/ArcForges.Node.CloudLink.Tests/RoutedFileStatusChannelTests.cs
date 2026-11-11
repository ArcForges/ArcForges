// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real Node, SQLite, WebSocket and signatures; the channel peer and journal setup are isolated synthetic fixtures.</summary>
public sealed class RoutedFileStatusChannelTests
{
    [Fact(Timeout = 120_000)]
    public async Task SignedStatusReturnsOnlyOwnedJournalMetadataAndDropsAnUncommittedAudit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        var connection = await center.Channel.ProvedAsync();
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Human,
            LocalSessionId = CommandIds.New(),
        };
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "status-workspace")).FullName;
        var targetPath = Path.Combine(rootPath, "target.txt");
        var original = Encoding.UTF8.GetBytes("original-signed-status-file");
        var marker = Encoding.UTF8.GetBytes("SYNTHETIC_SIGNED_STATUS_BODY_5e1d02");
        File.WriteAllBytes(targetPath, original);
        var oldPath = Path.Combine(node.Root, "fixture-old-stage");
        var newPath = Path.Combine(node.Root, "fixture-new-stage");
        File.WriteAllBytes(oldPath, original);
        File.WriteAllBytes(newPath, marker);

        // This registration and named-stage journal input belong solely to the test fixture; neither is a write-effect acceptance.
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        using var root = WorkspacePath.OpenRoot(rootPath);
        var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        using var target = File.OpenHandle(targetPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var oldStage = File.OpenHandle(oldPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var newStage = File.OpenHandle(newPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var targetId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(target), directory: false);
        var oldId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(oldStage), directory: false);
        var newId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(newStage), directory: false);
        var meta = CloudNode.Command();
        var write = new FileServiceWriteFileRequest
        {
            Meta = meta,
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "target.txt" },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            Data = ByteString.CopyFrom(marker),
        };
        var raw = write.ToByteArray();
        var intent = new FileJournalIntent(FileOperationKind.Write, meta.CommandId.Value.ToByteArray(), meta.CorrelationId.Value.ToByteArray(),
            caller, registered.Id, "target.txt", rootId.Platform, rootId.Bytes, rootId.Bytes, targetId.Bytes, original.Length,
            SHA256.HashData(original), oldId.Bytes, marker.Length, SHA256.HashData(marker), newId.Bytes);
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(
            transaction => FileMutationJournal.Prepare(transaction, intent, raw), CommitDurability.Full));
        _ = node.Runtime.Store.Write(transaction => FileMutationJournal.MarkUnknown(transaction, intent.CommandId), CommitDurability.Full);

        var request = new FileServiceGetFileOperationRequest
        {
            OperationCommandId = meta.CommandId.Clone(),
        };
        ChannelCall Build(CenterCaller source, FileServiceGetFileOperationRequest selected) => center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.GetNodeFileOperation,
            Payload = selected.ToByteArray(),
            Caller = source,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;
        async Task<(ResultHeader Header, FileServiceGetFileOperationResponse Response, Id CallId)> Invoke(CenterCaller source)
        {
            var call = Build(source, request);
            await connection.SendCallAsync(call);
            var frame = await connection.ResultOfAsync(call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(call.CallId)),
                "independently verified status result");
            return (connection.VerifiedResults.Single(x => x.Header.CallId.Equals(call.CallId)).Header,
                FileServiceGetFileOperationResponse.Parser.ParseFrom(frame.Payload), call.CallId);
        }

        var (header, status, callId) = await Invoke(caller);
        Assert.Equal(RoutedOutcome.Executed, header.Outcome);
        Assert.True(NodeShapes.IsValid(status));
        Assert.Equal(callId, status.Meta.CorrelationId);
        Assert.Equal(FileOperationState.Unknown, status.Value.Operation.State);
        Assert.Equal(meta.CorrelationId, status.Value.Operation.Error.CorrelationId);
        Assert.Equal("file_outcome_unknown", status.Value.Operation.Error.Details.State.Reason);
        Assert.Equal(SHA256.HashData(raw), status.Value.Operation.RequestSha256.ToByteArray());
        Assert.Equal(registered.Id, status.Value.Operation.WorkspacePath.WorkspaceId.Value.ToByteArray());
        Assert.Equal("target.txt", status.Value.Operation.WorkspacePath.Path);
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var (foreignHeader, denied, foreignId) = await Invoke(foreign);
        Assert.Equal(RoutedOutcome.Executed, foreignHeader.Outcome);
        Assert.Equal("not_found", denied.Error.Code);
        Assert.True(NodeShapes.IsValid(denied));
        Assert.Equal(foreignId, denied.Error.CorrelationId);
        Assert.Null(denied.Value);
        Assert.Empty(connection.UnverifiedResults);

        // An actual SQLite audit insert failure means no signed reply, even though the verified call reached the node.
        node.Runtime.Store.Write(transaction => transaction.Execute("""
            CREATE TRIGGER test_fail_status_audit BEFORE INSERT ON file_workspace_audit
            BEGIN SELECT RAISE(ABORT, 'test_status_audit_failure'); END;
            """));
        var handler = ((RoutedDispatcher)node.Runtime.RoutedDispatcher!).FileHandlerForTests!;
        var attempted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.StatusBeforeAuditForTests = () => attempted.TrySetResult();
        var failed = Build(caller, request);
        await connection.SendCallAsync(failed);
        await attempted.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
        await node.Runtime.Processor.ExecuteAsync(_ => 0).WaitAsync(TimeSpan.FromSeconds(10), ct);
        handler.StatusBeforeAuditForTests = null;
        await connection.SendHeartbeatAsync(63711, DateTimeOffset.UtcNow);
        await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat &&
            frame.Heartbeat.Seq == 63711), "channel remains live after status audit failure");
        Assert.DoesNotContain(connection.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult &&
            frame.CallResult.CallId.Equals(failed.CallId));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM routed_file_call_log
            WHERE call_id = $id AND decision = 5 AND response_sha256 IS NULL AND response_size IS NULL;
            """, ("$id", failed.CallId.Value.ToByteArray()))));
        node.Runtime.Store.Write(transaction => transaction.Execute("DROP TRIGGER test_fail_status_audit;"));
        Assert.Equal(original, File.ReadAllBytes(targetPath));

        foreach (var candidate in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(candidate)) continue;
            using var stream = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(marker));
        }
    }
}
