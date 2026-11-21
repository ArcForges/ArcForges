// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real node, SQLite and signed WebSocket with a synthetic center peer and retained file history.</summary>
public sealed class RoutedFileMutationChannelTests
{
    [Fact(Timeout = 120_000)]
    public async Task SignedWriteAndEditBindExactRequestsAndNeverPersistBodies()
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
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-mutation-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var path = Path.Combine(root, "target.txt");
        var original = Encoding.UTF8.GetBytes("signed-native-original-4e34");
        const string oldText = "SIGNED_EDIT_OLD_PRIVATE_7dbb1";
        const string newText = "SIGNED_EDIT_NEW_PRIVATE_7dbb2";
        var intended = Encoding.UTF8.GetBytes("SIGNED_NATIVE_PRIVATE_BODY_680ab " + oldText);
        var editedBody = Encoding.UTF8.GetBytes("SIGNED_NATIVE_PRIVATE_BODY_680ab " + newText);
        var later = Encoding.UTF8.GetBytes("independent-later-change");
        File.WriteAllBytes(path, later);

        async Task<(ResultHeader Header, ByteString Payload)> Invoke(RoutedMethod method, IMessage request, Id commandId, CenterCaller source,
            byte[]? transmitted = null)
        {
            var built = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = method,
                Payload = transmitted ?? request.ToByteArray(),
                Caller = source,
                CommandId = commandId,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            Assert.Equal(commandId, built.Header!.CommandId);
            var call = built.Call;
            await connection.SendCallAsync(call);
            var frame = await connection.ResultOfAsync(call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(value => value.Header.CallId.Equals(call.CallId)),
                "independently verified file mutation result");
            return (connection.VerifiedResults.Single(value => value.Header.CallId.Equals(call.CallId)).Header, frame.Payload);
        }

        var write = new FileServiceWriteFileRequest
        {
            Meta = CloudNode.Command(),
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target.txt" },
            Data = ByteString.CopyFrom(intended),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
        };
        var raw = write.ToByteArray();
        var edit = new FileServiceEditFileRequest
        {
            Meta = CloudNode.Command(),
            Path = write.Path.Clone(),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(intended)),
            OldText = oldText,
            NewText = newText,
            ExpectedOccurrences = 1,
        };
        var rawEdit = edit.ToByteArray();
        var rootId = ReadRootIdentity(root);
        var targetId = ReadFileIdentity(path);
        // Only fixture identities are materialized. The old and proposed bodies are held in memory for their exact hashes.
        var oldStage = FixtureStage(node.Root, "old-stage-identity", original.Length);
        var writtenStage = FixtureStage(node.Root, "write-stage-identity", intended.Length);
        var beforeEditStage = FixtureStage(node.Root, "edit-preimage-identity", intended.Length);
        var editedStage = FixtureStage(node.Root, "edit-stage-identity", editedBody.Length);
        var (retainedWrite, retainedEdit) = await node.Runtime.Processor.ExecuteAsync(command =>
        {
            var transaction = command.Transaction;
            byte[] Retain(FileOperationKind kind, RequestMeta meta, byte[] transmitted, byte[] before, byte[] after,
                RegisteredWorkspaces.RootIdentity preimage, RegisteredWorkspaces.RootIdentity result, uint? replacements)
            {
                var id = meta.CommandId.Value.ToByteArray();
                var resultHash = SHA256.HashData(after);
                var intent = new FileJournalIntent(kind, id, meta.CorrelationId.Value.ToByteArray(), caller, workspace.Id, write.Path.Path,
                    rootId.Platform, rootId.Bytes, rootId.Bytes, targetId.Bytes, before.Length, SHA256.HashData(before), preimage.Bytes,
                    after.Length, resultHash, result.Bytes);
                Assert.Equal(FileJournalPreparation.Prepared, FileMutationJournal.Prepare(transaction, intent, transmitted));
                return FileMutationJournal.CompleteVerifiedEffect(transaction, id, transmitted, after.Length, resultHash, replacements);
            }

            return (Retain(FileOperationKind.Write, write.Meta, raw, original, intended, oldStage, writtenStage, null),
                Retain(FileOperationKind.Edit, edit.Meta, rawEdit, intended, editedBody, beforeEditStage, editedStage, 1));
        }, CommitDurability.Full).WaitAsync(ct);

        var (header, payload) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller);
        Assert.Equal(RoutedOutcome.Executed, header.Outcome);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(payload);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal(write.Meta.CorrelationId, response.Meta.CorrelationId);
        Assert.Null(response.Error);
        Assert.Equal(retainedWrite, payload.ToByteArray());
        Assert.Equal(SHA256.HashData(intended), response.Value.Result.Sha256.ToByteArray());

        var (editHeader, editBytes) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, caller);
        Assert.Equal(RoutedOutcome.Executed, editHeader.Outcome);
        var edited = FileServiceEditFileResponse.Parser.ParseFrom(editBytes);
        Assert.True(NodeShapes.IsValid(edited));
        Assert.Equal(edit.Meta.CorrelationId, edited.Meta.CorrelationId);
        Assert.Null(edited.Error);
        Assert.Equal(retainedEdit, editBytes.ToByteArray());
        Assert.Equal(SHA256.HashData(editedBody), edited.Value.Result.Sha256.ToByteArray());
        Assert.Equal(1U, edited.Value.Result.Replacements);

        var (_, repeated) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller);
        Assert.Equal(payload, repeated);
        var (_, repeatedEdit) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, caller);
        Assert.Equal(editBytes, repeatedEdit);
        Assert.Equal(later, File.ReadAllBytes(path));

        var changed = write.Clone();
        changed.Meta.CorrelationId = CommandIds.New();
        var (_, changedBytes) = await Invoke(RoutedMethod.WriteNodeFile, changed, changed.Meta.CommandId, caller);
        Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(changedBytes).Error.Code);
        using var input = new CodedInputStream(raw);
        Assert.Equal(10U, input.ReadTag());
        input.SkipLastField();
        var firstField = checked((int)input.Position);
        byte[] reordered = [.. raw.AsSpan(firstField), .. raw.AsSpan(0, firstField)];
        Assert.NotEqual(raw, reordered);
        Assert.Equal(write, FileServiceWriteFileRequest.Parser.ParseFrom(reordered));
        var (_, reorderedBytes) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller, reordered);
        Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(reorderedBytes).Error.Code);

        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var (_, foreignBytes) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, foreign);
        Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(foreignBytes).Error.Code);
        var (_, foreignEdit) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, foreign);
        Assert.Equal("command_id_reused", FileServiceEditFileResponse.Parser.ParseFrom(foreignEdit).Error.Code);

        var tooLarge = write.Clone();
        tooLarge.Meta = CloudNode.Command();
        tooLarge.Data = ByteString.CopyFrom(new byte[196_609]);
        var (largeHeader, largeBytes) = await Invoke(RoutedMethod.WriteNodeFile, tooLarge, tooLarge.Meta.CommandId, caller);
        Assert.Equal(RoutedOutcome.Executed, largeHeader.Outcome);
        var large = FileServiceWriteFileResponse.Parser.ParseFrom(largeBytes);
        Assert.True(NodeShapes.IsValid(large));
        Assert.Equal("too_large", large.Error.Code);
        Assert.Equal("file_write_bytes", large.Error.Details.Limit.LimitName);
        Assert.Equal("196608", large.Error.Details.Limit.Maximum.Value);
        Assert.Equal(EffectCertainty.DidNotHappen, large.Error.Effect);
        var wrongHeader = write.Clone();
        wrongHeader.Meta = CloudNode.Command();
        var (wrong, wrongBytes) = await Invoke(RoutedMethod.WriteNodeFile, wrongHeader, CommandIds.New(), caller);
        Assert.Equal(RoutedOutcome.Executed, wrong.Outcome);
        Assert.Equal("invalid_argument", FileServiceWriteFileResponse.Parser.ParseFrom(wrongBytes).Error.Code);

        var agent = caller.Clone();
        agent.LocalOrigin = Origin.Agent;
        var denied = write.Clone();
        denied.Meta = CloudNode.Command();
        var (agentHeader, _) = await Invoke(RoutedMethod.WriteNodeFile, denied, denied.Meta.CommandId, agent);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, agentHeader.Outcome);
        Assert.Empty(connection.UnverifiedResults);
        Assert.Equal(later, File.ReadAllBytes(path));
        node.Runtime.Store.Read(reader =>
        {
            foreach (var (commandId, requestBytes) in new[] { (write.Meta.CommandId, raw), (edit.Meta.CommandId, rawEdit) })
            {
                var operation = FileMutationJournal.GetForCaller(reader, commandId.Value.Span, caller);
                Assert.NotNull(operation);
                Assert.Equal(FileOperationState.Completed, operation.State);
                Assert.False(operation.Held);
                Assert.Equal(SHA256.HashData(requestBytes), operation.RequestSha256.ToByteArray());
            }
            Assert.Equal(2L, reader.Scalar("SELECT count(*) FROM file_operation_journal;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_private_stage_reservation;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_stage_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_effect_worker;"));
            return 0;
        });
        byte[][] privateBodies = [intended, editedBody, Encoding.UTF8.GetBytes(oldText), Encoding.UTF8.GetBytes(newText)];
        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var file = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            var contents = copy.ToArray();
            foreach (var body in privateBodies)
                Assert.Equal(-1, contents.AsSpan().IndexOf(body));
        }
    }

    private static RegisteredWorkspaces.RootIdentity ReadRootIdentity(string path)
    {
        using var root = WorkspacePath.OpenRoot(path);
        return RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
    }

    private static RegisteredWorkspaces.RootIdentity ReadFileIdentity(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(handle), directory: false);
    }

    private static RegisteredWorkspaces.RootIdentity FixtureStage(string root, string name, int size)
    {
        var path = Path.Combine(root, name);
        File.WriteAllBytes(path, new byte[size]);
        return ReadFileIdentity(path);
    }
}
