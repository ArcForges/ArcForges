// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real node, SQLite, native files and signed WebSocket; the center peer and routed caller are synthetic.</summary>
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
        var intended = Encoding.UTF8.GetBytes("SIGNED_NATIVE_PRIVATE_BODY_680ab hello");
        File.WriteAllBytes(path, original);
        if (OperatingSystem.IsWindows()) File.SetAttributes(path, FileAttributes.Archive);

        async Task<(ResultHeader Header, ByteString Payload)> Invoke(RoutedMethod method, IMessage request, Id commandId, CenterCaller source)
        {
            var built = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = method,
                Payload = request.ToByteArray(),
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
        var (header, payload) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller);
        Assert.Equal(RoutedOutcome.Executed, header.Outcome);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(payload);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal(write.Meta.CorrelationId, response.Meta.CorrelationId);
        if (OperatingSystem.IsWindows())
        {
            Assert.Null(response.Error);
            Assert.Equal(intended, File.ReadAllBytes(path));
            Assert.Equal(SHA256.HashData(intended), response.Value.Result.Sha256.ToByteArray());
            var recorded = node.Runtime.Store.Read(reader =>
                FileMutationJournal.GetForCaller(reader, write.Meta.CommandId.Value.Span, caller));
            Assert.Equal(FileOperationState.Completed, recorded!.State);
            Assert.Equal(SHA256.HashData(raw), recorded.RequestSha256.ToByteArray());

            var edit = new FileServiceEditFileRequest
            {
                Meta = CloudNode.Command(),
                Path = write.Path.Clone(),
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(intended)),
                OldText = "hello",
                NewText = "world",
                ExpectedOccurrences = 1,
            };
            var (editHeader, editBytes) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, caller);
            Assert.Equal(RoutedOutcome.Executed, editHeader.Outcome);
            var edited = FileServiceEditFileResponse.Parser.ParseFrom(editBytes);
            Assert.True(NodeShapes.IsValid(edited));
            Assert.Null(edited.Error);
            Assert.Equal(1U, edited.Value.Result.Replacements);
            Assert.Equal("SIGNED_NATIVE_PRIVATE_BODY_680ab world", File.ReadAllText(path));

            var outside = Encoding.UTF8.GetBytes("independent-later-change");
            File.WriteAllBytes(path, outside);
            var (_, repeated) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller);
            Assert.Equal(payload, repeated);
            Assert.Equal(outside, File.ReadAllBytes(path));
            var (_, repeatedEdit) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, caller);
            Assert.Equal(editBytes, repeatedEdit);
            Assert.Equal(outside, File.ReadAllBytes(path));

            var changed = write.Clone();
            changed.Meta.CorrelationId = CommandIds.New();
            var (_, changedBytes) = await Invoke(RoutedMethod.WriteNodeFile, changed, changed.Meta.CommandId, caller);
            Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(changedBytes).Error.Code);
            var foreign = caller.Clone();
            foreign.LocalSessionId = CommandIds.New();
            var (_, foreignBytes) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, foreign);
            Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(foreignBytes).Error.Code);
        }
        else
        {
            Assert.Equal(ErrorCategory.Resource, response.Error.Category);
            Assert.Equal("enforcement_unavailable", response.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
            Assert.Equal(original, File.ReadAllBytes(path));
            Assert.Null(node.Runtime.Store.Read(reader =>
                FileMutationJournal.GetForCaller(reader, write.Meta.CommandId.Value.Span, caller)));
        }

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
        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var file = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(intended));
        }
    }
}
