// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real node, native filesystem, SQLite and signed WebSocket; the channel peer is a mocked center.</summary>
public sealed class RoutedDirectoryChannelTests
{
    [Fact(Timeout = 120_000)]
    public async Task SignedDirectoryPagesBindTheCallerAndPersistOnlyMetadataAudit()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
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
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-directory-root")).FullName;
        var marker = Encoding.UTF8.GetBytes("😀SIGNED_DIRECTORY_PRIVATE_FILE_BODY_641e9");
        File.WriteAllBytes(Path.Combine(root, "a"), marker);
        File.WriteAllText(Path.Combine(root, "b"), "second");
        var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = CloudNode.Command(), Path = root, Name = "signed-directory" };
        var registeredCall = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.RegisterNodeWorkspace,
            Payload = register.ToByteArray(),
            Caller = caller,
            CommandId = register.Meta.CommandId,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;
        await connection.SendCallAsync(registeredCall);
        var registeredFrame = await connection.ResultOfAsync(registeredCall.CallId);
        await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(registeredCall.CallId)), "signed registration");
        var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(registeredFrame.Payload);
        Assert.Null(registered.Error);
        var workspace = registered.Value.Workspace.WorkspaceId;
        var correlation = CommandIds.New();
        var request = new FileServiceListDirectoryRequest
        {
            Meta = new RequestMeta { CorrelationId = correlation },
            Path = new NodeFilePath { WorkspaceId = workspace, Path = "" },
            PageSize = 1,
        };
        async Task<(ResultHeader Header, FileServiceListDirectoryResponse Response)> Invoke(CenterCaller source)
        {
            var call = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.ListNodeDirectory,
                Payload = request.ToByteArray(),
                Caller = source,
                Lifetime = TimeSpan.FromSeconds(30),
            }).Call;
            await connection.SendCallAsync(call);
            var result = await connection.ResultOfAsync(call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(call.CallId)), "verified directory result");
            return (connection.VerifiedResults.Single(x => x.Header.CallId.Equals(call.CallId)).Header,
                FileServiceListDirectoryResponse.Parser.ParseFrom(result.Payload));
        }

        var (header, first) = await Invoke(caller);
        Assert.Equal(RoutedOutcome.Executed, header.Outcome);
        Assert.True(NodeShapes.IsValid(first));
        Assert.Null(first.Error);
        Assert.Equal(correlation, first.Meta.CorrelationId);
        Assert.Equal("a", Assert.Single(first.Value.Entries).Name);
        Assert.True(first.Value.HasNextCursor);
        var audit = Assert.Single(first.Audit.Observations);
        Assert.Equal(FileAuditKind.DirectoryMetadata, audit.Kind);
        Assert.Equal(first.Value.MetadataDigest, audit.Sha256);
        Assert.Equal(first.Value.MetadataBytes, audit.DigestInputBytes);
        request.Cursor = first.Value.NextCursor;
        var other = caller.Clone();
        other.LocalSessionId = CommandIds.New();
        var (refusalHeader, refusal) = await Invoke(other);
        Assert.Equal(RoutedOutcome.Executed, refusalHeader.Outcome);
        Assert.True(NodeShapes.IsValid(refusal));
        Assert.Equal("invalid_cursor", refusal.Error.Code);
        Assert.Equal(correlation, refusal.Error.CorrelationId);
        var (nextHeader, second) = await Invoke(caller);
        Assert.Equal(RoutedOutcome.Executed, nextHeader.Outcome);
        Assert.Null(second.Error);
        Assert.Equal("b", Assert.Single(second.Value.Entries).Name);
        Assert.Empty(connection.UnverifiedResults);
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = '' AND o.kind = 5;
            """, ("$workspace", workspace.Value.ToByteArray())))! >= 2);
        var search = new FileServiceSearchFilesRequest
        {
            Meta = new RequestMeta { CorrelationId = correlation },
            Path = new NodeFilePath { WorkspaceId = workspace, Path = "a" },
            Pattern = "PRIVATE_FILE_BODY_641e9",
            Mode = FileSearchMode.Literal,
        };
        async Task<(ResultHeader Header, FileServiceSearchFilesResponse Response)> SearchAsync()
        {
            var call = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.SearchNodeFiles,
                Payload = search.ToByteArray(),
                Caller = caller,
                Lifetime = TimeSpan.FromSeconds(30),
            }).Call;
            await connection.SendCallAsync(call);
            var frame = await connection.ResultOfAsync(call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(call.CallId)), "verified search result");
            return (connection.VerifiedResults.Single(x => x.Header.CallId.Equals(call.CallId)).Header,
                FileServiceSearchFilesResponse.Parser.ParseFrom(frame.Payload));
        }

        var (searchHeader, found) = await SearchAsync();
        Assert.Equal(RoutedOutcome.Executed, searchHeader.Outcome);
        Assert.Null(found.Error);
        Assert.True(NodeShapes.IsValid(found));
        Assert.Equal(correlation, found.Meta.CorrelationId);
        Assert.Equal("a", Assert.Single(found.Value.Matches).Path);
        Assert.Equal((ulong)marker.Length, found.Value.ScannedBytes);
        Assert.Equal(found.Value.ScanDigest, Assert.Single(found.Audit.Observations).Sha256);
        search.Pattern = ".";
        search.Mode = FileSearchMode.Regex;
        var (boundaryHeader, boundary) = await SearchAsync();
        Assert.Equal(RoutedOutcome.Executed, boundaryHeader.Outcome);
        Assert.True(NodeShapes.IsValid(boundary));
        Assert.Equal("invalid_argument", boundary.Error.Code);
        Assert.Equal("pattern: regex_scalar_boundary", boundary.Error.Details.State.Reason);
        Assert.Equal((ulong)marker.Length, Assert.Single(boundary.Audit.Observations).SizeBytes);
        Assert.Empty(connection.UnverifiedResults);
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'a' AND o.kind = 4;
            """, ("$workspace", workspace.Value.ToByteArray())))! >= 2);

        foreach (var candidate in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(candidate))
            {
                continue;
            }

            using var stream = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(marker));
        }
    }
}
