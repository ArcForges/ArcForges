// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real Node, SQLite and native filesystem via the routed dispatcher; not a real center acceptance test.</summary>
public sealed class FileDirectoryRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task DirectoryPagesBindTheActualCallerAndAuditTheirMetadataWithoutFileBodies()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "directory-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var marker = Encoding.UTF8.GetBytes("DIRECTORY_PRIVATE_BODY_4ae833_never_persist");
        File.WriteAllBytes(Path.Combine(root, "a.txt"), marker);
        File.WriteAllText(Path.Combine(root, "b.txt"), "second");
        var caller = calls.Relay(Origin.Agent);
        var request = List(workspace.Id, "", null, 1);
        Assert.True(NodeShapes.IsValid(request));
        var firstCall = await calls.CallAsync(caller, RoutedMethod.ListNodeDirectory, request.ToByteArray());
        Assert.Equal(RoutedOutcome.Executed, firstCall.Answer!.Outcome);
        var first = FileServiceListDirectoryResponse.Parser.ParseFrom(firstCall.Answer.Response);
        Assert.Null(first.Error);
        Assert.True(NodeShapes.IsValid(first));
        Assert.Equal(calls.LastCallId, first.Meta.CorrelationId);
        Assert.Equal("a.txt", Assert.Single(first.Value.Entries).Name);
        Assert.True(first.Value.HasNextCursor);
        Assert.Equal(2U, first.Value.SnapshotEntries);
        var (digest, transcriptSize) = DirectoryDigest(first.Value.Entries);
        Assert.Equal(digest, first.Value.MetadataDigest.ToByteArray());
        Assert.Equal(transcriptSize, first.Value.MetadataBytes);
        var observed = Assert.Single(first.Audit.Observations);
        Assert.Equal(FileAuditKind.DirectoryMetadata, observed.Kind);
        Assert.Equal(1U, observed.ItemCount);
        Assert.Equal(transcriptSize, observed.SizeBytes);
        Assert.Equal(transcriptSize, observed.DigestInputBytes);
        Assert.Equal(digest, observed.Sha256.ToByteArray());
        Assert.Equal(workspace.Id, firstCall.Answer.WorkspaceId);
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a
            JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            JOIN audit_log l ON l.seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = '' AND l.decision = 1
              AND o.kind = 5 AND o.item_count = 1 AND o.digest_input_bytes = $size AND o.sha256 = $digest;
            """, ("$workspace", workspace.Id), ("$size", (long)transcriptSize), ("$digest", digest)))! >= 1);

        var target = new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) };
        var wrapped = new FleetServiceListNodeDirectoryResponse
        {
            Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
            Value = new FleetServiceListNodeDirectoryValue { NodeId = target.Clone(), Response = first.ToByteString() },
        };
        Assert.True(RoutedFileResponseValidation.Directory(wrapped, target, request));
        var withoutMeta = first.Clone();
        withoutMeta.Meta = null;
        Assert.True(NodeShapes.IsValid(withoutMeta));
        wrapped.Value.Response = withoutMeta.ToByteString();
        Assert.True(RoutedFileResponseValidation.Directory(wrapped, target, request));
        withoutMeta.Meta = new ResponseMeta();
        Assert.False(NodeShapes.IsValid(withoutMeta));
        wrapped.Value.Response = withoutMeta.ToByteString();
        Assert.False(RoutedFileResponseValidation.Directory(wrapped, target, request));
        wrapped.Value.Response = first.ToByteString();
        wrapped.Value.NodeId = CommandIds.New();
        Assert.False(RoutedFileResponseValidation.Directory(wrapped, target, request));
        wrapped.Value.NodeId = target.Clone();
        var tampered = first.Clone();
        tampered.Value.Entries[0].Name = "forged.txt";
        wrapped.Value.Response = tampered.ToByteString();
        Assert.False(RoutedFileResponseValidation.Directory(wrapped, target, request));
        tampered = first.Clone();
        tampered.Audit.Observations[0].ItemCount = 2;
        wrapped.Value.Response = tampered.ToByteString();
        Assert.False(RoutedFileResponseValidation.Directory(wrapped, target, request));

        request.Cursor = first.Value.NextCursor;
        var differentSession = caller.Clone();
        differentSession.LocalSessionId = CommandIds.New();
        var foreign = await calls.CallAsync(differentSession, RoutedMethod.ListNodeDirectory, request.ToByteArray());
        var foreignResponse = FileServiceListDirectoryResponse.Parser.ParseFrom(foreign.Answer!.Response);
        Assert.Equal("invalid_cursor", foreignResponse.Error.Code);
        Assert.True(NodeShapes.IsValid(foreignResponse));
        Assert.Null(foreignResponse.Audit);
        var secondCall = await calls.CallAsync(caller, RoutedMethod.ListNodeDirectory, request.ToByteArray());
        var second = FileServiceListDirectoryResponse.Parser.ParseFrom(secondCall.Answer!.Response);
        Assert.Null(second.Error);
        Assert.Equal("b.txt", Assert.Single(second.Value.Entries).Name);
        Assert.False(second.Value.HasNextCursor);

        File.WriteAllText(Path.Combine(root, "added"), "new");
        var changed = await calls.CallAsync(caller, RoutedMethod.ListNodeDirectory, request.ToByteArray());
        Assert.Equal("invalid_cursor", FileServiceListDirectoryResponse.Parser.ParseFrom(changed.Answer!.Response).Error.Code);

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

    [Fact(Timeout = 120_000)]
    public async Task DirectoryRefusalsUsePublishedShapesRealCorrelationAndCurrentPermissions()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "directory-errors")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        File.WriteAllText(Path.Combine(root, "regular"), "content");
        var caller = calls.Relay(Origin.Human);
        var correlation = CommandIds.New();
        async Task<FileServiceListDirectoryResponse> Invoke(FileServiceListDirectoryRequest request)
        {
            var call = await calls.CallAsync(caller, RoutedMethod.ListNodeDirectory, request.ToByteArray());
            Assert.Equal(RoutedOutcome.Executed, call.Answer!.Outcome);
            var response = FileServiceListDirectoryResponse.Parser.ParseFrom(call.Answer.Response);
            Assert.NotNull(response.Error);
            Assert.True(NodeShapes.IsValid(response));
            Assert.True(NodeShapes.IsValid(response.Error));
            Assert.Equal(response.Meta.CorrelationId, response.Error.CorrelationId);
            return response;
        }

        var meta = new RequestMeta { CorrelationId = correlation };
        var missing = await Invoke(List(workspace.Id, "missing", meta, 1));
        Assert.Equal("path_not_found", missing.Error.Code);
        Assert.Equal(correlation, missing.Meta.CorrelationId);
        Assert.Equal("path_not_found", (await Invoke(List(workspace.Id, "regular", meta, 1))).Error.Code);
        var unknown = await Invoke(List(CommandIds.New().Value.ToByteArray(), "", meta, 1));
        Assert.Equal("invalid_argument", unknown.Error.Code);
        Assert.Equal("workspace_id.registered: required", unknown.Error.Details.State.Reason);
        var excessive = await Invoke(List(workspace.Id, new string('p', 4097), meta, 1));
        Assert.Equal("too_large", excessive.Error.Code);
        Assert.Equal("path_bytes", excessive.Error.Details.Limit.LimitName);
        Assert.Equal("4096", excessive.Error.Details.Limit.Maximum.Value);
        var malformed = await Invoke(List(workspace.Id, "", new RequestMeta(), 1));
        Assert.Equal("invalid_argument", malformed.Error.Code);
        Assert.Equal(calls.LastCallId, malformed.Meta.CorrelationId);
        var badCursor = List(workspace.Id, "", meta, 1);
        badCursor.Cursor = "not-a-cursor";
        Assert.Equal("invalid_cursor", (await Invoke(badCursor)).Error.Code);
        var badPage = List(workspace.Id, "", meta, 129);
        Assert.Equal("invalid_argument", (await Invoke(badPage)).Error.Code);

        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.FileRead,
            Origin = Origin.Agent,
            Decision = PermissionDecision.Deny,
        }))).Error);
        var agent = calls.Relay(Origin.Agent);
        var denied = await calls.CallAsync(agent, RoutedMethod.ListNodeDirectory, List(workspace.Id, "", meta, 1).ToByteArray());
        Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
        Assert.Equal("permission_denied", denied.Answer.Error!.Code);
        Assert.Equal(correlation, denied.Answer.Error.CorrelationId);
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a JOIN audit_log l ON l.seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = '' AND l.decision = 3;
            """, ("$workspace", workspace.Id)))! >= 1);
    }

    private static FileServiceListDirectoryRequest List(byte[] workspace, string path, RequestMeta? meta, uint page) => new()
    {
        Meta = meta,
        Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = path },
        PageSize = page,
    };

    private static (byte[] Digest, ulong Size) DirectoryDigest(IEnumerable<FileDirectoryEntry> entries)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges directory-list v1\0"u8);
        ulong bytes = (ulong)"ArcForges directory-list v1\0"u8.Length;
        Span<byte> word = stackalloc byte[8];
        foreach (var entry in entries)
        {
            var name = Encoding.UTF8.GetBytes(entry.Name);
            BinaryPrimitives.WriteUInt32BigEndian(word, (uint)name.Length);
            hash.AppendData(word[..4]);
            hash.AppendData(name);
            BinaryPrimitives.WriteUInt32BigEndian(word, (uint)entry.Kind);
            hash.AppendData(word[..4]);
            word[0] = entry.HasSizeBytes ? (byte)1 : (byte)0;
            hash.AppendData(word[..1]);
            bytes += (ulong)(9 + name.Length);
            if (entry.HasSizeBytes)
            {
                BinaryPrimitives.WriteUInt64BigEndian(word, entry.SizeBytes);
                hash.AppendData(word);
                bytes += 8;
            }
        }

        return (hash.GetHashAndReset(), bytes);
    }
}
