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

/// <summary>Real Node, SQLite and native filesystem through the routed dispatcher; not real-center acceptance.</summary>
public sealed class FileSearchRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task SearchSignsObservedTranscriptWithoutPersistingThePatternOrFileBody()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "search-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        const string pattern = "PRIVATE_SEARCH_PATTERN_41be0";
        var bytes = Encoding.UTF8.GetBytes("α😀" + pattern + "_FILE_BODY_MARKER_3cf5");
        File.WriteAllBytes(Path.Combine(root, "scan.txt"), bytes);
        var correlation = CommandIds.New();
        var request = Search(workspace.Id, "scan.txt", pattern, FileSearchMode.Literal, new RequestMeta { CorrelationId = correlation });
        Assert.True(NodeShapes.IsValid(request));
        var call = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.SearchNodeFiles, request.ToByteArray());
        Assert.Equal(RoutedOutcome.Executed, call.Answer!.Outcome);
        var response = FileServiceSearchFilesResponse.Parser.ParseFrom(call.Answer.Response);
        Assert.Null(response.Error);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal(correlation, response.Meta.CorrelationId);
        var match = Assert.Single(response.Value.Matches);
        Assert.Equal("scan.txt", match.Path);
        Assert.Equal(6UL, match.ByteOffset);
        Assert.Equal((uint)Encoding.UTF8.GetByteCount(pattern), match.ByteLength);
        Assert.Equal((ulong)bytes.Length, response.Value.ScannedBytes);
        Assert.Equal(1U, response.Value.ScanFileCount);
        var (digest, transcriptBytes) = ScanDigest("scan.txt", bytes);
        Assert.Equal(digest, response.Value.ScanDigest.ToByteArray());
        Assert.Equal(transcriptBytes, response.Value.ScanTranscriptBytes);
        var observation = Assert.Single(response.Audit.Observations);
        Assert.Equal(FileAuditKind.SearchTranscript, observation.Kind);
        Assert.Equal((ulong)bytes.Length, observation.SizeBytes);
        Assert.Equal(transcriptBytes, observation.DigestInputBytes);
        Assert.Equal(1U, observation.ItemCount);
        Assert.Equal(digest, observation.Sha256.ToByteArray());
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            JOIN audit_log l ON l.seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'scan.txt' AND l.decision = 1
              AND o.kind = 4 AND o.size_bytes = $size AND o.digest_input_bytes = $transcript AND o.sha256 = $digest;
            """, ("$workspace", workspace.Id), ("$size", bytes.Length), ("$transcript", (long)transcriptBytes), ("$digest", digest)))! >= 1);

        var target = new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) };
        var wrapped = new FleetServiceSearchNodeFilesResponse
        {
            Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
            Value = new FleetServiceSearchNodeFilesValue { NodeId = target.Clone(), Response = response.ToByteString() },
        };
        Assert.True(RoutedFileResponseValidation.Search(wrapped, target, request));
        var withoutMeta = response.Clone();
        withoutMeta.Meta = null;
        Assert.True(NodeShapes.IsValid(withoutMeta));
        wrapped.Value.Response = withoutMeta.ToByteString();
        Assert.True(RoutedFileResponseValidation.Search(wrapped, target, request));
        withoutMeta.Meta = new ResponseMeta();
        Assert.False(NodeShapes.IsValid(withoutMeta));
        wrapped.Value.Response = withoutMeta.ToByteString();
        Assert.False(RoutedFileResponseValidation.Search(wrapped, target, request));
        wrapped.Value.Response = response.ToByteString();
        wrapped.Value.NodeId = CommandIds.New();
        Assert.False(RoutedFileResponseValidation.Search(wrapped, target, request));
        wrapped.Value.NodeId = target.Clone();
        var tampered = response.Clone();
        tampered.Audit.Observations[0].Sha256 = ByteString.CopyFrom(new byte[32]);
        wrapped.Value.Response = tampered.ToByteString();
        Assert.False(RoutedFileResponseValidation.Search(wrapped, target, request));
        tampered = response.Clone();
        tampered.Value.Matches[0].Path = "outside.txt";
        wrapped.Value.Response = tampered.ToByteString();
        Assert.False(RoutedFileResponseValidation.Search(wrapped, target, request));

        var regex = Search(workspace.Id, "scan.txt", ".", FileSearchMode.Regex, new RequestMeta { CorrelationId = correlation });
        var refused = await calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.SearchNodeFiles, regex.ToByteArray());
        var refusal = FileServiceSearchFilesResponse.Parser.ParseFrom(refused.Answer!.Response);
        Assert.True(NodeShapes.IsValid(refusal));
        Assert.Equal("invalid_argument", refusal.Error.Code);
        Assert.Equal("pattern: regex_scalar_boundary", refusal.Error.Details.State.Reason);
        Assert.Equal(correlation, refusal.Error.CorrelationId);
        Assert.Equal(digest, Assert.Single(refusal.Audit.Observations).Sha256.ToByteArray());
        wrapped.Value.Response = refusal.ToByteString();
        Assert.True(RoutedFileResponseValidation.Search(wrapped, target, regex));
        refusal.Audit = null;
        wrapped.Value.Response = refusal.ToByteString();
        Assert.False(RoutedFileResponseValidation.Search(wrapped, target, regex));
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            JOIN audit_log l ON l.seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'scan.txt' AND l.decision = 3
              AND o.kind = 4 AND o.size_bytes = $size AND o.sha256 = $digest;
            """, ("$workspace", workspace.Id), ("$size", bytes.Length), ("$digest", digest)))! >= 1);

        foreach (var candidate in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(candidate))
            {
                continue;
            }

            using var stream = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(Encoding.UTF8.GetBytes(pattern)));
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(bytes));
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task SearchRefusalsAndPartialScansKeepActualBoundsAndPermissions()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "search-errors")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        File.WriteAllBytes(Path.Combine(root, "cut.txt"), "A€B"u8.ToArray());
        var correlation = CommandIds.New();
        var meta = new RequestMeta { CorrelationId = correlation };
        var human = calls.Relay(Origin.Human);
        async Task<FileServiceSearchFilesResponse> Invoke(FileServiceSearchFilesRequest request)
        {
            var call = await calls.CallAsync(human, RoutedMethod.SearchNodeFiles, request.ToByteArray());
            Assert.Equal(RoutedOutcome.Executed, call.Answer!.Outcome);
            var response = FileServiceSearchFilesResponse.Parser.ParseFrom(call.Answer.Response);
            Assert.True(NodeShapes.IsValid(response));
            return response;
        }

        var partial = Search(workspace.Id, "cut.txt", "A", FileSearchMode.Literal, meta);
        partial.MaxScanBytes = 3;
        var result = await Invoke(partial);
        Assert.Null(result.Error);
        Assert.Equal(3UL, result.Value.ScannedBytes);
        Assert.True(result.Value.Truncated);
        Assert.Equal("scan_bytes", result.Value.TruncationReason);
        var (partialHash, _) = ScanDigest("cut.txt", "A€"u8[..3]);
        Assert.Equal(partialHash, result.Value.ScanDigest.ToByteArray());
        Assert.Equal("path_not_found", (await Invoke(Search(workspace.Id, "missing", "x", FileSearchMode.Literal, meta))).Error.Code);
        var unknown = await Invoke(Search(CommandIds.New().Value.ToByteArray(), "cut.txt", "x", FileSearchMode.Literal, meta));
        Assert.Equal("invalid_argument", unknown.Error.Code);
        Assert.Equal("workspace_id.registered: required", unknown.Error.Details.State.Reason);
        var tooLong = await Invoke(Search(workspace.Id, new string('p', 4097), "x", FileSearchMode.Literal, meta));
        Assert.Equal("too_large", tooLong.Error.Code);
        Assert.Equal("path_bytes", tooLong.Error.Details.Limit.LimitName);
        Assert.Equal("4096", tooLong.Error.Details.Limit.Maximum.Value);
        var unsupported = await Invoke(Search(workspace.Id, "cut.txt", "(?=A)", FileSearchMode.Regex, meta));
        Assert.Equal("invalid_argument", unsupported.Error.Code);
        Assert.Null(unsupported.Audit);
        var emptyMeta = await Invoke(Search(workspace.Id, "cut.txt", "A", FileSearchMode.Literal, new RequestMeta()));
        Assert.Equal("invalid_argument", emptyMeta.Error.Code);
        Assert.Equal(calls.LastCallId, emptyMeta.Error.CorrelationId);
        Assert.Equal(calls.LastCallId, emptyMeta.Meta.CorrelationId);

        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await Sched.ChangePolicyAsync(channel, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.FileRead,
            Origin = Origin.Agent,
            Decision = PermissionDecision.Deny,
        }))).Error);
        var denied = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.SearchNodeFiles, partial.ToByteArray());
        Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
        Assert.Equal("permission_denied", denied.Answer.Error!.Code);
        Assert.Equal(correlation, denied.Answer.Error.CorrelationId);
    }

    private static FileServiceSearchFilesRequest Search(byte[] workspace, string path, string pattern, FileSearchMode mode, RequestMeta? meta) => new()
    {
        Meta = meta,
        Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = path },
        Pattern = pattern,
        Mode = mode,
    };

    private static (byte[] Digest, ulong Size) ScanDigest(string path, ReadOnlySpan<byte> data)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges search-scan v1\0"u8);
        var name = Encoding.UTF8.GetBytes(path);
        Span<byte> word = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(word, (uint)name.Length);
        hash.AppendData(word[..4]);
        hash.AppendData(name);
        BinaryPrimitives.WriteUInt64BigEndian(word, (ulong)data.Length);
        hash.AppendData(word);
        hash.AppendData(data);
        return (hash.GetHashAndReset(), (ulong)(25 + 12 + name.Length + data.Length));
    }
}
