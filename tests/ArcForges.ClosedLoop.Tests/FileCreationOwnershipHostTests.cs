// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "local")]
public sealed class FileCreationOwnershipHostTests
{
    // Native create, marker advancement and later quarantine remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 180_000)]
    public async Task RetainedCreationReceiptPreservesExactOwnerAndOwnershipEvidence()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var workspace = history.Workspace(ct);
        var owner = history.Caller(Origin.Agent);
        var request = new FileServiceWriteFileRequest
        {
            Meta = LegacyFileHostHistory.Command(), Path = LegacyFileHostHistory.FilePath(workspace, "owned"),
            ExpectedAbsent = true, Data = ByteString.CopyFromUtf8("history private body"),
        };
        var raw = request.ToByteArray();
        var digest = SHA256.HashData(raw);
        var body = request.Data.ToByteArray();
        var bodyHash = SHA256.HashData(body);
        var marker = SHA256.HashData("recorded creation marker fixture"u8);
        var id = request.Meta.CommandId.Value.ToByteArray();
        var file = Path.Combine(workspace.RootPath, request.Path.Path);
        var later = "replacement fixture content"u8.ToArray();
        File.WriteAllBytes(file, later);
        var identity = LegacyFileHostHistory.FileIdentity(file);
        var receipt = history.Store.Write(tx =>
        {
            LegacyFileHostHistory.PrepareMutation(tx, workspace, owner, FileOperationKind.Write, request.Meta, "owned", raw, null, body);
            return FileMutationJournal.CompleteVerifiedEffect(tx, id, raw, body.Length, bodyHash, null,
                createdOwnership: new WorkspaceCreatedOwnership(identity, marker));
        }, CommitDurability.Full);

        async Task AssertRetainedAsync()
        {
            var owned = await history.RouteAsync(RoutedMethod.WriteNodeFile, owner, request, request.Meta.CommandId, ct);
            Assert.Equal(receipt, owned?.Response?.ToByteArray());
            var outsider = owner.Clone();
            outsider.LocalSessionId = CommandIds.New();
            var denied = await history.RouteAsync(RoutedMethod.WriteNodeFile, outsider, request, request.Meta.CommandId, ct);
            Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(denied!.Response).Error.Code);
            history.Store.Read(reader =>
            {
                using var query = reader.CreateCommand("""
                    SELECT caller, creation_command_id, creation_request_sha256, object_identity, creation_marker, last_written_size, last_written_sha256
                    FROM file_creation_ownership WHERE workspace_id = $workspace AND relative_path = 'owned';
                    """);
                query.Parameters.AddWithValue("$workspace", workspace.Id);
                using var row = query.ExecuteReader();
                Assert.True(row.Read());
                Assert.Equal(owner, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(0)));
                Assert.Equal(id, (byte[])row.GetValue(1));
                Assert.Equal(digest, (byte[])row.GetValue(2));
                Assert.Equal(identity.Bytes, (byte[])row.GetValue(3));
                Assert.Equal(marker, (byte[])row.GetValue(4));
                Assert.Equal(body.Length, row.GetInt64(5));
                Assert.Equal(bodyHash, (byte[])row.GetValue(6));
                Assert.False(row.Read());
                return 0;
            });
            Assert.Equal(later, File.ReadAllBytes(file));
        }

        await AssertRetainedAsync();
        await history.ReopenAsync();
        await AssertRetainedAsync();
    }
}
