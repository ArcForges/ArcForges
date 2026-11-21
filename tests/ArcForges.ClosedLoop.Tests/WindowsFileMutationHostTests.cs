// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
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

/// <summary>Retained journal and replay over a real Windows object using an offline routed fixture.</summary>
[Trait("loop", "local")]
[Trait("env", "windows-real")]
public sealed class WindowsFileMutationHostTests
{
    // The native producer and signed installed-host case remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 180_000)]
    public async Task RetainedWriteAndEditReplaysPreserveTheWindowsObjectAcrossReopen()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("The retained fixture checks Windows file identity and attributes.");
            return;
        }

        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var workspace = RetainedHostWorkspace.Seed(history, "windows-file", ct);
        var owner = history.Caller(Origin.Human);
        const string targetName = "target.txt";
        var target = Path.Combine(workspace.RootPath, targetName);
        var stream = target + ":arcforges-test";
        var original = "WIN_HOST_ORIGINAL_80ae hello"u8.ToArray();
        var written = "WIN_HOST_WRITTEN_21f3 hello"u8.ToArray();
        var edited = "WIN_HOST_WRITTEN_21f3 world"u8.ToArray();
        var alternate = "WIN_HOST_ALTERNATE_STREAM_786c"u8.ToArray();
        var later = "later independent content"u8.ToArray();
        File.WriteAllBytes(target, later);
        File.WriteAllBytes(stream, alternate);
        File.SetAttributes(target, FileAttributes.Archive);
        var attributes = File.GetAttributes(target);
        var identity = LegacyFileHostHistory.FileIdentity(target);
        var sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
        var security = new FileInfo(target).GetAccessControl(sections).GetSecurityDescriptorBinaryForm();

        var stale = new FileServiceWriteFileRequest
        {
            Meta = LegacyFileHostHistory.Command(),
            Path = LegacyFileHostHistory.FilePath(workspace, targetName),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            Data = ByteString.CopyFrom(written),
        };
        var write = stale.Clone();
        write.Meta = LegacyFileHostHistory.Command();
        var edit = new FileServiceEditFileRequest
        {
            Meta = LegacyFileHostHistory.Command(),
            Path = write.Path.Clone(),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(written)),
            OldText = "hello",
            NewText = "world",
            ExpectedOccurrences = 1,
        };
        var rawWrite = write.ToByteArray();
        var rawEdit = edit.ToByteArray();
        var (staleReceipt, writeReceipt, editReceipt) = history.Store.Write(tx =>
        {
            var rawStale = stale.ToByteArray();
            var failed = LegacyFileHostHistory.PrepareMutation(tx, workspace, owner, FileOperationKind.Write,
                stale.Meta, targetName, rawStale, original, written);
            var refused = FileMutationJournal.CompleteKnownTargetChanged(tx, failed.Kind, failed.CommandId, owner, rawStale, "hash_mismatch");
            var first = LegacyFileHostHistory.PrepareMutation(tx, workspace, owner, FileOperationKind.Write,
                write.Meta, targetName, rawWrite, original, written);
            var wrote = FileMutationJournal.CompleteVerifiedEffect(tx, first.CommandId, rawWrite, written.Length, SHA256.HashData(written), null);
            var second = LegacyFileHostHistory.PrepareMutation(tx, workspace, owner, FileOperationKind.Edit,
                edit.Meta, targetName, rawEdit, written, edited);
            var changed = FileMutationJournal.CompleteVerifiedEffect(tx, second.CommandId, rawEdit, edited.Length, SHA256.HashData(edited), 1);
            return (refused, wrote, changed);
        }, CommitDurability.Full);

        async Task AssertRetainedAsync()
        {
            var staleAnswer = await history.RouteAsync(RoutedMethod.WriteNodeFile, owner, stale, stale.Meta.CommandId, ct);
            Assert.Equal(staleReceipt, staleAnswer?.Response?.ToByteArray());
            var conflict = FileServiceWriteFileResponse.Parser.ParseFrom(staleAnswer!.Response).Error;
            Assert.Equal(("file_changed", "hash_mismatch", EffectCertainty.DidNotHappen),
                (conflict.Code, conflict.Details.State.Reason, conflict.Effect));
            var writeAnswer = await history.RouteAsync(RoutedMethod.WriteNodeFile, owner, write, write.Meta.CommandId, ct);
            Assert.Equal(RoutedOutcome.Executed, writeAnswer?.Outcome);
            Assert.Equal(writeReceipt, writeAnswer?.Response?.ToByteArray());
            var savedWrite = FileServiceWriteFileResponse.Parser.ParseFrom(writeAnswer!.Response);
            Assert.Equal(write.Meta.CorrelationId, savedWrite.Meta.CorrelationId);
            Assert.Equal(SHA256.HashData(written), savedWrite.Value.Result.Sha256.ToByteArray());
            var editAnswer = await history.RouteAsync(RoutedMethod.EditNodeFile, owner, edit, edit.Meta.CommandId, ct);
            Assert.Equal(RoutedOutcome.Executed, editAnswer?.Outcome);
            Assert.Equal(editReceipt, editAnswer?.Response?.ToByteArray());
            var savedEdit = FileServiceEditFileResponse.Parser.ParseFrom(editAnswer!.Response);
            Assert.Equal(edit.Meta.CorrelationId, savedEdit.Meta.CorrelationId);
            Assert.Equal(1U, savedEdit.Value.Result.Replacements);
            Assert.Equal(SHA256.HashData(edited), savedEdit.Value.Result.Sha256.ToByteArray());

            var read = await RetainedHostWorkspace.ReadAsync(history, workspace, owner, targetName, ct);
            Assert.Null(read.Error);
            Assert.Equal(later, read.Value.Data.ToByteArray());
            Assert.Equal(identity.Bytes, LegacyFileHostHistory.FileIdentity(target).Bytes);
            Assert.Equal(attributes, File.GetAttributes(target));
            Assert.Equal(security, new FileInfo(target).GetAccessControl(sections).GetSecurityDescriptorBinaryForm());
            Assert.Equal(alternate, File.ReadAllBytes(stream));
        }

        await AssertRetainedAsync();
        var fresh = write.Clone();
        fresh.Meta = LegacyFileHostHistory.Command();
        var agent = owner.Clone();
        agent.LocalOrigin = Origin.Agent;
        agent.LocalSessionId = CommandIds.New();
        var denied = await history.RouteAsync(RoutedMethod.WriteNodeFile, agent, fresh, fresh.Meta.CommandId, ct);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, denied?.Outcome);
        Assert.Equal("permission_denied", denied?.Error?.Code);
        Assert.Null(denied?.Response);
        var unknown = await history.RouteAsync(RoutedMethod.WriteNodeFile, owner, fresh, fresh.Meta.CommandId, ct);
        var current = FileServiceWriteFileResponse.Parser.ParseFrom(unknown!.Response);
        Assert.Null(current.Value);
        Assert.Equal(("operation_failed", "file_outcome_unknown", EffectCertainty.Unknown, RetryMode.Never),
            (current.Error.Code, current.Error.Details.State.Reason, current.Error.Effect, current.Error.Retry.Mode));

        await history.ReopenAsync();
        await AssertRetainedAsync();
        var changedRaw = write.Clone();
        changedRaw.Meta.CorrelationId = CommandIds.New();
        var changedAnswer = await history.RouteAsync(RoutedMethod.WriteNodeFile, owner, changedRaw, write.Meta.CommandId, ct);
        Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(changedAnswer!.Response).Error.Code);
        var changedOwner = owner.Clone();
        changedOwner.LocalSessionId = CommandIds.New();
        var wrongOwner = await history.RouteAsync(RoutedMethod.EditNodeFile, changedOwner, edit, edit.Meta.CommandId, ct);
        Assert.Equal("command_id_reused", FileServiceEditFileResponse.Parser.ParseFrom(wrongOwner!.Response).Error.Code);
        AssertJournal(history.Store, write.Meta.CommandId, rawWrite, written, identity.Bytes);
        AssertJournal(history.Store, edit.Meta.CommandId, rawEdit, edited, identity.Bytes);
        Assert.Equal(3L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_effect_worker;")));
        Assert.Equal(later, File.ReadAllBytes(target));
        RetainedHostWorkspace.AssertPrivateBytesAbsent(history, written, edited, alternate);
    }

    private static void AssertJournal(NodeStore store, Id command, byte[] raw, byte[] expected, byte[] identity) => store.Read(reader =>
    {
        using var query = reader.CreateCommand("""
            SELECT phase, held, request_sha256, target_identity, intended_size, intended_sha256
            FROM file_operation_journal WHERE command_id = $id;
            """);
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(2, row.GetInt32(0));
        Assert.Equal(0, row.GetInt32(1));
        Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(2));
        Assert.Equal(identity, (byte[])row.GetValue(3));
        Assert.Equal(expected.LongLength, row.GetInt64(4));
        Assert.Equal(SHA256.HashData(expected), (byte[])row.GetValue(5));
        Assert.False(row.Read());
        return 0;
    });
}

internal static class RetainedHostWorkspace
{
    internal static RegisteredWorkspace Seed(LegacyFileHostHistory history, string name, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var root = WorkspacePath.OpenRoot(Directory.CreateDirectory(Path.Combine(history.Root, name)).FullName);
        var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        return history.Store.Write(tx =>
        {
            var id = StoreIds.NewUuid7(tx.Clock);
            var now = tx.NowMicroseconds;
            tx.Execute("""
                INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                VALUES ($id, 1, 2, $name, $path, $now, $now, 0);
                """, ("$id", id), ("$name", name), ("$path", root.RootPath), ("$now", now));
            tx.Execute("""
                INSERT INTO workspace_root_identity
                    (workspace_id, format_version, platform, native_identity, canonical_path, registered_at)
                VALUES ($id, 1, $platform, $native, $path, $now);
                """, ("$id", id), ("$platform", identity.Platform), ("$native", identity.Bytes), ("$path", root.RootPath), ("$now", now));
            return new RegisteredWorkspace(id, name, root.RootPath, now, now);
        }, CommitDurability.Full);
    }

    internal static async Task<FileServiceReadFileResponse> ReadAsync(LegacyFileHostHistory history, RegisteredWorkspace workspace,
        CenterCaller caller, string path, CancellationToken token)
    {
        var request = new FileServiceReadFileRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            Path = LegacyFileHostHistory.FilePath(workspace, path),
            Offset = 0,
            Length = 256,
        };
        var result = await history.RouteAsync(RoutedMethod.ReadNodeFile, caller, request, null, token);
        Assert.Equal(RoutedOutcome.Executed, result?.Outcome);
        var response = FileServiceReadFileResponse.Parser.ParseFrom(result!.Response);
        Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
        return response;
    }

    internal static void AssertPrivateBytesAbsent(LegacyFileHostHistory history, params byte[][] privateBytes)
    {
        var db = history.Store.DatabasePath;
        var log = Path.Combine(history.Root, "data", "logs", "node");
        foreach (var file in new[] { db, db + "-wal" }.Concat(Directory.EnumerateFiles(log)))
        {
            if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes) continue;
            foreach (var value in privateBytes)
                Assert.Equal(-1, bytes.AsSpan().IndexOf(value));
        }
    }
}
