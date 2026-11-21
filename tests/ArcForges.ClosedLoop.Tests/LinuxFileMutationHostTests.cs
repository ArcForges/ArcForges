// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "local")]
[Trait("env", "linux-real")]
public sealed class LinuxFileMutationHostTests
{
    // Native worker, file identity and metadata round trips remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 180_000)]
    public async Task RetainedLinuxWriteAndEditReplaysLeaveTheLaterFileUntouched()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The retained journal uses Linux identity encoding.");
        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var workspace = history.Workspace(ct);
        var owner = history.Caller(Origin.Human);
        var file = Path.Combine(workspace.RootPath, "target");
        var before = "historical preimage"u8.ToArray();
        var written = "historical write private payload"u8.ToArray();
        var edited = "historical edit private payload"u8.ToArray();
        var later = "independent fixture file"u8.ToArray();
        File.WriteAllBytes(file, later);
        var identity = LegacyFileHostHistory.FileIdentity(file);
        var write = new FileServiceWriteFileRequest
        {
            Meta = LegacyFileHostHistory.Command(), Path = LegacyFileHostHistory.FilePath(workspace, "target"),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(before)), Data = ByteString.CopyFrom(written),
        };
        var edit = new FileServiceEditFileRequest
        {
            Meta = LegacyFileHostHistory.Command(), Path = write.Path.Clone(), ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(written)),
            OldText = "write", NewText = "edit", ExpectedOccurrences = 1,
        };
        var rawWrite = write.ToByteArray();
        var rawEdit = edit.ToByteArray();
        var (writeReceipt, editReceipt) = history.Store.Write(tx =>
        {
            var first = LegacyFileHostHistory.PrepareMutation(tx, workspace, owner,
                FileOperationKind.Write, write.Meta, "target", rawWrite, before, written);
            var writeBytes = FileMutationJournal.CompleteVerifiedEffect(tx, first.CommandId, rawWrite, written.Length, SHA256.HashData(written), null);
            var second = LegacyFileHostHistory.PrepareMutation(tx, workspace, owner,
                FileOperationKind.Edit, edit.Meta, "target", rawEdit, written, edited);
            return (writeBytes, FileMutationJournal.CompleteVerifiedEffect(tx, second.CommandId, rawEdit, edited.Length, SHA256.HashData(edited), 1));
        }, CommitDurability.Full);

        async Task AssertReplayAsync()
        {
            var writeResult = await history.RouteAsync(RoutedMethod.WriteNodeFile, owner, write, write.Meta.CommandId, ct);
            Assert.NotNull(writeResult);
            Assert.Equal(RoutedOutcome.Executed, writeResult.Outcome);
            Assert.Equal(writeReceipt, writeResult.Response?.ToByteArray());
            var editResult = await history.RouteAsync(RoutedMethod.EditNodeFile, owner, edit, edit.Meta.CommandId, ct);
            Assert.NotNull(editResult);
            Assert.Equal(RoutedOutcome.Executed, editResult.Outcome);
            Assert.Equal(editReceipt, editResult.Response?.ToByteArray());
            Assert.Equal(1U, FileServiceEditFileResponse.Parser.ParseFrom(editResult.Response).Value.Result.Replacements);
            Assert.Equal(later, File.ReadAllBytes(file));
            Assert.Equal(identity.Bytes, LegacyFileHostHistory.FileIdentity(file).Bytes);
            Assert.Equal(2L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal WHERE phase = 2 AND held = 0;")));
            Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_effect_worker;")));
        }

        await AssertReplayAsync();
        await history.ReopenAsync();
        await AssertReplayAsync();
        var other = owner.Clone();
        other.LocalSessionId = LegacyFileHostHistory.Command().CommandId;
        var denied = await history.RouteAsync(RoutedMethod.EditNodeFile, other, edit, edit.Meta.CommandId, ct);
        Assert.Equal("command_id_reused", FileServiceEditFileResponse.Parser.ParseFrom(denied!.Response).Error.Code);
    }
}
