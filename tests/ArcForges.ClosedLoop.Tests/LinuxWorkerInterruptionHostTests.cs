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
public sealed class LinuxWorkerInterruptionHostTests
{
    // Native interruption and deadline evidence remains executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 120_000)]
    public async Task AnUnprovenRetainedWorkerKeepsTheRecoveredWriteHeld()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The retained fence belongs to the Linux worker.");
        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var workspace = history.Workspace(ct);
        var owner = history.Caller(Origin.Human);
        var file = Path.Combine(workspace.RootPath, "target");
        var partial = "independent partial effect fixture"u8.ToArray();
        var original = "historical preimage"u8.ToArray();
        var intended = "historical intended data"u8.ToArray();
        File.WriteAllBytes(file, partial);
        var request = new FileServiceWriteFileRequest
        {
            Meta = LegacyFileHostHistory.Command(),
            Path = LegacyFileHostHistory.FilePath(workspace, "target"),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            Data = ByteString.CopyFrom(intended),
        };
        var raw = request.ToByteArray();
        var digest = SHA256.HashData(raw);
        var id = request.Meta.CommandId.Value.ToByteArray();
        history.Store.Write(tx =>
        {
            LegacyFileHostHistory.PrepareMutation(tx, workspace, owner, FileOperationKind.Write, request.Meta, "target", raw, original, intended);
            // The historical worker row has no usable boot identity. It cannot name any live process or qualify as ended.
            tx.Execute("""
                INSERT INTO file_effect_worker (command_id, boot_id, pid_namespace, process_id, start_ticks, ended)
                VALUES ($id, $boot, 'pid:[0]', $pid, 1, 0);
                """, ("$id", id), ("$boot", Guid.Empty.ToString("D")), ("$pid", int.MaxValue));
        }, CommitDurability.Full);

        await history.ReopenAsync();
        Assert.Equal(1, history.Store.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
        var retained = Assert.IsType<byte[]>(history.Store.Read(reader => reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id))));
        var reply = await history.RouteAsync(RoutedMethod.WriteNodeFile, owner, request, request.Meta.CommandId, ct);
        Assert.NotNull(reply);
        Assert.Equal(RoutedOutcome.Executed, reply.Outcome);
        Assert.Equal(retained, reply.Response?.ToByteArray());
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(reply.Response);
        Assert.Equal(("file_outcome_unknown", EffectCertainty.Unknown, RetryMode.Never),
            (response.Error.Details.State.Reason, response.Error.Effect, response.Error.Retry.Mode));

        var human = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
        FileJournalAcknowledgment Acknowledge(byte[] hash) => history.Store.Write(tx =>
            FileMutationJournal.AcknowledgeFromVerifiedHuman(tx, id, hash, human), CommitDurability.Full);
        Assert.Equal(FileJournalAcknowledgment.DigestMismatch, Acknowledge(new byte[32]));
        Assert.Equal(FileJournalAcknowledgment.WorkerNotEnded, Acknowledge(digest));
        Assert.True(history.Store.Read(reader => FileMutationJournal.HasWorkspaceHold(reader, workspace.Id)));
        Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT ended FROM file_effect_worker WHERE command_id = $id;", ("$id", id))));

        // Represent a separately proved terminal observation in the fixture; the actual acknowledgment still releases custody.
        Assert.Equal(1, history.Store.Write(tx => tx.Execute("UPDATE file_effect_worker SET ended = 1 WHERE command_id = $id;", ("$id", id)),
            CommitDurability.Full));
        Assert.Equal(FileJournalAcknowledgment.Acknowledged, Acknowledge(digest));
        var settled = history.Store.Read(reader => FileMutationJournal.GetForCaller(reader, id, owner));
        Assert.NotNull(settled);
        Assert.Equal(FileOperationState.Unknown, settled.State);
        Assert.True(settled.Acknowledged);
        Assert.False(settled.Held);
        Assert.Equal(retained, history.Store.Read(reader => reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id))) as byte[]);
        Assert.Equal(partial, File.ReadAllBytes(file));
    }
}
