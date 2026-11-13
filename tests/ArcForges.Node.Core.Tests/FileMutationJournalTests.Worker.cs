// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

public sealed partial class FileMutationJournalTests
{
    [Theory]
    [InlineData("hash_mismatch")]
    [InlineData("file_identity_changed")]
    [InlineData("directory_identity_changed")]
    [InlineData("root_changed")]
    [InlineData("guard_unavailable")]
    public void PreparedWorkerRefusalIsBoundAndReplayedWithoutAnEffect(string reason)
    {
        using var fixture = new Fixture();
        using var store = fixture.Open();
        var workspace = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(fixture.Workspace,
            cancellationToken: TestContext.Current.CancellationToken);
        var marker = Encoding.UTF8.GetBytes("worker-refusal-private-bc25");
        var (intent, raw) = fixture.WriteIntent(workspace.Id, marker);
        var original = File.ReadAllBytes(fixture.Target);
        Assert.Equal(FileJournalPreparation.Prepared,
            store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
        var foreign = intent.Caller.Clone();
        foreign.AccountId = CommandIds.New();
        Assert.Throws<InvalidOperationException>(() => store.Write(t => FileMutationJournal.CompleteKnownTargetChanged(t,
            intent.Kind, intent.CommandId, foreign, raw, "hash_mismatch"), CommitDurability.Full));
        var changed = raw.Concat(new byte[] { 0x80, 0x06, 0x01 }).ToArray();
        Assert.Throws<InvalidOperationException>(() => store.Write(t => FileMutationJournal.CompleteKnownTargetChanged(t,
            intent.Kind, intent.CommandId, intent.Caller, changed, "hash_mismatch"), CommitDurability.Full));
        var result = store.Write(t => reason == "guard_unavailable"
            ? FileMutationJournal.CompleteKnownGuardUnavailable(t, intent.Kind, intent.CommandId, intent.Caller, raw)
            : FileMutationJournal.CompleteKnownTargetChanged(t, intent.Kind, intent.CommandId, intent.Caller, raw, reason),
            CommitDurability.Full);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(result);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal(reason == "guard_unavailable" ? "enforcement_unavailable" : "file_changed", response.Error.Code);
        Assert.Equal(reason == "guard_unavailable" ? "file_guard_unavailable" : reason, response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(result, store.Read(r => FileMutationJournal.Replay(r, intent.Kind, intent.CommandId, intent.Caller, raw)));
        var operation = store.Read(r => FileMutationJournal.GetForCaller(r, intent.CommandId, intent.Caller));
        Assert.Equal(FileOperationState.Completed, operation!.State);
        Assert.False(operation.Held);
        Assert.Equal(response.Error, operation.Error);
        Assert.Equal(original, File.ReadAllBytes(fixture.Target));
        AssertNoContent(store.DatabasePath, marker);
    }

    [Fact(Timeout = 120_000)]
    [Trait("feature", "file-guard-helper")]
    [Trait("env", "linux-real")]
    public async Task LiveRecordedChildPreventsHumanAcknowledgmentAcrossRuntimeRestart()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux procfs owned-child lifetime fence.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new Fixture();
        await using var node = await InProcessNode.Create().StartAsync();
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(fixture.Workspace, cancellationToken: ct);
        var marker = Encoding.UTF8.GetBytes("worker-intended-body-600a");
        var (intent, raw) = fixture.WriteIntent(registered.Id, marker);
        var digest = SHA256.HashData(raw);
        var socketRoot = Directory.CreateTempSubdirectory("af-worker-fence-").FullName;
        var socketPath = Path.Combine(socketRoot, "ipc");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        listener.Listen(1);
        var start = new ProcessStartInfo("python3")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add("import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1]); x=sys.stdin.buffer.read(32); s.sendall(x); sys.stdin.buffer.read(1)");
        start.ArgumentList.Add(socketPath);
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Could not start owned child.");
        try
        {
            using var peer = await listener.AcceptAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct);
            using var worker = LinuxOwnedPidfd.OpenPending(peer, child);
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(
                t => FileEffectWorker.RecordPreparedChild(t, intent, raw, worker), CommitDurability.Full)); // no PREPARED
            Assert.Equal(FileJournalPreparation.Prepared,
                node.Runtime.Store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(
                t => FileEffectWorker.RecordPreparedChild(t, intent, raw, worker), CommitDurability.Full)); // not sealed
            using var challenge = new LinuxPeerChallenge();
            _ = worker.AuthenticateAndSeal(peer, challenge);
            var foreign = intent.Caller.Clone();
            foreign.AccountId = CommandIds.New();
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(
                t => FileEffectWorker.RecordPreparedChild(t, intent with { Caller = foreign }, raw, worker), CommitDurability.Full));
            var laterSession = intent.Caller.Clone();
            laterSession.SessionId = CommandIds.New();
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(
                t => FileEffectWorker.RecordPreparedChild(t, intent with { Caller = laterSession }, raw, worker), CommitDurability.Full));
            var alteredRaw = raw.Concat(new byte[] { 0x80, 0x06, 0x01 }).ToArray(); // Same known fields, distinct wire bytes.
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(
                t => FileEffectWorker.RecordPreparedChild(t, intent, alteredRaw, worker), CommitDurability.Full));
            var otherTarget = intent.TargetIdentity!.ToArray();
            otherTarget[^1] ^= 1;
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(
                t => FileEffectWorker.RecordPreparedChild(t, intent with { TargetIdentity = otherTarget }, raw, worker), CommitDurability.Full));
            var otherStage = intent.IntendedStageIdentity.ToArray();
            otherStage[^1] ^= 1;
            Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(
                t => FileEffectWorker.RecordPreparedChild(t, intent with { IntendedStageIdentity = otherStage }, raw, worker), CommitDurability.Full));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_effect_worker;")));
            node.Runtime.Store.Write(t => FileEffectWorker.RecordPreparedChild(t, intent, raw, worker), CommitDurability.Full);
            Assert.Throws<SqliteException>(() => node.Runtime.Store.Write(
                t => FileEffectWorker.RecordPreparedChild(t, intent, raw, worker), CommitDurability.Full)); // one worker per command
            Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_effect_worker WHERE ended = 0;")));
            Assert.Equal(0, await node.StopAsync());
            await node.StartAsync(); // Runtime restart inside the test process; the owned peer remains genuinely live.
            var recovered = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, intent.CommandId, intent.Caller))!;
            Assert.Equal(FileOperationState.Unknown, recovered.State);
            Assert.True(recovered.Held);
            Assert.Equal(digest, recovered.RequestSha256.ToByteArray());

            var blockedOldWriter = Assert.Throws<SqliteException>(() => node.Runtime.Store.Write(t => t.Execute("""
                UPDATE file_operation_journal SET held = 0, acknowledged = 1 WHERE command_id = $id;
                """, ("$id", intent.CommandId)), CommitDurability.Full));
            Assert.Contains("file_worker_still_running", blockedOldWriter.Message, StringComparison.Ordinal);
            await using var human = await node.ChannelAsync(helloAsHuman: true);
            var request = new FileServiceAcknowledgeFileOperationRequest
            {
                Meta = InProcessNode.Command(),
                OperationCommandId = new Id { Value = ByteString.CopyFrom(intent.CommandId) },
                OperationDigest = ByteString.CopyFrom(digest),
            };
            var refused = await human.Files.AcknowledgeFileOperationAsync(request, cancellationToken: ct);
            Assert.True(NodeShapes.IsValid(refused));
            Assert.Equal("invalid_argument", refused.Error.Code);
            Assert.True(node.Runtime.Store.Read(r => FileMutationJournal.GetForVerifiedHuman(r, intent.CommandId))!.Held);
            Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_effect_worker WHERE ended = 0;")));
            Assert.Equal("original test bytes", File.ReadAllText(fixture.Target));

            await child.StandardInput.WriteLineAsync("exit");
            await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal(0, child.ExitCode);
            // The previous acknowledgment command was durably refused; exact replay remains that same refusal.
            var replay = await human.Files.AcknowledgeFileOperationAsync(request, cancellationToken: ct);
            Assert.Equal(refused.ToByteArray(), replay.ToByteArray());
            var next = request.Clone();
            next.Meta = InProcessNode.Command();
            var acknowledged = await human.Files.AcknowledgeFileOperationAsync(next, cancellationToken: ct);
            Assert.True(NodeShapes.IsValid(acknowledged));
            Assert.Null(acknowledged.Error);
            Assert.Equal(FileOperationState.Unknown, acknowledged.Value.Operation.State);
            Assert.False(acknowledged.Value.Operation.Held);
            Assert.True(acknowledged.Value.Operation.Acknowledged);
            Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_effect_worker WHERE ended = 1;")));
            Assert.Equal(digest, acknowledged.Value.Operation.RequestSha256.ToByteArray());
            Assert.Equal("original test bytes", File.ReadAllText(fixture.Target));
            AssertNoContent(node.Runtime.Store.DatabasePath, marker);
        }
        finally
        {
            child.StandardInput.Close();
            if (!child.HasExited)
                Assert.True(child.WaitForExit(10_000), "The owned child did not exit after its private input closed.");
            listener.Dispose();
            Directory.Delete(socketRoot, recursive: true);
        }
    }
}
