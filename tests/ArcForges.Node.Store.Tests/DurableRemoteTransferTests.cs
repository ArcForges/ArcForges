// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Store.Tests;

public sealed partial class DurableCommandStoreTests
{
    [Fact]
    public void RemoteImportAuthorityStaysBoundDuringEveryPhaseAndUnknownSettlement()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var commands = Commands(store, root.Path);
        var binding = CreateRemoteBinding(store, commands, clock.GetUtcNow());
        var begin = RemoteTransferBegin(commands, binding, TransferRecords.BeginImportMethod);
        var reserved = TransferReservation(begin, StoredTransferDirection.Import, clock.GetUtcNow());
        Assert.Throws<ArgumentException>(() => commands.Admit(begin with { ExpectedSandboxId = NewRemoteId() },
            tx => TransferRecords.Reserve(tx, reserved)));
        foreach (var altered in new[] { binding with { AccountId = NewRemoteId() }, binding with { ProtocolEpoch = NewRemoteId() } })
        {
            Assert.Equal(DurableDecision.RevisionConflict, commands.Admit(begin with { Remote = altered },
                tx => TransferRecords.Reserve(tx, reserved)).Decision);
        }
        Assert.Null(commands.Inspect(begin.CommandId));

        Assert.Equal(DurableDecision.Execute, commands.Admit(begin, tx =>
        {
            Assert.Equal(CommitDurability.Full, tx.Durability);
            TransferRecords.Reserve(tx, reserved);
        }).Decision);
        var open = NextTransfer(reserved, pending: null) with { StagingIdentity = "synthetic-held-stage" };
        commands.SetResult(begin.CommandId, "SUCCEEDED", 2, "{}", tx => Assert.True(TransferRecords.Advance(tx, reserved, open)));
        Assert.True(store.Read(reader => TransferRecords.HasBoundBeginReceipt(reader, open, binding)));

        var write = RemoteTransferStep(commands, binding, open, TransferRecords.WriteMethod);
        var writing = NextTransfer(open, new(StoredTransferPhase.Chunk, StoreIds.ToHex(write.CommandId), 0, 1, new string('c', 64)));
        Assert.Equal(DurableDecision.RevisionConflict, commands.Admit(write with { Remote = binding with { ActorId = NewRemoteId() } },
            tx => Assert.Fail("a different actor reached native-intent admission")).Decision);
        Assert.Equal(DurableDecision.EpochRetired, commands.Admit(write with { OwnerEpoch = Convert.FromHexString(NewRemoteId()) },
            tx => Assert.Fail("a different owner epoch reached admission")).Decision);
        Assert.Null(commands.Inspect(write.CommandId));
        Assert.Equal(DurableDecision.Execute, commands.Admit(write,
            tx => Assert.True(TransferRecords.Advance(tx, open, writing))).Decision);
        var written = NextTransfer(writing, pending: null) with { State = StoredTransferState.Streaming, VerifiedOffset = 1 };
        commands.SetResult(write.CommandId, "SUCCEEDED", 2, "{}", tx => Assert.True(TransferRecords.Advance(tx, writing, written)));

        var commit = RemoteTransferStep(commands, binding, written, TransferRecords.CommitMethod);
        var publishing = NextTransfer(written, new(StoredTransferPhase.Publish, StoreIds.ToHex(commit.CommandId),
            TargetIdentity: written.StagingIdentity, ParentIdentity: written.Manifest.TargetParentIdentity));
        Assert.Equal(DurableDecision.Execute, commands.Admit(commit,
            tx => Assert.True(TransferRecords.Advance(tx, written, publishing))).Decision);
        var revoke = Intent(commands, method: "NodeService.RevokeRemoteGrant") with
        {
            AggregateKind = "grant",
            AggregateId = binding.GrantId,
            Grant = new(binding.GrantRevision, DurableGrantAction.Revoke),
        };
        Assert.Equal(DurableDecision.Replay, commands.AdmitObserved(revoke, "SUCCEEDED", 2, "{}", tx => Assert.Equal(1,
            RemoteGrantRecords.Revoke(tx, written.OwnerId, binding.GrantId, binding.GrantRevision, clock.GetUtcNow(), binding.EnrollmentId))).Decision);
        var interrupted = NextTransfer(publishing, publishing.Manifest.Pending) with { State = StoredTransferState.RecoveryRequired, Effect = 3 };
        commands.SetResult(commit.CommandId, "UNKNOWN", 3, "{}", tx => Assert.True(TransferRecords.Advance(tx, publishing, interrupted)));
        Assert.Equal("UNKNOWN", commands.InspectRemote(commit.OwnerEpoch, commit.CommandId, binding)?.State);
        Assert.Equal(StoredTransferState.RecoveryRequired, store.Read(reader => TransferRecords.Get(reader, written.OwnerId, written.TransferId))?.State);

        var close = RemoteTransferStep(commands, binding, interrupted, TransferRecords.CloseMethod) with { SafetyParent = begin.CommandId };
        Assert.Equal(DurableDecision.RevisionConflict, commands.Admit(close).Decision);
        Assert.Null(commands.Inspect(close.CommandId));
    }

    [Fact]
    public void RemoteExportCloseSharesItsExactBeginAndLeavesTheObservationRetained()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var commands = Commands(store, root.Path);
        var binding = CreateRemoteBinding(store, commands, clock.GetUtcNow());
        var begin = RemoteTransferBegin(commands, binding, TransferRecords.BeginExportMethod);
        var reserved = TransferReservation(begin, StoredTransferDirection.Export, clock.GetUtcNow());
        Assert.Equal(DurableDecision.Execute, commands.Admit(begin, tx => TransferRecords.Reserve(tx, reserved)).Decision);
        var complete = NextTransfer(reserved, pending: null) with
        {
            State = StoredTransferState.Complete,
            StagingIdentity = "synthetic-held-snapshot",
            ExpectedSha256 = new('e', 64),
            VerifiedOffset = 1,
            Effect = 2,
        };
        complete = complete with { Manifest = complete.Manifest with { SnapshotVersion = "verified-snapshot-version" } };
        commands.SetResult(begin.CommandId, "SUCCEEDED", 2, "{}", tx => Assert.True(TransferRecords.Advance(tx, reserved, complete)));
        var close = RemoteTransferStep(commands, binding, complete, TransferRecords.CloseMethod) with { SafetyParent = begin.CommandId };
        Assert.Equal(DurableDecision.RevisionConflict, commands.Admit(close with { SafetyParent = Convert.FromHexString(NewRemoteId()) }).Decision);
        Assert.Equal(DurableDecision.RevisionConflict, commands.Admit(close with { Remote = binding with { ActorId = NewRemoteId() } }).Decision);
        var closing = NextTransfer(complete, new(StoredTransferPhase.Close, StoreIds.ToHex(close.CommandId)));
        Assert.Equal(DurableDecision.Execute, commands.Admit(close,
            tx => Assert.True(TransferRecords.Advance(tx, complete, closing))).Decision);
        var closed = NextTransfer(closing, pending: null) with
        { ClosedAt = clock.GetUtcNow(), CloseReason = StoredTransferCloseReason.ExplicitClose };
        commands.SetResult(close.CommandId, "SUCCEEDED", 2, "{}", tx => Assert.True(TransferRecords.Advance(tx, closing, closed)));
        Assert.True(store.Read(reader => TransferRecords.HasBoundBeginReceipt(reader, closed, binding)));
        Assert.Equal("SUCCEEDED", commands.InspectRemote(close.OwnerEpoch, close.CommandId, binding)?.State);
        var retained = store.Read(reader => TransferRecords.Get(reader, closed.OwnerId, closed.TransferId));
        Assert.Equal(closed.ClosedAt, retained?.ClosedAt);
        Assert.Equal(complete.ExpectedSha256, retained?.ExpectedSha256);
    }

    [Fact]
    public void LocalImportStillOwnsItsOriginalCloseReservation()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var commands = Commands(store, root.Path);
        var binding = CreateRemoteBinding(store, commands, clock.GetUtcNow());
        var begin = RemoteTransferBegin(commands, binding, TransferRecords.BeginImportMethod) with { Remote = null };
        var reserved = TransferReservation(begin, StoredTransferDirection.Import, clock.GetUtcNow());
        Assert.Equal(DurableDecision.Execute, commands.Admit(begin, tx => TransferRecords.Reserve(tx, reserved)).Decision);
        var open = NextTransfer(reserved, pending: null) with { StagingIdentity = "synthetic-local-stage" };
        commands.SetResult(begin.CommandId, "SUCCEEDED", 2, "{}", tx => Assert.True(TransferRecords.Advance(tx, reserved, open)));
        var write = RemoteTransferStep(commands, binding, open, TransferRecords.WriteMethod) with { Remote = null };
        var writing = NextTransfer(open, new(StoredTransferPhase.Chunk, StoreIds.ToHex(write.CommandId), 0, 1, new string('c', 64)));
        Assert.Equal(DurableDecision.Execute, commands.Admit(write,
            tx => Assert.True(TransferRecords.Advance(tx, open, writing))).Decision);
        Assert.Null(commands.Inspect(write.CommandId)?.Remote);
    }

    private static DurableIntent RemoteTransferBegin(DurableCommandStore commands, DurableRemoteBinding binding, string method) =>
        new(Convert.FromHexString(NewRemoteId()), commands.OwnerEpoch.ToArray(), method, TransferRecords.Aggregate,
            NewRemoteId(), [], ExpectedSandboxRevision: 1, ExpectedSandboxId: binding.SandboxId, Remote: binding);

    private static DurableIntent RemoteTransferStep(DurableCommandStore commands, DurableRemoteBinding binding, StoredTransfer row, string method) =>
        new(Convert.FromHexString(NewRemoteId()), commands.OwnerEpoch.ToArray(), method, TransferRecords.Aggregate, row.TransferId, [], Remote: binding);

    private static StoredTransfer TransferReservation(DurableIntent begin, StoredTransferDirection direction, DateTimeOffset now)
    {
        string beginId = StoreIds.ToHex(begin.CommandId);
        bool importing = direction == StoredTransferDirection.Import;
        var binding = begin.Remote;
        var manifest = new StoredTransferManifest(1, binding?.ActorId ?? "fixture-owner", 1, "supplied-root-metadata", 1, "work/transfer.bin",
            GrantId: binding?.GrantId, GrantRevision: binding?.GrantRevision, EnrollmentId: binding?.EnrollmentId,
            Pending: new(StoredTransferPhase.Begin, beginId), TargetParentIdentity: importing ? "synthetic-parent" : null,
            StageRootIdentity: "synthetic-stage-root");
        return new(begin.AggregateId!, begin.ExpectedSandboxId!, "fixture-owner", begin.OwnerEpoch, beginId, direction,
            StoredTransferState.Open, manifest, TransferRecords.UnboundStage, 1, 0, importing ? new('c', 64) : "", now.AddMinutes(5));
    }

    private static StoredTransfer NextTransfer(StoredTransfer row, StoredTransferPending? pending) =>
        row with { Manifest = row.Manifest with { Revision = row.Manifest.Revision + 1, Pending = pending } };
}
