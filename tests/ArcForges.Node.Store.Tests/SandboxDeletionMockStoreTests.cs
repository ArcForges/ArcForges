// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;

namespace ArcForges.Node.Store.Tests;

/// <summary>Deterministic filesystem observations supplied to the real durable deletion journal and receipt transactions.</summary>
public sealed class SandboxDeletionMockStoreTests
{
    private const string Owner = "mock-delete-owner";
    private const string OtherOwner = "mock-delete-other-owner";
    private const string QuarantineIdentity = "observed-fixture-quarantine";
    private const string Unknown = """{"reason":"mock_removal_observation_unavailable"}""";
    private const string OlderUnknown = """{"reason":"mock_successor_interrupted"}""";
    private const string OriginalResult = """{"deletion":"original_observed_complete"}""";
    private const string SuccessorResult = """{"deletion":"successor_observed_complete"}""";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingOrFaultedObservationCannotCommitATombstone(bool faultAfterTombstoneWrite)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        DurableIntent original;
        StoredSandbox before;
        StoredSandboxDeletion journal;
        DurableReceipt originalReceipt;
        using (var store = root.Open(clock))
        using (var commands = OpenCommands(store, root.Path))
        {
            original = AdmitOriginal(store, commands);
            var locked = ReadJournal(store, original);
            Assert.Equal("locked", locked.Phase);
            Assert.Throws<InvalidOperationException>(() => commands.RecordSandboxRemovalVerified(original.CommandId, null));
            Assert.Equal(locked, ReadJournal(store, original));

            Advance(store, original, "quarantined");
            Advance(store, original, "removing");
            before = ReadSandbox(store, original.AggregateId!);
            var withoutWitness = ReadJournal(store, original);
            Assert.False(withoutWitness.RemovalVerified);
            Assert.False(store.Write(transaction => SandboxDeletionRecords.TryComplete(transaction, before, original.OwnerEpoch, withoutWitness),
                CommitDurability.Full));
            Assert.Throws<InvalidOperationException>(() => commands.SettleSandboxDeletion(original.CommandId, null, OriginalResult, null,
                _ => Assert.Fail("Missing evidence must be rejected before the tombstone callback.")));

            commands.MarkSandboxDeletionUnknown(original.CommandId, null, Unknown, null);
            if (faultAfterTombstoneWrite)
            {
                commands.RecordSandboxRemovalVerified(original.CommandId, null);
            }

            journal = ReadJournal(store, original);
            originalReceipt = Assert.IsType<DurableReceipt>(commands.Inspect(original.CommandId));
            Assert.Equal(faultAfterTombstoneWrite, journal.RemovalVerified);
            if (faultAfterTombstoneWrite)
            {
                Assert.Throws<MockObservationException>(() => commands.SettleSandboxDeletion(original.CommandId, null, OriginalResult, null,
                    transaction =>
                    {
                        Assert.True(SandboxDeletionRecords.TryComplete(transaction, before, original.OwnerEpoch, journal));
                        Assert.True(HasTombstone(transaction, original, null));
                        throw new MockObservationException();
                    }));
            }
            else
            {
                Assert.Throws<MockObservationException>(() => commands.RecordSandboxRemovalVerified(original.CommandId, null,
                    _ => throw new MockObservationException()));
            }

            Assert.True(commands.MaintenanceRequired);
            Assert.Equal(originalReceipt, commands.Inspect(original.CommandId));
            Assert.Equal(journal, ReadJournal(store, original));
            Assert.Equal(before, ReadSandbox(store, original.AggregateId!));
            Assert.False(store.Read(reader => HasTombstone(reader, original, null)));
        }

        using var reopened = root.Open(clock);
        using var afterFault = OpenCommands(reopened, root.Path);
        // SQLite rolled back while the owner fence retained the interrupted transition.
        Assert.True(afterFault.MaintenanceRequired);
        Assert.Equal(originalReceipt, afterFault.Inspect(original.CommandId));
        Assert.Equal(journal, ReadJournal(reopened, original));
        Assert.Equal(before, ReadSandbox(reopened, original.AggregateId!));
        Assert.False(reopened.Read(reader => HasTombstone(reader, original, null)));
    }

    [Fact]
    public void ProvedRemovalSurvivesReopenAndSettlesOnlyTheExactOwnerAndSuccessorLineage()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        DurableIntent original;
        DurableIntent older;
        DurableIntent current;
        StoredSandbox sibling;
        StoredSandbox foreign;
        StoredSandboxDeletion proved;
        DurableReceipt retained;
        using (var store = root.Open(clock))
        using (var commands = OpenCommands(store, root.Path))
        {
            sibling = CreateReadySandbox(store, Owner);
            foreign = CreateReadySandbox(store, OtherOwner);
            original = AdmitOriginal(store, commands);
            Advance(store, original, "quarantined");
            Advance(store, original, "removing");
            commands.MarkSandboxDeletionUnknown(original.CommandId, null, Unknown, null);
            older = AdmitSuccessor(store, commands, original);
            commands.MarkSandboxDeletionUnknown(original.CommandId, older.CommandId, "{}", OlderUnknown);
            current = AdmitSuccessor(store, commands, original);

            var unfinished = ReadJournal(store, original);
            Assert.Equal(Id(current), unfinished.LatestSuccessorId);
            Assert.Equal("ACCEPTED", unfinished.LatestSuccessorState);
            Assert.Throws<InvalidOperationException>(() => commands.RecordSandboxRemovalVerified(original.CommandId, older.CommandId));
            Assert.Equal(unfinished, ReadJournal(store, original));

            commands.RecordSandboxRemovalVerified(original.CommandId, current.CommandId);
            proved = ReadJournal(store, original);
            retained = Assert.IsType<DurableReceipt>(commands.Inspect(original.CommandId));
            Assert.True(proved.RemovalVerified);
            Assert.Equal("UNKNOWN", retained.State);
            Assert.Contains("mock_removal_observation_unavailable", retained.ResponseJson, StringComparison.Ordinal);
            Assert.Equal(SandboxDeletionRecords.RemovalWitness(proved, original.OwnerEpoch),
                SandboxDeletionRecords.ReadRemovalWitness(retained.ResponseJson));

            commands.RecordSandboxRemovalVerified(original.CommandId, current.CommandId,
                _ => Assert.Fail("An existing exact witness must be replayed without reacquiring observation."));
            Assert.Equal(retained, commands.Inspect(original.CommandId));
        }

        using var reopened = root.Open(clock);
        using var recovered = OpenCommands(reopened, root.Path);
        using var other = OpenCommands(reopened, root.Path, OtherOwner);
        Assert.False(recovered.MaintenanceRequired);
        Assert.Equal(proved, ReadJournal(reopened, original));
        Assert.Equal(retained, recovered.Inspect(original.CommandId));
        Assert.Equal("UNKNOWN", recovered.Inspect(older.CommandId)?.State);
        Assert.Equal("ACCEPTED", recovered.Inspect(current.CommandId)?.State);
        Assert.Equal(DurableDecision.EpochRetired, other.Admit(current).Decision);
        Assert.Null(other.Inspect(original.CommandId));
        Assert.Throws<InvalidOperationException>(() => recovered.SettleSandboxDeletion(original.CommandId, older.CommandId,
            OriginalResult, SuccessorResult, _ => Assert.Fail("An older successor cannot settle the deletion.")));

        var before = ReadSandbox(reopened, original.AggregateId!);
        var completion = recovered.SettleSandboxDeletion(original.CommandId, current.CommandId, OriginalResult, SuccessorResult,
            transaction => Assert.True(SandboxDeletionRecords.TryComplete(transaction, before, original.OwnerEpoch, proved)));
        var deleted = ReadSandbox(reopened, original.AggregateId!);
        Assert.Equal(StoredSandboxState.Deleted, deleted.State);
        Assert.Equal(before.Revision + 1, deleted.Revision);
        Assert.Equal(before.RootIdentity, deleted.RootIdentity);
        Assert.True(reopened.Read(reader => HasTombstone(reader, original, Id(current))));
        Assert.False(reopened.Read(reader => HasTombstone(reader, original, Id(older))));
        Assert.False(reopened.Read(reader => SandboxDeletionRecords.HasTombstone(reader, OtherOwner, original.OwnerEpoch,
            original.AggregateId!, Id(original), Id(current))));
        Assert.Equal(sibling, ReadSandbox(reopened, sibling.SandboxId));
        Assert.Equal(foreign, ReadSandbox(reopened, foreign.SandboxId, OtherOwner));

        AssertReplays(recovered, original, OriginalResult);
        AssertReplays(recovered, older, SuccessorResult);
        AssertReplays(recovered, current, SuccessorResult);
        Assert.Equal(completion, recovered.SettleSandboxDeletion(original.CommandId, current.CommandId,
            OriginalResult, SuccessorResult, _ => Assert.Fail("Replay cannot run the tombstone callback.")));
        Assert.Equal(deleted, ReadSandbox(reopened, original.AggregateId!));
    }

    private static DurableCommandStore OpenCommands(NodeStore store, string root, string owner = Owner) =>
        new(store, owner, NodeSecretStores.ForTestDataRoot(root));

    private static StoredSandbox CreateReadySandbox(NodeStore store, string owner)
    {
        var id = Guid.NewGuid().ToString("N");
        var now = store.Clock.GetUtcNow();
        var reservation = new StoredSandbox(id, owner, id, id, 1, StoredSandboxState.Creating, "sandboxes/" + id,
            SandboxRecords.PendingRootIdentity, 1, now, now, new("fixture-profile", "1", "{}", new string('0', 64)));
        store.Write(transaction =>
        {
            SandboxRecords.Reserve(transaction, reservation);
            Assert.True(SandboxRecords.SettleCreation(transaction, owner, id, "observed-fixture-root/" + id, StoredSandboxState.Ready));
        }, CommitDurability.Full);
        return ReadSandbox(store, id, owner);
    }

    private static DurableIntent NewIntent(DurableCommandStore commands, StoredSandbox sandbox, string request) =>
        new(Guid.NewGuid().ToByteArray(), commands.OwnerEpoch.ToArray(), SandboxDeletionRecords.Method, "sandbox",
            sandbox.SandboxId, Encoding.UTF8.GetBytes(request), sandbox.Revision);

    private static DurableIntent AdmitOriginal(NodeStore store, DurableCommandStore commands)
    {
        var sandbox = CreateReadySandbox(store, Owner);
        var plan = Guid.NewGuid().ToString("N");
        var intent = NewIntent(commands, sandbox, plan);
        Assert.Equal(DurableDecision.Execute, commands.Admit(intent, transaction =>
            Assert.True(SandboxDeletionRecords.TryAdmitFresh(transaction, sandbox, intent.OwnerEpoch, plan, Id(intent), sandbox.Config))).Decision);
        return intent;
    }

    private static DurableIntent AdmitSuccessor(NodeStore store, DurableCommandStore commands, DurableIntent original)
    {
        var sandbox = ReadSandbox(store, original.AggregateId!);
        var journal = ReadJournal(store, original);
        var intent = NewIntent(commands, sandbox, journal.OriginalCommandId) with
        {
            Deletion = new(journal.OriginalCommandId, journal.DeletionId),
        };
        Assert.Equal(DurableDecision.Execute, commands.Admit(intent, transaction =>
            Assert.True(SandboxDeletionRecords.TryLinkSuccessor(transaction, sandbox, intent.OwnerEpoch, journal, Id(intent), sandbox.Config))).Decision);
        return intent;
    }

    private static void Advance(NodeStore store, DurableIntent original, string phase)
    {
        var sandbox = ReadSandbox(store, original.AggregateId!);
        var journal = ReadJournal(store, original);
        Assert.True(store.Write(transaction => SandboxDeletionRecords.TryAdvance(transaction, sandbox, original.OwnerEpoch, journal,
            phase, QuarantineIdentity), CommitDurability.Full));
    }

    private static void AssertReplays(DurableCommandStore commands, DurableIntent intent, string expectedBody)
    {
        var replay = commands.Admit(intent);
        Assert.Equal(DurableDecision.Replay, replay.Decision);
        var receipt = Assert.IsType<DurableReceipt>(replay.Receipt);
        Assert.Equal(Id(intent), receipt.CommandId);
        Assert.Equal("SUCCEEDED", receipt.State);
        Assert.Equal(2, receipt.Effect);
        Assert.Equal(expectedBody, receipt.ResponseJson);
    }

    private static StoredSandbox ReadSandbox(NodeStore store, string sandboxId, string owner = Owner) =>
        Assert.IsType<StoredSandbox>(store.Read(reader => SandboxRecords.Get(reader, owner, sandboxId)));

    private static StoredSandboxDeletion ReadJournal(NodeStore store, DurableIntent original) =>
        Assert.IsType<StoredSandboxDeletion>(store.Read(reader => SandboxDeletionRecords.ReadOriginal(reader, Owner,
            original.OwnerEpoch, original.AggregateId!, Id(original))));

    private static bool HasTombstone(StoreReader reader, DurableIntent original, string? successor) =>
        SandboxDeletionRecords.HasTombstone(reader, Owner, original.OwnerEpoch, original.AggregateId!, Id(original), successor);

    private static string Id(DurableIntent intent) => Convert.ToHexStringLower(intent.CommandId);

    private sealed class MockObservationException : Exception;
}
