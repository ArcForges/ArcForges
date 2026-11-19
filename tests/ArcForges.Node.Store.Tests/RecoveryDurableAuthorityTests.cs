// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.Node.Store.Tests;

public sealed class RecoveryDurableAuthorityTests
{
    private const string Owner = "recovery-fixture-owner";

    [Fact]
    public void ByteSaturationKeepsBothPromisedSafetyIdentitiesAdmissible()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        using var authority = new DurableCommandStore(store, Owner, NodeSecretStores.ForTestDataRoot(root.Path),
            new(20, 2, 1024, 15370));
        var first = NewIntent(authority, "FixtureService.Start");
        var second = NewIntent(authority, "FixtureService.Start");
        Assert.Equal(DurableDecision.Execute, authority.Admit(first).Decision);
        Assert.Equal(DurableDecision.Execute, authority.Admit(second).Decision);

        var ordinary = NewIntent(authority, "FixtureService.Record");
        Assert.Equal(DurableDecision.Replay, authority.AdmitObserved(ordinary, "SUCCEEDED", 2, "{}").Decision);
        var refused = NewIntent(authority, "FixtureService.Record");
        Assert.Equal(DurableDecision.Capacity, authority.AdmitObserved(refused, "SUCCEEDED", 2, "{}").Decision);
        Assert.Null(authority.Inspect(refused.CommandId));

        var firstSafety = NewIntent(authority, "FixtureService.Stop") with { SafetyParent = first.CommandId };
        var secondSafety = NewIntent(authority, "FixtureService.Stop") with { SafetyParent = second.CommandId };
        Assert.Equal(DurableDecision.Execute, authority.Admit(firstSafety).Decision);
        Assert.Equal("SUCCEEDED", authority.SetResult(firstSafety.CommandId, "SUCCEEDED", 2, "{}").State);
        Assert.Equal(DurableDecision.Execute, authority.Admit(secondSafety).Decision);
        Assert.Equal("SUCCEEDED", authority.SetResult(secondSafety.CommandId, "SUCCEEDED", 2, "{}").State);
        Assert.Equal(DurableDecision.InProgress, authority.Admit(first).Decision);
        Assert.Equal(DurableDecision.InProgress, authority.Admit(second).Decision);
        Assert.Equal(DurableDecision.Replay, authority.Admit(firstSafety).Decision);
        Assert.Equal(DurableDecision.Replay, authority.Admit(secondSafety).Decision);
    }

    [Fact]
    public void SettledKnownCommandsDoNotAccumulateUnownedSafetyPromises()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        using var authority = new DurableCommandStore(store, Owner, NodeSecretStores.ForTestDataRoot(root.Path),
            new(12, 1, 1024, 65536));
        var durable = new List<DurableIntent>();
        for (int index = 0; index < 5; index++)
        {
            var ordinary = NewIntent(authority, "FixtureService.Record");
            Assert.Equal(DurableDecision.Replay, authority.AdmitObserved(ordinary, "SUCCEEDED", 2, "{}").Decision);
            durable.Add(ordinary);
        }

        var pending = NewIntent(authority, "FixtureService.Start");
        Assert.Equal(DurableDecision.Execute, authority.Admit(pending).Decision);
        foreach (var original in durable)
        {
            Assert.Equal(DurableDecision.Replay, authority.Admit(original).Decision);
        }
    }

    [Fact]
    public void AcceptedStartBackupCannotOmitALaterPreparationWitness()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var sourceSecrets = NodeSecretStores.ForTestDataRoot(source.Path);
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        using (var store = source.Open(clock))
        using (var authority = new DurableCommandStore(store, Owner, sourceSecrets))
        {
            var (start, run) = AdmitStartingRun(store, authority);
            authority.CreateBackup(backup.Path, backupSecrets);
            Assert.Throws<InvalidOperationException>(() => authority.RecordRunPreparing(start.CommandId, run.RunId, Guid.NewGuid().ToString("N")));
            authority.RecordRunPreparing(start.CommandId, run.RunId, run.Epoch);
            Assert.True(store.Read(reader => RunRecoveryRecords.Read(reader, Owner, run))!.PrepareStarted);
            Assert.Equal("ACCEPTED", authority.Inspect(start.CommandId)!.State);
        }

        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupSecrets,
            source.Path, sourceSecrets, destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path)));
        Assert.False(File.Exists(destination.Database));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedStartAndUnprovedLinkedStopSettleWithTheTerminalRun(bool earlierUncertainty)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var authority = new DurableCommandStore(store, Owner, NodeSecretStores.ForTestDataRoot(root.Path));
        var (start, run) = AdmitStartingRun(store, authority);
        var stop = NewIntent(authority, "RunService.Stop") with
        {
            AggregateKind = "run",
            AggregateId = run.RunId,
            SafetyParent = start.CommandId,
        };
        Assert.Equal(DurableDecision.Execute, authority.Admit(stop).Decision);
        const string firstUncertainty = """{"reason":"earlier_stop_evidence_unavailable"}""";
        const string finalUncertainty = """{"reason":"stop_effect_unconfirmed"}""";
        if (earlierUncertainty)
        {
            authority.SetResult(stop.CommandId, "UNKNOWN", 3, firstUncertainty);
        }

        var failed = authority.SetResult(start.CommandId, "FAILED", 1, "{}",
            transaction => Assert.True(RunRecords.TryAdvance(transaction, Owner, run.RunId, run.Epoch, run.Revision, run.State,
                new(StoredRunState.Failed, StoredPayloadStart.NotStarted, 1, EndedAt: clock.GetUtcNow(), ExitSource: "supervisor",
                    TerminationReason: "native_launch_rejected", GroupEmptyVerified: true))),
            settledSafetyCommand: stop.CommandId, settledSafetyJson: finalUncertainty, settledSafetyState: "UNKNOWN");
        Assert.Equal("FAILED", failed.State);
        Assert.Equal(StoredRunState.Failed, store.Read(reader => RunRecords.Get(reader, Owner, run.RunId))!.State);
        var retained = authority.Inspect(stop.CommandId)!;
        Assert.Equal("UNKNOWN", retained.State);
        Assert.Equal(3, retained.Effect);
        Assert.Equal(earlierUncertainty ? firstUncertainty : finalUncertainty, retained.ResponseJson);
    }

    private static (DurableIntent Start, StoredRun Run) AdmitStartingRun(NodeStore store, DurableCommandStore authority)
    {
        string sandboxId = Guid.NewGuid().ToString("N");
        string runId = Guid.NewGuid().ToString("N");
        string digest = new('0', 64);
        var now = store.Clock.GetUtcNow();
        var sandbox = new StoredSandbox(sandboxId, Owner, "fixture", "fixture", 1, StoredSandboxState.Creating,
            "sandboxes/" + sandboxId, SandboxRecords.PendingRootIdentity, 1, now, now, new("profile", "1", "{}", digest));
        store.Write(transaction =>
        {
            SandboxRecords.Reserve(transaction, sandbox);
            Assert.True(SandboxRecords.SettleCreation(transaction, Owner, sandboxId, "fixture-root", StoredSandboxState.Ready));
        }, CommitDurability.Full);
        var run = new StoredRun(runId, sandboxId, 1, 1, StoredRunState.Starting, Guid.NewGuid().ToString("N"),
            digest, "{}", StoredPayloadStart.Unknown, now);
        var start = NewIntent(authority, "RunService.Start") with { AggregateKind = "run", AggregateId = runId };
        Assert.Equal(DurableDecision.Execute, authority.Admit(start, transaction =>
        {
            Assert.True(RunRecords.InsertStarting(transaction, Owner, run));
            Assert.True(RunRecoveryRecords.Insert(transaction, Owner, run, new("boot-1", "supervisor", digest, "installation")));
        }).Decision);
        return (start, run);
    }

    private static DurableIntent NewIntent(DurableCommandStore authority, string method) =>
        new(RandomNumberGenerator.GetBytes(16), authority.OwnerEpoch.ToArray(), method, null, null, []);
}
