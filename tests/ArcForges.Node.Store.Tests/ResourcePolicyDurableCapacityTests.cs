// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store.Tests;

[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
public sealed class ResourcePolicyDurableCapacityTests
{
    private const string Owner = "fixture-owner";
    private const string Start = "RunService.Start";
    private const string Stop = "RunService.Stop";
    private const string SetPolicy = "ResourceService.SetPolicy";

    [Theory]
    [InlineData(5, 32768, 3)]
    [InlineData(20, 9500, 1)]
    public void RepeatedPolicyEditsUseOrdinaryReceiptCapacityAndKeepTheOwningRunsStopReserve(
        int maximumReceipts, int maximumJournalBytes, int permittedEdits)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var commands = new DurableCommandStore(store, Owner, NodeSecretStores.ForTestDataRoot(root.Path),
            new(maximumReceipts, 1, 1024, maximumJournalBytes));
        var sandboxId = Guid.NewGuid().ToString("N");
        var runId = Guid.NewGuid().ToString("N");
        var now = clock.GetUtcNow();
        string digest = new('0', 64);
        var sandbox = new StoredSandbox(sandboxId, Owner, "fixture", "fixture", 1, StoredSandboxState.Creating,
            "sandboxes/" + sandboxId, SandboxRecords.PendingRootIdentity, 1, now, now, new("profile", "1", "{}", digest));
        store.Write(tx =>
        {
            SandboxRecords.Reserve(tx, sandbox);
            Assert.True(SandboxRecords.SettleCreation(tx, Owner, sandboxId, "fixture-root", StoredSandboxState.Ready));
        }, CommitDurability.Full);

        var run = new StoredRun(runId, sandboxId, 1, 1, StoredRunState.Starting, "run-epoch",
            digest, "{}", StoredPayloadStart.Unknown, now);
        var start = NewIntent(Start);
        Assert.Equal(DurableDecision.Execute,
            commands.Admit(start, tx => Assert.True(RunRecords.InsertStarting(tx, Owner, run))).Decision);

        for (int edit = 0; edit < permittedEdits; edit++)
        {
            long revision = edit + 2;
            var intent = NewIntent(SetPolicy);
            var desired = new StoredResourcePolicy("run", runId, revision, "{}");
            Assert.Equal(DurableDecision.Execute, commands.Admit(intent, tx =>
                Assert.True(ResourceStateRecords.TryWritePolicy(tx, Owner, desired, edit == 0 ? null : revision - 1))).Decision);
            _ = commands.SetResult(intent.CommandId, "SUCCEEDED", 2, "{}");
            Assert.Equal(DurableDecision.Replay, commands.Admit(intent).Decision);
        }

        var refused = NewIntent(SetPolicy);
        Assert.Equal(DurableDecision.Capacity, commands.Admit(refused).Decision);
        Assert.Null(commands.Inspect(refused.CommandId));
        Assert.Equal(1024L, store.Read(reader => reader.Scalar(
            "SELECT length(reserve_storage) FROM owner_epoch_capacity WHERE owner_id = $owner;", ("$owner", Owner))));
        Assert.Equal(permittedEdits + 1L,
            store.Read(reader => reader.Scalar("SELECT count(*) FROM command_receipt WHERE owner_id = $owner;", ("$owner", Owner))));

        var stop = NewIntent(Stop) with { SafetyParent = start.CommandId };
        Assert.Equal(DurableDecision.Execute, commands.Admit(stop).Decision);
        Assert.Equal(DurableDecision.InProgress,
            commands.Admit(stop with { CommandId = RandomNumberGenerator.GetBytes(16) }).Decision);

        DurableIntent NewIntent(string method) =>
            new(RandomNumberGenerator.GetBytes(16), commands.OwnerEpoch.ToArray(), method, "run", runId, []);
    }
}
