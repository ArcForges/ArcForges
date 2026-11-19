// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.Node.Store.Tests;

[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
public sealed class SecurityRemoteGrantRecordsTests
{
    private const string Owner = "fixture-owner";
    private const string Set = "NodeService.SetRemoteGrant";
    private const string Revoke = "NodeService.RevokeRemoteGrant";

    [Fact]
    public void GrantEditsPreserveTheOwnersReservedRevokeAndReplayItsOriginalRevision()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var capacity = new DurableCapacity(12, 1, 1024, 65536);
        var id = NewId();
        var enrollment = NewId();
        DurableIntent original;
        DurableIntent revoke;
        using (var store = root.Open(clock))
        using (var commands = OpenCommands(store, root.Path, capacity))
        {
            original = Intent(commands, Set, id);
            var provision = Provision(id, enrollment, CommandIdentity(original), clock.GetUtcNow());
            Assert.Equal(DurableDecision.Replay, commands.AdmitObserved(original, "SUCCEEDED", 2, """{"revision":1}""", tx =>
                Assert.Equal(1, RemoteGrantRecords.Insert(tx, provision))).Decision);
            Assert.Null(store.Read(reader => RemoteGrantRecords.Get(reader, "foreign-owner", id)));
            Assert.Empty(store.Read(reader => RemoteGrantRecords.List(reader, Owner, null, NewId(), null, 2)));
            Assert.Equal(new[] { id }, store.Read(reader => RemoteGrantRecords.List(reader, Owner, null, enrollment, null, 2))
                .Select(grant => grant.GrantId));

            var refused = Intent(commands, Set, NewId());
            Assert.Equal(DurableDecision.Capacity, commands.AdmitObserved(refused, "SUCCEEDED", 2, """{"revision":1}""", _ =>
                Assert.Fail("The only reserved lane belongs to the existing grant.")).Decision);

            var edit = Intent(commands, Set, id, new(1, DurableGrantAction.Replace));
            var replacement = provision with { Revision = 2, PolicyJson = """{"selectedPolicy":"private-policy-fixture"}""" };
            Assert.Equal(0, store.Write(tx => RemoteGrantRecords.Replace(tx,
                replacement with { CreationTemplateJson = """{"changedTemplate":true}""" }, 1), CommitDurability.Full));
            Assert.Equal(DurableDecision.Replay, commands.AdmitObserved(edit, "SUCCEEDED", 2, """{"revision":2}""", tx =>
                Assert.Equal(1, RemoteGrantRecords.Replace(tx, replacement, 1, clock.GetUtcNow()))).Decision);
            Assert.Equal(2, store.Read(reader => RemoteGrantRecords.ListVersion(reader, Owner, null, enrollment)));
            Assert.Equal("""{"revision":1}""", commands.Admit(original).Receipt?.ResponseJson);
            Assert.Equal(DurableDecision.RevisionConflict, commands.AdmitObserved(Intent(commands, Revoke, id, new(1, DurableGrantAction.Revoke)),
                "SUCCEEDED", 2, """{"revision":2}""", _ => Assert.Fail("A stale grant cannot revoke the new revision.")).Decision);
            Assert.Equal(0, store.Write(tx => RemoteGrantRecords.Revoke(tx, Owner, id, 2, clock.GetUtcNow(), NewId()),
                CommitDurability.Full));

            revoke = Intent(commands, Revoke, id, new(2, DurableGrantAction.Revoke));
            Assert.Equal(DurableDecision.Replay, commands.AdmitObserved(revoke, "SUCCEEDED", 2, """{"revision":3}""", tx =>
            {
                Assert.Equal(1, RemoteGrantRecords.Revoke(tx, Owner, id, 2, clock.GetUtcNow(), enrollment));
                Assert.Equal(1, RemoteGrantRecords.AppendAudit(tx, Owner, "actor-fixture", "remote", CommandIdentity(revoke),
                    Revoke, id, enrollment, NewId(), 3, 2, "grant_revoked", clock.GetUtcNow()));
            }).Decision);
            Assert.Equal(DurableDecision.Conflict, commands.AdmitObserved(Intent(commands, Set, id), "SUCCEEDED", 2,
                """{"revision":1}""", _ => Assert.Fail("A revoked ID cannot reactivate.")).Decision);
            Assert.Equal(1024L, store.Read(reader => reader.Scalar("SELECT length(reserve_storage) FROM owner_epoch_capacity;")));
            Assert.DoesNotContain("private-policy-fixture", (string)store.Read(reader => reader.Scalar("SELECT metadata_json FROM audit;"))!,
                StringComparison.Ordinal);
        }

        using var reopened = root.Open(clock);
        using var repaired = OpenCommands(reopened, root.Path, capacity);
        Assert.Equal("""{"revision":3}""", repaired.Admit(revoke).Receipt?.ResponseJson);
        Assert.Equal(StoredRemoteGrantState.Revoked, reopened.Read(reader => RemoteGrantRecords.Get(reader, Owner, id))?.State);
        clock.Advance(TimeSpan.FromHours(25));
        Assert.Equal(3, repaired.CompactKnownResponses());
        Assert.Equal(DurableDecision.Compacted, repaired.Admit(original).Decision);
        Assert.Equal(DurableDecision.Compacted, repaired.Admit(revoke).Decision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProvisioningKeepsItsExactReservationAcrossUnknownAndSettlesOnlyItsOriginalChild(bool substituteChild)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var capacity = new DurableCapacity(12, 3, 1024, 65536);
        var grantId = NewId();
        var enrollment = NewId();
        var issuedAt = clock.GetUtcNow();
        var sandboxId = NewId();
        var binding = new DurableProvisionBinding(grantId, 1, NewId());
        DurableIntent create;
        StoredRemoteGrant provision;
        StoredRemoteGrant child;
        using (var initialStore = root.Open(clock))
        using (var initialCommands = OpenCommands(initialStore, root.Path, capacity))
        {
            var parent = Intent(initialCommands, Set, grantId);
            provision = Provision(grantId, enrollment, CommandIdentity(parent), issuedAt) with { ExpiresAt = issuedAt.AddMinutes(5) };
            Assert.Equal(DurableDecision.Replay, initialCommands.AdmitObserved(parent, "SUCCEEDED", 2, "{}",
                tx => Assert.Equal(1, RemoteGrantRecords.Insert(tx, provision))).Decision);
            create = new(RandomNumberGenerator.GetBytes(16), initialCommands.OwnerEpoch.ToArray(), "SandboxService.Create",
                "sandbox", sandboxId, [], AdditionalSafetyReservations: 1, Provision: binding);
            Assert.Throws<ArgumentException>(() => initialCommands.Admit(create with { Provision = null }));
            Assert.Equal(DurableDecision.RevisionConflict, initialCommands.Admit(create with
            {
                Provision = binding with { ParentGrantRevision = 2 },
            }).Decision);
            var sandbox = new StoredSandbox(sandboxId, Owner, "fixture", "fixture", 1, StoredSandboxState.Creating,
                "sandboxes/" + sandboxId, SandboxRecords.PendingRootIdentity, 1, issuedAt, issuedAt,
                new("fixture-profile", "1", "{}", new string('0', 64)));
            var admitted = initialCommands.Admit(create, tx => SandboxRecords.Reserve(tx, sandbox));
            Assert.Equal(DurableDecision.Execute, admitted.Decision);
            Assert.Equal(binding, admitted.Receipt?.Provision);
            Assert.Equal(DurableDecision.Conflict, initialCommands.Admit(create with { AdditionalSafetyReservations = 0, Provision = null }).Decision);
            Assert.Equal(DurableDecision.Conflict, initialCommands.Admit(create with
            {
                Provision = binding with { DerivedGrantId = NewId() },
            }).Decision);
            child = new(binding.DerivedGrantId, Owner, enrollment, StoredRemoteGrantScope.Sandbox, sandboxId, provision.GrantId,
                provision.Revision, 1, StoredRemoteGrantState.Active, "{}", CommandIdentity(create), null, null, issuedAt,
                provision.ExpiresAt, null);
            Assert.Equal(0, initialStore.Write(tx => RemoteGrantRecords.Insert(tx, child), CommitDurability.Full));
            var unknown = initialCommands.SetResult(create.CommandId, "UNKNOWN", 3, """{"reason":"pending-root"}""");
            Assert.Equal(binding, unknown.Provision);
            Assert.Contains("pending-root", unknown.ResponseJson, StringComparison.Ordinal);
        }

        using var store = root.Open(clock);
        using var commands = OpenCommands(store, root.Path, capacity);
        var replay = commands.Admit(create with { Provision = null });
        Assert.Equal(DurableDecision.InProgress, replay.Decision);
        Assert.Equal(binding, replay.Receipt?.Provision);
        Assert.Equal(DurableDecision.Capacity, commands.AdmitObserved(Intent(commands, Set, NewId()), "SUCCEEDED", 2, "{}", _ =>
            Assert.Fail("The unresolved provisioning still reserves its child grant.")).Decision);

        if (substituteChild)
        {
            var substitute = child with { GrantId = NewId() };
            Assert.Throws<InvalidOperationException>(() => commands.SetResult(create.CommandId, "SUCCEEDED", 2, "{}", tx =>
            {
                Assert.True(SandboxRecords.SettleCreation(tx, Owner, sandboxId, "fixture-root-proof", StoredSandboxState.Ready));
                Assert.Equal(1, RemoteGrantRecords.Insert(tx, substitute));
            }));
            Assert.Equal(StoredSandboxState.Creating, store.Read(reader => SandboxRecords.Get(reader, Owner, sandboxId))?.State);
            Assert.Null(store.Read(reader => RemoteGrantRecords.Get(reader, Owner, substitute.GrantId)));
            Assert.Equal(binding, commands.Inspect(create.CommandId)?.Provision);
            return;
        }

        commands.SetResult(create.CommandId, "SUCCEEDED", 2, """{"revision":1}""", tx =>
        {
            Assert.True(SandboxRecords.SettleCreation(tx, Owner, sandboxId, "fixture-root-proof", StoredSandboxState.Ready));
            Assert.Equal(0, RemoteGrantRecords.Insert(tx, child with { ParentGrantRevision = 2 }));
            Assert.Equal(0, RemoteGrantRecords.Insert(tx, child with { EnrollmentId = NewId() }));
            Assert.Equal(0, RemoteGrantRecords.Insert(tx, child with { ExpiresAt = null }));
            Assert.Equal(1, RemoteGrantRecords.Insert(tx, child));
        });
        Assert.Equal(StoredSandboxState.Ready, store.Read(reader => SandboxRecords.Get(reader, Owner, sandboxId))?.State);
        Assert.Equal(child, store.Read(reader => RemoteGrantRecords.Get(reader, Owner, child.GrantId)));
        Assert.True(store.Read(reader => RemoteGrantRecords.HasActiveDerivedGrant(reader, Owner, sandboxId,
            CommandIdentity(create), provision.GrantId, 1, clock.GetUtcNow())));
        Assert.False(store.Read(reader => RemoteGrantRecords.HasActiveDerivedGrant(reader, Owner, sandboxId,
            CommandIdentity(create), provision.GrantId, 2, clock.GetUtcNow())));
        Assert.False(store.Read(reader => RemoteGrantRecords.HasActiveDerivedGrant(reader, Owner, sandboxId,
            NewId(), provision.GrantId, 1, clock.GetUtcNow())));
        Assert.False(store.Read(reader => RemoteGrantRecords.HasActiveDerivedGrant(reader, Owner, sandboxId,
            CommandIdentity(create), provision.GrantId, 1, issuedAt.AddMinutes(5))));
        Assert.Null(commands.Inspect(create.CommandId)?.SafetyParentCommandId);
        Assert.Null(commands.Inspect(create.CommandId)?.Provision);
        Assert.Equal(DurableDecision.Replay, commands.Admit(create with { Provision = null }).Decision);
        Assert.Equal(DurableDecision.Capacity, commands.AdmitObserved(Intent(commands, Set, NewId()), "SUCCEEDED", 2, "{}", _ =>
            Assert.Fail("The settled child now owns that same reserve.")).Decision);

        foreach (var grant in new[] { child, provision })
        {
            var revoke = Intent(commands, Revoke, grant.GrantId, new(1, DurableGrantAction.Revoke));
            Assert.Equal(DurableDecision.Replay, commands.AdmitObserved(revoke, "SUCCEEDED", 2, """{"revision":2}""",
                tx => Assert.Equal(1, RemoteGrantRecords.Revoke(tx, Owner, grant.GrantId, 1, clock.GetUtcNow(), enrollment))).Decision);
        }
        Assert.False(store.Read(reader => RemoteGrantRecords.HasActiveDerivedGrant(reader, Owner, sandboxId,
            CommandIdentity(create), provision.GrantId, 1, clock.GetUtcNow())));
        Assert.Equal(3072L, store.Read(reader => reader.Scalar("SELECT length(reserve_storage) FROM owner_epoch_capacity;")));
        clock.Advance(TimeSpan.FromHours(25));
        Assert.Equal(4, commands.CompactKnownResponses());
        Assert.Equal(DurableDecision.Compacted, commands.Admit(create with { Provision = null }).Decision);
    }

    [Fact]
    public void ObservedExpirationIsFencedAcrossClockRollbackAndReopening()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var capacity = new DurableCapacity(12, 1, 1024, 65536);
        var id = NewId();
        using (var store = root.Open(clock))
        using (var commands = OpenCommands(store, root.Path, capacity))
        {
            var create = Intent(commands, Set, id);
            var issuedAt = clock.GetUtcNow();
            var grant = Provision(id, NewId(), CommandIdentity(create), issuedAt) with { ExpiresAt = issuedAt.AddMinutes(1) };
            commands.AdmitObserved(create, "SUCCEEDED", 2, "{}", tx => Assert.Equal(1, RemoteGrantRecords.Insert(tx, grant)));
            Assert.Equal(0, commands.ObserveGrantExpirations(clock.GetUtcNow()));
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT admission_sequence FROM owner_epoch;")));
            clock.Advance(TimeSpan.FromMinutes(1));
            var nextCreate = Intent(commands, Set, NewId());
            Assert.Equal(DurableDecision.Capacity, commands.AdmitObserved(nextCreate, "SUCCEEDED", 2, "{}", _ =>
                Assert.Fail("Unobserved clock expiry cannot free the grant's safety slot.")).Decision);
            Assert.Equal(1, commands.ObserveGrantExpirations(clock.GetUtcNow()));
            Assert.Equal(0, commands.ObserveGrantExpirations(clock.GetUtcNow()));
            Assert.Equal(2L, store.Read(reader => reader.Scalar("SELECT admission_sequence FROM owner_epoch;")));
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_receipt;")));
            Assert.Equal(1L, store.Read(reader => reader.Scalar("""
                SELECT count(*) FROM audit WHERE command_id IS NULL AND origin='system' AND reason_code='grant_expired'
                  AND json_extract(metadata_json,'$.revision')=2;
                """)));
            var nextGrant = Provision(nextCreate.AggregateId!, NewId(), CommandIdentity(nextCreate), clock.GetUtcNow());
            Assert.Equal(DurableDecision.Replay, commands.AdmitObserved(nextCreate, "SUCCEEDED", 2, "{}",
                tx => Assert.Equal(1, RemoteGrantRecords.Insert(tx, nextGrant))).Decision);
        }

        clock.Advance(-TimeSpan.FromMinutes(1));
        using var reopened = root.Open(clock);
        using var reconciled = OpenCommands(reopened, root.Path, capacity);
        Assert.False(reconciled.MaintenanceRequired);
        var expired = reopened.Read(reader => RemoteGrantRecords.Get(reader, Owner, id));
        Assert.NotNull(expired);
        Assert.Equal(StoredRemoteGrantState.Expired, expired.State);
        Assert.Equal(2, expired.Revision);
        Assert.False(reopened.Read(reader => RemoteGrantRecords.IsActiveRevision(reader, Owner, id, 2, clock.GetUtcNow())));
        Assert.Equal(DurableDecision.RevisionConflict, reconciled.AdmitObserved(Intent(reconciled, Revoke, id, new(2, DurableGrantAction.Revoke)),
            "SUCCEEDED", 2, "{}", _ => Assert.Fail("Observed expiry cannot be undone by clock rollback.")).Decision);
    }

    private static StoredRemoteGrant Provision(string grantId, string enrollment, string commandId, DateTimeOffset created) =>
        new(grantId, Owner, enrollment, StoredRemoteGrantScope.Provision, null, null, null, 1, StoredRemoteGrantState.Active, "{}",
            commandId, 1, "{}", created, null, null);

    private static DurableCommandStore OpenCommands(NodeStore store, string dataRoot, DurableCapacity capacity) =>
        new(store, Owner, NodeSecretStores.ForTestDataRoot(dataRoot), capacity);

    private static DurableIntent Intent(DurableCommandStore store, string method, string id, DurableGrantPrecondition? grant = null) =>
        new(RandomNumberGenerator.GetBytes(16), store.OwnerEpoch.ToArray(), method, "grant", id, [], Grant: grant);

    private static string CommandIdentity(DurableIntent intent) => Convert.ToHexStringLower(intent.CommandId);

    private static string NewId() => Guid.NewGuid().ToString("N");
}
