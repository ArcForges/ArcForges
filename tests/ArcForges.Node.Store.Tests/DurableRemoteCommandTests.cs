// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

public sealed partial class DurableCommandStoreTests
{
    [Fact]
    public void RemoteReceiptRequiresItsOriginalBindingAcrossCompactionAndReopen()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        DurableIntent original;
        DurableIntent local;
        DurableRemoteBinding binding;
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            binding = CreateRemoteBinding(store, commands, clock.GetUtcNow());
            original = RemoteStart(commands, binding);
            local = Intent(commands);
            Assert.Equal(DurableDecision.RevisionConflict, commands.Admit(original with
            {
                Remote = binding with { GrantRevision = binding.GrantRevision + 1 },
            }).Decision);
            Assert.Null(commands.Inspect(original.CommandId));
            Assert.Equal(DurableDecision.Execute, commands.Admit(original).Decision);
            Assert.Equal(DurableDecision.Replay, commands.AdmitObserved(local, "SUCCEEDED", 2, "{}").Decision);
            var collision = commands.Admit(original with { CommandId = local.CommandId });
            Assert.Equal(DurableDecision.Conflict, collision.Decision);
            Assert.Null(collision.Receipt);
            commands.SetResult(original.CommandId, "SUCCEEDED", 2, "{\"revision\":1}");
            Assert.Null(commands.InspectRemote(original.OwnerEpoch, local.CommandId, binding));
            Assert.Equal(original.AggregateId, commands.InspectRemote(original.OwnerEpoch, original.CommandId, binding)?.AggregateId);
            Assert.Throws<SqliteException>(() => store.Write(tx => tx.Execute("UPDATE remote_command_binding SET grant_revision=2;")));
            Assert.Throws<SqliteException>(() => store.Write(tx => tx.Execute("DELETE FROM remote_command_binding;")));
            Assert.Throws<SqliteException>(() => store.Write(tx => tx.Execute(
                "INSERT OR REPLACE INTO remote_command_binding SELECT * FROM remote_command_binding;")));
            clock.Advance(TimeSpan.FromHours(24));
            Assert.Equal(3, commands.CompactKnownResponses());
        }

        using var reopened = root.Open(clock);
        using var authority = Commands(reopened, root.Path);
        var retained = Assert.IsType<DurableReceipt>(authority.InspectRemote(original.OwnerEpoch, original.CommandId, binding));
        Assert.True(retained.Compacted);
        Assert.Equal(binding, retained.Remote);
        Assert.Null(retained.ResponseJson);
        foreach (var other in new[]
        {
            binding with { AccountId = NewRemoteId() }, binding with { ActorId = NewRemoteId() },
            binding with { EnrollmentId = NewRemoteId() }, binding with { ProtocolEpoch = NewRemoteId() },
            binding with { GrantId = NewRemoteId() }, binding with { GrantRevision = 2 },
            binding with { SandboxId = NewRemoteId() }, binding with { ScopeKind = "provision", SandboxId = null },
        })
        {
            Assert.Null(authority.InspectRemote(original.OwnerEpoch, original.CommandId, other));
        }
        Assert.Null(authority.InspectRemote(RandomNumberGenerator.GetBytes(16), original.CommandId, binding));
        Assert.Equal(DurableDecision.Compacted, authority.Admit(original).Decision);
        Assert.Equal(DurableDecision.Compacted, authority.Admit(local).Decision);
        Assert.Equal(DurableDecision.Conflict, authority.Admit(original with { Remote = null }).Decision);
        var altered = authority.Admit(original with { CanonicalBody = [7] });
        Assert.Equal(DurableDecision.Conflict, altered.Decision);
        Assert.Null(altered.Receipt);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RemoteBindingAndCommandReservationShareTheFullCommit(bool afterCommit)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var commands = Commands(store, root.Path);
        var original = RemoteStart(commands, CreateRemoteBinding(store, commands, clock.GetUtcNow()));

        Assert.Throws<FixtureBoundaryException>(() => commands.Admit(original, transaction =>
        {
            Assert.Equal(CommitDurability.Full, transaction.Durability);
            if (afterCommit) transaction.AfterCommitForTests = () => throw new FixtureBoundaryException();
            else throw new FixtureBoundaryException();
        }));

        string command = StoreIds.ToHex(original.CommandId);
        long expected = afterCommit ? 1L : 0L;
        Assert.Equal(expected, store.Read(r => r.Scalar("SELECT count(*) FROM command_receipt WHERE command_id=$id;", ("$id", command))));
        Assert.Equal(expected, store.Read(r => r.Scalar("SELECT count(*) FROM remote_command_binding WHERE command_id=$id;", ("$id", command))));
        Assert.Equal(DurableDecision.Maintenance, commands.Admit(original).Decision);
    }

    [Fact]
    public void RemoteRunMutationsRetainTheOwnedTargetAndExactStopIdentity()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var commands = Commands(store, root.Path);
        var binding = CreateRemoteBinding(store, commands, clock.GetUtcNow());
        var localStart = RemoteStart(commands, binding) with { Remote = null };
        var run = new StoredRun(localStart.AggregateId!, binding.SandboxId!, 1, 1, StoredRunState.Starting, NewRemoteId(),
            new string('0', 64), "{}", StoredPayloadStart.Unknown, clock.GetUtcNow());
        Assert.Equal(DurableDecision.Execute, commands.Admit(localStart,
            tx => Assert.True(RunRecords.InsertStarting(tx, "fixture-owner", run))).Decision);

        var policy = new DurableIntent(RandomNumberGenerator.GetBytes(16), localStart.OwnerEpoch, "ResourceService.SetPolicy",
            "run", run.RunId, [], Remote: binding);
        Assert.Equal(DurableDecision.RevisionConflict, commands.AdmitObserved(policy with { AggregateId = NewRemoteId() },
            "SUCCEEDED", 2, "{}").Decision);
        Assert.Equal(DurableDecision.Replay, commands.AdmitObserved(policy, "SUCCEEDED", 2, "{}").Decision);
        var stop = new DurableIntent(RandomNumberGenerator.GetBytes(16), localStart.OwnerEpoch, "RunService.Stop", "run", run.RunId,
            [], SafetyParent: localStart.CommandId, Remote: binding);
        Assert.Equal(DurableDecision.Execute, commands.Admit(stop).Decision);
        Assert.Equal(DurableDecision.InProgress, commands.Admit(stop).Decision);
        var collision = commands.Admit(stop with { CommandId = RandomNumberGenerator.GetBytes(16) });
        Assert.Equal(DurableDecision.Conflict, collision.Decision);
        Assert.Null(collision.Receipt);
        Assert.Null(commands.InspectRemote(localStart.OwnerEpoch, localStart.CommandId, binding));
        Assert.Equal(StoreIds.ToHex(stop.CommandId), commands.InspectRemote(stop.OwnerEpoch, stop.CommandId, binding)?.CommandId);
    }

    [Theory]
    [InlineData("sandbox")]
    [InlineData("provision")]
    public void RemoteSelfRevokeRequiresItsOwnExactGrantAndRevision(string scopeKind)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var commands = Commands(store, root.Path);
        var now = clock.GetUtcNow();
        var binding = CreateRemoteBinding(store, commands, now, scopeKind);
        var revoke = Intent(commands, method: "NodeService.RevokeRemoteGrant") with
        {
            AggregateKind = "grant", AggregateId = binding.GrantId,
            Grant = new(binding.GrantRevision, DurableGrantAction.Revoke), Remote = binding,
        };

        Assert.Throws<ArgumentException>(() => commands.Admit(revoke with { AggregateId = NewRemoteId() }));
        Assert.Throws<ArgumentException>(() => commands.Admit(revoke with { Grant = new(2, DurableGrantAction.Revoke) }));
        Assert.Throws<ArgumentException>(() => commands.Admit(revoke with
        {
            Method = "NodeService.SetRemoteGrant", Grant = new(1, DurableGrantAction.Replace),
        }));
        var result = commands.AdmitObserved(revoke, "SUCCEEDED", 2, "{}", tx => Assert.Equal(1,
            RemoteGrantRecords.Revoke(tx, "fixture-owner", binding.GrantId, binding.GrantRevision, now, binding.EnrollmentId)));
        Assert.Equal(DurableDecision.Replay, result.Decision);
        Assert.Equal(binding, result.Receipt?.Remote);
        Assert.Equal(StoredRemoteGrantState.Revoked, store.Read(r => RemoteGrantRecords.Get(r, "fixture-owner", binding.GrantId))?.State);
    }

    private static DurableRemoteBinding CreateRemoteBinding(NodeStore store, DurableCommandStore commands, DateTimeOffset now,
        string scopeKind = "sandbox")
    {
        bool sandboxScope = scopeKind == "sandbox";
        var binding = new DurableRemoteBinding(NewRemoteId(), NewRemoteId(), NewRemoteId(), NewRemoteId(), NewRemoteId(), 1,
            scopeKind, sandboxScope ? NewRemoteId() : null);
        var grantCommand = Intent(commands, method: "NodeService.SetRemoteGrant") with { AggregateKind = "grant", AggregateId = binding.GrantId };
        var scope = sandboxScope ? StoredRemoteGrantScope.Sandbox : StoredRemoteGrantScope.Provision;
        var grant = new StoredRemoteGrant(binding.GrantId, "fixture-owner", binding.EnrollmentId, scope, binding.SandboxId,
            null, null, 1, StoredRemoteGrantState.Active, "{}", StoreIds.ToHex(grantCommand.CommandId),
            sandboxScope ? null : 1, sandboxScope ? null : "{}", now, null, null);

        var observed = commands.AdmitObserved(grantCommand, "SUCCEEDED", 2, "{}", transaction =>
        {
            if (binding.SandboxId is { } sandboxId)
            {
                transaction.Execute("""
                    INSERT INTO sandbox(sandbox_id,owner_id,display_name,normalized_name,revision,state,root_relative,root_identity,root_generation,
                        created_utc,updated_utc)
                    VALUES($id,'fixture-owner','remote fixture','remote fixture',1,2,'owned/fixture','supplied-root-metadata',1,'2026-10-15','2026-10-15');
                    """, ("$id", sandboxId));
                transaction.Execute("""
                    INSERT INTO sandbox_config(sandbox_id,revision,profile_id,profile_version,config_json,config_sha256,created_utc)
                    VALUES($id,1,'fixture','1','{}',$digest,'2026-10-15');
                    """, ("$id", sandboxId), ("$digest", new string('0', 64)));
            }
            Assert.Equal(1, RemoteGrantRecords.Insert(transaction, grant));
        });
        Assert.Equal(DurableDecision.Replay, observed.Decision);
        return binding;
    }

    private static DurableIntent RemoteStart(DurableCommandStore commands, DurableRemoteBinding binding) =>
        new(RandomNumberGenerator.GetBytes(16), commands.OwnerEpoch.ToArray(), "RunService.Start", "run", NewRemoteId(),
            Encoding.UTF8.GetBytes("synthetic private launch intent"), 1, ExpectedSandboxId: binding.SandboxId, Remote: binding);

    private static string NewRemoteId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}
