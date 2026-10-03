// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Persistence.Sqlite;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Xunit;
using ContentOrigin = ArcForges.Contracts.Foundation.V1.ContentOrigin;
using Instant = ArcForges.Foundation.Instant;

namespace ArcForges.Security.Tests;

/// <summary>
/// Leases over the real SQLite store of PLT.01, used by a test-only adapter of the lease store contract (as the approval store is):
/// production Security stays Foundation-only, and the durable adapter is the host's to supply. These tests prove that a lease, its
/// revocation, its expiry and the end of its task are committed durably and cannot be undone by a restart or a clock step.
/// </summary>
public sealed class SqliteLeaseStoreTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ALeaseAndItsRevocationSurviveClosingAndReopeningTheStore()
    {
        using var database = new DatabaseFile();
        var h = new LeaseHarness();
        CapabilityLease lease;
        using (var store = new SqliteLeaseStore(database.Path, database.StoreId))
        {
            var manager = new CapabilityLeaseManager(h.Clock.Clock, store, h.Sink, h.Ceilings);
            var result = await manager.IssueAsync(h.Request(resources: ["resource/42", "resource/43"]), Token);
            Assert.True(result.Issued);
            lease = result.Lease!;
        }

        using (var reopened = new SqliteLeaseStore(database.Path, database.StoreId))
        {
            var loaded = await reopened.ReadAsync(lease.Id, Token);
            AssertSameLease(lease, loaded!);
            Assert.Equal(["resource/42", "resource/43"], loaded!.ResourceIds);
            var manager = new CapabilityLeaseManager(h.Clock.Clock, reopened, h.Sink, h.Ceilings);
            Assert.Equal(LeaseUseVerdict.Valid, await manager.ValidateAsync(h.Use(lease), Token));
            var revoked = await manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);
            Assert.True(revoked.TryGetValue(out var transition));
            Assert.True(transition.Changed);
        }

        using (var again = new SqliteLeaseStore(database.Path, database.StoreId))
        {
            var loaded = await again.ReadAsync(lease.Id, Token);
            Assert.Equal(LeaseState.Revoked, loaded!.State);
            Assert.Equal(LeaseRevocationReason.OwnerRevoked, loaded.RevocationReason);
            Assert.True(loaded.EndEventRecorded);
            Assert.Equal(3, loaded.Version);
            var restarted = new CapabilityLeaseManager(h.Clock.Clock, again, h.Sink, h.Ceilings);
            Assert.Equal(LeaseUseVerdict.Revoked, await restarted.ValidateAsync(h.Use(lease), Token));
        }

        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
    }

    [Fact]
    public async Task AnObservedExpirySurvivesARestartEvenIfTheWallClockIsSetBack()
    {
        using var database = new DatabaseFile();
        var h = new LeaseHarness();
        CapabilityLease lease;
        using (var store = new SqliteLeaseStore(database.Path, database.StoreId))
        {
            var manager = new CapabilityLeaseManager(h.Clock.Clock, store, h.Sink, h.Ceilings);
            lease = (await manager.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(10)), Token)).Lease!;
            h.Clock.Advance(TimeSpan.FromMinutes(10));
            Assert.Equal(LeaseUseVerdict.Expired, await manager.ValidateAsync(h.Use(lease), Token));
        }

        h.Clock.StepWallClock(TimeSpan.FromHours(-5));

        using var reopened = new SqliteLeaseStore(database.Path, database.StoreId);
        var restarted = new CapabilityLeaseManager(h.Clock.Clock, reopened, h.Sink, h.Ceilings);
        Assert.Equal(LeaseUseVerdict.Expired, await restarted.ValidateAsync(h.Use(lease), Token));
        var loaded = await reopened.ReadAsync(lease.Id, Token);
        Assert.Equal(LeaseState.Expired, loaded!.State);
        Assert.Equal(lease.ExpiresAt, loaded.EndedAt);
    }

    [Fact]
    public async Task TheEndOfATasksLeasesIsDurableAndOnlyTheListedLeasesAreSwept()
    {
        using var database = new DatabaseFile();
        var h = new LeaseHarness();
        var other = TaskId.New();
        CapabilityLease a;
        CapabilityLease b;
        using (var store = new SqliteLeaseStore(database.Path, database.StoreId))
        {
            var manager = new CapabilityLeaseManager(h.Clock.Clock, store, h.Sink, h.Ceilings);
            a = (await manager.IssueAsync(h.Request(), Token)).Lease!;
            b = (await manager.IssueAsync(h.Request(task: other), Token)).Lease!;
            var sweep = await manager.EndTaskAsync(h.Task, Token);
            Assert.Equal(new LeaseSweep(1, 1, 0), sweep);
        }

        using var reopened = new SqliteLeaseStore(database.Path, database.StoreId);
        Assert.Equal(LeaseState.TaskEnded, (await reopened.ReadAsync(a.Id, Token))!.State);
        Assert.Equal(LeaseState.Active, (await reopened.ReadAsync(b.Id, Token))!.State);
        var restarted = new CapabilityLeaseManager(h.Clock.Clock, reopened, h.Sink, h.Ceilings);
        Assert.Equal(LeaseUseVerdict.Expired, await restarted.ValidateAsync(h.Use(a), Token));
        Assert.Equal(LeaseUseVerdict.Valid, await restarted.ValidateAsync(h.Use(b), Token));
        Assert.Empty(await reopened.ListUnsettledAsync(h.Task, null, 10, Token));
        Assert.Equal([b.Id], (await reopened.ListUnsettledAsync(other, null, 10, Token)).Select(lease => lease.Id));
        Assert.Empty(await reopened.ListUnsettledAsync(other, h.Now, 10, Token));
        Assert.Equal([b.Id], (await reopened.ListUnsettledAsync(null, new Instant(b.ExpiresAt.UnixSeconds + 1, 0), 10, Token)).Select(lease => lease.Id));
    }

    [Fact]
    public async Task AFactStillOwedAfterARestartIsListedAndRecordedBySweeping()
    {
        using var database = new DatabaseFile();
        var h = new LeaseHarness();
        CapabilityLease lease;
        using (var store = new SqliteLeaseStore(database.Path, database.StoreId))
        {
            var manager = new CapabilityLeaseManager(h.Clock.Clock, store, h.Sink, h.Ceilings);
            lease = (await manager.IssueAsync(h.Request(), Token)).Lease!;
            h.Sink.Fail = true;
            var revoked = await manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.RiskRejected, Token);
            Assert.True(revoked.TryGetValue(out var transition));
            Assert.False(transition.EndRecorded);
        }

        h.Sink.Fail = false;
        using var reopened = new SqliteLeaseStore(database.Path, database.StoreId);
        var owed = Assert.Single(await reopened.ListUnsettledAsync(null, h.Now, 10, Token));
        Assert.Equal(lease.Id, owed.Id);
        var restarted = new CapabilityLeaseManager(h.Clock.Clock, reopened, h.Sink, h.Ceilings);

        var sweep = await restarted.ExpireDueAsync(Token);

        Assert.Equal(new LeaseSweep(0, 1, 0), sweep);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
        Assert.Equal(LeaseRevocationReason.RiskRejected, h.Sink.Events[1].Lease.RevocationReason);
        Assert.Empty(await reopened.ListUnsettledAsync(null, h.Now, 10, Token));
    }

    [Fact]
    public async Task AStaleReplacementAcrossTwoOpenStoresIsRefusedAndTheLeaseOnlyMovesForward()
    {
        using var database = new DatabaseFile();
        var h = new LeaseHarness();
        using var first = new SqliteLeaseStore(database.Path, database.StoreId);
        using var second = new SqliteLeaseStore(database.Path, database.StoreId);
        var lease = (await new CapabilityLeaseManager(h.Clock.Clock, first, h.Sink, h.Ceilings).IssueAsync(h.Request(), Token)).Lease!;
        var loadedByBoth = await second.ReadAsync(lease.Id, Token);
        AssertSameLease(lease, loadedByBoth!);

        var revoked = LeaseHarness.Ended(lease, LeaseState.Revoked, h.Now, LeaseRevocationReason.OwnerRevoked);
        var expired = LeaseHarness.Ended(lease, LeaseState.Expired, h.Now);

        Assert.True(await first.TryReplaceAsync(lease.Id, 1, revoked, Token));
        Assert.False(await second.TryReplaceAsync(lease.Id, 1, expired, Token));
        Assert.Equal(LeaseState.Revoked, (await second.ReadAsync(lease.Id, Token))!.State);
        Assert.False(await first.TryReplaceAsync(lease.Id, 2, LeaseHarness.Ended(lease, LeaseState.Expired, h.Now, recorded: true), Token));
    }

    [Fact]
    public async Task ACreateOfAnExistingLeaseIsRefusedAndAnUnknownLeaseReadsNull()
    {
        using var database = new DatabaseFile();
        var h = new LeaseHarness();
        using var store = new SqliteLeaseStore(database.Path, database.StoreId);
        var lease = (await new CapabilityLeaseManager(h.Clock.Clock, store, h.Sink, h.Ceilings).IssueAsync(h.Request(), Token)).Lease!;

        Assert.False(await store.TryCreateAsync(lease, Token));
        Assert.Null(await store.ReadAsync(CapabilityLeaseId.New(), Token));
        Assert.False(await store.TryReplaceAsync(CapabilityLeaseId.New(), 1, lease, Token));
    }

    [Fact]
    public async Task SimultaneousRevocationsAcrossTwoOpenStoresEndTheLeaseOnce()
    {
        using var database = new DatabaseFile();
        var h = new LeaseHarness();
        using var first = new SqliteLeaseStore(database.Path, database.StoreId);
        using var second = new SqliteLeaseStore(database.Path, database.StoreId);
        var managerA = new CapabilityLeaseManager(h.Clock.Clock, first, h.Sink, h.Ceilings);
        var managerB = new CapabilityLeaseManager(h.Clock.Clock, second, h.Sink, h.Ceilings);
        var lease = (await managerA.IssueAsync(h.Request(), Token)).Lease!;

        var outcomes = await Task.WhenAll(
            Task.Run(async () => await managerA.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token), Token),
            Task.Run(async () => await managerB.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.PolicyDenied, Token), Token));

        var transitions = outcomes.Select(outcome => outcome.TryGetValue(out var value) ? value : throw new InvalidOperationException()).ToArray();
        Assert.Equal(1, transitions.Count(transition => transition.Changed));
        Assert.Equal(LeaseState.Revoked, (await first.ReadAsync(lease.Id, Token))!.State);
        Assert.Equal(1, h.Sink.Kinds.Count(kind => kind == LeaseEventKind.Revoked));
    }

    private static void AssertSameLease(CapabilityLease expected, CapabilityLease actual)
    {
        Assert.Equal(expected.Id, actual.Id);
        Assert.Equal(expected.Owner, actual.Owner);
        Assert.Equal(expected.Scope, actual.Scope);
        Assert.Equal(expected.Task, actual.Task);
        Assert.Equal(expected.Holder, actual.Holder);
        Assert.Equal(expected.CapabilityKey, actual.CapabilityKey);
        Assert.Equal(expected.ResourceIds, actual.ResourceIds);
        Assert.Equal(expected.EffectiveRisk, actual.EffectiveRisk);
        Assert.Equal(expected.Origin, actual.Origin);
        Assert.Equal(expected.Basis, actual.Basis);
        Assert.Equal(expected.IssuedAt, actual.IssuedAt);
        Assert.Equal(expected.ExpiresAt, actual.ExpiresAt);
        Assert.Equal(expected.State, actual.State);
        Assert.Equal(expected.Version, actual.Version);
        Assert.Equal(expected.EndedAt, actual.EndedAt);
        Assert.Equal(expected.RevocationReason, actual.RevocationReason);
        Assert.Equal(expected.EndEventRecorded, actual.EndEventRecorded);
        Assert.Equal(ActorChainSnapshot.Encode(expected.IssuedBy), ActorChainSnapshot.Encode(actual.IssuedBy));
    }

    private sealed class DatabaseFile : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcforges-security-lease-" + Guid.NewGuid().ToString("N") + ".db");

        internal Guid StoreId { get; } = Guid.NewGuid();

        public void Dispose()
        {
            foreach (var suffix in new[] { string.Empty, "-wal", "-shm", "-journal" })
            {
                var path = Path + suffix;
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
        }
    }

    /// <summary>A test-only adapter of <see cref="ILeaseStore"/> over the real SQLite store, one aggregate per lease.</summary>
    private sealed class SqliteLeaseStore : ILeaseStore, IDisposable
    {
        private const string AggregateKind = "security.lease.snapshot.v1";
        private const string Operation = "security.lease.snapshot";
        private const string IndexKind = "security.lease.index.v1";
        private const string IndexOperation = "security.lease.index";
        private static readonly Guid IndexId = StableGuid("arcforges.security.lease.index");
        private readonly SqliteStore _store;

        internal SqliteLeaseStore(string path, Guid storeId)
        {
            _store = new SqliteStore(path, storeId, new AllowWrites());
        }

        public ValueTask<CapabilityLease?> ReadAsync(CapabilityLeaseId id, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ReadCurrent(id.Value));
        }

        public ValueTask<bool> TryCreateAsync(CapabilityLease lease, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(lease);
            if (lease.State != LeaseState.Active || lease.Version != 1)
            {
                return ValueTask.FromResult(false);
            }

            if (ReadCurrent(lease.Id.Value) is not null)
            {
                return ValueTask.FromResult(false);
            }

            try
            {
                if (_store.Write(CreateWrite(lease, StoreVersion.NewRoot)).Replayed)
                {
                    return ValueTask.FromResult(false);
                }
            }
            catch (InvalidOperationException)
            {
                if (ReadCurrent(lease.Id.Value) is null)
                {
                    throw;
                }

                return ValueTask.FromResult(false);
            }

            AddToIndex(lease);
            return ValueTask.FromResult(true);
        }

        public ValueTask<bool> TryReplaceAsync(CapabilityLeaseId id, long expectedVersion, CapabilityLease replacement, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(replacement);
            var current = ReadCurrent(id.Value);
            if (current is null || current.Version != expectedVersion || replacement.Id != id || replacement.Version != checked(expectedVersion + 1)
                || !IsForward(current, replacement))
            {
                return ValueTask.FromResult(false);
            }

            try
            {
                _ = _store.Write(CreateWrite(replacement, StoreVersion.Native(new((ulong)expectedVersion))));
                return ValueTask.FromResult(true);
            }
            catch (InvalidOperationException)
            {
                var after = ReadCurrent(id.Value);
                if (after is null)
                {
                    throw;
                }

                return ValueTask.FromResult(after.Version == replacement.Version && Encode(after).AsSpan().SequenceEqual(Encode(replacement)));
            }
        }

        public ValueTask<IReadOnlyList<CapabilityLease>> ListUnsettledAsync(TaskId? task, Instant? dueAt, int limit, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ids = ReadIndex().Ids;
            IReadOnlyList<CapabilityLease> result =
            [
                .. ids.Select(ReadCurrent).OfType<CapabilityLease>()
                    .Where(lease => task is null || lease.Task == task)
                    .Where(lease => lease.State == LeaseState.Active ? dueAt is null || lease.ExpiresAt <= dueAt : !lease.EndEventRecorded)
                    .OrderBy(lease => lease.IssuedAt.UnixSeconds).ThenBy(lease => lease.Id.Value)
                    .Take(limit),
            ];
            return ValueTask.FromResult(result);
        }

        public void Dispose() => _store.Dispose();

        private static bool IsForward(CapabilityLease current, CapabilityLease replacement)
        {
            var sameCoverage = current.Owner == replacement.Owner && current.Scope == replacement.Scope && current.Task == replacement.Task
                && current.Holder == replacement.Holder && current.CapabilityKey == replacement.CapabilityKey
                && current.ResourceIds.SequenceEqual(replacement.ResourceIds, StringComparer.Ordinal)
                && current.EffectiveRisk == replacement.EffectiveRisk && current.Origin == replacement.Origin && current.Basis == replacement.Basis
                && current.IssuedAt == replacement.IssuedAt && current.ExpiresAt == replacement.ExpiresAt
                && ActorChainSnapshot.Encode(current.IssuedBy).AsSpan().SequenceEqual(ActorChainSnapshot.Encode(replacement.IssuedBy));
            if (!sameCoverage)
            {
                return false;
            }

            return current.State == LeaseState.Active
                ? replacement.State != LeaseState.Active && !replacement.EndEventRecorded
                : replacement.State == current.State && !current.EndEventRecorded && replacement.EndEventRecorded
                    && replacement.EndedAt == current.EndedAt && replacement.RevocationReason == current.RevocationReason;
        }

        private CapabilityLease? ReadCurrent(Guid id)
        {
            var content = _store.Read(AggregateKind, id);
            if (content is null)
            {
                return null;
            }

            if (content.Version.Kind != StoreVersionKind.Native || content.Version.NativeRevision!.Value.Value > (ulong)long.MaxValue
                || content.Origin.Profile != "arcforges.content-origin.v1"
                || content.Origin.PayloadSha256 != Convert.ToHexStringLower(SHA256.HashData(content.Payload.Span)))
            {
                throw new InvalidDataException("The lease aggregate's version or origin is invalid.");
            }

            var lease = Decode(content.Payload.Span);
            if (lease.Id.Value != id || lease.Version != (long)content.Version.NativeRevision.Value.Value)
            {
                throw new InvalidDataException("The lease payload does not match its aggregate record.");
            }

            return lease;
        }

        private static WriteCommand CreateWrite(CapabilityLease lease, StoreVersion expected) => CreateWrite(
            AggregateKind, Operation, lease.Id.Value, lease.Version, expected, Encode(lease), lease.Owner.Id, lease.EndedAt ?? lease.IssuedAt);

        private static WriteCommand CreateWrite(string kind, string operation, Guid id, long version, StoreVersion expected, byte[] payload, UserId actor, Instant at)
        {
            var origin = new ContentOrigin
            {
                Profile = "arcforges.content-origin.v1",
                OriginId = new ContentOriginId(StableGuid($"origin\0{kind}\0{id:D}\0{version}")).ToWire(),
                ContentUnitId = new ContentUnitId(StableGuid($"unit\0{kind}\0{id:D}\0{version}")).ToWire(),
                PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(payload)),
                ProducerKind = "deterministic",
                OmittedParentCount = 0,
            };
            origin.Kinds.Add("nonAi");
            return new WriteCommand(
                new CommandId(StableGuid($"command\0{kind}\0{id:D}\0{version}")),
                kind,
                id,
                expected,
                new StoredContent(StoreVersion.Native(new((ulong)version)), payload, origin),
                operation,
                actor,
                StableGuid($"correlation\0{kind}\0{id:D}\0{version}"),
                at);
        }

        // SqliteStore has no enumeration, so this test-only adapter keeps one index aggregate of lease identities. A production adapter
        // would index its own table; the index is written after the lease, so a crash between the two leaves an unlisted lease.
        private (long Version, List<Guid> Ids) ReadIndex()
        {
            var content = _store.Read(IndexKind, IndexId);
            if (content is null)
            {
                return (0, []);
            }

            var bytes = content.Payload.ToArray();
            var ids = new List<Guid>();
            for (var offset = 0; offset < bytes.Length; offset += 16)
            {
                ids.Add(new Guid(bytes.AsSpan(offset, 16)));
            }

            return ((long)content.Version.NativeRevision!.Value.Value, ids);
        }

        private void AddToIndex(CapabilityLease lease)
        {
            for (var attempt = 0; attempt < 16; attempt++)
            {
                var (version, ids) = ReadIndex();
                if (ids.Contains(lease.Id.Value))
                {
                    return;
                }

                ids.Add(lease.Id.Value);
                var payload = ids.SelectMany(id => id.ToByteArray()).ToArray();
                var next = version + 1;
                try
                {
                    _ = _store.Write(CreateWrite(
                        IndexKind, IndexOperation, IndexId, next, version == 0 ? StoreVersion.NewRoot : StoreVersion.Native(new((ulong)version)),
                        payload, lease.Owner.Id, lease.IssuedAt));
                    return;
                }
                catch (InvalidOperationException)
                {
                    // A competing writer advanced the index: read it again and retry.
                }
            }

            throw new InvalidOperationException("The lease index could not be updated.");
        }

        private static Guid StableGuid(string value) => new(SHA256.HashData(Encoding.UTF8.GetBytes(value)).AsSpan(0, 16));

        private static byte[] Encode(CapabilityLease lease)
        {
            using var stream = new MemoryStream();
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), leaveOpen: true))
            {
                writer.Write("ArcForges.Security.CapabilityLease.v1");
                writer.Write(lease.Id.Value.ToByteArray());
                writer.Write(lease.Owner.Realm.Value.ToByteArray());
                writer.Write(lease.Owner.Id.Value.ToByteArray());
                writer.Write((int)lease.Owner.Kind);
                writer.Write(lease.Scope.Realm.Value.ToByteArray());
                writer.Write(lease.Scope.Workspace is not null);
                if (lease.Scope.Workspace is { } workspace)
                {
                    writer.Write(workspace.Value.ToByteArray());
                }

                writer.Write(lease.Task.Value.ToByteArray());
                writer.Write((int)lease.Holder.Kind);
                writer.Write(lease.Holder.ActorId.ToByteArray());
                writer.Write(lease.CapabilityKey);
                writer.Write(lease.ResourceIds.Count);
                foreach (var resource in lease.ResourceIds)
                {
                    writer.Write(resource);
                }

                writer.Write((int)lease.EffectiveRisk);
                writer.Write((int)lease.Origin);
                writer.Write((int)lease.Basis);
                var chain = ActorChainSnapshot.Encode(lease.IssuedBy);
                writer.Write(chain.Length);
                writer.Write(chain);
                WriteInstant(writer, lease.IssuedAt);
                WriteInstant(writer, lease.ExpiresAt);
                writer.Write((int)lease.State);
                writer.Write(lease.Version);
                writer.Write(lease.EndedAt is not null);
                if (lease.EndedAt is { } ended)
                {
                    WriteInstant(writer, ended);
                }

                writer.Write((int)lease.RevocationReason);
                writer.Write(lease.EndEventRecorded);
            }

            return stream.ToArray();
        }

        private static CapabilityLease Decode(ReadOnlySpan<byte> payload)
        {
            using var stream = new MemoryStream(payload.ToArray(), writable: false);
            using var reader = new BinaryReader(stream, new UTF8Encoding(false, true), leaveOpen: true);
            if (reader.ReadString() != "ArcForges.Security.CapabilityLease.v1")
            {
                throw new InvalidDataException("Unsupported lease encoding.");
            }

            var id = new CapabilityLeaseId(new Guid(reader.ReadBytes(16)));
            var owner = new HumanPrincipal(new RealmId(new Guid(reader.ReadBytes(16))), new UserId(new Guid(reader.ReadBytes(16))), (HumanIdentityKind)reader.ReadInt32());
            var realm = new RealmId(new Guid(reader.ReadBytes(16)));
            var scope = new DecisionScope(realm, reader.ReadBoolean() ? new WorkspaceId(new Guid(reader.ReadBytes(16))) : null);
            var task = new TaskId(new Guid(reader.ReadBytes(16)));
            var holder = new LeaseHolder((ActorKind)reader.ReadInt32(), new Guid(reader.ReadBytes(16)));
            var capability = reader.ReadString();
            var count = reader.ReadInt32();
            var resources = new List<string>(count);
            for (var index = 0; index < count; index++)
            {
                resources.Add(reader.ReadString());
            }

            var risk = (RiskLevel)reader.ReadInt32();
            var origin = (DecisionOrigin)reader.ReadInt32();
            var basis = (LeaseIssueBasis)reader.ReadInt32();
            var chainBytes = reader.ReadBytes(reader.ReadInt32());
            var chain = ActorChainSnapshot.Decode(chainBytes).Chain;
            var issuedAt = ReadInstant(reader);
            var expiresAt = ReadInstant(reader);
            var state = (LeaseState)reader.ReadInt32();
            var version = reader.ReadInt64();
            Instant? endedAt = reader.ReadBoolean() ? ReadInstant(reader) : null;
            var reason = (LeaseRevocationReason)reader.ReadInt32();
            var recorded = reader.ReadBoolean();
            if (stream.Position != stream.Length)
            {
                throw new InvalidDataException("The lease encoding contains trailing bytes.");
            }

            return new CapabilityLease(id, owner, scope, task, holder, capability, resources, risk, origin, basis, chain, issuedAt, expiresAt, state, version, endedAt, reason, recorded);
        }

        private static void WriteInstant(BinaryWriter writer, Instant instant)
        {
            writer.Write(instant.UnixSeconds);
            writer.Write(instant.Nanoseconds);
        }

        private static Instant ReadInstant(BinaryReader reader) => new(reader.ReadInt64(), reader.ReadUInt32());

        private sealed class AllowWrites : IStoreAuthorization
        {
            public bool CanWrite(WriteCommand command) =>
                (command.AggregateKind == AggregateKind && command.Operation == Operation)
                || (command.AggregateKind == IndexKind && command.Operation == IndexOperation);
        }
    }
}
