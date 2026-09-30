// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Persistence.Sqlite;
using ArcForges.Security.Approvals;
using Xunit;
using ContentOrigin = ArcForges.Contracts.Foundation.V1.ContentOrigin;

namespace ArcForges.Security.Tests;

public sealed class SqliteApprovalStoreTests
{
    [Fact]
    public async Task ApprovalAndDecisionSurviveClosingAndReopeningTheSqliteStore()
    {
        using var database = new DatabaseFile();
        var clock = new TestClock();
        var intent = new ApprovalIntent(Guid.NewGuid(), new CommandId(Guid.NewGuid()), Principal(),
            "account.security.change-email", "account/email", "revision:7", new string('A', 64), RiskLevel.R3);
        var decision = new ApprovalDecisionRequest(Guid.NewGuid(), ApprovalDecisionKind.Approve, intent.Owner,
            new DeviceId(Guid.NewGuid()), ApprovalOrigin.Local, "reviewed exact action");

        ApprovalSnapshot pending;
        using (var store = new SqliteApprovalStore(database.Path, database.StoreId))
        {
            var coordinator = new ApprovalCoordinator(clock.Clock, store);
            var created = Value(await coordinator.RequestAsync(intent, TimeSpan.FromMinutes(2),
                TestContext.Current.CancellationToken));
            Assert.True(created.Applied);
            pending = created.Snapshot;
        }

        ApprovalSnapshot approved;
        using (var reopened = new SqliteApprovalStore(database.Path, database.StoreId))
        {
            var loaded = NotNull(await reopened.ReadAsync(intent.ApprovalId,
                TestContext.Current.CancellationToken));
            AssertSnapshotEqual(pending, loaded);

            var coordinator = new ApprovalCoordinator(clock.Clock, reopened);
            var recorded = Value(await coordinator.DecideAsync(intent.ApprovalId, decision,
                TestContext.Current.CancellationToken));
            Assert.True(recorded.Applied);
            approved = recorded.Snapshot;
        }

        using (var reopenedAgain = new SqliteApprovalStore(database.Path, database.StoreId))
        {
            var loaded = NotNull(await reopenedAgain.ReadAsync(intent.ApprovalId,
                TestContext.Current.CancellationToken));
            AssertSnapshotEqual(approved, loaded);
            Assert.Equal(ApprovalState.Approved, loaded.State);
            Assert.Equal(decision.DecisionId, loaded.Decision!.DecisionId);
            Assert.Equal(decision.Kind, loaded.Decision.Kind);
            Assert.Equal(decision.DecidedBy, loaded.Decision.DecidedBy);
            Assert.Equal(decision.Device, loaded.Decision.Device);
            Assert.Equal(decision.Origin, loaded.Decision.Origin);
            Assert.Equal(decision.Reason, loaded.Decision.Reason);

            var coordinator = new ApprovalCoordinator(clock.Clock, reopenedAgain);
            var replay = Value(await coordinator.DecideAsync(intent.ApprovalId, decision,
                TestContext.Current.CancellationToken));
            Assert.False(replay.Applied);
            AssertSnapshotEqual(approved, replay.Snapshot);
        }
    }

    [Fact]
    public async Task SqliteStoreRejectsStaleApprovalReplacementAcrossOpenInstances()
    {
        using var database = new DatabaseFile();
        var clock = new TestClock();
        var intent = new ApprovalIntent(Guid.NewGuid(), new CommandId(Guid.NewGuid()), Principal(),
            "workspace.archive", "workspace/primary", "revision:12", new string('B', 64), RiskLevel.R4);
        var requestedAt = clock.Clock.GetCurrentInstant();
        var expiresAt = new Instant(requestedAt.UnixSeconds + 120, requestedAt.Nanoseconds);
        var pending = new ApprovalSnapshot(intent.ApprovalId, intent.CommandId, intent.Owner, intent.OperationId,
            intent.TargetResourceId, intent.TargetRevision, intent.EffectSha256, intent.EffectiveRisk,
            requestedAt, expiresAt, ApprovalState.Pending, version: 1);

        using var writeBarrier = new Barrier(2);
        using var first = new SqliteApprovalStore(database.Path, database.StoreId, writeBarrier);
        using var second = new SqliteApprovalStore(database.Path, database.StoreId, writeBarrier);
        Assert.True(await first.TryCreatePendingAsync(pending, TestContext.Current.CancellationToken));
        Assert.False(await second.TryCreatePendingAsync(pending, TestContext.Current.CancellationToken));

        var approvedDecision = new ApprovalDecision(Guid.NewGuid(), ApprovalDecisionKind.Approve, intent.Owner,
            new DeviceId(Guid.NewGuid()), ApprovalOrigin.Local, requestedAt, "approved exact binding");
        var deniedDecision = new ApprovalDecision(Guid.NewGuid(), ApprovalDecisionKind.Deny, intent.Owner,
            new DeviceId(Guid.NewGuid()), ApprovalOrigin.Local, requestedAt, "denied exact binding");
        var approved = Resolve(pending, ApprovalState.Approved, approvedDecision);
        var denied = Resolve(pending, ApprovalState.Denied, deniedDecision);

        var attempts = await Task.WhenAll(
            Task.Run(async () => await first.TryResolveAsync(intent.ApprovalId, 1, approved,
                TestContext.Current.CancellationToken).ConfigureAwait(false)),
            Task.Run(async () => await second.TryResolveAsync(intent.ApprovalId, 1, denied,
                TestContext.Current.CancellationToken).ConfigureAwait(false)));
        Assert.Single(attempts, applied => applied);
        var final = NotNull(await second.ReadAsync(intent.ApprovalId, TestContext.Current.CancellationToken));
        Assert.Contains(final.State, new[] { ApprovalState.Approved, ApprovalState.Denied });
        Assert.Equal(2, final.Version);
        Assert.Contains(final.Decision!.DecisionId, new[] { approvedDecision.DecisionId, deniedDecision.DecisionId });
    }

    private static ApprovalSnapshot Resolve(ApprovalSnapshot pending, ApprovalState state, ApprovalDecision decision) =>
        new(pending.ApprovalId, pending.CommandId, pending.Owner, pending.OperationId, pending.TargetResourceId,
            pending.TargetRevision, pending.EffectSha256, pending.EffectiveRisk, pending.RequestedAt,
            pending.ExpiresAt, state, checked(pending.Version + 1), decision.DecidedAt, decision);

    private static void AssertSnapshotEqual(ApprovalSnapshot expected, ApprovalSnapshot actual)
    {
        Assert.Equal(expected.ApprovalId, actual.ApprovalId);
        Assert.Equal(expected.CommandId, actual.CommandId);
        Assert.Equal(expected.Owner, actual.Owner);
        Assert.Equal(expected.OperationId, actual.OperationId);
        Assert.Equal(expected.TargetResourceId, actual.TargetResourceId);
        Assert.Equal(expected.TargetRevision, actual.TargetRevision);
        Assert.Equal(expected.EffectSha256, actual.EffectSha256);
        Assert.Equal(expected.EffectiveRisk, actual.EffectiveRisk);
        Assert.Equal(expected.RequestedAt, actual.RequestedAt);
        Assert.Equal(expected.ExpiresAt, actual.ExpiresAt);
        Assert.Equal(expected.State, actual.State);
        Assert.Equal(expected.Version, actual.Version);
        Assert.Equal(expected.ResolvedAt, actual.ResolvedAt);
        Assert.Equal(expected.Decision, actual.Decision);
        Assert.Equal(expected.CancelledBy, actual.CancelledBy);
    }

    private static HumanPrincipal Principal() => new(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()),
        HumanIdentityKind.LocalHuman);

    private static T NotNull<T>(T? value) where T : class
    {
        Assert.NotNull(value);
        return value;
    }

    private static T Value<T>(ArcForges.Foundation.Errors.Outcome<T> outcome)
    {
        Assert.True(outcome.TryGetValue(out var value), outcome.TryGetFailure(out var failure)
            ? failure!.Code : "Expected a successful outcome.");
        return value!;
    }

    private sealed class DatabaseFile : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "arcforges-security-approval-" + Guid.NewGuid().ToString("N") + ".db");
        internal Guid StoreId { get; } = Guid.NewGuid();

        public void Dispose()
        {
            foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
            {
                var path = Path + suffix;
                if (File.Exists(path)) File.Delete(path);
            }
        }
    }

    private sealed class TestClock
    {
        private readonly ManualTimeProvider provider = new();
        internal Clock Clock { get; } = null!;

        internal TestClock() => Clock = new Clock(provider);
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset now = new(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class SqliteApprovalStore : IApprovalStore, IDisposable
    {
        private const string AggregateKind = "security.approval.snapshot.v1";
        private readonly SqliteStore store;
        private readonly Barrier? resolveWriteBarrier;

        internal SqliteApprovalStore(string path, Guid storeId, Barrier? resolveWriteBarrier = null)
        {
            store = new SqliteStore(path, storeId, new AllowWrites());
            this.resolveWriteBarrier = resolveWriteBarrier;
        }

        public ValueTask<ApprovalSnapshot?> ReadAsync(Guid approvalId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var content = store.Read(AggregateKind, approvalId);
            if (content is null)
            {
                return ValueTask.FromResult<ApprovalSnapshot?>(null);
            }

            if (content.Version.Kind != StoreVersionKind.Native || content.Version.NativeRevision!.Value.Value > (ulong)long.MaxValue)
            {
                throw new InvalidDataException("Approval aggregate has a non-native or out-of-range storage version.");
            }

            var origin = content.Origin;
            if (origin.Profile != "arcforges.content-origin.v1" || origin.PayloadSha256 !=
                Convert.ToHexStringLower(SHA256.HashData(content.Payload.Span)))
            {
                throw new InvalidDataException("Approval aggregate origin does not identify its exact payload.");
            }

            var snapshot = SnapshotCodec.Decode(content.Payload.Span);
            if (snapshot.ApprovalId != approvalId || snapshot.Version != (long)content.Version.NativeRevision.Value.Value)
            {
                throw new InvalidDataException("Approval payload identity/version does not match its aggregate record.");
            }

            return ValueTask.FromResult<ApprovalSnapshot?>(snapshot);
        }

        public ValueTask<bool> TryCreatePendingAsync(ApprovalSnapshot snapshot, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(snapshot);
            if (snapshot.State != ApprovalState.Pending || snapshot.Version != 1)
            {
                return ValueTask.FromResult(false);
            }

            var payload = SnapshotCodec.Encode(snapshot);
            if (store.Read(AggregateKind, snapshot.ApprovalId) is not null)
            {
                _ = ReadCurrent(snapshot.ApprovalId);
                return ValueTask.FromResult(false);
            }

            var command = CreateWrite(snapshot, StoreVersion.NewRoot, payload);
            try
            {
                return ValueTask.FromResult(!store.Write(command).Replayed);
            }
            catch (InvalidOperationException)
            {
                if (store.Read(AggregateKind, snapshot.ApprovalId) is null)
                {
                    throw;
                }

                _ = ReadCurrent(snapshot.ApprovalId);
                return ValueTask.FromResult(false);
            }
        }

        public async ValueTask<bool> TryResolveAsync(Guid approvalId, long expectedVersion, ApprovalSnapshot resolved,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(resolved);
            if (approvalId == Guid.Empty || expectedVersion <= 0 || resolved.ApprovalId != approvalId ||
                resolved.Version != checked(expectedVersion + 1) || resolved.State is not (ApprovalState.Approved or
                    ApprovalState.Denied or ApprovalState.Cancelled or ApprovalState.Expired))
            {
                return false;
            }

            var current = await ReadAsync(approvalId, cancellationToken).ConfigureAwait(false);
            if (current is null || current.Version != expectedVersion || current.State != ApprovalState.Pending ||
                !HasSameActionBinding(current, resolved))
            {
                return false;
            }

            if (resolveWriteBarrier is not null && !resolveWriteBarrier.SignalAndWait(TimeSpan.FromSeconds(15), cancellationToken))
            {
                throw new TimeoutException("Concurrent SQLite approval writers did not reach the compare-and-swap barrier.");
            }

            var payload = SnapshotCodec.Encode(resolved);
            var command = CreateWrite(resolved, StoreVersion.Native(new((ulong)expectedVersion)), payload);
            try
            {
                _ = store.Write(command);
                return true;
            }
            catch (InvalidOperationException)
            {
                var after = await ReadAsync(approvalId, cancellationToken).ConfigureAwait(false);
                if (after is null)
                {
                    throw;
                }

                if (after.Version == resolved.Version && SnapshotCodec.Encode(after).AsSpan().SequenceEqual(payload))
                {
                    return true;
                }

                if (after.Version != expectedVersion)
                {
                    return false;
                }

                throw;
            }
        }

        private static bool HasSameActionBinding(ApprovalSnapshot left, ApprovalSnapshot right) =>
            left.ApprovalId == right.ApprovalId && left.CommandId == right.CommandId && left.Owner == right.Owner &&
            left.OperationId == right.OperationId && left.TargetResourceId == right.TargetResourceId &&
            left.TargetRevision == right.TargetRevision && left.EffectSha256 == right.EffectSha256 &&
            left.EffectiveRisk == right.EffectiveRisk && left.RequestedAt == right.RequestedAt && left.ExpiresAt == right.ExpiresAt;

        private static WriteCommand CreateWrite(ApprovalSnapshot snapshot, StoreVersion expected, byte[] payload)
        {
            var nextVersion = StoreVersion.Native(new((ulong)snapshot.Version));
            var actor = snapshot.Owner.Id;
            var origin = new ContentOrigin
            {
                Profile = "arcforges.content-origin.v1",
                OriginId = new ContentOriginId(StableGuid($"origin\0{snapshot.ApprovalId:D}\0{snapshot.Version}")).ToWire(),
                ContentUnitId = new ContentUnitId(StableGuid($"unit\0{snapshot.ApprovalId:D}\0{snapshot.Version}")).ToWire(),
                PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(payload)),
                ProducerKind = "deterministic",
                OmittedParentCount = 0,
            };
            origin.Kinds.Add("nonAi");
            return new WriteCommand(
                new(StableGuid($"command\0{snapshot.ApprovalId:D}\0{snapshot.Version}")),
                AggregateKind,
                snapshot.ApprovalId,
                expected,
                new StoredContent(nextVersion, payload, origin),
                "security.approval.snapshot",
                actor,
                StableGuid($"correlation\0{snapshot.ApprovalId:D}\0{snapshot.Version}"),
                new Instant(snapshot.RequestedAt.UnixSeconds, snapshot.RequestedAt.Nanoseconds));
        }

        private static Guid StableGuid(string value) =>
            new(SHA256.HashData(Encoding.UTF8.GetBytes(value)).AsSpan(0, 16));

        private ApprovalSnapshot? ReadCurrent(Guid approvalId)
        {
            var content = store.Read(AggregateKind, approvalId);
            if (content is null)
            {
                return null;
            }

            var origin = content.Origin;
            if (content.Version.Kind != StoreVersionKind.Native || content.Version.NativeRevision!.Value.Value > (ulong)long.MaxValue ||
                origin.Profile != "arcforges.content-origin.v1" || origin.PayloadSha256 !=
                Convert.ToHexStringLower(SHA256.HashData(content.Payload.Span)))
            {
                throw new InvalidDataException("Approval aggregate version or origin is invalid.");
            }

            var snapshot = SnapshotCodec.Decode(content.Payload.Span);
            if (snapshot.ApprovalId != approvalId || snapshot.Version != (long)content.Version.NativeRevision.Value.Value)
            {
                throw new InvalidDataException("Approval payload identity/version does not match its aggregate record.");
            }

            return snapshot;
        }

        public void Dispose() => store.Dispose();

        private sealed class AllowWrites : IStoreAuthorization
        {
            public bool CanWrite(WriteCommand command) => command.AggregateKind == AggregateKind &&
                command.Operation == "security.approval.snapshot";
        }
    }

    private static class SnapshotCodec
    {
        private const string Header = "ArcForges.Security.ApprovalSnapshot.v1";
        private const int MaximumPayloadBytes = 16 * 1024;

        internal static byte[] Encode(ApprovalSnapshot snapshot)
        {
            using var stream = new MemoryStream();
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), leaveOpen: true))
            {
                writer.Write(Header);
                WriteGuid(writer, snapshot.ApprovalId);
                WriteGuid(writer, snapshot.CommandId.Value);
                WritePrincipal(writer, snapshot.Owner);
                writer.Write(snapshot.OperationId);
                writer.Write(snapshot.TargetResourceId);
                writer.Write(snapshot.TargetRevision);
                writer.Write(snapshot.EffectSha256);
                writer.Write((int)snapshot.EffectiveRisk);
                WriteInstant(writer, snapshot.RequestedAt);
                WriteInstant(writer, snapshot.ExpiresAt);
                writer.Write((int)snapshot.State);
                writer.Write(snapshot.Version);
                writer.Write(snapshot.ResolvedAt is not null);
                if (snapshot.ResolvedAt is { } resolvedAt)
                {
                    WriteInstant(writer, resolvedAt);
                }

                writer.Write(snapshot.Decision is not null);
                if (snapshot.Decision is { } decision)
                {
                    WriteGuid(writer, decision.DecisionId);
                    writer.Write((int)decision.Kind);
                    WritePrincipal(writer, decision.DecidedBy);
                    WriteGuid(writer, decision.Device.Value);
                    writer.Write((int)decision.Origin);
                    WriteInstant(writer, decision.DecidedAt);
                    WriteNullableString(writer, decision.Reason);
                }

                writer.Write(snapshot.CancelledBy is not null);
                if (snapshot.CancelledBy is { } cancelledBy)
                {
                    WritePrincipal(writer, cancelledBy);
                }
            }

            if (stream.Length > MaximumPayloadBytes)
            {
                throw new InvalidDataException("Approval snapshot exceeds its bounded storage encoding.");
            }

            return stream.ToArray();
        }

        internal static ApprovalSnapshot Decode(ReadOnlySpan<byte> payload)
        {
            if (payload.Length == 0 || payload.Length > MaximumPayloadBytes)
            {
                throw new InvalidDataException("Approval snapshot payload is empty or exceeds its bound.");
            }

            using var stream = new MemoryStream(payload.ToArray(), writable: false);
            using var reader = new BinaryReader(stream, new UTF8Encoding(false, true), leaveOpen: true);
            if (reader.ReadString() != Header)
            {
                throw new InvalidDataException("Unsupported approval snapshot encoding.");
            }

            var approvalId = ReadGuid(reader);
            var commandId = new CommandId(ReadGuid(reader));
            var owner = ReadPrincipal(reader);
            var operationId = reader.ReadString();
            var targetResourceId = reader.ReadString();
            var targetRevision = reader.ReadString();
            var effectSha256 = reader.ReadString();
            var effectiveRisk = (RiskLevel)reader.ReadInt32();
            var requestedAt = ReadInstant(reader);
            var expiresAt = ReadInstant(reader);
            var state = (ApprovalState)reader.ReadInt32();
            var version = reader.ReadInt64();
            Instant? resolvedAt = reader.ReadBoolean() ? ReadInstant(reader) : null;
            ApprovalDecision? decision = null;
            if (reader.ReadBoolean())
            {
                var decisionId = ReadGuid(reader);
                var kind = (ApprovalDecisionKind)reader.ReadInt32();
                var decidedBy = ReadPrincipal(reader);
                var device = new DeviceId(ReadGuid(reader));
                var origin = (ApprovalOrigin)reader.ReadInt32();
                var decidedAt = ReadInstant(reader);
                var reason = ReadNullableString(reader);
                decision = new ApprovalDecision(decisionId, kind, decidedBy, device, origin, decidedAt, reason);
            }

            var cancelledBy = reader.ReadBoolean() ? ReadPrincipal(reader) : null;
            if (stream.Position != stream.Length)
            {
                throw new InvalidDataException("Approval snapshot encoding contains trailing bytes.");
            }

            return new ApprovalSnapshot(approvalId, commandId, owner, operationId, targetResourceId,
                targetRevision, effectSha256, effectiveRisk, requestedAt, expiresAt, state, version,
                resolvedAt, decision, cancelledBy);
        }

        private static void WritePrincipal(BinaryWriter writer, HumanPrincipal principal)
        {
            WriteGuid(writer, principal.Realm.Value);
            WriteGuid(writer, principal.Id.Value);
            writer.Write((int)principal.Kind);
        }

        private static HumanPrincipal ReadPrincipal(BinaryReader reader) => new(new RealmId(ReadGuid(reader)),
            new UserId(ReadGuid(reader)), (HumanIdentityKind)reader.ReadInt32());

        private static void WriteInstant(BinaryWriter writer, Instant instant)
        {
            writer.Write(instant.UnixSeconds);
            writer.Write(instant.Nanoseconds);
        }

        private static Instant ReadInstant(BinaryReader reader) => new(reader.ReadInt64(), reader.ReadUInt32());

        private static void WriteNullableString(BinaryWriter writer, string? value)
        {
            writer.Write(value is not null);
            if (value is not null)
            {
                writer.Write(value);
            }
        }

        private static string? ReadNullableString(BinaryReader reader) => reader.ReadBoolean() ? reader.ReadString() : null;

        private static void WriteGuid(BinaryWriter writer, Guid value) => writer.Write(value.ToByteArray());

        private static Guid ReadGuid(BinaryReader reader)
        {
            var bytes = reader.ReadBytes(16);
            if (bytes.Length != 16)
            {
                throw new EndOfStreamException("Approval snapshot ended inside a fixed-length identity.");
            }

            return new Guid(bytes);
        }
    }
}
