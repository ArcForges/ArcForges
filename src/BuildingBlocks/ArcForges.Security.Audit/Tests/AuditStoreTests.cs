// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security;
using ArcForges.Security.Audit;
using Microsoft.Data.Sqlite;
using Xunit;

namespace ArcForges.Security.Audit.Tests;

public sealed class AuditStoreTests
{
    [Fact]
    public void AppendQueryPreservesEveryRequiredSecurityFactAndSeparatesTelemetry()
    {
        using var fixture = new AuditFixture();
        var eventValue = fixture.CreateEvent(delegated: true);

        var appended = fixture.Store.Append(eventValue);
        var occurredAt = appended.OccurredAt.ToDateTimeOffset();
        var page = fixture.Store.Query(new AuditQuery(occurredAt.AddMinutes(-1), occurredAt.AddMinutes(1), 10));

        var read = Assert.Single(page);
        Assert.Equal(appended.Sequence, read.Sequence);
        Assert.Equal(appended.EventId, read.EventId);
        Assert.Equal(fixture.NowInstant, appended.OccurredAt);
        Assert.Equal(appended.OccurredAt, read.OccurredAt);
        Assert.DoesNotContain(typeof(AuditStore).GetMethod(nameof(AuditStore.PlaceLegalHold))!.GetParameters(),
            parameter => parameter.ParameterType == typeof(DateTimeOffset));
        Assert.DoesNotContain(typeof(AuditEvent).GetConstructors().SelectMany(constructor => constructor.GetParameters()),
            parameter => parameter.ParameterType == typeof(DateTimeOffset));
        Assert.Equal(eventValue.EventType, read.Event.EventType);
        Assert.Equal(eventValue.ActorChain.Owner, read.Event.ActorChain.Owner);
        Assert.Equal(eventValue.ActorChain.Device, read.Event.ActorChain.Device);
        Assert.Equal(eventValue.ActorChain.Installation, read.Event.ActorChain.Installation);
        Assert.Equal(eventValue.ActorChain.Session, read.Event.ActorChain.Session);
        Assert.Equal(eventValue.ActorChain.CallerInstance, read.Event.ActorChain.CallerInstance);
        Assert.Equal(ActorChainSnapshot.Encode(eventValue.ActorChain), ActorChainSnapshot.Encode(read.Event.ActorChain));
        Assert.Equal(eventValue.Executor, read.Event.Executor);
        Assert.Equal(eventValue.SoftwareIdentity, read.Event.SoftwareIdentity);
        Assert.Equal(eventValue.Capability, read.Event.Capability);
        Assert.Equal(eventValue.Resource, read.Event.Resource);
        Assert.Equal(eventValue.Risk, read.Event.Risk);
        Assert.Equal(eventValue.Decision, read.Event.Decision);
        Assert.Equal(eventValue.Reason, read.Event.Reason);
        Assert.Equal(eventValue.Origin, read.Event.Origin);
        Assert.Equal(eventValue.Workspace, read.Event.Workspace);
        Assert.Equal(eventValue.Task, read.Event.Task);
        Assert.Equal(eventValue.Correlation, read.Event.Correlation);
        Assert.Equal(64, read.IntegritySha256.Length);
        Assert.Empty(fixture.Store.Query(new AuditQuery(occurredAt.AddMinutes(-1), occurredAt.AddMinutes(1), 10,
            afterSequence: read.Sequence)));

        Assert.DoesNotContain(typeof(AuditStore).Assembly.GetReferencedAssemblies(),
            reference => StringComparer.Ordinal.Equals(reference.Name, "ArcForges.Observability"));
        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%telemetry%';";
        Assert.Null(command.ExecuteScalar());
        Assert.Throws<ArgumentException>(() => new AuditCapabilityId("C:\\private\\secret.txt"));
    }

    [Fact]
    public void OrdinarySqlConnectionsCannotUpdateDeleteOrEnableMaintenanceGate()
    {
        using var fixture = new AuditFixture();
        fixture.Store.Append(fixture.CreateEvent());

        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE local_audit SET risk=4;";
        Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
        command.CommandText = "DELETE FROM local_audit;";
        Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
        command.CommandText = "UPDATE local_audit_maintenance_gate SET enabled=1 WHERE singleton=1;";
        Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
        command.CommandText = "SELECT COUNT(*) FROM local_audit;";
        Assert.Equal(1L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void OrdinaryCallersCannotConstructOrRequestMaintenanceCapabilities()
    {
        using var fixture = new AuditFixture();
        Assert.False(typeof(AuditMaintenanceCapability).IsVisible);
        Assert.Null(typeof(AuditStore).GetMethod("CreateMaintenanceCapability", BindingFlags.Public | BindingFlags.Instance));
        Assert.Null(typeof(AuditStore).GetMethod("PurgeExpiredPartition", BindingFlags.Public | BindingFlags.Instance));
        Assert.Null(typeof(AuditStore).GetMethod("ReleaseLegalHold", BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(AuditMaintenanceCapability).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void WrongStorePolicyOwnerActionAndExpiredCapabilitiesFailClosed()
    {
        using var fixture = new AuditFixture();
        var recent = fixture.Now.AddHours(-1);
        var oldTime = recent.AddYears(-2);
        fixture.SetWallClock(oldTime);
        fixture.Store.Append(fixture.CreateEvent());
        var oldPartition = AuditPartition.For(fixture.Actor.Owner, oldTime);
        var partition = AuditPartition.For(fixture.Actor.Owner, recent);
        fixture.SetWallClock(recent);
        fixture.Store.Append(fixture.CreateEvent());
        var notExpired = fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, partition);
        Assert.Throws<InvalidOperationException>(() => fixture.Store.PurgeExpiredPartition(notExpired));

        using var secondStore = fixture.OpenSecondStore();
        var wrongStore = fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, oldPartition, store: secondStore);
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Store.PurgeExpiredPartition(wrongStore));

        using var otherPolicy = fixture.OpenAlternateStore(new AuditRetentionPolicy(Guid.NewGuid(), 30));
        var wrongPolicy = fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, oldPartition, store: otherPolicy);
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Store.PurgeExpiredPartition(wrongPolicy));

        var otherOwnerPartition = new AuditPartition(new RealmId(Guid.NewGuid()), fixture.Actor.Owner.Id,
            oldPartition.Year, oldPartition.Month);
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Capability(
            AuditMaintenanceAction.PurgeExpiredPartition, otherOwnerPartition));

        var wrongAction = fixture.Capability(AuditMaintenanceAction.ReleaseLegalHold, oldPartition, holdId: Guid.NewGuid());
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Store.PurgeExpiredPartition(wrongAction));

        var expired = fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, oldPartition,
            lifetime: TimeSpan.FromMilliseconds(1));
        fixture.AdvanceMonotonic(TimeSpan.FromMilliseconds(20));
        fixture.SetWallClock(new DateTimeOffset(1900, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Store.PurgeExpiredPartition(expired));
        Assert.Single(fixture.Store.Query(new AuditQuery(recent.AddMinutes(-1), recent.AddMinutes(1), 10)));
    }

    [Fact]
    public void ExpiredUnheldPartitionPurgeRetainsSingleUseAuthorityAndCoverageReceipt()
    {
        using var fixture = new AuditFixture();
        var oldTime = new DateTimeOffset(2024, 1, 12, 13, 14, 15, TimeSpan.Zero);
        fixture.SetWallClock(oldTime);
        var first = fixture.Store.Append(fixture.CreateEvent());
        var second = fixture.Store.Append(fixture.CreateEvent());
        var partition = AuditPartition.For(fixture.Actor.Owner, oldTime);
        fixture.SetWallClock(oldTime.AddYears(2));
        var capability = fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, partition);

        var receipt = fixture.Store.PurgeExpiredPartition(capability);

        Assert.Equal(2, receipt.EventCount);
        Assert.Equal(first.Sequence, receipt.FirstEventSequence);
        Assert.Equal(second.Sequence, receipt.LastEventSequence);
        Assert.Equal(64, receipt.EventsSha256.Length);
        Assert.Equal(capability.Receipt.CapabilityId, receipt.Authority.CapabilityId);
        Assert.Empty(fixture.Store.Query(new AuditQuery(oldTime.AddDays(-1), oldTime.AddMonths(1), 10)));
        var persistedReceipt = Assert.Single(fixture.Store.ReadPurgeReceipts());
        Assert.Equal(receipt.Sequence, persistedReceipt.Sequence);
        Assert.Equal(receipt.Authority.CapabilityId, persistedReceipt.Authority.CapabilityId);
        Assert.Equal(receipt.EventsSha256, persistedReceipt.EventsSha256);
        Assert.Equal(AuditMaintenanceAction.PurgeExpiredPartition, persistedReceipt.Authority.Action);
        Assert.Equal(fixture.MaintenanceActor.Owner, persistedReceipt.Authority.AuthorityActor.Owner);
        Assert.Equal(fixture.MaintenanceSoftware, persistedReceipt.Authority.SoftwareIdentity);
        Assert.Throws<InvalidOperationException>(() => fixture.Store.PurgeExpiredPartition(capability));
        fixture.SetWallClock(oldTime.AddDays(4));
        Assert.Throws<InvalidOperationException>(() => fixture.Store.Append(fixture.CreateEvent()));
    }

    [Fact]
    public void ActiveLegalHoldBlocksPurgeUntilInternalReleaseCapabilityAndReceipt()
    {
        using var fixture = new AuditFixture();
        var oldTime = new DateTimeOffset(2024, 3, 4, 5, 6, 7, TimeSpan.Zero);
        fixture.SetWallClock(oldTime);
        fixture.Store.Append(fixture.CreateEvent());
        var partition = AuditPartition.For(fixture.Actor.Owner, oldTime);
        fixture.SetWallClock(oldTime.AddYears(2));
        var holdId = Guid.NewGuid();
        var placedAt = fixture.NowInstant;
        var placed = fixture.Store.PlaceLegalHold(holdId, partition, AuditHoldReason.LegalPreservation,
            fixture.Actor, fixture.OwnerSoftware, AuditOrigin.Local);
        Assert.False(placed.Released);
        Assert.Equal(placedAt, placed.OccurredAt);
        Assert.Single(fixture.Store.ReadActiveLegalHolds(partition));

        var purge = fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, partition);
        Assert.Throws<InvalidOperationException>(() => fixture.Store.PurgeExpiredPartition(purge));
        Assert.Single(fixture.Store.Query(new AuditQuery(oldTime.AddDays(-1), oldTime.AddMonths(1), 10)));

        var release = fixture.Capability(AuditMaintenanceAction.ReleaseLegalHold, partition, holdId);
        fixture.AdvanceWallOnly(TimeSpan.FromDays(3650));
        var releasedAt = fixture.NowInstant;
        var releaseReceipt = fixture.Store.ReleaseLegalHold(release);
        Assert.Equal(release.Receipt.CapabilityId, releaseReceipt.CapabilityId);
        Assert.Empty(fixture.Store.ReadActiveLegalHolds(partition));
        using (var connection = fixture.OpenRawConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT occurred_unix_seconds,occurred_nanoseconds FROM local_audit_holds WHERE hold_id=$hold AND action=2;";
            command.Parameters.AddWithValue("$hold", holdId.ToString("N", System.Globalization.CultureInfo.InvariantCulture));
            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(releasedAt, new Instant(reader.GetInt64(0), checked((uint)reader.GetInt64(1))));
            Assert.False(reader.Read());
        }
        Assert.Contains(fixture.Store.ReadMaintenanceReceipts(), item => item.CapabilityId == releaseReceipt.CapabilityId
            && item.Action == AuditMaintenanceAction.ReleaseLegalHold
            && item.AuthorityActor.Owner == fixture.MaintenanceActor.Owner
            && item.SoftwareIdentity == fixture.MaintenanceSoftware);
        var receipt = fixture.Store.PurgeExpiredPartition(fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, partition));
        Assert.Equal(1, receipt.EventCount);
        Assert.Single(fixture.Store.ReadPurgeReceipts());
    }

    [Fact]
    public async Task ConcurrentStoreInstancesSerializeAppendsWithoutLosingRows()
    {
        using var fixture = new AuditFixture();
        using var secondStore = fixture.OpenSecondStore();
        var events = Enumerable.Range(0, 24)
            .Select(_ => fixture.CreateEvent())
            .ToArray();
        var writes = events.Select((eventValue, index) => Task.Run(() =>
            (index % 2 == 0 ? fixture.Store : secondStore).Append(eventValue)));
        var records = await Task.WhenAll(writes);

        Assert.Equal(events.Length, records.Select(record => record.Sequence).Distinct().Count());
        var from = records.Min(value => value.OccurredAt.ToDateTimeOffset()).AddSeconds(-1);
        var to = records.Max(value => value.OccurredAt.ToDateTimeOffset()).AddSeconds(1);
        var page = fixture.Store.Query(new AuditQuery(from, to, 100));
        Assert.Equal(events.Length, page.Count);
        Assert.Equal(page.Count, page.Select(record => record.EventId).Distinct().Count());
    }

    [Fact]
    public void AuditPartitionForUsesUtcMonthBoundaries()
    {
        using var fixture = new AuditFixture();
        var westOfUtc = new DateTimeOffset(2025, 1, 31, 23, 30, 0, TimeSpan.FromHours(-2));
        var partition = AuditPartition.For(fixture.Actor.Owner, westOfUtc);

        Assert.Equal(2025, partition.Year);
        Assert.Equal(2, partition.Month);
        Assert.Equal(new DateTimeOffset(2025, 2, 1, 0, 0, 0, TimeSpan.Zero), partition.StartUtc);
        Assert.Equal(new DateTimeOffset(2025, 3, 1, 0, 0, 0, TimeSpan.Zero), partition.EndExclusiveUtc);
    }

    [Fact]
    public void DisposedAuditStoreRefusesFurtherOperations()
    {
        using var fixture = new AuditFixture();
        fixture.Store.Dispose();

        Assert.Throws<ObjectDisposedException>(() => fixture.Store.Append(fixture.CreateEvent()));
    }

    private sealed class AuditFixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "ArcForges-Audit-" + Guid.NewGuid().ToString("N"));
        private readonly string databasePath;
        private readonly ManualTimeProvider timeProvider = new(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        private readonly IClock clock;

        public AuditFixture()
        {
            Directory.CreateDirectory(directory);
            databasePath = Path.Combine(directory, "local_audit.db");
            clock = new Clock(timeProvider);
            var realm = new RealmId(Guid.NewGuid());
            var owner = new UserId(Guid.NewGuid());
            Actor = new ActorChain(new HumanPrincipal(realm, owner, HumanIdentityKind.LocalHuman),
                new DeviceId(Guid.NewGuid()), new InstallationId(Guid.NewGuid()), SessionId.New(),
                new InstanceId(Guid.NewGuid()), [new DelegatedActor(ActorKind.Agent, Guid.NewGuid(),
                    new InstanceId(Guid.NewGuid()), "owned.audit/1")]);
            MaintenanceActor = new ActorChain(Actor.Owner, Actor.Device, Actor.Installation,
                Actor.Session, Actor.CallerInstance, []);
            OwnerSoftware = new AuditSoftwareIdentity("owned.audit/1");
            MaintenanceSoftware = new AuditSoftwareIdentity("policy.maintenance/1");
            Policy = new AuditRetentionPolicy(Guid.NewGuid(), 30);
            Store = new AuditStore(databasePath, realm, owner, Policy, clock);
        }

        public ActorChain Actor { get; }
        public ActorChain MaintenanceActor { get; }
        public AuditSoftwareIdentity OwnerSoftware { get; }
        public AuditSoftwareIdentity MaintenanceSoftware { get; }
        public AuditRetentionPolicy Policy { get; }
        public AuditStore Store { get; }
        public DateTimeOffset Now => timeProvider.GetUtcNow();
        public Instant NowInstant => clock.GetCurrentInstant();

        public AuditEvent CreateEvent(bool delegated = false)
        {
            var chain = delegated ? Actor : new ActorChain(Actor.Owner, Actor.Device, Actor.Installation,
                Actor.Session, Actor.CallerInstance, []);
            var software = delegated ? OwnerSoftware : new AuditSoftwareIdentity("arcscope.desktop/1");
            return new AuditEvent(AuditEventType.SecretUsed, chain, software,
                new AuditCapabilityId("secrets.use"), new AuditResourceReference(AuditResourceKind.Secret, Guid.NewGuid()),
                AuditRisk.High, AuditDecision.Allowed, AuditDecisionReason.PolicyAllowed, AuditOrigin.Remote,
                new WorkspaceId(Guid.NewGuid()), new TaskId(Guid.NewGuid()), new CorrelationId(Guid.NewGuid()));
        }

        public void SetWallClock(DateTimeOffset value) => timeProvider.SetWallClock(value);
        public void AdvanceMonotonic(TimeSpan value) => timeProvider.AdvanceMonotonic(value);
        public void AdvanceWallOnly(TimeSpan value) => timeProvider.AdvanceWallOnly(value);

        public AuditMaintenanceCapability Capability(AuditMaintenanceAction action, AuditPartition partition,
            Guid? holdId = null, AuditStore? store = null, TimeSpan? lifetime = null) =>
            (store ?? Store).CreateMaintenanceCapability(action, partition, MaintenanceActor,
                MaintenanceSoftware, lifetime ?? TimeSpan.FromMinutes(1), holdId);

        public SqliteConnection OpenRawConnection()
        {
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Pooling = false,
                ForeignKeys = true,
            }.ToString());
            connection.Open();
            return connection;
        }

        public AuditStore OpenSecondStore() => new(databasePath, Actor.Owner.Realm, Actor.Owner.Id, Policy, clock);

        public AuditStore OpenAlternateStore(AuditRetentionPolicy policy) =>
            new(Path.Combine(directory, "alternate-local-audit.db"), Actor.Owner.Realm, Actor.Owner.Id, policy, clock);

        public void Dispose()
        {
            Store.Dispose();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class ManualTimeProvider(DateTimeOffset initialWallClock) : TimeProvider
    {
        private DateTimeOffset wallClock = initialWallClock.ToUniversalTime();
        private long monotonicTicks;

        public override DateTimeOffset GetUtcNow() => wallClock;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => monotonicTicks;

        public void SetWallClock(DateTimeOffset value) => wallClock = value.ToUniversalTime();
        public void AdvanceMonotonic(TimeSpan value) => monotonicTicks = checked(monotonicTicks + value.Ticks);
        public void AdvanceWallOnly(TimeSpan value) => wallClock = wallClock.Add(value);
    }
}
