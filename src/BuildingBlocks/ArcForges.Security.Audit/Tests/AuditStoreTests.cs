// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
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
    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "This untrimmed test inspects the compiled audit assembly references to guard its no-telemetry dependency boundary.")]
    [Fact]
    public void AppendQueryPreservesEveryRequiredSecurityFactAndSeparatesTelemetry()
    {
        using var fixture = new AuditFixture();
        var eventValue = fixture.CreateEvent(delegated: true);
        AuditEvent WithEnums(AuditEventType eventType = AuditEventType.SecretUsed,
            AuditRisk risk = AuditRisk.R3, AuditDecision decision = AuditDecision.Allowed,
            AuditDecisionReason reason = AuditDecisionReason.PolicyAllowed,
            AuditOrigin origin = AuditOrigin.Remote) => new(eventType, eventValue.ActorChain,
            eventValue.SoftwareIdentity, eventValue.Capability, eventValue.Resource, risk, decision, reason, origin);

        Assert.Throws<ArgumentOutOfRangeException>(() => WithEnums(eventType: AuditEventType.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => WithEnums(risk: AuditRisk.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => WithEnums(decision: AuditDecision.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => WithEnums(reason: AuditDecisionReason.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => WithEnums(origin: AuditOrigin.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditResourceReference(AuditResourceKind.None, Guid.NewGuid()));
        var partition = AuditPartition.For(eventValue.ActorChain.Owner, fixture.NowInstant);
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditHoldRecord(1, Guid.NewGuid(), partition,
            AuditHoldReason.None, fixture.NowInstant, false, eventValue.ActorChain, eventValue.SoftwareIdentity,
            AuditOrigin.Remote));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditHoldRecord(1, Guid.NewGuid(), partition,
            AuditHoldReason.LegalPreservation, fixture.NowInstant, false, eventValue.ActorChain,
            eventValue.SoftwareIdentity, AuditOrigin.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Store.CreateMaintenanceCapability(
            AuditMaintenanceAction.None, partition, fixture.MaintenanceActor, fixture.MaintenanceSoftware,
            TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditQuery(fixture.Now.AddMinutes(-1),
            fixture.Now.AddMinutes(1), 10, AuditEventType.None));

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

        var atLifetime = fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, oldPartition,
            lifetime: TimeSpan.FromMilliseconds(1));
        fixture.AdvanceMonotonic(TimeSpan.FromMilliseconds(1));
        fixture.SetWallClock(new DateTimeOffset(1900, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Store.PurgeExpiredPartition(atLifetime));

        var pastLifetime = fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, oldPartition,
            lifetime: TimeSpan.FromMilliseconds(1));
        fixture.AdvanceMonotonic(TimeSpan.FromMilliseconds(20));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Store.PurgeExpiredPartition(pastLifetime));
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

    // The following tests prove the PLT.44 typed intake contracts only. They do not prove that the real PLT.41
    // egress enforcement path or a real PLT.43 lease runtime emits to them; neither producer is delivered here.

    [Fact]
    public void EgressAllowedAndDeniedDecisionsAppendBeforeReturnWithEveryTypedFact()
    {
        using var fixture = new AuditFixture();
        var adapter = new EgressDecisionAuditAdapter(fixture.Store);
        var authority = new Revision(Guid.NewGuid(), new CloudRevision(7));
        var correlation = new CorrelationId(Guid.NewGuid());
        var resource = new AuditResourceReference(AuditResourceKind.Export, Guid.NewGuid());
        (EgressDecisionOutcome Outcome, AuditDecisionReason Reason, AuditEventType Type, AuditDecision Decision)[] cases =
        [
            (EgressDecisionOutcome.Allowed, AuditDecisionReason.UserApproved, AuditEventType.DataEgressAuthorized, AuditDecision.Allowed),
            (EgressDecisionOutcome.Denied, AuditDecisionReason.PolicyDenied, AuditEventType.DataEgressDenied, AuditDecision.Denied),
        ];

        foreach (var (outcome, reason, type, decision) in cases)
        {
            var fact = fixture.CreateEgressFact(outcome, reason, authority, correlation, resource);
            var appended = adapter.Record(fact);

            // Durable before Record returned: an independent store over the same file sees exactly this row.
            using var independent = fixture.OpenSecondStore();
            var occurredAt = appended.OccurredAt.ToDateTimeOffset();
            var read = Assert.Single(independent.Query(new AuditQuery(occurredAt.AddMinutes(-1), occurredAt.AddMinutes(1), 10,
                afterSequence: appended.Sequence - 1)));
            Assert.Equal(appended.EventId, read.EventId);
            Assert.Equal(fixture.NowInstant, read.OccurredAt);
            Assert.Equal(type, read.Event.EventType);
            Assert.Equal(decision, read.Event.Decision);
            Assert.Equal(reason, read.Event.Reason);
            Assert.Equal(AuditRisk.R3, read.Event.Risk);
            Assert.Equal(correlation, read.Event.Correlation);
            Assert.Equal(resource, read.Event.Resource);
            Assert.Equal(outcome, fact.Outcome);
            var egress = Assert.IsType<AuditEgressDetail>(read.Event.Egress);
            Assert.Equal(AuditEgressDataClass.CanonicalUserData, egress.DataClass);
            Assert.Equal(AuditEgressDestinationClass.CloudAiProvider, egress.DestinationClass);
            Assert.Equal("api.provider.example:443", egress.Destination.Value);
            Assert.Equal(authority, egress.Authority);
            Assert.Equal(7, egress.Authority.Value.Value);
            Assert.Equal(64, read.IntegritySha256.Length);
        }

        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit WHERE egress_destination_id='api.provider.example:443' AND egress_authority_revision=7;";
        Assert.Equal(2L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void EgressAppendFailureSurfacesBeforeAnyCallerContinuationAndWritesNothing()
    {
        using var fixture = new AuditFixture();
        var adapter = new EgressDecisionAuditAdapter(fixture.Store);
        var authority = new Revision(Guid.NewGuid(), new CloudRevision(1));
        var allowed = fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority);

        // Wrong owner: the store refuses, the call throws, and the code after Record (the transfer) never runs.
        var otherOwner = AuditFixture.NewActor(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()), []);
        var foreign = fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority,
            actor: otherOwner);
        var transferred = false;
        Assert.Throws<UnauthorizedAccessException>(() => { adapter.Record(foreign); transferred = true; });
        Assert.False(transferred);

        // A partition with a retained purge receipt refuses appends.
        var oldTime = new DateTimeOffset(2024, 1, 12, 13, 14, 15, TimeSpan.Zero);
        fixture.SetWallClock(oldTime);
        fixture.Store.Append(fixture.CreateEvent());
        var partition = AuditPartition.For(fixture.Actor.Owner, oldTime);
        fixture.SetWallClock(oldTime.AddYears(2));
        _ = fixture.Store.PurgeExpiredPartition(fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, partition));
        fixture.SetWallClock(oldTime.AddDays(3));
        Assert.Throws<InvalidOperationException>(() => { adapter.Record(allowed); transferred = true; });
        Assert.False(transferred);

        // A disposed store refuses before any write.
        fixture.SetWallClock(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        fixture.Store.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { adapter.Record(allowed); transferred = true; });
        Assert.False(transferred);

        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit WHERE event_type IN (15,16);";
        Assert.Equal(0L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void EgressFactsRejectUnclassifiedUntypedAndContradictoryInputs()
    {
        using var fixture = new AuditFixture();
        var authority = new Revision(Guid.NewGuid(), new CloudRevision(1));

        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.None, AuditDecisionReason.PolicyAllowed, authority));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateEgressFact((EgressDecisionOutcome)9, AuditDecisionReason.PolicyAllowed, authority));
        Assert.Throws<ArgumentException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyDenied, authority));
        Assert.Throws<ArgumentException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.NotApplicable, authority));
        Assert.Throws<ArgumentException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Denied, AuditDecisionReason.PolicyAllowed, authority));
        Assert.Throws<ArgumentException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Denied, AuditDecisionReason.NotApplicable, authority));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority, dataClass: AuditEgressDataClass.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority, dataClass: (AuditEgressDataClass)99));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority, destinationClass: AuditEgressDestinationClass.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority, destinationClass: (AuditEgressDestinationClass)99));
        Assert.Throws<ArgumentException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, default));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority, risk: (RiskLevel)9));
        Assert.Throws<ArgumentException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority, correlation: default(CorrelationId)));
        Assert.Throws<ArgumentException>(() => fixture.CreateEgressFact(EgressDecisionOutcome.Allowed, AuditDecisionReason.PolicyAllowed, authority, actor: fixture.Actor, software: new AuditSoftwareIdentity("other.software/1")));

        foreach (var invalid in new[] { "https://api.example.com/v1", "Example.COM", "api.example.com/path", "user@example.com", "a b",
                     "api..example.com", "-bad.example.com", "bad-.example.com", "host:0", "host:65536", "host:", "host:1:2", ":443", string.Empty })
        {
            Assert.ThrowsAny<ArgumentException>(() => new AuditEgressDestinationId(invalid));
        }

        Assert.Equal("connector-label", new AuditEgressDestinationId("connector-label").Value);
        Assert.Equal("a.b-c.example:65535", new AuditEgressDestinationId("a.b-c.example:65535").Value);

        // The generic append shape cannot express an egress decision without its typed detail, or the reverse.
        var generic = fixture.CreateEvent();
        var detail = new AuditEgressDetail(AuditEgressDataClass.ManagedAsset, AuditEgressDestinationClass.Public,
            new AuditEgressDestinationId("example.org"), authority);
        var correlation = new CorrelationId(Guid.NewGuid());
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.DataEgressAuthorized, generic.ActorChain,
            generic.SoftwareIdentity, generic.Capability, generic.Resource, AuditRisk.R3, AuditDecision.Allowed,
            AuditDecisionReason.PolicyAllowed, AuditOrigin.Local, correlation: correlation));
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.SecretUsed, generic.ActorChain,
            generic.SoftwareIdentity, generic.Capability, generic.Resource, AuditRisk.R3, AuditDecision.Allowed,
            AuditDecisionReason.PolicyAllowed, AuditOrigin.Local, correlation: correlation, egress: detail));
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.DataEgressAuthorized, generic.ActorChain,
            generic.SoftwareIdentity, generic.Capability, generic.Resource, AuditRisk.R3, AuditDecision.Denied,
            AuditDecisionReason.PolicyDenied, AuditOrigin.Local, correlation: correlation, egress: detail));
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.DataEgressDenied, generic.ActorChain,
            generic.SoftwareIdentity, generic.Capability, generic.Resource, AuditRisk.R3, AuditDecision.Denied,
            AuditDecisionReason.PolicyDenied, AuditOrigin.Local, egress: detail));

        // No transferred content, secret value or property bag is representable by the typed fact.
        var parameterTypes = typeof(EgressDecisionFact).GetConstructors().Single().GetParameters().Select(parameter => parameter.ParameterType);
        Assert.DoesNotContain(parameterTypes, type => type == typeof(string) || type == typeof(object) || type == typeof(byte[])
            || type.IsArray || typeof(System.Collections.IEnumerable).IsAssignableFrom(type));
    }

    [Fact]
    public void CapabilityLeaseLifecycleKindsAppendDurablyAndPreserveTheGuidIdentity()
    {
        using var fixture = new AuditFixture();
        var adapter = new CapabilityLeaseAuditAdapter(fixture.Store);
        var leaseGuid = Guid.NewGuid();
        var lease = new AuditCapabilityLeaseId(leaseGuid);
        var task = new TaskId(Guid.NewGuid());
        (CapabilityLeaseLifecycleKind Kind, AuditDecisionReason Reason, AuditEventType Type, AuditDecision Decision)[] cases =
        [
            (CapabilityLeaseLifecycleKind.Issued, AuditDecisionReason.StepUpSatisfied, AuditEventType.CapabilityLeaseIssued, AuditDecision.Allowed),
            (CapabilityLeaseLifecycleKind.Revoked, AuditDecisionReason.UserRejected, AuditEventType.CapabilityLeaseRevoked, AuditDecision.Completed),
            (CapabilityLeaseLifecycleKind.Expired, AuditDecisionReason.PolicyExpired, AuditEventType.CapabilityLeaseExpired, AuditDecision.Completed),
            (CapabilityLeaseLifecycleKind.TaskEnded, AuditDecisionReason.NotApplicable, AuditEventType.CapabilityLeaseTaskEnded, AuditDecision.Completed),
        ];

        var appended = cases.Select(item => adapter.Record(fixture.CreateLeaseFact(item.Kind, item.Reason, lease, task))).ToArray();
        var otherLeaseGuid = Guid.NewGuid();
        _ = adapter.Record(fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Issued,
            AuditDecisionReason.PolicyAllowed, new AuditCapabilityLeaseId(otherLeaseGuid), task));

        using var independent = fixture.OpenSecondStore();
        var at = appended[0].OccurredAt.ToDateTimeOffset();
        var page = independent.Query(new AuditQuery(at.AddMinutes(-1), at.AddMinutes(1), 100));
        Assert.Equal(5, page.Count);
        for (var index = 0; index < cases.Length; index++)
        {
            var read = page[index];
            Assert.Equal(appended[index].EventId, read.EventId);
            Assert.Equal(cases[index].Type, read.Event.EventType);
            Assert.Equal(cases[index].Decision, read.Event.Decision);
            Assert.Equal(cases[index].Reason, read.Event.Reason);
            Assert.Equal(AuditResourceKind.CapabilityLease, read.Event.Resource.Kind);
            Assert.Equal(leaseGuid, read.Event.Resource.Id);
            Assert.Equal(task, read.Event.Task);
            Assert.Equal(AuditRisk.R2, read.Event.Risk);
            Assert.Null(read.Event.Egress);
        }

        Assert.Equal(otherLeaseGuid, page[4].Event.Resource.Id);
        Assert.NotEqual(leaseGuid, page[4].Event.Resource.Id);

        // The identity is stored as the exact Guid, never stringified, hashed or truncated into another form.
        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit WHERE resource_kind=16 AND resource_id=$id AND event_type IN (41,42,43,44);";
        command.Parameters.AddWithValue("$id", leaseGuid.ToString("N", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(4L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void CapabilityLeaseFactsRejectUnknownKindsEmptyIdentitiesAndContradictoryShapes()
    {
        using var fixture = new AuditFixture();
        var lease = new AuditCapabilityLeaseId(Guid.NewGuid());
        var task = new TaskId(Guid.NewGuid());

        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.None, AuditDecisionReason.PolicyAllowed, lease, task));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateLeaseFact((CapabilityLeaseLifecycleKind)99, AuditDecisionReason.PolicyAllowed, lease, task));
        Assert.Throws<ArgumentException>(() => new AuditCapabilityLeaseId(Guid.Empty));
        Assert.Throws<ArgumentException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Issued, AuditDecisionReason.PolicyAllowed, default, task));
        Assert.Throws<ArgumentException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.TaskEnded, AuditDecisionReason.NotApplicable, lease, null));
        Assert.Throws<ArgumentException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Issued, AuditDecisionReason.NotApplicable, lease, task));
        Assert.Throws<ArgumentException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Issued, AuditDecisionReason.PolicyDenied, lease, task));
        Assert.Throws<ArgumentException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Revoked, AuditDecisionReason.PolicyAllowed, lease, task));
        Assert.Throws<ArgumentException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Expired, AuditDecisionReason.UserRejected, lease, task));
        Assert.Throws<ArgumentException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.TaskEnded, AuditDecisionReason.PolicyExpired, lease, task));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Issued, AuditDecisionReason.PolicyAllowed, lease, task, risk: (RiskLevel)9));

        // The generic append shape cannot misuse a lease event type or the lease resource kind.
        var generic = fixture.CreateEvent();
        var leaseResource = new AuditResourceReference(AuditResourceKind.CapabilityLease, lease.Value);
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.CapabilityLeaseIssued, generic.ActorChain,
            generic.SoftwareIdentity, generic.Capability, generic.Resource, AuditRisk.R2, AuditDecision.Allowed,
            AuditDecisionReason.PolicyAllowed, AuditOrigin.Local));
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.SecretUsed, generic.ActorChain,
            generic.SoftwareIdentity, generic.Capability, leaseResource, AuditRisk.R2, AuditDecision.Allowed,
            AuditDecisionReason.PolicyAllowed, AuditOrigin.Local));
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.CapabilityLeaseExpired, generic.ActorChain,
            generic.SoftwareIdentity, generic.Capability, leaseResource, AuditRisk.R2, AuditDecision.Allowed,
            AuditDecisionReason.PolicyExpired, AuditOrigin.Local));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditEvent((AuditEventType)999, generic.ActorChain,
            generic.SoftwareIdentity, generic.Capability, leaseResource, AuditRisk.R2, AuditDecision.Completed,
            AuditDecisionReason.NotApplicable, AuditOrigin.Local));

        // Nothing was appended by any rejection above.
        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit;";
        Assert.Equal(0L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void RetentionPurgeVerifiesAndCoversTypedEgressAndLeaseRows()
    {
        using var fixture = new AuditFixture();
        var oldTime = new DateTimeOffset(2024, 5, 6, 7, 8, 9, TimeSpan.Zero);
        fixture.SetWallClock(oldTime);
        var egress = new EgressDecisionAuditAdapter(fixture.Store).Record(fixture.CreateEgressFact(EgressDecisionOutcome.Denied,
            AuditDecisionReason.RiskRejected, new Revision(Guid.NewGuid(), new CloudRevision(3))));
        var lease = new CapabilityLeaseAuditAdapter(fixture.Store).Record(fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Expired,
            AuditDecisionReason.PolicyExpired, new AuditCapabilityLeaseId(Guid.NewGuid()), null));
        var partition = AuditPartition.For(fixture.Actor.Owner, oldTime);
        fixture.SetWallClock(oldTime.AddYears(2));

        var receipt = fixture.Store.PurgeExpiredPartition(fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, partition));

        Assert.Equal(2, receipt.EventCount);
        Assert.Equal(egress.Sequence, receipt.FirstEventSequence);
        Assert.Equal(lease.Sequence, receipt.LastEventSequence);
        Assert.Empty(fixture.Store.Query(new AuditQuery(oldTime.AddDays(-1), oldTime.AddMonths(1), 10)));
    }

    [Theory]
    [InlineData(RiskLevel.R0, AuditRisk.R0, 1)]
    [InlineData(RiskLevel.R1, AuditRisk.R1, 2)]
    [InlineData(RiskLevel.R2, AuditRisk.R2, 3)]
    [InlineData(RiskLevel.R3, AuditRisk.R3, 4)]
    [InlineData(RiskLevel.R4, AuditRisk.R4, 5)]
    public void EveryRiskLevelIsStoredAndRoundTrippedLosslesslyThroughBothAdapters(RiskLevel level, AuditRisk expected, int storedValue)
    {
        using var fixture = new AuditFixture();
        var egress = new EgressDecisionAuditAdapter(fixture.Store).Record(fixture.CreateEgressFact(EgressDecisionOutcome.Allowed,
            AuditDecisionReason.PolicyAllowed, new Revision(Guid.NewGuid(), new CloudRevision(2)), risk: level));
        var lease = new CapabilityLeaseAuditAdapter(fixture.Store).Record(fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Issued,
            AuditDecisionReason.PolicyAllowed, new AuditCapabilityLeaseId(Guid.NewGuid()), null, risk: level));

        var at = egress.OccurredAt.ToDateTimeOffset();
        var page = fixture.Store.Query(new AuditQuery(at.AddMinutes(-1), at.AddMinutes(1), 10));
        Assert.Equal(2, page.Count);
        Assert.All(page, record => Assert.Equal(expected, record.Event.Risk));
        Assert.Equal(expected, egress.Event.Risk);
        Assert.Equal(expected, lease.Event.Risk);
        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit WHERE risk=$risk;";
        command.Parameters.AddWithValue("$risk", storedValue);
        Assert.Equal(2L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Every statement is a fixed literal of this test against its own temporary database; no external value is concatenated.")]
    [Fact]
    public void TamperedStoredRowsFailQueryAndPurgeClosedAndLeaveThePartitionUntouched()
    {
        foreach (var tamper in new[]
        {
            "UPDATE local_audit SET egress_destination_id='tampered.example' WHERE event_type=15;",
            "UPDATE local_audit SET egress_authority_revision=99 WHERE event_type=15;",
            "UPDATE local_audit SET egress_data_class=2 WHERE event_type=15;",
            "UPDATE local_audit SET egress_destination_class=4 WHERE event_type=15;",
            "UPDATE local_audit SET risk=1 WHERE event_type=15;",
            "UPDATE local_audit SET decision=2, reason=2 WHERE event_type=15;",
            "UPDATE local_audit SET occurred_unix_seconds=occurred_unix_seconds+1 WHERE event_type=15;",
            "UPDATE local_audit SET policy_id='00000000000000000000000000000001' WHERE event_type=15;",
            "UPDATE local_audit SET executor_id='00000000000000000000000000000001' WHERE event_type=15;",
            "UPDATE local_audit SET partition_month=(partition_month % 12)+1 WHERE event_type=15;",
        })
        {
            using var fixture = new AuditFixture();
            var oldTime = new DateTimeOffset(2024, 2, 3, 4, 5, 6, TimeSpan.Zero);
            fixture.SetWallClock(oldTime);
            _ = new EgressDecisionAuditAdapter(fixture.Store).Record(fixture.CreateEgressFact(EgressDecisionOutcome.Allowed,
                AuditDecisionReason.PolicyAllowed, new Revision(Guid.NewGuid(), new CloudRevision(5))));
            _ = fixture.Store.Append(fixture.CreateEvent());
            var partition = AuditPartition.For(fixture.Actor.Owner, oldTime);
            var pristine = fixture.Store.Query(new AuditQuery(oldTime.AddDays(-1), oldTime.AddMonths(1), 10));
            Assert.Equal(2, pristine.Count);

            // A person controlling the file can drop the trigger; verification must then refuse the altered row.
            using (var connection = fixture.OpenRawConnection())
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "DROP TRIGGER local_audit_no_update;";
                command.ExecuteNonQuery();
                command.CommandText = tamper;
                Assert.Equal(1, command.ExecuteNonQuery());
            }

            Assert.Throws<InvalidDataException>(() => fixture.Store.Query(new AuditQuery(oldTime.AddDays(-1), oldTime.AddMonths(2), 10)));
            fixture.SetWallClock(oldTime.AddYears(2));
            // A row moved to another month is outside this month's digest by construction; its own month
            // refuses it when it is read or purged. Every other alteration blocks this month's purge.
            if (!tamper.Contains("partition_month", StringComparison.Ordinal))
            {
                Assert.Throws<InvalidDataException>(() => fixture.Store.PurgeExpiredPartition(
                    fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, partition)));
            }

            using var check = fixture.OpenRawConnection();
            using var count = check.CreateCommand();
            count.CommandText = "SELECT (SELECT COUNT(*) FROM local_audit),(SELECT COUNT(*) FROM local_audit_purge_receipts),(SELECT COUNT(*) FROM local_audit_authority_receipts);";
            using var reader = count.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(2L, reader.GetInt64(0));
            Assert.Equal(0L, reader.GetInt64(1));
            Assert.Equal(0L, reader.GetInt64(2));
        }
    }

    [Fact]
    public void PurgeReceiptDigestEqualsAnIndependentRecomputationFromTheStoredEventDigests()
    {
        using var fixture = new AuditFixture();
        var oldTime = new DateTimeOffset(2024, 7, 8, 9, 10, 11, TimeSpan.Zero);
        fixture.SetWallClock(oldTime);
        _ = new EgressDecisionAuditAdapter(fixture.Store).Record(fixture.CreateEgressFact(EgressDecisionOutcome.Denied,
            AuditDecisionReason.PolicyDenied, new Revision(Guid.NewGuid(), new CloudRevision(4))));
        _ = new CapabilityLeaseAuditAdapter(fixture.Store).Record(fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Revoked,
            AuditDecisionReason.UserRejected, new AuditCapabilityLeaseId(Guid.NewGuid()), null));
        _ = fixture.Store.Append(fixture.CreateEvent());
        var partition = AuditPartition.For(fixture.Actor.Owner, oldTime);
        var records = fixture.Store.Query(new AuditQuery(oldTime.AddDays(-1), oldTime.AddMonths(1), 10));
        Assert.Equal(3, records.Count);
        Assert.Equal(3, records.Select(record => record.IntegritySha256).Distinct(StringComparer.Ordinal).Count());

        using var aggregate = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        foreach (var record in records)
        {
            var sequence = new byte[sizeof(long)];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(sequence, record.Sequence);
            aggregate.AppendData(sequence);
            aggregate.AppendData(Convert.FromHexString(record.IntegritySha256));
        }

        fixture.SetWallClock(oldTime.AddYears(2));
        var receipt = fixture.Store.PurgeExpiredPartition(fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, partition));
        Assert.Equal(Convert.ToHexString(aggregate.GetHashAndReset()), receipt.EventsSha256);
        Assert.Equal(records[0].Sequence, receipt.FirstEventSequence);
        Assert.Equal(records[^1].Sequence, receipt.LastEventSequence);
        Assert.Equal(3, receipt.EventCount);
    }

    [Fact]
    public void ReopeningWithADifferentOwnerPolicyRetentionOrAForeignDatabaseFailsClosed()
    {
        using var fixture = new AuditFixture();
        fixture.Store.Append(fixture.CreateEvent());
        var realm = fixture.Actor.Owner.Realm;
        var owner = fixture.Actor.Owner.Id;

        using (var same = fixture.OpenWith(realm, owner, fixture.Policy))
        {
            Assert.Single(same.Query(new AuditQuery(fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(1), 10)));
        }

        Assert.Throws<InvalidDataException>(() => fixture.OpenWith(realm, new UserId(Guid.NewGuid()), fixture.Policy));
        Assert.Throws<InvalidDataException>(() => fixture.OpenWith(new RealmId(Guid.NewGuid()), owner, fixture.Policy));
        Assert.Throws<InvalidDataException>(() => fixture.OpenWith(realm, owner, new AuditRetentionPolicy(Guid.NewGuid(), fixture.Policy.RetentionDays)));
        Assert.Throws<InvalidDataException>(() => fixture.OpenWith(realm, owner, new AuditRetentionPolicy(fixture.Policy.PolicyId, fixture.Policy.RetentionDays + 1)));

        var foreign = Path.Combine(Path.GetDirectoryName(fixture.DatabasePath)!, "foreign.db");
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = foreign, Pooling = false }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE unrelated(id INTEGER PRIMARY KEY);";
            command.ExecuteNonQuery();
        }

        Assert.Throws<InvalidDataException>(() => new AuditStore(foreign, realm, owner, fixture.Policy));
        Assert.Throws<ArgumentException>(() => new AuditRetentionPolicy(Guid.Empty, 30));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditRetentionPolicy(Guid.NewGuid(), 0));
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Every statement is a fixed literal of this test against its own temporary database; no external value is concatenated.")]
    [Fact]
    public void RawSqlCannotMutateHoldsReceiptsOrStorePolicyOrForgeRetentionAuthority()
    {
        using var fixture = new AuditFixture();
        var oldTime = new DateTimeOffset(2024, 9, 1, 2, 3, 4, TimeSpan.Zero);
        fixture.SetWallClock(oldTime);
        fixture.Store.Append(fixture.CreateEvent());
        var partition = AuditPartition.For(fixture.Actor.Owner, oldTime);
        var holdId = Guid.NewGuid();
        _ = fixture.Store.PlaceLegalHold(holdId, partition, AuditHoldReason.LegalPreservation, fixture.Actor, fixture.OwnerSoftware, AuditOrigin.Local);
        var otherPartition = AuditPartition.For(fixture.Actor.Owner, oldTime.AddMonths(-3));
        fixture.SetWallClock(otherPartition.StartUtc.AddDays(3));
        fixture.Store.Append(fixture.CreateEvent());
        fixture.SetWallClock(oldTime.AddYears(2));
        _ = fixture.Store.PurgeExpiredPartition(fixture.Capability(AuditMaintenanceAction.PurgeExpiredPartition, otherPartition));
        Assert.Single(fixture.Store.ReadPurgeReceipts());

        using var connection = fixture.OpenRawConnection();
        void Refuses(string sql)
        {
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.Parameters.AddWithValue("$hold", holdId.ToString("N", System.Globalization.CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$actor", ActorChainSnapshot.Encode(fixture.Actor));
            Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
        }

        Refuses("UPDATE local_audit_holds SET reason=2;");
        Refuses("DELETE FROM local_audit_holds;");
        Refuses("UPDATE local_audit_authority_receipts SET action=1;");
        Refuses("DELETE FROM local_audit_authority_receipts;");
        Refuses("UPDATE local_audit_purge_receipts SET event_count=1;");
        Refuses("DELETE FROM local_audit_purge_receipts;");
        Refuses("UPDATE local_audit_store SET retention_days=1;");
        Refuses("DELETE FROM local_audit_store;");
        Refuses("DELETE FROM local_audit_maintenance_gate;");

        // Forged retention authority: a hold release or receipt inserted by an ordinary SQL role is refused.
        Refuses("INSERT INTO local_audit_holds(hold_id,partition_year,partition_month,action,reason,occurred_unix_seconds,occurred_nanoseconds,actor_chain,software_identity,origin,capability_id) VALUES($hold,2024,9,2,1,1,0,$actor,'owned.audit/1',1,NULL);");
        Refuses("INSERT INTO local_audit_authority_receipts(capability_id,action,policy_id,partition_realm,partition_owner,partition_year,partition_month,issued_unix_seconds,issued_nanoseconds,expires_unix_seconds,expires_nanoseconds,hold_id,authority_actor_chain,software_identity) VALUES('00000000000000000000000000000009',2,'00000000000000000000000000000001','00000000000000000000000000000001','00000000000000000000000000000001',2024,9,1,0,2,0,$hold,$actor,'owned.audit/1');");
        Refuses("INSERT INTO local_audit_purge_receipts(capability_id,partition_realm,partition_owner,partition_year,partition_month,purged_unix_seconds,purged_nanoseconds,event_count,first_event_sequence,last_event_sequence,events_sha256) VALUES('00000000000000000000000000000009','00000000000000000000000000000001','00000000000000000000000000000001',2024,9,1,0,1,1,1,'00');");

        Assert.Single(fixture.Store.ReadActiveLegalHolds(partition));
        Assert.Single(fixture.Store.ReadPurgeReceipts());
        Assert.DoesNotContain(fixture.Store.ReadMaintenanceReceipts(), item => item.Action == AuditMaintenanceAction.ReleaseLegalHold);
    }

    private sealed class AuditFixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "ArcForges-Audit-" + Guid.NewGuid().ToString("N"));
        private readonly string databasePath;
        private readonly ManualTimeProvider timeProvider = new(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        private readonly Clock clock;

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
                AuditRisk.R3, AuditDecision.Allowed, AuditDecisionReason.PolicyAllowed, AuditOrigin.Remote,
                new WorkspaceId(Guid.NewGuid()), new TaskId(Guid.NewGuid()), new CorrelationId(Guid.NewGuid()));
        }

        public static ActorChain NewActor(RealmId realm, UserId owner, DelegatedActor[] delegated) =>
            new(new HumanPrincipal(realm, owner, HumanIdentityKind.LocalHuman), new DeviceId(Guid.NewGuid()),
                new InstallationId(Guid.NewGuid()), SessionId.New(), new InstanceId(Guid.NewGuid()), delegated);

        public EgressDecisionFact CreateEgressFact(EgressDecisionOutcome outcome, AuditDecisionReason reason,
            Revision authority, CorrelationId? correlation = null, AuditResourceReference? resource = null,
            AuditEgressDataClass dataClass = AuditEgressDataClass.CanonicalUserData,
            AuditEgressDestinationClass destinationClass = AuditEgressDestinationClass.CloudAiProvider,
            RiskLevel risk = RiskLevel.R3, ActorChain? actor = null, AuditSoftwareIdentity? software = null) =>
            new(outcome, reason, dataClass, destinationClass, new AuditEgressDestinationId("api.provider.example:443"),
                authority, risk, actor ?? MaintenanceActor, software ?? new AuditSoftwareIdentity("arcscope.desktop/1"),
                new AuditCapabilityId("egress.send"), resource ?? new AuditResourceReference(AuditResourceKind.Export, Guid.NewGuid()),
                AuditOrigin.Local, correlation ?? new CorrelationId(Guid.NewGuid()),
                new WorkspaceId(Guid.NewGuid()), new TaskId(Guid.NewGuid()));

        public CapabilityLeaseLifecycleFact CreateLeaseFact(CapabilityLeaseLifecycleKind kind, AuditDecisionReason reason,
            AuditCapabilityLeaseId lease, TaskId? task, RiskLevel risk = RiskLevel.R2) =>
            new(kind, lease, reason, risk, MaintenanceActor, new AuditSoftwareIdentity("arcscope.desktop/1"),
                new AuditCapabilityId("tools.invoke"), AuditOrigin.Local, new WorkspaceId(Guid.NewGuid()), task,
                new CorrelationId(Guid.NewGuid()));

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

        public string DatabasePath => databasePath;

        public AuditStore OpenWith(RealmId realm, UserId owner, AuditRetentionPolicy policy) =>
            new(databasePath, realm, owner, policy, clock);

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
