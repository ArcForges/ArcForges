// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security;
using ArcForges.Security.Audit;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;
using ArcForges.Security.Leases;
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

    // The lease tests below prove the PLT.44 typed lease intake contract and the real PLT.43 manager through its sink.

    // Egress intake: the audit side of the delivered PLT.41 egress port. These tests project real EgressAuditRecord values and also drive
    // the real EgressAuthority against a real AuditStore through EgressAuditSink. They do not run a host composition root.

    private static readonly EgressReason[] EveryRefusal =
    [
        EgressReason.DestinationNotDeclared, EgressReason.DestinationMalformed, EgressReason.ContentUnclassified, EgressReason.SecretMaterial,
        EgressReason.NotAllowlisted, EgressReason.AllowlistMismatch, EgressReason.DataClassAboveAllowlist, EgressReason.AiIneligibleContent,
        EgressReason.NoGrant, EgressReason.GrantExplicitlyDenied, EgressReason.GrantMismatch, EgressReason.GrantOutsideLifetime,
        EgressReason.DataClassAboveGrant, EgressReason.ClassifierUnavailable, EgressReason.AllowlistUnavailable,
        EgressReason.GrantSourceUnavailable, EgressReason.AuditUnavailable,
    ];

    [Fact]
    public void AllowedAndRefusedEgressDecisionsAppendBeforeReturnWithTheProjectedFacts()
    {
        using var fixture = new AuditFixture();
        var adapter = fixture.EgressAdapter();
        var correlation = new CommandId(Guid.NewGuid());
        var resource = new ResourceReference("doc/123", "rev-7");

        foreach (var reason in new[] { EgressReason.None, EgressReason.NotAllowlisted })
        {
            var record = fixture.CreateEgressRecord(reason, correlation: correlation, resource: resource);
            var appended = adapter.Record(record);

            // Durable before Record returned: an independent store over the same file sees exactly this row.
            using var independent = fixture.OpenSecondStore();
            var occurredAt = appended.OccurredAt.ToDateTimeOffset();
            var read = Assert.Single(independent.Query(new AuditQuery(occurredAt.AddMinutes(-1), occurredAt.AddMinutes(1), 10,
                afterSequence: appended.Sequence - 1)));
            Assert.Equal(appended.EventId, read.EventId);
            Assert.Equal(fixture.NowInstant, read.OccurredAt);
            Assert.Equal(AuditRisk.NotAssessed, read.Event.Risk);
            Assert.Equal(new CorrelationId(correlation.Value), read.Event.Correlation);
            Assert.Equal(default(AuditResourceReference), read.Event.Resource);
            Assert.Equal(record.Scope.Workspace, read.Event.Workspace);
            Assert.Equal(AuditOrigin.Local, read.Event.Origin);
            Assert.Equal(new AuditCapabilityId("egress.send"), read.Event.Capability);
            var egress = Assert.IsType<AuditEgressDetail>(read.Event.Egress);
            Assert.Equal(AuditEgressContentReference.From("doc/123", "rev-7"), egress.Content);
            Assert.Equal(64, egress.Content.Value.Length);
            Assert.Equal("api.example.com", egress.Destination!.Value);
            Assert.Equal(AuditEgressDataClass.WorkspaceContent, egress.DataClass);
            if (reason == EgressReason.None)
            {
                Assert.Equal(AuditEventType.DataEgressAuthorized, read.Event.EventType);
                Assert.Equal(AuditDecision.Allowed, read.Event.Decision);
                Assert.Equal(AuditDecisionReason.UserApproved, read.Event.Reason);
                Assert.Equal(AuditEgressReason.Authorized, egress.Reason);
                Assert.Equal(AuditEgressDestinationClass.ThirdParty, egress.DestinationClass);
                Assert.Equal(AuditEgressAuthorityKind.UserConsent, egress.AuthorityKind);
                Assert.Equal("consent-1", egress.AuthorityReference!.Value);
                Assert.Equal("grant-generation-1", egress.GrantGeneration!.Value);
            }
            else
            {
                Assert.Equal(AuditEventType.DataEgressDenied, read.Event.EventType);
                Assert.Equal(AuditDecision.Denied, read.Event.Decision);
                Assert.Equal(AuditDecisionReason.PolicyDenied, read.Event.Reason);
                Assert.Equal(AuditEgressReason.NotAllowlisted, egress.Reason);
                Assert.Equal(AuditEgressDestinationClass.Undetermined, egress.DestinationClass);
                Assert.Equal(AuditEgressAuthorityKind.NoAuthority, egress.AuthorityKind);
                Assert.Null(egress.AuthorityReference);
                Assert.Null(egress.GrantGeneration);
            }

            Assert.Equal(64, read.IntegritySha256.Length);
        }

        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit WHERE resource_kind=0 AND resource_id='' AND risk=6 AND egress_destination_id='api.example.com' AND egress_content_sha256 IS NOT NULL;";
        Assert.Equal(2L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void ADelegatedChainRecordsItsFinalActorAndTheFallbackIdentityIsUsedOnlyForADirectDecision()
    {
        using var fixture = new AuditFixture();
        var adapter = fixture.EgressAdapter();
        var delegated = adapter.Record(fixture.CreateEgressRecord(EgressReason.None, actor: fixture.Actor));
        var direct = adapter.Record(fixture.CreateEgressRecord(EgressReason.None));

        Assert.Equal("owned.audit/1", delegated.Event.SoftwareIdentity.Value);
        Assert.Equal(fixture.Actor.Actors[^1].Executor, delegated.Event.Executor);
        Assert.Equal("arcscope.desktop/1", direct.Event.SoftwareIdentity.Value);
        Assert.Equal(fixture.Actor.CallerInstance, direct.Event.Executor);
    }

    [Fact]
    public void EveryRefusalReasonProjectsWithExplicitMarkersAndNoInventedValue()
    {
        // The expectation is this test's own table of what the PLT.41 authority had determined at each refusal; it is not the
        // production table.
        (AuditEgressReason Egress, AuditDecisionReason Generic, AuditEgressDataClass Data, AuditEgressDestinationClass Class, bool Destination)[] expected =
        [
            (AuditEgressReason.DestinationNotDeclared, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.Unclassified, AuditEgressDestinationClass.Undetermined, true),
            (AuditEgressReason.DestinationMalformed, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.Unclassified, AuditEgressDestinationClass.Undetermined, false),
            (AuditEgressReason.ContentUnclassified, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.Unclassified, AuditEgressDestinationClass.Undetermined, true),
            (AuditEgressReason.SecretMaterial, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.SecretMaterial, AuditEgressDestinationClass.Undetermined, true),
            (AuditEgressReason.NotAllowlisted, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.WorkspaceContent, AuditEgressDestinationClass.Undetermined, true),
            (AuditEgressReason.AllowlistMismatch, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.WorkspaceContent, AuditEgressDestinationClass.Undetermined, true),
            (AuditEgressReason.DataClassAboveAllowlist, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
            (AuditEgressReason.AiIneligibleContent, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
            (AuditEgressReason.NoGrant, AuditDecisionReason.AuthorityMissing, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
            (AuditEgressReason.GrantExplicitlyDenied, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
            (AuditEgressReason.GrantMismatch, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
            (AuditEgressReason.GrantOutsideLifetime, AuditDecisionReason.PolicyExpired, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
            (AuditEgressReason.DataClassAboveGrant, AuditDecisionReason.PolicyDenied, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
            (AuditEgressReason.ClassifierUnavailable, AuditDecisionReason.ResourceUnavailable, AuditEgressDataClass.Unclassified, AuditEgressDestinationClass.Undetermined, true),
            (AuditEgressReason.AllowlistUnavailable, AuditDecisionReason.ResourceUnavailable, AuditEgressDataClass.WorkspaceContent, AuditEgressDestinationClass.Undetermined, true),
            (AuditEgressReason.GrantSourceUnavailable, AuditDecisionReason.ResourceUnavailable, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
            (AuditEgressReason.AuditUnavailable, AuditDecisionReason.ResourceUnavailable, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true),
        ];
        Assert.Equal(EveryRefusal.Length, expected.Length);

        using var fixture = new AuditFixture();
        var adapter = fixture.EgressAdapter();
        for (var index = 0; index < EveryRefusal.Length; index++)
        {
            var reason = EveryRefusal[index];
            var want = expected[index];
            Assert.Equal(reason.ToString(), want.Egress.ToString());
            var appended = adapter.Record(fixture.CreateEgressRecord(reason));
            var at = appended.OccurredAt.ToDateTimeOffset();
            var read = Assert.Single(fixture.Store.Query(new AuditQuery(at.AddMinutes(-1), at.AddMinutes(1), 10, afterSequence: appended.Sequence - 1)));
            var egress = Assert.IsType<AuditEgressDetail>(read.Event.Egress);
            Assert.Equal(AuditEventType.DataEgressDenied, read.Event.EventType);
            Assert.Equal(AuditDecision.Denied, read.Event.Decision);
            Assert.Equal(want.Egress, egress.Reason);
            Assert.Equal(want.Generic, read.Event.Reason);
            Assert.Equal(want.Data, egress.DataClass);
            Assert.Equal(want.Class, egress.DestinationClass);
            Assert.Equal(want.Destination, egress.Destination is not null);
            Assert.Equal(AuditEgressAuthorityKind.NoAuthority, egress.AuthorityKind);
            Assert.Null(egress.AuthorityReference);
            Assert.Null(egress.GrantGeneration);
            Assert.Equal(AuditRisk.NotAssessed, read.Event.Risk);
        }
    }

    [Fact]
    public void EgressAuthorityKindsMapToTheirOwnAllowedReasonAndNeverToAnInventedOne()
    {
        using var fixture = new AuditFixture();
        var adapter = fixture.EgressAdapter();
        foreach (var (kind, auditKind, reason) in new[]
        {
            (EgressAuthorityKind.UserConsent, AuditEgressAuthorityKind.UserConsent, AuditDecisionReason.UserApproved),
            (EgressAuthorityKind.WorkspacePolicy, AuditEgressAuthorityKind.WorkspacePolicy, AuditDecisionReason.PolicyAllowed),
            (EgressAuthorityKind.ProductRoute, AuditEgressAuthorityKind.ProductRoute, AuditDecisionReason.PolicyAllowed),
        })
        {
            var appended = adapter.Record(fixture.CreateEgressRecord(EgressReason.None, authority: kind));
            Assert.Equal(auditKind, appended.Event.Egress!.AuthorityKind);
            Assert.Equal(reason, appended.Event.Reason);
        }
    }

    [Fact]
    public void EgressAppendFailureSurfacesBeforeAnyCallerContinuationAndWritesNothing()
    {
        using var fixture = new AuditFixture();
        var adapter = fixture.EgressAdapter();
        var allowed = fixture.CreateEgressRecord(EgressReason.None);

        // Wrong owner: the store refuses, the call throws, and the code after Record (the transfer) never runs.
        var otherOwner = AuditFixture.NewActor(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()), []);
        var foreign = fixture.CreateEgressRecord(EgressReason.None, actor: otherOwner);
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
    public void ARecordTheClosedShapeCannotHoldIsRefusedAndNothingIsStored()
    {
        using var fixture = new AuditFixture();
        var adapter = fixture.EgressAdapter();
        var allowed = fixture.CreateEgressRecord(EgressReason.None);
        var refused = fixture.CreateEgressRecord(EgressReason.NoGrant);
        var delegated = fixture.CreateEgressRecord(EgressReason.None, actor: fixture.Actor);

        EgressAuditRecord[] unrepresentable =
        [
            allowed with { Kind = EgressAuditKind.None },
            allowed with { Kind = (EgressAuditKind)9 },
            allowed with { Reason = EgressReason.NoGrant },
            allowed with { ReasonCode = "egress.no_grant" },
            allowed with { RegisteredCode = "perm.egress_denied" },
            refused with { ReasonCode = "egress.not_allowlisted" },
            refused with { RegisteredCode = "resource.unavailable" },
            refused with { Reason = EgressReason.None },
            refused with { Reason = (EgressReason)99, ReasonCode = null, RegisteredCode = null },
            refused with { Authority = EgressAuthorityKind.UserConsent },
            refused with { AuthorityReference = "consent-1" },
            refused with { GrantGeneration = "grant-generation-1" },
            refused with { GrantIssuer = "owner.egress" },
            allowed with { Authority = EgressAuthorityKind.None },
            allowed with { Authority = (EgressAuthorityKind)9 },
            allowed with { AuthorityReference = null },
            allowed with { AuthorityReference = new string('r', 257) },
            allowed with { AuthorityReference = "line\nbreak" },
            allowed with { GrantGeneration = null },
            allowed with { DataClass = EgressDataClass.None },
            allowed with { DataClass = EgressDataClass.SecretMaterial },
            allowed with { DataClass = (EgressDataClass)99 },
            allowed with { DestinationClass = EgressDestinationClass.None },
            allowed with { DestinationClass = (EgressDestinationClass)99 },
            allowed with { Destination = null },
            allowed with { Destination = "https://API.example.com" },
            allowed with { Destination = "https://api.example.com/" },
            allowed with { Destination = "https://api.example.com/v1" },
            allowed with { Destination = "http://api.example.com" },
            allowed with { Destination = "api.example.com" },
            allowed with { Destination = "https://localhost" },
            allowed with { CapabilityKey = "Bad Key" },
            allowed with { Origin = DecisionOrigin.None },
            allowed with { Executor = new InstanceId(Guid.NewGuid()) },
            delegated with { SoftwareIdentity = "other.software/1" },
            delegated with { SoftwareIdentity = null },
            fixture.CreateEgressRecord(EgressReason.NoGrant) with { DataClass = EgressDataClass.None },
            fixture.CreateEgressRecord(EgressReason.NoGrant) with { DestinationClass = EgressDestinationClass.None },
            fixture.CreateEgressRecord(EgressReason.NoGrant) with { Destination = null },
            fixture.CreateEgressRecord(EgressReason.NotAllowlisted) with { DestinationClass = EgressDestinationClass.ThirdParty },
            fixture.CreateEgressRecord(EgressReason.ContentUnclassified) with { DataClass = EgressDataClass.Public },
            fixture.CreateEgressRecord(EgressReason.SecretMaterial) with { DataClass = EgressDataClass.WorkspaceContent },
            fixture.CreateEgressRecord(EgressReason.NoGrant) with { DataClass = EgressDataClass.SecretMaterial },
            fixture.CreateEgressRecord(EgressReason.DestinationMalformed) with { Destination = "https://api.example.com" },
        ];

        foreach (var record in unrepresentable)
        {
            Assert.ThrowsAny<ArgumentException>(() => adapter.Record(record));
        }

        Assert.Throws<ArgumentNullException>(() => adapter.Record(null!));
        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit;";
        Assert.Equal(0L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void TheEgressShapeRefusesInventedOrContradictoryDetailAndOnlyEgressMayLeaveRiskUnassessed()
    {
        using var fixture = new AuditFixture();
        var generic = fixture.CreateEvent();
        var content = AuditEgressContentReference.From("doc/1", "rev-1");
        var destination = new AuditEgressDestinationId("example.org");
        var consent = new AuditReferenceText("consent-1");
        var generation = new AuditReferenceText("generation-1");
        var correlation = new CorrelationId(Guid.NewGuid());

        AuditEgressDetail Allowed(AuditEgressDataClass data = AuditEgressDataClass.Public,
            AuditEgressDestinationClass destinationClass = AuditEgressDestinationClass.Public) =>
            new(AuditEgressReason.Authorized, data, destinationClass, destination, AuditEgressAuthorityKind.UserConsent, consent, generation, content);

        AuditEvent Event(AuditEventType type, AuditDecision decision, AuditDecisionReason reason, AuditEgressDetail? detail,
            AuditRisk risk = AuditRisk.NotAssessed, AuditResourceReference? resource = null, CorrelationId? withCorrelation = null) =>
            new(type, generic.ActorChain, generic.SoftwareIdentity, generic.Capability, resource ?? default, risk, decision, reason,
                AuditOrigin.Local, correlation: withCorrelation ?? correlation, egress: detail);

        // The exact valid shapes, including every supplied risk level and the explicit marker.
        foreach (var risk in new[] { AuditRisk.NotAssessed, AuditRisk.R0, AuditRisk.R1, AuditRisk.R2, AuditRisk.R3, AuditRisk.R4 })
        {
            _ = Event(AuditEventType.DataEgressAuthorized, AuditDecision.Allowed, AuditDecisionReason.UserApproved, Allowed(), risk);
        }

        // Wrong event type, decision or generic reason for the detail.
        Assert.Throws<ArgumentException>(() => Event(AuditEventType.DataEgressDenied, AuditDecision.Denied, AuditDecisionReason.PolicyDenied, Allowed()));
        Assert.Throws<ArgumentException>(() => Event(AuditEventType.DataEgressAuthorized, AuditDecision.Denied, AuditDecisionReason.UserApproved, Allowed()));
        Assert.Throws<ArgumentException>(() => Event(AuditEventType.DataEgressAuthorized, AuditDecision.Allowed, AuditDecisionReason.PolicyAllowed, Allowed()));
        Assert.Throws<ArgumentException>(() => Event(AuditEventType.DataEgressAuthorized, AuditDecision.Allowed, AuditDecisionReason.UserApproved, null));
        Assert.Throws<ArgumentException>(() => Event(AuditEventType.SecretUsed, AuditDecision.Allowed, AuditDecisionReason.PolicyAllowed, Allowed(),
            resource: generic.Resource));
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.DataEgressAuthorized, generic.ActorChain, generic.SoftwareIdentity,
            generic.Capability, default, AuditRisk.NotAssessed, AuditDecision.Allowed, AuditDecisionReason.UserApproved, AuditOrigin.Local, egress: Allowed()));
        Assert.Throws<ArgumentException>(() => Event(AuditEventType.DataEgressAuthorized, AuditDecision.Allowed, AuditDecisionReason.UserApproved,
            Allowed(), resource: generic.Resource));

        // The marker is only for egress; every other event type states a real risk.
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.SecretUsed, generic.ActorChain, generic.SoftwareIdentity,
            generic.Capability, generic.Resource, AuditRisk.NotAssessed, AuditDecision.Allowed, AuditDecisionReason.PolicyAllowed, AuditOrigin.Local));
        Assert.Throws<ArgumentException>(() => new AuditEvent(AuditEventType.CapabilityLeaseIssued, generic.ActorChain, generic.SoftwareIdentity,
            new AuditCapabilityId("tools.invoke"), new AuditResourceReference(AuditResourceKind.CapabilityLease, Guid.NewGuid()),
            AuditRisk.NotAssessed, AuditDecision.Allowed, AuditDecisionReason.PolicyAllowed, AuditOrigin.Local));

        // Detail combinations the decision could not produce.
        Assert.Throws<ArgumentException>(() => Allowed(AuditEgressDataClass.Unclassified));
        Assert.Throws<ArgumentException>(() => Allowed(AuditEgressDataClass.SecretMaterial));
        Assert.Throws<ArgumentException>(() => Allowed(destinationClass: AuditEgressDestinationClass.Undetermined));
        Assert.Throws<ArgumentException>(() => new AuditEgressDetail(AuditEgressReason.Authorized, AuditEgressDataClass.Public,
            AuditEgressDestinationClass.Public, null, AuditEgressAuthorityKind.UserConsent, consent, generation, content));
        Assert.Throws<ArgumentException>(() => new AuditEgressDetail(AuditEgressReason.Authorized, AuditEgressDataClass.Public,
            AuditEgressDestinationClass.Public, destination, AuditEgressAuthorityKind.NoAuthority, consent, generation, content));
        Assert.Throws<ArgumentException>(() => new AuditEgressDetail(AuditEgressReason.NoGrant, AuditEgressDataClass.Public,
            AuditEgressDestinationClass.Public, destination, AuditEgressAuthorityKind.UserConsent, consent, generation, content));
        Assert.Throws<ArgumentException>(() => new AuditEgressDetail(AuditEgressReason.NoGrant, AuditEgressDataClass.Public,
            AuditEgressDestinationClass.Undetermined, destination, AuditEgressAuthorityKind.NoAuthority, null, null, content));
        Assert.Throws<ArgumentException>(() => new AuditEgressDetail(AuditEgressReason.DestinationMalformed, AuditEgressDataClass.Unclassified,
            AuditEgressDestinationClass.Undetermined, destination, AuditEgressAuthorityKind.NoAuthority, null, null, content));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditEgressDetail(AuditEgressReason.None, AuditEgressDataClass.Public,
            AuditEgressDestinationClass.Public, destination, AuditEgressAuthorityKind.UserConsent, consent, generation, content));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuditEgressDetail((AuditEgressReason)99, AuditEgressDataClass.Public,
            AuditEgressDestinationClass.Public, destination, AuditEgressAuthorityKind.UserConsent, consent, generation, content));
        Assert.Throws<ArgumentNullException>(() => new AuditEgressDetail(AuditEgressReason.Authorized, AuditEgressDataClass.Public,
            AuditEgressDestinationClass.Public, destination, AuditEgressAuthorityKind.UserConsent, consent, generation, null!));

        // Bounded references and the content fingerprint.
        Assert.Throws<ArgumentException>(() => new AuditReferenceText(string.Empty));
        Assert.Throws<ArgumentException>(() => new AuditReferenceText(new string('a', 257)));
        Assert.Throws<ArgumentException>(() => new AuditReferenceText("tab\there"));
        Assert.Equal(256, new AuditReferenceText(new string('a', 256)).Value.Length);
        Assert.Throws<ArgumentException>(() => new AuditEgressContentReference(new string('a', 64)));
        Assert.Throws<ArgumentException>(() => new AuditEgressContentReference(new string('A', 63)));
        Assert.Throws<ArgumentException>(() => new AuditEgressContentReference(new string('G', 64)));
        Assert.NotEqual(AuditEgressContentReference.From("a", "bc"), AuditEgressContentReference.From("ab", "c"));
        Assert.NotEqual(AuditEgressContentReference.From("doc/1", "rev-1"), AuditEgressContentReference.From("doc/1", "rev-2"));
        Assert.NotEqual(AuditEgressContentReference.From("doc/1", "rev-1"), AuditEgressContentReference.From("doc/2", "rev-1"));
        Assert.Equal(AuditEgressContentReference.From("doc/1", "rev-1"), AuditEgressContentReference.From("doc/1", "rev-1"));
        Assert.Throws<ArgumentException>(() => AuditEgressContentReference.From(string.Empty, "rev-1"));

        foreach (var invalid in new[] { "https://api.example.com/v1", "Example.COM", "api.example.com/path", "user@example.com", "a b",
                     "api..example.com", "-bad.example.com", "bad-.example.com", "host:0", "host:65536", "host:", "host:1:2", ":443", string.Empty })
        {
            Assert.ThrowsAny<ArgumentException>(() => new AuditEgressDestinationId(invalid));
        }

        Assert.Equal("connector-label", new AuditEgressDestinationId("connector-label").Value);
        Assert.Equal("a.b-c.example:65535", new AuditEgressDestinationId("a.b-c.example:65535").Value);

        // No transferred content, secret value, path or property bag is representable by the typed detail.
        var parameterTypes = typeof(AuditEgressDetail).GetConstructors().Single().GetParameters().Select(parameter => parameter.ParameterType);
        Assert.DoesNotContain(parameterTypes, type => type == typeof(string) || type == typeof(object) || type == typeof(byte[])
            || type.IsArray || typeof(System.Collections.IEnumerable).IsAssignableFrom(type));
    }

    [Fact]
    public async Task TheRealEgressAuthorityAuditsAllowedAndRefusedDecisionsThroughTheDurableSink()
    {
        using var fixture = new AuditFixture();
        var rig = new EgressRig(fixture);
        var request = rig.Request();
        rig.Permit(request);

        var allowed = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);
        Assert.True(allowed.Allowed);

        // Refusals before classification: malformed destination, a destination the invocation did not declare, an unavailable
        // classifier, content the classifier cannot name, and secret material.
        var malformed = await rig.Authority.DecideAsync(request, "http://not-https.example.com", TestContext.Current.CancellationToken);
        var undeclared = await rig.Authority.DecideAsync(request, "https://other.example.com", TestContext.Current.CancellationToken);
        rig.Classifier = (_, _, _) => throw new InvalidOperationException("classifier down");
        var unavailable = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);
        rig.Classifier = (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(null);
        var unclassified = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);
        rig.Classifier = (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(new EgressContentFacts(EgressDataClass.SecretMaterial, false));
        var secret = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);

        // After classification: not allowlisted, and content above the grant.
        rig.Classifier = (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(new EgressContentFacts(EgressDataClass.WorkspaceContent, true));
        rig.Allowlist = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(null);
        var notListed = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);
        rig.Permit(request);
        rig.Classifier = (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(new EgressContentFacts(EgressDataClass.SensitiveContent, true));
        rig.Allowlist = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressRig.Entry(request, EgressDataClass.SensitiveContent));
        var aboveGrant = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);

        Assert.Equal(EgressReason.DestinationMalformed, malformed.Reason);
        Assert.Equal(EgressReason.DestinationNotDeclared, undeclared.Reason);
        Assert.Equal(EgressReason.ClassifierUnavailable, unavailable.Reason);
        Assert.Equal(EgressReason.ContentUnclassified, unclassified.Reason);
        Assert.Equal(EgressReason.SecretMaterial, secret.Reason);
        Assert.Equal(EgressReason.NotAllowlisted, notListed.Reason);
        Assert.Equal(EgressReason.DataClassAboveGrant, aboveGrant.Reason);

        var rows = fixture.Store.Query(new AuditQuery(fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(1), 50));
        Assert.Equal(8, rows.Count);
        Assert.All(rows, row => Assert.Equal(new CorrelationId(request.CommandId.Value), row.Event.Correlation));
        Assert.All(rows, row => Assert.Equal(AuditRisk.NotAssessed, row.Event.Risk));
        Assert.All(rows, row => Assert.Equal("owned.audit/1", row.Event.SoftwareIdentity.Value));
        Assert.All(rows, row => Assert.Equal(AuditEgressContentReference.From("doc/123", "rev-7"), row.Event.Egress!.Content));

        void Check(int index, AuditEventType type, AuditEgressReason reason, AuditEgressDataClass data, AuditEgressDestinationClass destinationClass, bool destination)
        {
            Assert.Equal(type, rows[index].Event.EventType);
            var detail = rows[index].Event.Egress!;
            Assert.Equal(reason, detail.Reason);
            Assert.Equal(data, detail.DataClass);
            Assert.Equal(destinationClass, detail.DestinationClass);
            Assert.Equal(destination, detail.Destination is not null);
        }

        Check(0, AuditEventType.DataEgressAuthorized, AuditEgressReason.Authorized, AuditEgressDataClass.WorkspaceContent, AuditEgressDestinationClass.ThirdParty, true);
        Assert.Equal("consent-1", rows[0].Event.Egress!.AuthorityReference!.Value);
        Assert.Equal("grant-generation-1", rows[0].Event.Egress!.GrantGeneration!.Value);
        Assert.Equal("api.example.com", rows[0].Event.Egress!.Destination!.Value);
        Check(1, AuditEventType.DataEgressDenied, AuditEgressReason.DestinationMalformed, AuditEgressDataClass.Unclassified, AuditEgressDestinationClass.Undetermined, false);
        Check(2, AuditEventType.DataEgressDenied, AuditEgressReason.DestinationNotDeclared, AuditEgressDataClass.Unclassified, AuditEgressDestinationClass.Undetermined, true);
        Check(3, AuditEventType.DataEgressDenied, AuditEgressReason.ClassifierUnavailable, AuditEgressDataClass.Unclassified, AuditEgressDestinationClass.Undetermined, true);
        Check(4, AuditEventType.DataEgressDenied, AuditEgressReason.ContentUnclassified, AuditEgressDataClass.Unclassified, AuditEgressDestinationClass.Undetermined, true);
        Check(5, AuditEventType.DataEgressDenied, AuditEgressReason.SecretMaterial, AuditEgressDataClass.SecretMaterial, AuditEgressDestinationClass.Undetermined, true);
        Check(6, AuditEventType.DataEgressDenied, AuditEgressReason.NotAllowlisted, AuditEgressDataClass.WorkspaceContent, AuditEgressDestinationClass.Undetermined, true);
        Check(7, AuditEventType.DataEgressDenied, AuditEgressReason.DataClassAboveGrant, AuditEgressDataClass.SensitiveContent, AuditEgressDestinationClass.ThirdParty, true);
    }

    [Fact]
    public async Task AnAuditFailureRefusesAnAllowedTransferAndLeavesNoRowWhileARefusalKeepsItsOwnReason()
    {
        using var fixture = new AuditFixture();
        var rig = new EgressRig(fixture);
        var request = rig.Request();
        rig.Permit(request);
        fixture.Store.Dispose();

        // The sink throws; the authority refuses the transfer instead of releasing it unaudited.
        var allowed = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);
        Assert.False(allowed.Allowed);
        Assert.Equal(EgressReason.AuditUnavailable, allowed.Reason);
        Assert.Equal("resource.unavailable", allowed.RegisteredCode);

        // A refusal stays the refusal it was; PLT.41 does not retry its audit write, so it has no row either.
        rig.Allowlist = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(null);
        var refused = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);
        Assert.Equal(EgressReason.NotAllowlisted, refused.Reason);

        using var independent = fixture.OpenSecondStore();
        Assert.Empty(independent.Query(new AuditQuery(fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(1), 10)));
    }

    [Fact]
    public async Task ALateAuthorizedWriteAfterATimeoutLandsBesideTheRefusalAndAuthorizesNothing()
    {
        using var fixture = new AuditFixture();
        var gate = new TaskCompletionSource();
        var landed = new TaskCompletionSource();
        var gated = new GatedSink(new EgressAuditSink(fixture.EgressAdapter()), gate.Task, landed);
        var rig = new EgressRig(fixture, gated, new EgressAuthorityOptions { StepTimeout = TimeSpan.FromMilliseconds(150) });
        var request = rig.Request();
        rig.Permit(request);

        var decision = await rig.Authority.DecideAsync(request, EgressRig.Destination, TestContext.Current.CancellationToken);

        Assert.False(decision.Allowed);
        Assert.Equal(EgressReason.AuditUnavailable, decision.Reason);
        Assert.Empty(fixture.Store.Query(new AuditQuery(fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(1), 10)));

        gate.SetResult();
        await landed.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        var row = Assert.Single(fixture.Store.Query(new AuditQuery(fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(1), 10)));
        Assert.Equal(AuditEventType.DataEgressAuthorized, row.Event.EventType);
        Assert.Equal(AuditEgressReason.Authorized, row.Event.Egress!.Reason);
        Assert.False(decision.Allowed);
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Every statement is a fixed literal of this test against its own temporary database; no external value is concatenated.")]
    [Fact]
    public async Task AVersionOneFileOrAnEgressRowWithATypedResourceIsRefusedClosed()
    {
        using var fixture = new AuditFixture();
        fixture.Store.Dispose();
        using (var connection = fixture.OpenRawConnection())
        using (var command = connection.CreateCommand())
        {
            // A person controlling the file can drop the trigger; the version check then refuses the file at open.
            command.CommandText = "DROP TRIGGER local_audit_store_no_update; UPDATE local_audit_store SET schema_version=1;";
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        Assert.Throws<InvalidDataException>(() => fixture.OpenSecondStore());

        using var other = new AuditFixture();
        await new EgressAuditSink(other.EgressAdapter()).WriteAsync(other.CreateEgressRecord(EgressReason.None), TestContext.Current.CancellationToken);
        using (var connection = other.OpenRawConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "DROP TRIGGER local_audit_no_update;";
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
            // The table constraint refuses a typed resource on an egress row.
            command.CommandText = "UPDATE local_audit SET resource_kind=7, resource_id='00000000000000000000000000000001' WHERE event_type=15;";
            await Assert.ThrowsAnyAsync<SqliteException>(() => command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        }
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
        var egress = fixture.EgressAdapter().Record(fixture.CreateEgressRecord(EgressReason.NoGrant));
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
        // The delivered PLT.41 record carries no risk, so a supplied R0-R4 reaches the egress shape through the event itself.
        var template = fixture.EgressAdapter().Record(fixture.CreateEgressRecord(EgressReason.None));
        var egress = fixture.Store.Append(new AuditEvent(AuditEventType.DataEgressAuthorized, template.Event.ActorChain,
            template.Event.SoftwareIdentity, template.Event.Capability, default, expected, AuditDecision.Allowed,
            AuditDecisionReason.UserApproved, AuditOrigin.Local, correlation: template.Event.Correlation, egress: template.Event.Egress));
        var lease = new CapabilityLeaseAuditAdapter(fixture.Store).Record(fixture.CreateLeaseFact(CapabilityLeaseLifecycleKind.Issued,
            AuditDecisionReason.PolicyAllowed, new AuditCapabilityLeaseId(Guid.NewGuid()), null, risk: level));

        var at = egress.OccurredAt.ToDateTimeOffset();
        var page = fixture.Store.Query(new AuditQuery(at.AddMinutes(-1), at.AddMinutes(1), 10, afterSequence: template.Sequence));
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
            "UPDATE local_audit SET egress_authority_ref='tampered-consent' WHERE event_type=15;",
            "UPDATE local_audit SET egress_grant_generation='tampered' WHERE event_type=15;",
            "UPDATE local_audit SET egress_content_sha256='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE event_type=15;",
            "UPDATE local_audit SET egress_data_class=3 WHERE event_type=15;",
            "UPDATE local_audit SET egress_destination_class=4 WHERE event_type=15;",
            "UPDATE local_audit SET egress_authority_kind=3 WHERE event_type=15;",
            "UPDATE local_audit SET egress_reason=6, decision=2, reason=2, event_type=16 WHERE event_type=15;",
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
            _ = fixture.EgressAdapter().Record(fixture.CreateEgressRecord(EgressReason.None));
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
        _ = fixture.EgressAdapter().Record(fixture.CreateEgressRecord(EgressReason.NotAllowlisted));
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

    [Fact]
    public async Task TheRealLeaseManagerWritesEveryLifecycleFactIntoTheDurableAuditWithTheStableIdentity()
    {
        using var fixture = new AuditFixture();
        var leases = new LeaseRig(fixture);
        var cancellation = TestContext.Current.CancellationToken;

        var issuedOnly = await leases.IssueAsync(LeaseIssueBasis.StepUpSatisfied, RiskLevel.R3, cancellation);
        var revoked = await leases.IssueAsync(LeaseIssueBasis.PolicyAllowed, RiskLevel.R1, cancellation);
        var expiring = await leases.IssueAsync(LeaseIssueBasis.RiskAccepted, RiskLevel.R2, cancellation, TimeSpan.FromMinutes(5));
        var ended = await leases.IssueAsync(LeaseIssueBasis.UserApproved, RiskLevel.R4, cancellation);

        var revocation = await leases.Manager.RevokeAsync(revoked.Id, fixture.Actor.Owner, LeaseRevocationReason.OwnerRevoked, cancellation);
        Assert.True(revocation.TryGetValue(out var transition));
        Assert.True(transition.Changed);
        Assert.True(transition.EndRecorded);

        var ending = await leases.Manager.EndTaskAsync(ended.Task, cancellation);
        Assert.Equal(new LeaseSweep(1, 1, 0), ending);

        leases.Advance(TimeSpan.FromMinutes(6));
        var sweep = await leases.Manager.ExpireDueAsync(cancellation);
        Assert.Equal(new LeaseSweep(1, 1, 0), sweep);

        // Re-running the sweeps writes nothing more: each lease ends exactly once and its fact is recorded exactly once.
        Assert.Equal(new LeaseSweep(0, 0, 0), await leases.Manager.ExpireDueAsync(cancellation));
        Assert.Equal(new LeaseSweep(0, 0, 0), await leases.Manager.EndTaskAsync(ended.Task, cancellation));

        using var independent = fixture.OpenSecondStore();
        var rows = ReadAll(independent, fixture);
        var byLease = rows.GroupBy(row => row.Event.Resource.Id).ToDictionary(group => group.Key, group => group.OrderBy(row => row.Sequence).ToArray());
        Assert.Equal(4, byLease.Count);
        Assert.Equal(7, rows.Count);
        Assert.All(rows, row =>
        {
            Assert.Equal(AuditResourceKind.CapabilityLease, row.Event.Resource.Kind);
            Assert.Equal(fixture.Actor.Owner, row.Event.ActorChain.Owner);
            Assert.Equal(new AuditCapabilityId("tools.invoke"), row.Event.Capability);
            Assert.Equal(AuditOrigin.Remote, row.Event.Origin);
            Assert.Equal(leases.Workspace, row.Event.Workspace);
            Assert.Null(row.Event.Egress);
            Assert.Null(row.Event.Correlation);
        });

        var first = byLease[issuedOnly.Id.Value];
        var firstRow = Assert.Single(first);
        Assert.Equal(AuditEventType.CapabilityLeaseIssued, firstRow.Event.EventType);
        Assert.Equal(AuditDecision.Allowed, firstRow.Event.Decision);
        Assert.Equal(AuditDecisionReason.StepUpSatisfied, firstRow.Event.Reason);
        Assert.Equal(AuditRisk.R3, firstRow.Event.Risk);
        Assert.Equal(issuedOnly.Task, firstRow.Event.Task);
        Assert.Equal(new AuditSoftwareIdentity("arcscope.desktop/1"), firstRow.Event.SoftwareIdentity);

        var revokedRows = byLease[revoked.Id.Value];
        Assert.Equal([AuditEventType.CapabilityLeaseIssued, AuditEventType.CapabilityLeaseRevoked], revokedRows.Select(row => row.Event.EventType));
        Assert.Equal([AuditDecisionReason.PolicyAllowed, AuditDecisionReason.UserRejected], revokedRows.Select(row => row.Event.Reason));
        Assert.Equal([AuditDecision.Allowed, AuditDecision.Completed], revokedRows.Select(row => row.Event.Decision));
        Assert.All(revokedRows, row => Assert.Equal(AuditRisk.R1, row.Event.Risk));

        var expiredRows = byLease[expiring.Id.Value];
        Assert.Equal([AuditEventType.CapabilityLeaseIssued, AuditEventType.CapabilityLeaseExpired], expiredRows.Select(row => row.Event.EventType));
        Assert.Equal([AuditDecisionReason.RiskAccepted, AuditDecisionReason.PolicyExpired], expiredRows.Select(row => row.Event.Reason));
        Assert.All(expiredRows, row => Assert.Equal(AuditRisk.R2, row.Event.Risk));

        var endedRows = byLease[ended.Id.Value];
        Assert.Equal([AuditEventType.CapabilityLeaseIssued, AuditEventType.CapabilityLeaseTaskEnded], endedRows.Select(row => row.Event.EventType));
        Assert.Equal([AuditDecisionReason.UserApproved, AuditDecisionReason.NotApplicable], endedRows.Select(row => row.Event.Reason));
        Assert.All(endedRows, row =>
        {
            Assert.Equal(AuditRisk.R4, row.Event.Risk);
            Assert.Equal(ended.Task, row.Event.Task);
        });

        // The identity is stored as the exact Guid of the manager's lease, not a string, hash or truncation.
        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit WHERE resource_kind=16 AND resource_id=$id;";
        command.Parameters.AddWithValue("$id", revoked.Id.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(2L, Convert.ToInt64(await command.ExecuteScalarAsync(cancellation), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task AnIssueWhoseFactCannotBeAppendedIssuesNothingAndAnOwedEndFactIsAppendedOnceWhenAuditRecovers()
    {
        using var fixture = new AuditFixture();
        var leases = new LeaseRig(fixture);
        var cancellation = TestContext.Current.CancellationToken;

        leases.AuditDown = true;
        var refused = await leases.Manager.IssueAsync(leases.Request(LeaseIssueBasis.UserApproved, RiskLevel.R1, TimeSpan.FromMinutes(30)), cancellation);
        Assert.False(refused.Issued);
        Assert.Equal(LeaseIssueRefusal.AuditUnavailable, refused.Refusal);
        Assert.Empty(leases.Store.All);
        Assert.Empty(ReadAll(fixture.Store, fixture));

        leases.AuditDown = false;
        var lease = await leases.IssueAsync(LeaseIssueBasis.UserApproved, RiskLevel.R1, cancellation);
        Assert.Single(ReadAll(fixture.Store, fixture));

        // Revocation is stored first, so authority ends although the audit write fails; the fact is owed, not lost.
        leases.AuditDown = true;
        var revocation = await leases.Manager.RevokeAsync(lease.Id, fixture.Actor.Owner, LeaseRevocationReason.AuthorityLost, cancellation);
        Assert.True(revocation.TryGetValue(out var transition));
        Assert.True(transition.Changed);
        Assert.False(transition.EndRecorded);
        Assert.Equal(LeaseState.Revoked, transition.Lease.State);
        Assert.Single(ReadAll(fixture.Store, fixture));
        Assert.Equal(new LeaseSweep(0, 0, 1), await leases.Manager.ExpireDueAsync(cancellation));

        leases.AuditDown = false;
        Assert.Equal(new LeaseSweep(0, 1, 0), await leases.Manager.ExpireDueAsync(cancellation));
        var rows = ReadAll(fixture.Store, fixture);
        Assert.Equal(2, rows.Count);
        Assert.Equal(AuditEventType.CapabilityLeaseRevoked, rows[1].Event.EventType);
        Assert.Equal(AuditDecisionReason.AuthorityMissing, rows[1].Event.Reason);
        Assert.Equal(lease.Id.Value, rows[1].Event.Resource.Id);
        Assert.Equal(new LeaseSweep(0, 0, 0), await leases.Manager.ExpireDueAsync(cancellation));
        Assert.Equal(2, ReadAll(fixture.Store, fixture).Count);
    }

    [Fact]
    public async Task AFactTheAuditShapeCannotHoldFailsTheRealIssueClosedAndLeavesNoRowAndNoLease()
    {
        using var fixture = new AuditFixture();
        var cancellation = TestContext.Current.CancellationToken;

        // A capability key that the audit does not accept as a canonical key refuses the issue instead of storing a different key.
        var leases = new LeaseRig(fixture, capability: "Tools/Invoke");
        var badKey = await leases.Manager.IssueAsync(leases.Request(LeaseIssueBasis.UserApproved, RiskLevel.R1, TimeSpan.FromMinutes(30)), cancellation);
        Assert.Equal(LeaseIssueRefusal.AuditUnavailable, badKey.Refusal);
        Assert.Empty(leases.Store.All);

        // A lease of another owner than the store's owner is refused by the store (owner scoping), so no foreign lease is audited.
        var foreign = new LeaseRig(fixture, owner: new HumanPrincipal(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()), HumanIdentityKind.LocalHuman));
        var foreignIssue = await foreign.Manager.IssueAsync(foreign.Request(LeaseIssueBasis.UserApproved, RiskLevel.R1, TimeSpan.FromMinutes(30)), cancellation);
        Assert.Equal(LeaseIssueRefusal.AuditUnavailable, foreignIssue.Refusal);
        Assert.Empty(foreign.Store.All);

        // A disposed store fails closed too.
        var disposed = new LeaseRig(fixture);
        fixture.Store.Dispose();
        var disposedIssue = await disposed.Manager.IssueAsync(disposed.Request(LeaseIssueBasis.UserApproved, RiskLevel.R1, TimeSpan.FromMinutes(30)), cancellation);
        Assert.Equal(LeaseIssueRefusal.AuditUnavailable, disposedIssue.Refusal);
        Assert.Empty(disposed.Store.All);

        using var reopened = fixture.OpenSecondStore();
        Assert.Empty(ReadAll(reopened, fixture));
    }

    [Fact]
    public async Task EveryIssueBasisAndRevocationReasonMapsToItsOwnAuditReasonAndOnlyTheSinkEntryPointExists()
    {
        using var fixture = new AuditFixture();
        var sink = new CapabilityLeaseEventAuditSink(new CapabilityLeaseAuditAdapter(fixture.Store), new AuditSoftwareIdentity("arcscope.desktop/1"));
        var now = fixture.NowInstant;
        var cancellation = TestContext.Current.CancellationToken;

        (LeaseIssueBasis Basis, AuditDecisionReason Reason)[] bases =
        [
            (LeaseIssueBasis.PolicyAllowed, AuditDecisionReason.PolicyAllowed),
            (LeaseIssueBasis.UserApproved, AuditDecisionReason.UserApproved),
            (LeaseIssueBasis.StepUpSatisfied, AuditDecisionReason.StepUpSatisfied),
            (LeaseIssueBasis.RiskAccepted, AuditDecisionReason.RiskAccepted),
        ];
        (LeaseRevocationReason Reason, AuditDecisionReason Expected)[] revocations =
        [
            (LeaseRevocationReason.OwnerRevoked, AuditDecisionReason.UserRejected),
            (LeaseRevocationReason.PolicyDenied, AuditDecisionReason.PolicyDenied),
            (LeaseRevocationReason.RiskRejected, AuditDecisionReason.RiskRejected),
            (LeaseRevocationReason.AuthorityLost, AuditDecisionReason.AuthorityMissing),
        ];

        var expected = new List<(Guid Lease, AuditEventType Type, AuditDecisionReason Reason, AuditRisk Risk)>();
        RiskLevel[] risks = [RiskLevel.R0, RiskLevel.R1, RiskLevel.R2, RiskLevel.R3, RiskLevel.R4];
        var index = 0;
        foreach (var (basis, reason) in bases)
        {
            var risk = risks[index++ % risks.Length];
            var lease = LeaseOf(fixture, basis, risk, LeaseState.Active);
            await sink.WriteAsync(new CapabilityLeaseEvent(LeaseEventKind.Issued, lease, now), cancellation);
            expected.Add((lease.Id.Value, AuditEventType.CapabilityLeaseIssued, reason, RiskOf(risk)));
        }

        foreach (var (revocation, reason) in revocations)
        {
            var risk = risks[index++ % risks.Length];
            var endedLease = LeaseOf(fixture, LeaseIssueBasis.UserApproved, risk, LeaseState.Revoked, revocation);
            await sink.WriteAsync(new CapabilityLeaseEvent(LeaseEventKind.Revoked, endedLease, now), cancellation);
            expected.Add((endedLease.Id.Value, AuditEventType.CapabilityLeaseRevoked, reason, RiskOf(risk)));
        }

        var expiredLease = LeaseOf(fixture, LeaseIssueBasis.UserApproved, RiskLevel.R2, LeaseState.Expired);
        await sink.WriteAsync(new CapabilityLeaseEvent(LeaseEventKind.Expired, expiredLease, now), cancellation);
        expected.Add((expiredLease.Id.Value, AuditEventType.CapabilityLeaseExpired, AuditDecisionReason.PolicyExpired, AuditRisk.R2));
        var taskEndedLease = LeaseOf(fixture, LeaseIssueBasis.UserApproved, RiskLevel.R2, LeaseState.TaskEnded);
        await sink.WriteAsync(new CapabilityLeaseEvent(LeaseEventKind.TaskEnded, taskEndedLease, now), cancellation);
        expected.Add((taskEndedLease.Id.Value, AuditEventType.CapabilityLeaseTaskEnded, AuditDecisionReason.NotApplicable, AuditRisk.R2));

        var rows = ReadAll(fixture.Store, fixture);
        Assert.Equal(expected.Count, rows.Count);
        for (var row = 0; row < expected.Count; row++)
        {
            Assert.Equal(expected[row].Lease, rows[row].Event.Resource.Id);
            Assert.Equal(expected[row].Type, rows[row].Event.EventType);
            Assert.Equal(expected[row].Reason, rows[row].Event.Reason);
            Assert.Equal(expected[row].Risk, rows[row].Event.Risk);
        }

        // A null fact and a pre-cancelled call append nothing, and the constructor refuses missing collaborators.
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await sink.WriteAsync(null!, cancellation).ConfigureAwait(false));
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var again = LeaseOf(fixture, LeaseIssueBasis.UserApproved, RiskLevel.R1, LeaseState.Active);
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await sink.WriteAsync(new CapabilityLeaseEvent(LeaseEventKind.Issued, again, now), cancelled.Token).ConfigureAwait(false));
        Assert.Equal(expected.Count, ReadAll(fixture.Store, fixture).Count);
        Assert.Throws<ArgumentNullException>(() => new CapabilityLeaseEventAuditSink(null!, new AuditSoftwareIdentity("arcscope.desktop/1")));
        Assert.Throws<ArgumentNullException>(() => new CapabilityLeaseEventAuditSink(new CapabilityLeaseAuditAdapter(fixture.Store), null!));
    }

    [Fact]
    public async Task ADelegatedIssuingChainRecordsItsFinalActorSoftwareIdentityAndTheFallbackIsUsedOnlyForADirectIssue()
    {
        using var fixture = new AuditFixture();
        var sink = new CapabilityLeaseEventAuditSink(new CapabilityLeaseAuditAdapter(fixture.Store), new AuditSoftwareIdentity("fallback.composition/1"));
        var now = fixture.NowInstant;
        var automation = new DelegatedActor(ActorKind.Automation, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), "owned.automation/2");
        var chain = new ActorChain(fixture.Actor.Owner, fixture.Actor.Device, fixture.Actor.Installation, SessionId.New(), fixture.Actor.CallerInstance, [automation]);
        var delegated = LeaseOf(fixture, LeaseIssueBasis.PolicyAllowed, RiskLevel.R1, LeaseState.Active, issuedBy: chain);
        var direct = LeaseOf(fixture, LeaseIssueBasis.PolicyAllowed, RiskLevel.R1, LeaseState.Active);

        await sink.WriteAsync(new CapabilityLeaseEvent(LeaseEventKind.Issued, delegated, now), TestContext.Current.CancellationToken);
        await sink.WriteAsync(new CapabilityLeaseEvent(LeaseEventKind.Issued, direct, now), TestContext.Current.CancellationToken);

        var rows = ReadAll(fixture.Store, fixture);
        Assert.Equal(new AuditSoftwareIdentity("owned.automation/2"), rows[0].Event.SoftwareIdentity);
        Assert.Equal(automation.Executor, rows[0].Event.Executor);
        Assert.Equal(new AuditSoftwareIdentity("fallback.composition/1"), rows[1].Event.SoftwareIdentity);
        Assert.Equal(direct.IssuedBy.CallerInstance, rows[1].Event.Executor);
    }

    private static List<AuditEventRecord> ReadAll(AuditStore store, AuditFixture fixture)
    {
        var from = fixture.Now.AddDays(-1);
        var to = fixture.Now.AddDays(1);
        var all = new List<AuditEventRecord>();
        long after = 0;
        while (true)
        {
            var page = store.Query(new AuditQuery(from, to, 100, afterSequence: after));
            if (page.Count == 0) return all;
            all.AddRange(page);
            after = page[^1].Sequence;
        }
    }

    private static AuditRisk RiskOf(RiskLevel level) => level switch
    {
        RiskLevel.R0 => AuditRisk.R0,
        RiskLevel.R1 => AuditRisk.R1,
        RiskLevel.R2 => AuditRisk.R2,
        RiskLevel.R3 => AuditRisk.R3,
        RiskLevel.R4 => AuditRisk.R4,
        _ => throw new ArgumentOutOfRangeException(nameof(level)),
    };

    private static CapabilityLease LeaseOf(AuditFixture fixture, LeaseIssueBasis basis, RiskLevel risk, LeaseState state,
        LeaseRevocationReason revocation = LeaseRevocationReason.None, ActorChain? issuedBy = null)
    {
        var chain = issuedBy ?? new ActorChain(fixture.Actor.Owner, fixture.Actor.Device, fixture.Actor.Installation,
            SessionId.New(), fixture.Actor.CallerInstance, []);
        var terminal = state != LeaseState.Active;
        return new CapabilityLease(new CapabilityLeaseId(Guid.NewGuid()), fixture.Actor.Owner,
            new DecisionScope(fixture.Actor.Owner.Realm, new WorkspaceId(Guid.NewGuid())), new TaskId(Guid.NewGuid()),
            new LeaseHolder(ActorKind.Extension, Guid.NewGuid()), "tools.invoke", ["resource/1"], risk, DecisionOrigin.Local, basis,
            chain, fixture.NowInstant, Instant.FromDateTimeOffset(fixture.Now.AddMinutes(30)), state, terminal ? 2 : 1,
            terminal ? Instant.FromDateTimeOffset(fixture.Now.AddMinutes(1)) : null, revocation);
    }

    // Retention runner: the production entry to policy-governed purge. Proved offline against a real store with the store's own
    // manual clock; no host composition root calls it.

    private static readonly DateTimeOffset RunnerNow = new(2024, 12, 20, 0, 0, 0, TimeSpan.Zero);

    private static AuditPartition MonthOf(AuditFixture fixture, DateTimeOffset when) => AuditPartition.For(fixture.Actor.Owner, when);

    private static void AppendAt(AuditFixture fixture, DateTimeOffset when, int count = 1)
    {
        fixture.SetWallClock(when);
        for (var index = 0; index < count; index++) fixture.Store.Append(fixture.CreateEvent());
    }

    private static int CountRows(AuditFixture fixture, AuditPartition partition)
    {
        using var connection = fixture.OpenRawConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM local_audit WHERE partition_year=$year AND partition_month=$month;";
        command.Parameters.AddWithValue("$year", partition.Year);
        command.Parameters.AddWithValue("$month", partition.Month);
        return checked((int)Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void TheRunnerPurgesOnlyExpiredUnheldMonthsUnderTheDeclaredPolicyAndNothingElse()
    {
        using var fixture = new AuditFixture();
        var expired = new DateTimeOffset(2024, 3, 10, 1, 2, 3, TimeSpan.Zero);
        var held = new DateTimeOffset(2024, 4, 10, 1, 2, 3, TimeSpan.Zero);
        var notYetExpired = new DateTimeOffset(2024, 11, 15, 1, 2, 3, TimeSpan.Zero);
        AppendAt(fixture, expired, 3);
        AppendAt(fixture, held, 2);
        var holdId = Guid.NewGuid();
        _ = fixture.Store.PlaceLegalHold(holdId, MonthOf(fixture, held), AuditHoldReason.LegalPreservation,
            fixture.MaintenanceActor, fixture.MaintenanceSoftware, AuditOrigin.Local);
        AppendAt(fixture, notYetExpired, 4);
        AppendAt(fixture, RunnerNow, 5);
        var runner = fixture.Runner();

        var first = runner.RunOnce(TestContext.Current.CancellationToken);

        Assert.False(first.MoreExpiredMonthsRemain);
        Assert.Equal(2, first.Partitions.Count);
        Assert.Equal(MonthOf(fixture, expired), first.Partitions[0].Partition);
        Assert.Equal(AuditRetentionOutcome.Purged, first.Partitions[0].Outcome);
        Assert.Equal(3, first.Partitions[0].Receipt!.EventCount);
        Assert.Equal(MonthOf(fixture, held), first.Partitions[1].Partition);
        Assert.Equal(AuditRetentionOutcome.SkippedHeld, first.Partitions[1].Outcome);
        Assert.Null(first.Partitions[1].Receipt);
        Assert.Equal(1, first.PurgedCount);
        Assert.Equal(0, CountRows(fixture, MonthOf(fixture, expired)));
        Assert.Equal(2, CountRows(fixture, MonthOf(fixture, held)));
        Assert.Equal(4, CountRows(fixture, MonthOf(fixture, notYetExpired)));
        Assert.Equal(5, CountRows(fixture, MonthOf(fixture, RunnerNow)));

        // The purge is audited by its authority and purge receipts, bound to the maintenance chain and software identity.
        var receipt = Assert.Single(fixture.Store.ReadPurgeReceipts());
        Assert.Equal(first.Partitions[0].Receipt!.EventsSha256, receipt.EventsSha256);
        Assert.Equal(fixture.MaintenanceActor.CallerInstance, receipt.Authority.AuthorityActor.CallerInstance);
        Assert.Equal(fixture.MaintenanceSoftware, receipt.Authority.SoftwareIdentity);
        Assert.Equal(AuditMaintenanceAction.PurgeExpiredPartition, receipt.Authority.Action);

        // A second run finds the purged month empty and the held month still held: nothing changes.
        var second = runner.RunOnce(TestContext.Current.CancellationToken);
        Assert.Equal(0, second.PurgedCount);
        Assert.Equal(AuditRetentionOutcome.SkippedHeld, Assert.Single(second.Partitions).Outcome);
        Assert.Equal(2, CountRows(fixture, MonthOf(fixture, held)));

        // Releasing the hold (the internal authority) lets the next run purge the month.
        _ = fixture.Store.ReleaseLegalHold(fixture.Capability(AuditMaintenanceAction.ReleaseLegalHold, MonthOf(fixture, held), holdId));
        var third = runner.RunOnce(TestContext.Current.CancellationToken);
        Assert.Equal(AuditRetentionOutcome.Purged, Assert.Single(third.Partitions).Outcome);
        Assert.Equal(0, CountRows(fixture, MonthOf(fixture, held)));
        Assert.Equal(4, CountRows(fixture, MonthOf(fixture, notYetExpired)));
        Assert.Equal(5, CountRows(fixture, MonthOf(fixture, RunnerNow)));
        Assert.Equal(2, fixture.Store.ReadPurgeReceipts().Count);
    }

    [Fact]
    public void TheRunnerPurgesAtTheExactPolicyBoundaryAndNeverEarlier()
    {
        using var fixture = new AuditFixture();
        AppendAt(fixture, new DateTimeOffset(2024, 5, 10, 0, 0, 0, TimeSpan.Zero));
        var month = MonthOf(fixture, new DateTimeOffset(2024, 5, 10, 0, 0, 0, TimeSpan.Zero));
        var runner = fixture.Runner();

        // Month end (2024-06-01) plus the 30 retention days is 2024-07-01T00:00:00Z.
        fixture.SetWallClock(new DateTimeOffset(2024, 6, 30, 23, 59, 59, TimeSpan.Zero));
        Assert.Empty(runner.RunOnce(TestContext.Current.CancellationToken).Partitions);
        Assert.Equal(1, CountRows(fixture, month));

        fixture.SetWallClock(new DateTimeOffset(2024, 7, 1, 0, 0, 0, TimeSpan.Zero));
        var result = runner.RunOnce(TestContext.Current.CancellationToken);
        Assert.Equal(AuditRetentionOutcome.Purged, Assert.Single(result.Partitions).Outcome);
        Assert.Equal(0, CountRows(fixture, month));
    }

    [Fact]
    public void TheRunnerAcceptsNoCallerChosenPartitionTimeOrCapability()
    {
        var methods = typeof(AuditRetentionRunner).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        var run = Assert.Single(methods);
        Assert.Equal("RunOnce", run.Name);
        Assert.Equal([typeof(CancellationToken)], run.GetParameters().Select(parameter => parameter.ParameterType));
        var constructor = Assert.Single(typeof(AuditRetentionRunner).GetConstructors());
        Assert.Equal([typeof(AuditStore), typeof(ActorChain), typeof(AuditSoftwareIdentity)],
            constructor.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.DoesNotContain(typeof(AuditRetentionRunner).GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static),
            field => !field.IsLiteral);
        Assert.DoesNotContain(typeof(AuditRetentionRunner).GetProperties(BindingFlags.Public | BindingFlags.Instance), property => property.CanWrite);
    }

    [Fact]
    public void TheRunnerRefusesAnotherOwnersChainAMismatchedIdentityAndNullsAndDeletesNothing()
    {
        using var fixture = new AuditFixture();
        AppendAt(fixture, new DateTimeOffset(2024, 3, 10, 0, 0, 0, TimeSpan.Zero));
        var month = MonthOf(fixture, new DateTimeOffset(2024, 3, 10, 0, 0, 0, TimeSpan.Zero));
        fixture.SetWallClock(RunnerNow);
        var otherOwner = AuditFixture.NewActor(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()), []);
        var sameRealmOtherUser = AuditFixture.NewActor(fixture.Actor.Owner.Realm, new UserId(Guid.NewGuid()), []);

        Assert.Throws<UnauthorizedAccessException>(() => new AuditRetentionRunner(fixture.Store, otherOwner, fixture.MaintenanceSoftware));
        Assert.Throws<UnauthorizedAccessException>(() => new AuditRetentionRunner(fixture.Store, sameRealmOtherUser, fixture.MaintenanceSoftware));
        Assert.Throws<ArgumentException>(() => new AuditRetentionRunner(fixture.Store, fixture.Actor, fixture.MaintenanceSoftware));
        Assert.Throws<ArgumentNullException>(() => new AuditRetentionRunner(null!, fixture.MaintenanceActor, fixture.MaintenanceSoftware));
        Assert.Throws<ArgumentNullException>(() => new AuditRetentionRunner(fixture.Store, null!, fixture.MaintenanceSoftware));
        Assert.Throws<ArgumentNullException>(() => new AuditRetentionRunner(fixture.Store, fixture.MaintenanceActor, null!));
        Assert.Equal(1, CountRows(fixture, month));

        // A delegated chain with its own identity is accepted and recorded as the authority.
        var delegated = new AuditRetentionRunner(fixture.Store, fixture.Actor, fixture.OwnerSoftware);
        var result = delegated.RunOnce(TestContext.Current.CancellationToken);
        Assert.Equal(AuditRetentionOutcome.Purged, Assert.Single(result.Partitions).Outcome);
        Assert.Equal(fixture.Actor.Actors[^1].Executor, Assert.Single(fixture.Store.ReadPurgeReceipts()).Authority.AuthorityActor.Actors[^1].Executor);
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Every statement is a fixed literal of this test against its own temporary database; no external value is concatenated.")]
    [Fact]
    public void ACorruptMonthFailsVerificationAloneAndNeverBlocksOrDeletesAnyOtherMonth()
    {
        using var fixture = new AuditFixture();
        var corrupt = new DateTimeOffset(2024, 3, 10, 0, 0, 0, TimeSpan.Zero);
        var healthy = new DateTimeOffset(2024, 4, 10, 0, 0, 0, TimeSpan.Zero);
        AppendAt(fixture, corrupt, 2);
        AppendAt(fixture, healthy, 2);
        AppendAt(fixture, RunnerNow, 1);
        using (var connection = fixture.OpenRawConnection())
        using (var command = connection.CreateCommand())
        {
            // A person controlling the file can drop the trigger; verification must then refuse the altered month.
            command.CommandText = "DROP TRIGGER local_audit_no_update; UPDATE local_audit SET risk=1 WHERE partition_month=3 AND sequence=(SELECT MIN(sequence) FROM local_audit WHERE partition_month=3);";
            command.ExecuteNonQuery();
        }

        var result = fixture.Runner().RunOnce(TestContext.Current.CancellationToken);

        Assert.Equal(2, result.Partitions.Count);
        Assert.Equal(AuditRetentionOutcome.FailedVerification, result.Partitions[0].Outcome);
        Assert.Equal(AuditRetentionOutcome.Purged, result.Partitions[1].Outcome);
        Assert.Equal(2, CountRows(fixture, MonthOf(fixture, corrupt)));
        Assert.Equal(0, CountRows(fixture, MonthOf(fixture, healthy)));
        Assert.Equal(1, CountRows(fixture, MonthOf(fixture, RunnerNow)));
        Assert.Single(fixture.Store.ReadPurgeReceipts());
        Assert.Single(fixture.Store.ReadMaintenanceReceipts());
    }

    [Fact]
    public void EveryMonthGetsItsOwnSingleUseCapabilityAndAuthorityReceipt()
    {
        using var fixture = new AuditFixture();
        var months = new[] { new DateTimeOffset(2024, 1, 5, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2024, 2, 5, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2024, 3, 5, 0, 0, 0, TimeSpan.Zero) };
        foreach (var month in months) AppendAt(fixture, month);
        fixture.SetWallClock(RunnerNow);

        var result = fixture.Runner().RunOnce(TestContext.Current.CancellationToken);

        Assert.Equal(3, result.PurgedCount);
        Assert.Equal(months.Select(month => MonthOf(fixture, month)), result.Partitions.Select(partition => partition.Partition));
        var receipts = fixture.Store.ReadMaintenanceReceipts();
        Assert.Equal(3, receipts.Count);
        Assert.Equal(3, receipts.Select(receipt => receipt.CapabilityId).Distinct().Count());
        Assert.Equal(3, receipts.Select(receipt => receipt.Partition).Distinct().Count());
        Assert.All(receipts, receipt => Assert.Equal(AuditMaintenanceAction.PurgeExpiredPartition, receipt.Action));
        Assert.All(receipts, receipt => Assert.Equal(fixture.Policy.PolicyId, receipt.PolicyId));
        Assert.Equal(3, fixture.Store.ReadPurgeReceipts().Count);
    }

    [Fact]
    public async Task ConcurrentWritersLoseNoRowsWhileTheRunnerPurgesAndTwoRunnersPurgeEachMonthOnce()
    {
        using var fixture = new AuditFixture();
        AppendAt(fixture, new DateTimeOffset(2024, 3, 10, 0, 0, 0, TimeSpan.Zero), 3);
        AppendAt(fixture, new DateTimeOffset(2024, 4, 10, 0, 0, 0, TimeSpan.Zero), 3);
        fixture.SetWallClock(RunnerNow);
        using var second = fixture.OpenSecondStore();
        var firstRunner = fixture.Runner();
        var secondRunner = new AuditRetentionRunner(second, fixture.MaintenanceActor, fixture.MaintenanceSoftware);
        var token = TestContext.Current.CancellationToken;

        var writers = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (var index = 0; index < 25; index++) fixture.Store.Append(fixture.CreateEvent());
        }, token)).ToArray();
        var firstRun = Task.Run(() => firstRunner.RunOnce(token), token);
        var secondRun = Task.Run(() => secondRunner.RunOnce(token), token);
        await Task.WhenAll(writers);
        var runs = new[] { await firstRun.ConfigureAwait(true), await secondRun.ConfigureAwait(true) };

        // Every concurrent append survived, both expired months are gone, and each was purged by exactly one run.
        Assert.Equal(200, CountRows(fixture, MonthOf(fixture, RunnerNow)));
        Assert.Equal(0, CountRows(fixture, MonthOf(fixture, new DateTimeOffset(2024, 3, 10, 0, 0, 0, TimeSpan.Zero))));
        Assert.Equal(0, CountRows(fixture, MonthOf(fixture, new DateTimeOffset(2024, 4, 10, 0, 0, 0, TimeSpan.Zero))));
        Assert.Equal(2, runs.Sum(run => run.PurgedCount));
        Assert.Equal(2, fixture.Store.ReadPurgeReceipts().Count);
        Assert.All(runs.SelectMany(run => run.Partitions),
            result => Assert.True(result.Outcome is AuditRetentionOutcome.Purged or AuditRetentionOutcome.Refused));
        var rows = fixture.Store.Query(new AuditQuery(RunnerNow.AddDays(-1), RunnerNow.AddDays(1), 1000));
        Assert.Equal(200, rows.Count);
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Every statement is a fixed literal of this test against its own temporary database; no external value is concatenated.")]
    [Fact]
    public void AuditStaysImmutableThroughRetentionAndTheMaintenanceGateIsClosedAfterARun()
    {
        using var fixture = new AuditFixture();
        AppendAt(fixture, new DateTimeOffset(2024, 3, 10, 0, 0, 0, TimeSpan.Zero), 2);
        AppendAt(fixture, RunnerNow, 2);
        var result = fixture.Runner().RunOnce(TestContext.Current.CancellationToken);
        Assert.Equal(1, result.PurgedCount);

        using var connection = fixture.OpenRawConnection();
        foreach (var statement in new[]
        {
            "DELETE FROM local_audit;",
            "DELETE FROM local_audit WHERE partition_month=12;",
            "UPDATE local_audit SET risk=1;",
            "UPDATE local_audit_maintenance_gate SET enabled=1;",
            "DELETE FROM local_audit_purge_receipts;",
            "DELETE FROM local_audit_authority_receipts;",
        })
        {
            using var command = connection.CreateCommand();
            command.CommandText = statement;
            Assert.ThrowsAny<SqliteException>(() => command.ExecuteNonQuery());
        }

        using var check = connection.CreateCommand();
        check.CommandText = "SELECT (SELECT enabled FROM local_audit_maintenance_gate),(SELECT COUNT(*) FROM local_audit),(SELECT COUNT(*) FROM local_audit_purge_receipts);";
        using var reader = check.ExecuteReader();
        Assert.True(reader.Read());
        Assert.Equal(0L, reader.GetInt64(0));
        Assert.Equal(2L, reader.GetInt64(1));
        Assert.Equal(1L, reader.GetInt64(2));
    }

    [Fact]
    public void TheRunnerFailsClosedForACancelledTokenADisposedStoreAndANothingToDoStore()
    {
        using var fixture = new AuditFixture();
        var empty = fixture.Runner().RunOnce(TestContext.Current.CancellationToken);
        Assert.Empty(empty.Partitions);
        Assert.False(empty.MoreExpiredMonthsRemain);

        var old = new DateTimeOffset(2024, 3, 10, 0, 0, 0, TimeSpan.Zero);
        AppendAt(fixture, old);
        fixture.SetWallClock(RunnerNow);
        var runner = fixture.Runner();
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            Assert.Throws<OperationCanceledException>(() => runner.RunOnce(cancelled.Token));
        }

        Assert.Equal(1, CountRows(fixture, MonthOf(fixture, old)));
        fixture.Store.Dispose();
        Assert.Throws<ObjectDisposedException>(() => runner.RunOnce(TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ABacklogLargerThanOneRunIsFinishedByFurtherRunsAndNeverSkipsAMonth()
    {
        using var fixture = new AuditFixture();
        var first = new DateTimeOffset(2000, 1, 15, 0, 0, 0, TimeSpan.Zero);
        const int months = AuditRetentionRunner.MaximumMonthsPerRun + 1;
        for (var index = 0; index < months; index++) AppendAt(fixture, first.AddMonths(index));
        fixture.SetWallClock(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var runner = fixture.Runner();

        var one = runner.RunOnce(TestContext.Current.CancellationToken);
        Assert.Equal(AuditRetentionRunner.MaximumMonthsPerRun, one.PurgedCount);
        Assert.True(one.MoreExpiredMonthsRemain);
        Assert.Equal(MonthOf(fixture, first), one.Partitions[0].Partition);

        var two = runner.RunOnce(TestContext.Current.CancellationToken);
        Assert.Equal(1, two.PurgedCount);
        Assert.False(two.MoreExpiredMonthsRemain);
        Assert.Equal(MonthOf(fixture, first.AddMonths(months - 1)), Assert.Single(two.Partitions).Partition);
        Assert.Equal(months, fixture.Store.ReadPurgeReceipts(1000).Count);
    }

    /// <summary>The real lease manager over an in-memory lease store, with the audit sink under test as its only event sink.</summary>
    private sealed class LeaseRig
    {
        private readonly AuditFixture fixture;
        private readonly string capability;
        private readonly HumanPrincipal owner;
        private readonly SwitchableSink sink;

        public LeaseRig(AuditFixture fixture, string capability = "tools.invoke", HumanPrincipal? owner = null)
        {
            this.fixture = fixture;
            this.capability = capability;
            this.owner = owner ?? fixture.Actor.Owner;
            Workspace = new WorkspaceId(Guid.NewGuid());
            Scope = new DecisionScope(this.owner.Realm, Workspace);
            Store = new InMemoryLeaseStore();
            sink = new SwitchableSink(new CapabilityLeaseEventAuditSink(new CapabilityLeaseAuditAdapter(fixture.Store),
                new AuditSoftwareIdentity("arcscope.desktop/1")));
            Manager = new CapabilityLeaseManager(fixture.Clock, Store, sink, new Ceilings(fixture));
        }

        public bool AuditDown
        {
            get => sink.Down;
            set => sink.Down = value;
        }

        public WorkspaceId Workspace { get; }
        public DecisionScope Scope { get; }
        public InMemoryLeaseStore Store { get; }
        public CapabilityLeaseManager Manager { get; }

        public void Advance(TimeSpan duration)
        {
            fixture.AdvanceMonotonic(duration);
            fixture.AdvanceWallOnly(duration);
        }

        public LeaseRequest Request(LeaseIssueBasis basis, RiskLevel risk, TimeSpan lifetime) => new(
            new ActorChain(owner, fixture.Actor.Device, fixture.Actor.Installation, SessionId.New(), fixture.Actor.CallerInstance, []),
            Scope, new TaskId(Guid.NewGuid()), new LeaseHolder(ActorKind.Extension, Guid.NewGuid()), capability,
            ["resource/1"], risk, DecisionOrigin.Remote, basis, lifetime);

        public async Task<CapabilityLease> IssueAsync(LeaseIssueBasis basis, RiskLevel risk, CancellationToken cancellationToken,
            TimeSpan? lifetime = null)
        {
            var result = await Manager.IssueAsync(Request(basis, risk, lifetime ?? TimeSpan.FromMinutes(30)), cancellationToken).ConfigureAwait(false);
            Assert.True(result.Issued, result.Refusal.ToString());
            return result.Lease!;
        }

        private sealed class SwitchableSink(ILeaseEventSink inner) : ILeaseEventSink
        {
            public bool Down { get; set; }

            public ValueTask WriteAsync(CapabilityLeaseEvent leaseEvent, CancellationToken cancellationToken)
            {
                if (Down) throw new InvalidOperationException("audit offline");
                return inner.WriteAsync(leaseEvent, cancellationToken);
            }
        }

        private sealed class Ceilings(AuditFixture fixture) : ILeaseCeilingSource
        {
            public ValueTask<PermissionGrantRecord?> FindAsync(string principalKey, string capabilityKey, string scopeKey, CancellationToken cancellationToken) =>
                ValueTask.FromResult<PermissionGrantRecord?>(new PermissionGrantRecord("owner.test", principalKey, capabilityKey, scopeKey,
                    PermissionGrantState.Granted, [], fixture.Now.AddHours(-1), fixture.Now.AddHours(20), "generation-1"));
        }
    }

    /// <summary>A minimal durable-store stand-in with the lease store contract: insert-if-absent and compare-and-swap on the version.</summary>
    private sealed class InMemoryLeaseStore : ILeaseStore
    {
        private readonly Lock gate = new();
        private readonly Dictionary<CapabilityLeaseId, CapabilityLease> leases = [];

        public IReadOnlyList<CapabilityLease> All
        {
            get
            {
                lock (gate) return [.. leases.Values];
            }
        }

        public ValueTask<CapabilityLease?> ReadAsync(CapabilityLeaseId id, CancellationToken cancellationToken)
        {
            lock (gate) return ValueTask.FromResult(leases.GetValueOrDefault(id));
        }

        public ValueTask<bool> TryCreateAsync(CapabilityLease lease, CancellationToken cancellationToken)
        {
            lock (gate) return ValueTask.FromResult(leases.TryAdd(lease.Id, lease));
        }

        public ValueTask<bool> TryReplaceAsync(CapabilityLeaseId id, long expectedVersion, CapabilityLease replacement, CancellationToken cancellationToken)
        {
            lock (gate)
            {
                if (!leases.TryGetValue(id, out var current) || current.Version != expectedVersion) return ValueTask.FromResult(false);
                leases[id] = replacement;
                return ValueTask.FromResult(true);
            }
        }

        public ValueTask<IReadOnlyList<CapabilityLease>> ListUnsettledAsync(TaskId? task, Instant? dueAt, int limit, CancellationToken cancellationToken)
        {
            lock (gate)
            {
                IReadOnlyList<CapabilityLease> result =
                [
                    .. leases.Values
                        .Where(lease => task is null || lease.Task == task)
                        .Where(lease => lease.State == LeaseState.Active ? dueAt is null || lease.ExpiresAt <= dueAt : !lease.EndEventRecorded)
                        .OrderBy(lease => lease.IssuedAt.UnixSeconds).ThenBy(lease => lease.Id.Value)
                        .Take(limit),
                ];
                return ValueTask.FromResult(result);
            }
        }
    }

    /// <summary>The real egress authority over controllable sources, with the audit sink under test as its sink.</summary>
    private sealed class EgressRig
    {
        public const string Destination = "https://api.example.com";
        private readonly AuditFixture fixture;

        public EgressRig(AuditFixture fixture, IEgressAuditSink? sink = null, EgressAuthorityOptions? options = null)
        {
            this.fixture = fixture;
            Authority = new EgressAuthority(fixture.Clock, new RigClassifier(this), new RigAllowlist(this), new RigGrants(this),
                sink ?? new EgressAuditSink(fixture.EgressAdapter()), options);
        }

        public EgressAuthority Authority { get; }

        public Func<DecisionRequest, EgressDestinationIdentity, CancellationToken, ValueTask<EgressContentFacts?>> Classifier { get; set; } =
            (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(new EgressContentFacts(EgressDataClass.WorkspaceContent, true));

        public Func<string, EgressDestinationIdentity, CancellationToken, ValueTask<EgressAllowlistEntry?>> Allowlist { get; set; } =
            (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(null);

        public Func<DecisionRequest, EgressDestinationIdentity, CancellationToken, ValueTask<IReadOnlyList<EgressGrantRecord>>> Grants { get; set; } =
            (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([]);

        public DecisionRequest Request(string? destination = Destination) => new(
            fixture.Actor, "egress.send", new DecisionScope(fixture.Actor.Owner.Realm, new WorkspaceId(Guid.NewGuid())),
            new CommandId(Guid.NewGuid()), new ResourceReference("doc/123", "rev-7"), new string('A', 64), DecisionOrigin.Local,
            TransportSessions.InProcess, egressDestination: destination);

        public static EgressAllowlistEntry Entry(DecisionRequest request, EgressDataClass max) =>
            new(request.ScopeKey, EgressDestinationIdentity.Parse(Destination), EgressDestinationClass.ThirdParty, max, "allowlist-generation-1");

        public void Permit(DecisionRequest request)
        {
            var entry = Entry(request, EgressDataClass.WorkspaceContent);
            var grant = new EgressGrantRecord("owner.egress", request.PrincipalKey, request.CapabilityKey, request.ScopeKey,
                EgressDestinationIdentity.Parse(Destination), EgressGrantState.Granted, EgressDataClass.WorkspaceContent,
                EgressAuthorityKind.UserConsent, "consent-1", fixture.Now.AddHours(-1), fixture.Now.AddHours(1), "grant-generation-1");
            Allowlist = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(entry);
            Grants = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([grant]);
        }

        private sealed class RigClassifier(EgressRig rig) : IEgressContentClassifier
        {
            public ValueTask<EgressContentFacts?> ClassifyAsync(DecisionRequest request, EgressDestinationIdentity destination, CancellationToken cancellationToken) =>
                rig.Classifier(request, destination, cancellationToken);
        }

        private sealed class RigAllowlist(EgressRig rig) : IEgressAllowlist
        {
            public ValueTask<EgressAllowlistEntry?> FindAsync(string scopeKey, EgressDestinationIdentity destination, CancellationToken cancellationToken) =>
                rig.Allowlist(scopeKey, destination, cancellationToken);
        }

        private sealed class RigGrants(EgressRig rig) : IEgressGrantSource
        {
            public ValueTask<IReadOnlyList<EgressGrantRecord>> FindAsync(DecisionRequest request, EgressDestinationIdentity destination, CancellationToken cancellationToken) =>
                rig.Grants(request, destination, cancellationToken);
        }
    }

    /// <summary>A sink that holds a write until released and ignores cancellation, so the authority's step timeout fires first.</summary>
    private sealed class GatedSink(IEgressAuditSink inner, Task gate, TaskCompletionSource landed) : IEgressAuditSink
    {
        public async ValueTask WriteAsync(EgressAuditRecord record, CancellationToken cancellationToken)
        {
            try
            {
                await gate.ConfigureAwait(false);
                await inner.WriteAsync(record, CancellationToken.None).ConfigureAwait(false);
                landed.SetResult();
            }
            catch (Exception exception)
            {
                landed.SetException(exception);
                throw;
            }
        }
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
        public Clock Clock => clock;
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

        public EgressDecisionAuditAdapter EgressAdapter(AuditStore? store = null) =>
            new(store ?? Store, new AuditSoftwareIdentity("arcscope.desktop/1"));

        /// <summary>
        /// A real PLT.41 audit record as the authority builds it for the given outcome (None is an allowed decision). The facts each
        /// refusal had determined are this fixture's own table, independent of the production projection.
        /// </summary>
        public EgressAuditRecord CreateEgressRecord(EgressReason reason, ActorChain? actor = null, CommandId? correlation = null,
            ResourceReference? resource = null, string capability = "egress.send", EgressAuthorityKind authority = EgressAuthorityKind.UserConsent)
        {
            var chain = actor ?? MaintenanceActor;
            var last = chain.Actors.Count == 0 ? null : chain.Actors[^1];
            var allowed = reason == EgressReason.None;
            const string destination = "https://api.example.com";
            var (dataClass, destinationClass, withDestination) = reason switch
            {
                EgressReason.None => (EgressDataClass.WorkspaceContent, EgressDestinationClass.ThirdParty, true),
                EgressReason.DestinationMalformed => (EgressDataClass.None, EgressDestinationClass.None, false),
                EgressReason.DestinationNotDeclared or EgressReason.ClassifierUnavailable
                    or EgressReason.ContentUnclassified => (EgressDataClass.None, EgressDestinationClass.None, true),
                EgressReason.SecretMaterial => (EgressDataClass.SecretMaterial, EgressDestinationClass.None, true),
                EgressReason.AllowlistUnavailable or EgressReason.NotAllowlisted
                    or EgressReason.AllowlistMismatch => (EgressDataClass.WorkspaceContent, EgressDestinationClass.None, true),
                _ => (EgressDataClass.SensitiveContent, EgressDestinationClass.ThirdParty, true),
            };
            var info = allowed ? null : EgressReasons.Describe(reason);
            return new EgressAuditRecord(
                allowed ? EgressAuditKind.Authorized : EgressAuditKind.Refused, reason, info?.Code, info?.RegisteredCode, NowInstant, chain,
                last?.Executor ?? chain.CallerInstance, last?.SoftwareIdentity, capability,
                resource ?? new ResourceReference("doc/123", "rev-7"),
                new DecisionScope(chain.Owner.Realm, new WorkspaceId(Guid.NewGuid())), DecisionOrigin.Local, chain.Device,
                correlation ?? new CommandId(Guid.NewGuid()), withDestination ? destination : null, destinationClass, dataClass, true,
                allowed ? authority : EgressAuthorityKind.None, allowed ? "consent-1" : null, allowed ? "owner.egress" : null,
                allowed ? "grant-generation-1" : null, destinationClass == EgressDestinationClass.None ? null : "allowlist-generation-1");
        }

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

        public AuditRetentionRunner Runner() => new(Store, MaintenanceActor, MaintenanceSoftware);

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
