// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Microsoft.Data.Sqlite;
using Xunit;
using Instant = ArcForges.Foundation.Instant;

// xUnit preserves its synchronization context; ConfigureAwait(false) is forbidden by xUnit1030.
#pragma warning disable CA2007
namespace ArcForges.Security.Audit.Tests;

public sealed class AuditDecisionTests
{
    [Fact]
    public async Task SecurityDecisionSinkPreservesEveryProducerFactAcrossReopenAndRejectsContradictions()
    {
        using var f = new Fixture();
        var sink = new SecurityDecisionAuditSink(f.Store, f.Software);
        foreach (var point in new[] { EnforcementPoint.TransportBoundary, EnforcementPoint.ServiceDecision, EnforcementPoint.OwnerFinalValidation })
        {
            foreach (var reason in DecisionReasons.All.Where(value => DecisionProfiles.StepsFor(point).Contains(value.Step)))
            {
                // Include an actual valid producer-null step 11 fact, and a foreign requested realm refused by step 4.
                var record = f.Security(point, reason, reason.Step < DecisionStep.EffectiveRisk || point == EnforcementPoint.OwnerFinalValidation ? null : RiskLevel.R4);
                if (reason.Reason == DecisionReason.S04RealmMismatch)
                    record = record with { Scope = new DecisionScope(new RealmId(Guid.NewGuid()), record.Scope.Workspace) };
                await sink.WriteAsync(record, TestContext.Current.CancellationToken);
            }
        }
        var delegated = new DelegatedActor(ActorKind.Agent, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), "owned.assistant/1");
        var chain = new ActorChain(f.Actor.Owner, f.Actor.Device, f.Actor.Installation, f.Actor.Session, f.Actor.CallerInstance, [delegated]);
        await sink.WriteAsync(f.Security(EnforcementPoint.OwnerFinalValidation, DecisionReasons.Describe(DecisionReason.S11OwnerRefused), null)
            with { Actors = chain, Executor = delegated.Executor, SoftwareIdentity = delegated.SoftwareIdentity }, TestContext.Current.CancellationToken);
        var rows = f.Read();
        Assert.Contains(rows, row => ((AuditSecurityDecisionDetail)row.Event.DecisionDetail!).Record.FailedStep == DecisionStep.OwnerValidation
            && row.Event.Risk == AuditRisk.NotAssessed);
        using var reopened = f.Open();
        var persisted = f.Read(reopened);
        Assert.Equal(rows.Select(row => row.IntegritySha256), persisted.Select(row => row.IntegritySha256));
        foreach (var (before, after) in rows.Zip(persisted))
        {
            Assert.Equal(DecisionAuditCodec.Encode(before.Event.DecisionDetail!), DecisionAuditCodec.Encode(after.Event.DecisionDetail!));
            var record = ((AuditSecurityDecisionDetail)after.Event.DecisionDetail!).Record;
            var expected = ((AuditSecurityDecisionDetail)before.Event.DecisionDetail!).Record;
            Assert.Equal(expected.Kind, record.Kind);
            Assert.Equal(expected.Point, record.Point);
            Assert.Equal(expected.FailedStep, record.FailedStep);
            Assert.Equal(expected.ReasonCode, record.ReasonCode);
            Assert.Equal(expected.RegisteredCode, record.RegisteredCode);
            Assert.Equal(ActorChainSnapshot.Encode(expected.Actors), ActorChainSnapshot.Encode(record.Actors));
            Assert.Equal(expected.Executor, record.Executor);
            Assert.Equal(expected.EffectiveRisk, record.EffectiveRisk);
            Assert.Equal(expected.Origin, record.Origin);
            Assert.Equal(expected.Device, record.Device);
            Assert.Equal(expected.Scope, record.Scope);
            Assert.Equal(expected.Correlation, record.Correlation);
            Assert.Equal(expected.Effect, record.Effect);
            Assert.Equal(expected.SoftwareIdentity, record.SoftwareIdentity);
            Assert.Equal("IChatOperations.AppendUserMessage", record.CapabilityKey);
            Assert.Equal("resource/exact:42", record.Resource.Id);
            Assert.Equal("revision:7", record.Resource.Revision);
            Assert.Equal(f.Lease, record.Lease);
            Assert.Equal(f.ProducerTime, record.OccurredAt);
            Assert.Equal(record.Correlation.Value, after.Event.Resource.Id);
        }
        var valid = f.Security(EnforcementPoint.ServiceDecision, DecisionReasons.Describe(DecisionReason.S02PolicyDisabled), null);
        await Assert.ThrowsAsync<ArgumentException>(async () => await sink.WriteAsync(valid with { Executor = new InstanceId(Guid.NewGuid()) }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(async () => await sink.WriteAsync(valid with { Device = new DeviceId(Guid.NewGuid()) }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(async () => await sink.WriteAsync(valid with { RegisteredCode = "internal.unexpected" }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(async () => await sink.WriteAsync(valid with { Effect = EffectCertainty.Happened }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(async () => await sink.WriteAsync(valid with { Kind = SecurityAuditKind.Executed }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(async () => await sink.WriteAsync(valid with { SoftwareIdentity = "invented.software" }, TestContext.Current.CancellationToken));
        Assert.Equal(rows.Count, f.Read().Count);
    }

    [Fact]
    public async Task DurableDecisionRecorderPersistsSuccessFailureCancellationAndRefusesForeignOwner()
    {
        using var f = new Fixture();
        var recorder = new DecisionResultRecorder(f.Store, f.Actor, f.Software, f.Scope, DecisionOrigin.Remote);
        foreach (var kind in new[] { DecisionResultKind.Success, DecisionResultKind.Failure, DecisionResultKind.Cancelled })
        {
            var record = new DecisionRecord(new CommandId(Guid.NewGuid()), "IScopeOperations.GetSession", new ResourceReference("target/42", "revision:99"),
                RiskLevel.R2, kind, kind == DecisionResultKind.Failure ? "internal.unexpected" : null,
                kind == DecisionResultKind.Success ? EffectCertainty.Happened : EffectCertainty.Unknown, f.ProducerTime);
            await recorder.RecordAsync(record, TestContext.Current.CancellationToken);
            var security = f.Security(EnforcementPoint.OwnerFinalValidation, DecisionReasons.Describe(DecisionReason.S11OwnerRefused), RiskLevel.R2) with
            {
                Kind = kind switch { DecisionResultKind.Success => SecurityAuditKind.Executed, DecisionResultKind.Failure => SecurityAuditKind.OwnerFailed, _ => SecurityAuditKind.OwnerCancelled },
                FailedStep = DecisionStep.None,
                ReasonCode = kind == DecisionResultKind.Success ? "" : DecisionReasons.Describe(DecisionReason.S12OwnerFailed).Code,
                RegisteredCode = record.FailureCode ?? "",
                Effect = record.Effect,
            };
            await new SecurityDecisionAuditSink(f.Store, f.Software).WriteAsync(security, TestContext.Current.CancellationToken);
        }
        using var reopened = f.Open();
        var rows = f.Read(reopened);
        Assert.Equal(6, rows.Count);
        var results = rows.Where(row => row.Event.EventType == AuditEventType.InvocationResult).Select(row => ((AuditDecisionResultDetail)row.Event.DecisionDetail!).Record).ToArray();
        Assert.Equal(new[] { DecisionResultKind.Success, DecisionResultKind.Failure, DecisionResultKind.Cancelled }, results.Select(record => record.Result));
        Assert.All(results, record => { Assert.Equal(f.ProducerTime, record.RecordedAt); Assert.Equal("revision:99", record.Resource.Revision); });
        var foreign = new ActorChain(new HumanPrincipal(f.Actor.Owner.Realm, new UserId(Guid.NewGuid()), HumanIdentityKind.LocalHuman), f.Actor.Device, f.Actor.Installation, f.Actor.Session, f.Actor.CallerInstance, []);
        Assert.Throws<UnauthorizedAccessException>(() => new DecisionResultRecorder(f.Store, foreign, f.Software, f.Scope, DecisionOrigin.Local));
    }

    [Fact]
    public async Task CancelledOrDisposedIntakeNeverReportsSuccess()
    {
        using var f = new Fixture();
        var sink = new SecurityDecisionAuditSink(f.Store, f.Software);
        var value = f.Security(EnforcementPoint.ServiceDecision, DecisionReasons.Describe(DecisionReason.S02PolicyDisabled), null);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await sink.WriteAsync(value, cancelled.Token));
        Assert.Empty(f.Read());
        await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(async () =>
            await sink.WriteAsync(value with { Correlation = new CommandId(Guid.NewGuid()) }, TestContext.Current.CancellationToken), TestContext.Current.CancellationToken)));
        Assert.Equal(12, f.Read().Count);
        f.Store.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await sink.WriteAsync(value, TestContext.Current.CancellationToken));
        using var reopened = f.Open();
        Assert.Equal(12, f.Read(reopened).Count);
    }

    [Fact]
    public void LegacyMigrationPreservesEveryHistoricalDigestAndFutureOrForeignSchemasFailBeforeDdl()
    {
        using var f = new Fixture();
        var old = f.Store.Append(new AuditEvent(AuditEventType.SecretUsed, f.Actor, f.Software, new AuditCapabilityId("secret.use"),
            new AuditResourceReference(AuditResourceKind.Secret, Guid.NewGuid()), AuditRisk.R1, AuditDecision.Allowed,
            AuditDecisionReason.PolicyAllowed, AuditOrigin.Local), TestContext.Current.CancellationToken);
        f.Store.Dispose();
        f.Raw("ALTER TABLE local_audit DROP COLUMN decision_detail; DROP TRIGGER local_audit_store_no_update; UPDATE local_audit_store SET schema_version=2; CREATE TRIGGER local_audit_store_no_update BEFORE UPDATE ON local_audit_store BEGIN SELECT RAISE(ABORT,'local audit policy is immutable'); END;");
        Assert.Throws<InvalidDataException>(() => new AuditStore(f.Path, f.Actor.Owner.Realm, new UserId(Guid.NewGuid()), f.Policy));
        Assert.Equal(0L, f.Scalar("SELECT COUNT(*) FROM pragma_table_info('local_audit') WHERE name='decision_detail';"));
        using (var migrated = f.Open())
        {
            Assert.Equal(old.EventId, Assert.Single(f.Read(migrated)).EventId);
            Assert.Equal(old.IntegritySha256, Assert.Single(f.Read(migrated)).IntegritySha256);
            Assert.Equal(3L, f.Scalar("SELECT schema_version FROM local_audit_store;"));
        }
        f.Raw("DROP TRIGGER local_audit_store_no_update; UPDATE local_audit_store SET schema_version=4;");
        Assert.Throws<InvalidDataException>(() => f.Open());
        Assert.Equal(4L, f.Scalar("SELECT schema_version FROM local_audit_store;"));
    }

    [Fact]
    public async Task DecisionDetailTamperingAndMissingRequiredDetailFailIntegrityVerification()
    {
        using var f = new Fixture();
        await new SecurityDecisionAuditSink(f.Store, f.Software).WriteAsync(f.Security(EnforcementPoint.OwnerFinalValidation,
            DecisionReasons.Describe(DecisionReason.S11OwnerRefused), null), TestContext.Current.CancellationToken);
        f.Raw("DROP TRIGGER local_audit_no_update; UPDATE local_audit SET decision_detail=zeroblob(32);");
        Assert.Throws<InvalidDataException>(() => f.Read());
        f.Raw("UPDATE local_audit SET decision_detail=NULL;");
        Assert.Throws<InvalidDataException>(() => f.Read());
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcforges-decisions-" + Guid.NewGuid().ToString("N"));
        internal Fixture()
        {
            Actor = new ActorChain(new HumanPrincipal(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()), HumanIdentityKind.LocalHuman), new DeviceId(Guid.NewGuid()), new InstallationId(Guid.NewGuid()), SessionId.New(), new InstanceId(Guid.NewGuid()), []);
            Scope = new DecisionScope(Actor.Owner.Realm, new WorkspaceId(Guid.NewGuid()));
            Store = Open();
        }
        internal ActorChain Actor { get; }
        internal DecisionScope Scope { get; }
        internal AuditSoftwareIdentity Software { get; } = new("arcscope.desktop/1");
        internal CapabilityLeaseId Lease { get; } = CapabilityLeaseId.New();
        internal Instant ProducerTime { get; } = new(1_700_000_123, 456_789);
        internal AuditRetentionPolicy Policy { get; } = new(Guid.NewGuid(), 30);
        internal string Path => System.IO.Path.Combine(directory, "audit.db");
        internal AuditStore Store { get; }
        internal AuditStore Open() => new(Path, Actor.Owner.Realm, Actor.Owner.Id, Policy);
        internal IReadOnlyList<AuditEventRecord> Read(AuditStore? store = null) => (store ?? Store).Query(new AuditQuery(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), 1000));
        internal SecurityAuditRecord Security(EnforcementPoint point, DecisionReasonInfo reason, RiskLevel? risk) => new(SecurityAuditKind.Refused,
            point, reason.Step, reason.Code, reason.RegisteredCode, ProducerTime, Actor, Actor.CallerInstance, null,
            "IChatOperations.AppendUserMessage", new ResourceReference("resource/exact:42", "revision:7"), risk,
            DecisionOrigin.Remote, Actor.Device, Scope, new CommandId(Guid.NewGuid()), EffectCertainty.DidNotHappen, Lease);
        [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Test-only literal SQL deliberately creates legacy/corrupt fixtures; no user input is accepted.")]
        internal void Raw(string sql) { using var connection = Connection(); using var command = connection.CreateCommand(); command.CommandText = sql; command.ExecuteNonQuery(); }
        [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Test-only literal SQL observes fixtures; no user input is accepted.")]
        internal long Scalar(string sql) { using var connection = Connection(); using var command = connection.CreateCommand(); command.CommandText = sql; return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture); }
        private SqliteConnection Connection() { var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path, Pooling = false }.ToString()); connection.Open(); return connection; }
        public void Dispose() { Store.Dispose(); Directory.Delete(directory, recursive: true); }
    }
}
