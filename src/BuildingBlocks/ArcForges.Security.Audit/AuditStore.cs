// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace ArcForges.Security.Audit;

/// <summary>
/// Owner-scoped local audit storage. Every write is serialized, data is append-only through ordinary
/// connections, and deletion is available only to this store's in-process policy-retention authority.
/// </summary>
public sealed class AuditStore : IDisposable
{
    private const string EventTable = "local_audit";
    private const string HoldTable = "local_audit_holds";
    private const string AuthorityReceiptTable = "local_audit_authority_receipts";
    private const string PurgeReceiptTable = "local_audit_purge_receipts";
    private const string GateTable = "local_audit_maintenance_gate";
    private const string EventColumns = "sequence,event_id,occurred_unix_seconds,occurred_nanoseconds,event_type,actor_chain,software_identity,capability_id,executor_id,resource_kind,resource_id,risk,decision,reason,origin,workspace_id,task_id,correlation_id,event_sha256,policy_id,partition_year,partition_month,egress_reason,egress_data_class,egress_destination_class,egress_destination_id,egress_authority_kind,egress_authority_ref,egress_grant_generation,egress_content_sha256,decision_detail";
    private const int SchemaVersion = 3;
    private static readonly StringComparer PathComparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Writers = new(PathComparer);
    private static readonly strdelegate_authorizer DatabaseAuthorizer = AuthorizeDatabase;

    private readonly string connectionString;
    private readonly string writerKey;
    private readonly RealmId realm;
    private readonly UserId owner;
    private readonly AuditRetentionPolicy retentionPolicy;
    private readonly IClock clock;
    private readonly AuditMaintenanceAuthority maintenanceAuthority;
    private int disposed;

    public AuditStore(string databasePath, RealmId realm, UserId owner, AuditRetentionPolicy retentionPolicy)
        : this(databasePath, realm, owner, retentionPolicy, Clock.System)
    {
    }

    internal AuditStore(string databasePath, RealmId realm, UserId owner, AuditRetentionPolicy retentionPolicy,
        IClock clock)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        _ = realm.ToWire();
        _ = owner.ToWire();
        ArgumentNullException.ThrowIfNull(retentionPolicy);
        ArgumentNullException.ThrowIfNull(clock);
        var fullPath = Path.GetFullPath(databasePath);
        var parent = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(parent)) throw new ArgumentException("Audit database path must have a parent directory.", nameof(databasePath));
        Directory.CreateDirectory(parent);
        this.realm = realm;
        this.owner = owner;
        this.retentionPolicy = retentionPolicy;
        this.clock = clock;
        maintenanceAuthority = new AuditMaintenanceAuthority(retentionPolicy, realm, owner);
        writerKey = fullPath;
        var writer = Writers.GetOrAdd(fullPath, static _ => new SemaphoreSlim(1, 1));
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Pooling = false,
            DefaultTimeout = 30,
            ForeignKeys = true,
        }.ToString();

        writer.Wait();
        try
        {
            InitializeSchemaAndPolicy();
        }
        finally
        {
            writer.Release();
        }
    }

    /// <summary>Append one complete typed security event and return its durable sequence and digest.</summary>
    public AuditEventRecord Append(AuditEvent auditEvent) => Append(auditEvent, CancellationToken.None);

    /// <summary>Durably append, cancelling queued intake or an interrupted transaction; a cancelled operation never reports success.</summary>
    public AuditEventRecord Append(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(auditEvent);
        EnsureOwner(auditEvent.ActorChain.Owner.Realm, auditEvent.ActorChain.Owner.Id);
        var occurredAt = clock.GetCurrentInstant();
        var partition = AuditPartition.For(auditEvent.ActorChain.Owner, occurredAt);
        var eventId = Guid.NewGuid();
        var fingerprint = ComputeEventHash(auditEvent, occurredAt, retentionPolicy.PolicyId, eventId);
        return WithWriteTransaction(static (connection, transaction, state, input) =>
        {
            using (var purged = connection.CreateCommand())
            {
                purged.Transaction = transaction;
                purged.CommandText = $"SELECT EXISTS(SELECT 1 FROM {PurgeReceiptTable} WHERE partition_realm=$realm AND partition_owner=$owner AND partition_year=$year AND partition_month=$month);";
                purged.Parameters.AddWithValue("$realm", GuidText(input.Partition.Realm.Value));
                purged.Parameters.AddWithValue("$owner", GuidText(input.Partition.Owner.Value));
                purged.Parameters.AddWithValue("$year", input.Partition.Year);
                purged.Parameters.AddWithValue("$month", input.Partition.Month);
                if (Convert.ToInt64(purged.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0)
                {
                    throw new InvalidOperationException("Events cannot be appended to a partition with a retained purge receipt.");
                }
            }

            InsertEvent(connection, transaction, input.EventId, input.Event, input.OccurredAt, input.Hash, input.PolicyId);
            var sequence = LastInsertSequence(connection, transaction);
            return new AuditEventRecord(sequence, input.EventId, input.OccurredAt, input.Event, input.Hash);
        }, (EventId: eventId, Event: auditEvent, OccurredAt: occurredAt, Hash: fingerprint, PolicyId: retentionPolicy.PolicyId, Partition: partition), cancellationToken);
    }

    /// <summary>Read a bounded page from this file's one configured realm/account owner.</summary>
    public IReadOnlyList<AuditEventRecord> Query(AuditQuery query)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(query);
        using var connection = OpenConnection(queryOnly: true);
        using var transaction = connection.BeginTransaction(deferred: true);
        var state = new AuthorizerState();
        SetAuthorizer(connection, state);
        try
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"SELECT {EventColumns} FROM {EventTable} WHERE (occurred_unix_seconds > $fromSeconds OR (occurred_unix_seconds=$fromSeconds AND occurred_nanoseconds >= $fromNanoseconds)) AND (occurred_unix_seconds < $toSeconds OR (occurred_unix_seconds=$toSeconds AND occurred_nanoseconds < $toNanoseconds)) AND sequence > $after AND ($event_type IS NULL OR event_type=$event_type) ORDER BY sequence LIMIT $limit;";
            var from = Instant.FromDateTimeOffset(query.FromInclusive);
            var to = Instant.FromDateTimeOffset(query.ToExclusive);
            command.Parameters.AddWithValue("$fromSeconds", from.UnixSeconds);
            command.Parameters.AddWithValue("$fromNanoseconds", (long)from.Nanoseconds);
            command.Parameters.AddWithValue("$toSeconds", to.UnixSeconds);
            command.Parameters.AddWithValue("$toNanoseconds", (long)to.Nanoseconds);
            command.Parameters.AddWithValue("$after", query.AfterSequence);
            command.Parameters.AddWithValue("$event_type", query.EventType is { } eventType ? (int)eventType : DBNull.Value);
            command.Parameters.AddWithValue("$limit", query.Limit);
            using var reader = command.ExecuteReader();
            var records = new List<AuditEventRecord>(Math.Min(query.Limit, 64));
            while (reader.Read()) records.Add(ReadAndVerifyEvent(reader));
            return records.AsReadOnly();
        }
        finally
        {
            ClearAuthorizer(connection);
        }
    }

    /// <summary>
    /// Internal privileged composition seam: mint a short-lived, exact-scope in-process maintenance
    /// capability. The capability cannot be serialized or constructed by ordinary callers.
    /// </summary>
    internal AuditMaintenanceCapability CreateMaintenanceCapability(AuditMaintenanceAction action,
        AuditPartition partition, ActorChain authorityActor, AuditSoftwareIdentity softwareIdentity,
        TimeSpan lifetime, Guid? holdId = null)
    {
        ThrowIfDisposed();
        return maintenanceAuthority.Mint(action, partition, holdId, authorityActor, softwareIdentity,
            clock.GetCurrentInstant(), clock.GetTimestamp(), lifetime);
    }

    /// <summary>Fail closed unless an actor chain belongs to this file's realm and owner.</summary>
    internal void RequireOwner(ActorChain actor)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(actor);
        EnsureOwner(actor.Owner.Realm, actor.Owner.Id);
    }

    /// <summary>
    /// The complete UTC months of this file's one owner that hold events and have expired under the declared retention policy at the
    /// store's own current instant, oldest first, at most <paramref name="limit"/>. The caller chooses neither the partitions nor the time.
    /// </summary>
    internal IReadOnlyList<AuditPartition> ListExpiredPartitions(int limit)
    {
        ThrowIfDisposed();
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        using var connection = OpenConnection(queryOnly: true);
        using var transaction = connection.BeginTransaction(deferred: true);
        var state = new AuthorizerState();
        SetAuthorizer(connection, state);
        try
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"SELECT DISTINCT partition_year,partition_month FROM {EventTable} ORDER BY partition_year,partition_month;";
            using var reader = command.ExecuteReader();
            var now = clock.GetCurrentInstant();
            var expired = new List<AuditPartition>();
            while (expired.Count < limit && reader.Read())
            {
                var partition = new AuditPartition(realm, owner, reader.GetInt32(0), reader.GetInt32(1));
                if (IsExpired(partition, retentionPolicy.RetentionDays, now)) expired.Add(partition);
            }

            return expired.AsReadOnly();
        }
        finally
        {
            ClearAuthorizer(connection);
        }
    }

    /// <summary>Append a legal hold over an existing month partition; ordinary holds cannot be edited.</summary>
    public AuditHoldRecord PlaceLegalHold(Guid holdId, AuditPartition partition, AuditHoldReason reason,
        ActorChain actorChain, AuditSoftwareIdentity softwareIdentity, AuditOrigin origin)
    {
        ThrowIfDisposed();
        if (holdId == Guid.Empty) throw new ArgumentException("A hold identity is required.", nameof(holdId));
        if (!AuditEnumValidation.IsWireValue(reason)) throw new ArgumentOutOfRangeException(nameof(reason));
        if (!AuditEnumValidation.IsWireValue(origin)) throw new ArgumentOutOfRangeException(nameof(origin));
        ArgumentNullException.ThrowIfNull(actorChain);
        ArgumentNullException.ThrowIfNull(softwareIdentity);
        EnsureOwner(actorChain.Owner.Realm, actorChain.Owner.Id);
        EnsurePartition(partition);
        ValidateSoftwareIdentity(actorChain, softwareIdentity);
        var at = clock.GetCurrentInstant();

        return WithWriteTransaction(static (connection, transaction, state, input) =>
        {
            if (PartitionEventCount(connection, transaction, input.Partition) == 0)
            {
                throw new InvalidOperationException("A legal hold must target a partition containing audit events.");
            }

            using (var existing = connection.CreateCommand())
            {
                existing.Transaction = transaction;
                existing.CommandText = $"SELECT EXISTS(SELECT 1 FROM {HoldTable} WHERE hold_id=$hold);";
                existing.Parameters.AddWithValue("$hold", GuidText(input.HoldId));
                if (Convert.ToInt64(existing.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0)
                {
                    throw new InvalidOperationException("A legal-hold identity is never reused.");
                }
            }

            InsertHold(connection, transaction, input.HoldId, input.Partition, input.Reason, input.At,
                released: false, actorChain: input.Actor, softwareIdentity: input.SoftwareIdentity,
                origin: input.Origin, capabilityId: null);
            return new AuditHoldRecord(LastInsertSequence(connection, transaction), input.HoldId,
                input.Partition, input.Reason, input.At, released: false, input.Actor,
                input.SoftwareIdentity, input.Origin);
        }, (HoldId: holdId, Partition: partition, Reason: reason, At: at, Actor: actorChain,
            SoftwareIdentity: softwareIdentity, Origin: origin));
    }

    /// <summary>Return active legal holds for one owner partition, with a hard result bound.</summary>
    public IReadOnlyList<AuditHoldRecord> ReadActiveLegalHolds(AuditPartition partition, int limit = 1000)
    {
        ThrowIfDisposed();
        EnsurePartition(partition);
        if (limit is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        using var connection = OpenConnection(queryOnly: true);
        using var transaction = connection.BeginTransaction(deferred: true);
        var state = new AuthorizerState();
        SetAuthorizer(connection, state);
        try
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"SELECT h.sequence,h.hold_id,h.partition_year,h.partition_month,h.reason,h.occurred_unix_seconds,h.occurred_nanoseconds,h.action,h.actor_chain,h.software_identity,h.origin FROM {HoldTable} h WHERE h.partition_year=$year AND h.partition_month=$month AND h.action=1 AND NOT EXISTS(SELECT 1 FROM {HoldTable} r WHERE r.hold_id=h.hold_id AND r.action=2 AND r.sequence>h.sequence) ORDER BY h.sequence LIMIT $limit;";
            command.Parameters.AddWithValue("$year", partition.Year);
            command.Parameters.AddWithValue("$month", partition.Month);
            command.Parameters.AddWithValue("$limit", limit);
            using var reader = command.ExecuteReader();
            var holds = new List<AuditHoldRecord>();
            while (reader.Read()) holds.Add(ReadHold(reader, partition, released: false));
            return holds.AsReadOnly();
        }
        finally
        {
            ClearAuthorizer(connection);
        }
    }

    /// <summary>Read the bounded immutable policy-retention authority and hold-release receipt history.</summary>
    public IReadOnlyList<AuditMaintenanceReceipt> ReadMaintenanceReceipts(int limit = 100)
    {
        ThrowIfDisposed();
        if (limit is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        using var connection = OpenConnection(queryOnly: true);
        using var transaction = connection.BeginTransaction(deferred: true);
        var state = new AuthorizerState();
        SetAuthorizer(connection, state);
        try
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"SELECT capability_id,action,policy_id,partition_realm,partition_owner,partition_year,partition_month,issued_unix_seconds,issued_nanoseconds,expires_unix_seconds,expires_nanoseconds,hold_id,authority_actor_chain,software_identity FROM {AuthorityReceiptTable} WHERE partition_realm=$realm AND partition_owner=$owner ORDER BY sequence DESC LIMIT $limit;";
            command.Parameters.AddWithValue("$realm", GuidText(realm.Value));
            command.Parameters.AddWithValue("$owner", GuidText(owner.Value));
            command.Parameters.AddWithValue("$limit", limit);
            using var reader = command.ExecuteReader();
            var receipts = new List<AuditMaintenanceReceipt>();
            while (reader.Read()) receipts.Add(ReadMaintenanceReceipt(reader));
            return receipts.AsReadOnly();
        }
        finally
        {
            ClearAuthorizer(connection);
        }
    }

    /// <summary>Release a specific active hold using this store's fresh in-process authority capability.</summary>
    internal AuditMaintenanceReceipt ReleaseLegalHold(AuditMaintenanceCapability capability)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(capability);
        _ = ValidateCapability(capability, AuditMaintenanceAction.ReleaseLegalHold);
        return WithWriteTransaction((connection, transaction, state, input) =>
        {
            var authority = ValidateCapability(input, AuditMaintenanceAction.ReleaseLegalHold);
            if (CapabilityWasUsed(connection, transaction, authority.CapabilityId))
            {
                throw new InvalidOperationException("A maintenance capability is single-use.");
            }

            var latest = ReadLatestHold(connection, transaction, authority.HoldId!.Value);
            if (latest is null || latest.Value.Released || latest.Value.Year != authority.Partition.Year
                || latest.Value.Month != authority.Partition.Month)
            {
                throw new InvalidOperationException("The maintenance capability does not name an active hold in this partition.");
            }

            _ = ValidateCapability(input, AuditMaintenanceAction.ReleaseLegalHold);
            state.IsMaintenance = true;
            InsertAuthorityReceipt(connection, transaction, authority);
            var releasedAt = clock.GetCurrentInstant();
            InsertHold(connection, transaction, authority.HoldId.Value, authority.Partition,
                latest.Value.Reason, releasedAt, released: true, actorChain: authority.AuthorityActor,
                softwareIdentity: authority.SoftwareIdentity, origin: AuditOrigin.Local,
                capabilityId: authority.CapabilityId);
            return authority;
        }, capability);
    }

    /// <summary>
    /// Purge one complete month only after expiry and a fresh exact-scope in-process capability. Data
    /// deletion and its authority/hash receipt commit atomically; any hold or failed check leaves data unchanged.
    /// </summary>
    internal AuditPurgeReceipt PurgeExpiredPartition(AuditMaintenanceCapability capability)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(capability);
        var initialAuthority = ValidateCapability(capability, AuditMaintenanceAction.PurgeExpiredPartition);
        if (!IsExpired(initialAuthority.Partition, retentionPolicy.RetentionDays, clock.GetCurrentInstant()))
        {
            throw new InvalidOperationException("The complete calendar-month partition has not expired under the declared policy.");
        }

        return WithWriteTransaction((connection, transaction, state, input) =>
        {
            var checkedAuthority = ValidateCapability(input, AuditMaintenanceAction.PurgeExpiredPartition);
            var now = clock.GetCurrentInstant();
            if (!IsExpired(checkedAuthority.Partition, retentionPolicy.RetentionDays, now))
            {
                throw new InvalidOperationException("The complete calendar-month partition has not expired under the declared policy.");
            }

            if (CapabilityWasUsed(connection, transaction, checkedAuthority.CapabilityId))
            {
                throw new InvalidOperationException("A maintenance capability is single-use.");
            }

            if (HasActiveHold(connection, transaction, checkedAuthority.Partition))
            {
                throw new InvalidOperationException("An active legal hold prevents this partition from being purged.");
            }

            var evidence = CalculatePartitionDigest(connection, transaction, checkedAuthority.Partition);
            if (evidence.Count == 0) throw new InvalidOperationException("An empty partition has no purge to approve.");

            checkedAuthority = ValidateCapability(input, AuditMaintenanceAction.PurgeExpiredPartition);
            now = clock.GetCurrentInstant();
            if (!IsExpired(checkedAuthority.Partition, retentionPolicy.RetentionDays, now))
            {
                throw new InvalidOperationException("The complete calendar-month partition has not expired under the declared policy.");
            }

            state.IsMaintenance = true;
            state.IsPurging = true;
            SetPurgeGate(connection, transaction, enabled: true);
            using (var delete = connection.CreateCommand())
            {
                delete.Transaction = transaction;
                delete.CommandText = $"DELETE FROM {EventTable} WHERE partition_year=$year AND partition_month=$month;";
                delete.Parameters.AddWithValue("$year", checkedAuthority.Partition.Year);
                delete.Parameters.AddWithValue("$month", checkedAuthority.Partition.Month);
                if (delete.ExecuteNonQuery() != evidence.Count)
                {
                    throw new InvalidDataException("Purged event count changed inside the serialized transaction.");
                }
            }

            InsertAuthorityReceipt(connection, transaction, checkedAuthority);
            InsertPurgeReceipt(connection, transaction, checkedAuthority, now, evidence);
            SetPurgeGate(connection, transaction, enabled: false);
            using var sequence = connection.CreateCommand();
            sequence.Transaction = transaction;
            sequence.CommandText = "SELECT last_insert_rowid();";
            var receiptSequence = Convert.ToInt64(sequence.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
            return new AuditPurgeReceipt(receiptSequence, checkedAuthority, checkedAuthority.Partition,
                now, evidence.Count, evidence.FirstSequence, evidence.LastSequence, evidence.Digest);
        }, capability);
    }

    /// <summary>Read a bounded page of retained immutable purge receipts.</summary>
    public IReadOnlyList<AuditPurgeReceipt> ReadPurgeReceipts(int limit = 100)
    {
        ThrowIfDisposed();
        if (limit is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        using var connection = OpenConnection(queryOnly: true);
        using var transaction = connection.BeginTransaction(deferred: true);
        var state = new AuthorizerState();
        SetAuthorizer(connection, state);
        try
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"SELECT p.sequence,p.capability_id,p.partition_realm,p.partition_owner,p.partition_year,p.partition_month,p.purged_unix_seconds,p.purged_nanoseconds,p.event_count,p.first_event_sequence,p.last_event_sequence,p.events_sha256,a.action,a.policy_id,a.issued_unix_seconds,a.issued_nanoseconds,a.expires_unix_seconds,a.expires_nanoseconds,a.hold_id,a.authority_actor_chain,a.software_identity FROM {PurgeReceiptTable} p JOIN {AuthorityReceiptTable} a ON a.capability_id=p.capability_id WHERE p.partition_realm=$realm AND p.partition_owner=$owner ORDER BY p.sequence DESC LIMIT $limit;";
            command.Parameters.AddWithValue("$realm", GuidText(realm.Value));
            command.Parameters.AddWithValue("$owner", GuidText(owner.Value));
            command.Parameters.AddWithValue("$limit", limit);
            using var reader = command.ExecuteReader();
            var receipts = new List<AuditPurgeReceipt>();
            while (reader.Read())
            {
                var receipt = ReadPurgeReceipt(reader);
                receipts.Add(receipt);
            }

            return receipts.AsReadOnly();
        }
        finally
        {
            ClearAuthorizer(connection);
        }
    }

    public void Dispose() => Interlocked.Exchange(ref disposed, 1);

    private void InitializeSchemaAndPolicy()
    {
        using var connection = OpenConnection(queryOnly: false);
        using (var journalMode = connection.CreateCommand())
        {
            journalMode.CommandText = "PRAGMA journal_mode=WAL;";
            _ = journalMode.ExecuteScalar();
        }
        using var transaction = connection.BeginTransaction(deferred: false);
        var state = new AuthorizerState { IsInitializing = true };
        SetAuthorizer(connection, state);
        try
        {
            var userTableCount = ScalarLong(connection, transaction,
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';");
            var hasStoreTable = ScalarLong(connection, transaction,
                $"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{EventTable}_store';") != 0;
            if (!hasStoreTable && userTableCount != 0)
            {
                throw new InvalidDataException("The audit database is not empty and has no recognized local audit schema.");
            }

            if (hasStoreTable)
            {
                // Verify identity and immutable policy before any DDL, including the additive migration.
                var version = VerifyStoredPolicy(connection, transaction, allowLegacy: true);
                if (version == 2)
                {
                    Execute(connection, transaction, $"ALTER TABLE {EventTable} ADD COLUMN decision_detail BLOB NULL;");
                    Execute(connection, transaction, $"DROP TRIGGER {EventTable}_store_no_update;");
                    Execute(connection, transaction, $"UPDATE {EventTable}_store SET schema_version={SchemaVersion} WHERE singleton=1;");
                }
            }

            CreateSchema(connection, transaction);
            var storeRows = ScalarLong(connection, transaction, $"SELECT COUNT(*) FROM {EventTable}_store;");
            if (storeRows == 0)
            {
                if (userTableCount != 0)
                {
                    throw new InvalidDataException("The audit database has tables but its owner/policy record is missing.");
                }

                using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = $"INSERT INTO {EventTable}_store(singleton,schema_version,realm_id,owner_id,policy_id,retention_days) VALUES(1,$version,$realm,$owner,$policy,$days);";
                insert.Parameters.AddWithValue("$version", SchemaVersion);
                insert.Parameters.AddWithValue("$realm", GuidText(realm.Value));
                insert.Parameters.AddWithValue("$owner", GuidText(owner.Value));
                insert.Parameters.AddWithValue("$policy", GuidText(retentionPolicy.PolicyId));
                insert.Parameters.AddWithValue("$days", retentionPolicy.RetentionDays);
                insert.ExecuteNonQuery();
                using var gate = connection.CreateCommand();
                gate.Transaction = transaction;
                gate.CommandText = $"INSERT INTO {GateTable}(singleton,enabled) VALUES(1,0);";
                gate.ExecuteNonQuery();
            }

            VerifyStoredPolicy(connection, transaction);
            if (ScalarLong(connection, transaction, $"SELECT COUNT(*) FROM {GateTable} WHERE singleton=1 AND enabled=0;") != 1)
            {
                throw new InvalidDataException("The local audit maintenance gate is missing or was left enabled.");
            }
            transaction.Commit();
        }
        finally
        {
            ClearAuthorizer(connection);
        }
    }

    private static void CreateSchema(SqliteConnection connection, SqliteTransaction transaction)
    {
        Execute(connection, transaction, $"CREATE TABLE IF NOT EXISTS {EventTable}_store(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL,realm_id TEXT NOT NULL,owner_id TEXT NOT NULL,policy_id TEXT NOT NULL,retention_days INTEGER NOT NULL);");
        Execute(connection, transaction, $"CREATE TABLE IF NOT EXISTS {GateTable}(singleton INTEGER PRIMARY KEY CHECK(singleton=1),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)));");
        Execute(connection, transaction, $"CREATE TABLE IF NOT EXISTS {EventTable}(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,occurred_unix_seconds INTEGER NOT NULL,occurred_nanoseconds INTEGER NOT NULL CHECK(occurred_nanoseconds BETWEEN 0 AND 999999999),partition_year INTEGER NOT NULL,partition_month INTEGER NOT NULL,event_type INTEGER NOT NULL,actor_chain BLOB NOT NULL,software_identity TEXT NOT NULL,capability_id TEXT NOT NULL,executor_id TEXT NOT NULL,resource_kind INTEGER NOT NULL,resource_id TEXT NOT NULL,risk INTEGER NOT NULL,decision INTEGER NOT NULL,reason INTEGER NOT NULL,origin INTEGER NOT NULL,workspace_id TEXT NULL,task_id TEXT NULL,correlation_id TEXT NULL,event_sha256 TEXT NOT NULL,policy_id TEXT NOT NULL,egress_reason INTEGER NULL,egress_data_class INTEGER NULL,egress_destination_class INTEGER NULL,egress_destination_id TEXT NULL,egress_authority_kind INTEGER NULL,egress_authority_ref TEXT NULL,egress_grant_generation TEXT NULL,egress_content_sha256 TEXT NULL,decision_detail BLOB NULL,CHECK(partition_month BETWEEN 1 AND 12),CHECK((egress_reason IS NULL AND egress_data_class IS NULL AND egress_destination_class IS NULL AND egress_destination_id IS NULL AND egress_authority_kind IS NULL AND egress_authority_ref IS NULL AND egress_grant_generation IS NULL AND egress_content_sha256 IS NULL AND resource_kind<>0 AND resource_id<>'') OR (egress_reason IS NOT NULL AND egress_data_class IS NOT NULL AND egress_destination_class IS NOT NULL AND egress_authority_kind IS NOT NULL AND egress_content_sha256 IS NOT NULL AND resource_kind=0 AND resource_id='')));");
        Execute(connection, transaction, $"CREATE TABLE IF NOT EXISTS {HoldTable}(sequence INTEGER PRIMARY KEY AUTOINCREMENT,hold_id TEXT NOT NULL,partition_year INTEGER NOT NULL,partition_month INTEGER NOT NULL,action INTEGER NOT NULL,reason INTEGER NOT NULL,occurred_unix_seconds INTEGER NOT NULL,occurred_nanoseconds INTEGER NOT NULL CHECK(occurred_nanoseconds BETWEEN 0 AND 999999999),actor_chain BLOB NOT NULL,software_identity TEXT NOT NULL,origin INTEGER NOT NULL,capability_id TEXT NULL REFERENCES {AuthorityReceiptTable}(capability_id),CHECK(action IN (1,2)),CHECK(partition_month BETWEEN 1 AND 12));");
        Execute(connection, transaction, $"CREATE TABLE IF NOT EXISTS {AuthorityReceiptTable}(sequence INTEGER PRIMARY KEY AUTOINCREMENT,capability_id TEXT NOT NULL UNIQUE,action INTEGER NOT NULL,policy_id TEXT NOT NULL,partition_realm TEXT NOT NULL,partition_owner TEXT NOT NULL,partition_year INTEGER NOT NULL,partition_month INTEGER NOT NULL,issued_unix_seconds INTEGER NOT NULL,issued_nanoseconds INTEGER NOT NULL CHECK(issued_nanoseconds BETWEEN 0 AND 999999999),expires_unix_seconds INTEGER NOT NULL,expires_nanoseconds INTEGER NOT NULL CHECK(expires_nanoseconds BETWEEN 0 AND 999999999),hold_id TEXT NULL,authority_actor_chain BLOB NOT NULL,software_identity TEXT NOT NULL);");
        Execute(connection, transaction, $"CREATE TABLE IF NOT EXISTS {PurgeReceiptTable}(sequence INTEGER PRIMARY KEY AUTOINCREMENT,capability_id TEXT NOT NULL UNIQUE REFERENCES {AuthorityReceiptTable}(capability_id),partition_realm TEXT NOT NULL,partition_owner TEXT NOT NULL,partition_year INTEGER NOT NULL,partition_month INTEGER NOT NULL,purged_unix_seconds INTEGER NOT NULL,purged_nanoseconds INTEGER NOT NULL CHECK(purged_nanoseconds BETWEEN 0 AND 999999999),event_count INTEGER NOT NULL,first_event_sequence INTEGER NOT NULL,last_event_sequence INTEGER NOT NULL,events_sha256 TEXT NOT NULL,CHECK(event_count>0));");
        Execute(connection, transaction, $"CREATE INDEX IF NOT EXISTS ix_{EventTable}_time_sequence ON {EventTable}(occurred_unix_seconds,occurred_nanoseconds,sequence);");
        Execute(connection, transaction, $"CREATE INDEX IF NOT EXISTS ix_{EventTable}_partition_sequence ON {EventTable}(partition_year,partition_month,sequence);");
        Execute(connection, transaction, $"CREATE INDEX IF NOT EXISTS ix_{HoldTable}_partition_hold_sequence ON {HoldTable}(partition_year,partition_month,hold_id,sequence);");
        Execute(connection, transaction, $"CREATE INDEX IF NOT EXISTS ix_{HoldTable}_hold_sequence ON {HoldTable}(hold_id,sequence);");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {EventTable}_no_update BEFORE UPDATE ON {EventTable} BEGIN SELECT RAISE(ABORT,'local audit is append-only'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {EventTable}_guarded_delete BEFORE DELETE ON {EventTable} WHEN COALESCE((SELECT enabled FROM {GateTable} WHERE singleton=1),0)<>1 BEGIN SELECT RAISE(ABORT,'local audit deletion requires approved retention maintenance'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {HoldTable}_no_update BEFORE UPDATE ON {HoldTable} BEGIN SELECT RAISE(ABORT,'local audit holds are append-only'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {HoldTable}_no_delete BEFORE DELETE ON {HoldTable} BEGIN SELECT RAISE(ABORT,'local audit holds are append-only'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {HoldTable}_guard_release BEFORE INSERT ON {HoldTable} WHEN NEW.action=2 AND arcforges_audit_retention_authorized()<>1 BEGIN SELECT RAISE(ABORT,'hold release requires internal policy-retention authority'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {AuthorityReceiptTable}_no_update BEFORE UPDATE ON {AuthorityReceiptTable} BEGIN SELECT RAISE(ABORT,'authority receipts are append-only'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {AuthorityReceiptTable}_no_delete BEFORE DELETE ON {AuthorityReceiptTable} BEGIN SELECT RAISE(ABORT,'authority receipts are append-only'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {AuthorityReceiptTable}_authorized_insert BEFORE INSERT ON {AuthorityReceiptTable} WHEN arcforges_audit_retention_authorized()<>1 BEGIN SELECT RAISE(ABORT,'authority receipt requires internal policy-retention maintenance'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {PurgeReceiptTable}_no_update BEFORE UPDATE ON {PurgeReceiptTable} BEGIN SELECT RAISE(ABORT,'purge receipts are append-only'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {PurgeReceiptTable}_no_delete BEFORE DELETE ON {PurgeReceiptTable} BEGIN SELECT RAISE(ABORT,'purge receipts are append-only'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {PurgeReceiptTable}_authorized_insert BEFORE INSERT ON {PurgeReceiptTable} WHEN arcforges_audit_retention_authorized()<>1 BEGIN SELECT RAISE(ABORT,'purge receipt requires internal policy-retention maintenance'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {GateTable}_authorized_update BEFORE UPDATE ON {GateTable} WHEN arcforges_audit_retention_authorized()<>1 BEGIN SELECT RAISE(ABORT,'maintenance gate requires internal approved policy authority'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {GateTable}_no_delete BEFORE DELETE ON {GateTable} BEGIN SELECT RAISE(ABORT,'maintenance gate cannot be deleted'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {EventTable}_store_no_update BEFORE UPDATE ON {EventTable}_store BEGIN SELECT RAISE(ABORT,'local audit policy is immutable'); END;");
        Execute(connection, transaction, $"CREATE TRIGGER IF NOT EXISTS {EventTable}_store_no_delete BEFORE DELETE ON {EventTable}_store BEGIN SELECT RAISE(ABORT,'local audit policy is immutable'); END;");
    }

    private int VerifyStoredPolicy(SqliteConnection connection, SqliteTransaction transaction, bool allowLegacy = false)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT schema_version,realm_id,owner_id,policy_id,retention_days FROM {EventTable}_store WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw new InvalidDataException("The local audit policy record is missing.");
        var version = reader.GetInt32(0);
        if ((version != SchemaVersion && !(allowLegacy && version == 2)) || reader.GetString(1) != GuidText(realm.Value)
            || reader.GetString(2) != GuidText(owner.Value) || reader.GetString(3) != GuidText(retentionPolicy.PolicyId)
            || reader.GetInt32(4) != retentionPolicy.RetentionDays)
        {
            throw new InvalidDataException("The audit file owner or immutable retention policy does not match configuration.");
        }

        if (reader.Read()) throw new InvalidDataException("The local audit database has multiple policy records.");
        return version;
    }

    private SqliteConnection OpenConnection(bool queryOnly)
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;";
            command.ExecuteNonQuery();
            if (queryOnly)
            {
                using var readOnly = connection.CreateCommand();
                readOnly.CommandText = "PRAGMA query_only=ON;";
                readOnly.ExecuteNonQuery();
            }

            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private T WithWriteTransaction<T, TInput>(Func<SqliteConnection, SqliteTransaction, AuthorizerState, TInput, T> action, TInput input,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var writer = Writers.GetOrAdd(writerKey, static _ => new SemaphoreSlim(1, 1));
        writer.Wait(cancellationToken);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            using var connection = OpenConnection(queryOnly: false);
            using var cancellation = cancellationToken.Register(static value =>
            {
                var active = (SqliteConnection)value!;
                if (active.Handle is { } handle) raw.sqlite3_interrupt(handle);
            }, connection);
            using var transaction = connection.BeginTransaction(deferred: false);
            var state = new AuthorizerState();
            SetAuthorizer(connection, state);
            try
            {
                var result = action(connection, transaction, state, input);
                cancellationToken.ThrowIfCancellationRequested();
                transaction.Commit();
                return result;
            }
            catch (SqliteException exception) when (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException("Audit transaction was interrupted.", exception, cancellationToken);
            }
            finally
            {
                ClearAuthorizer(connection);
            }
        }
        finally
        {
            writer.Release();
        }
    }

    private AuditMaintenanceReceipt ValidateCapability(AuditMaintenanceCapability capability,
        AuditMaintenanceAction expectedAction)
    {
        var receipt = maintenanceAuthority.Validate(capability, expectedAction, clock, clock.GetTimestamp());
        EnsurePartition(receipt.Partition);
        EnsureOwner(receipt.AuthorityActor.Owner.Realm, receipt.AuthorityActor.Owner.Id);
        if (receipt.PolicyId != retentionPolicy.PolicyId)
            throw new UnauthorizedAccessException("The maintenance capability names another retention policy.");
        return receipt;
    }

    private void EnsureOwner(RealmId actualRealm, UserId actualOwner)
    {
        if (actualRealm != realm || actualOwner != owner)
        {
            throw new UnauthorizedAccessException("The audit file is scoped to a different realm/account owner.");
        }
    }

    private void EnsurePartition(AuditPartition partition) => EnsureOwner(partition.Realm, partition.Owner);

    private static bool IsExpired(AuditPartition partition, int retentionDays, Instant now)
    {
        DateTimeOffset expiresAt;
        try
        {
            expiresAt = partition.EndExclusiveUtc.AddDays(retentionDays);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }

        return now >= Instant.FromDateTimeOffset(expiresAt);
    }

    private static void ValidateSoftwareIdentity(ActorChain actor, AuditSoftwareIdentity softwareIdentity)
    {
        if (actor.Actors.Count > 0 && !StringComparer.Ordinal.Equals(actor.Actors[^1].SoftwareIdentity, softwareIdentity.Value))
        {
            throw new ArgumentException("Software identity must match the final delegated actor.", nameof(softwareIdentity));
        }
    }

    private static void InsertEvent(SqliteConnection connection, SqliteTransaction transaction, Guid eventId,
        AuditEvent auditEvent, Instant occurredAt, string hash, Guid policyId)
    {
        var owner = auditEvent.ActorChain.Owner;
        var partition = AuditPartition.For(owner, occurredAt);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"INSERT INTO {EventTable}(event_id,occurred_unix_seconds,occurred_nanoseconds,partition_year,partition_month,event_type,actor_chain,software_identity,capability_id,executor_id,resource_kind,resource_id,risk,decision,reason,origin,workspace_id,task_id,correlation_id,event_sha256,policy_id,egress_reason,egress_data_class,egress_destination_class,egress_destination_id,egress_authority_kind,egress_authority_ref,egress_grant_generation,egress_content_sha256,decision_detail) VALUES($event,$seconds,$nanoseconds,$year,$month,$type,$actor,$software,$capability,$executor,$resourceKind,$resourceId,$risk,$decision,$reason,$origin,$workspace,$task,$correlation,$hash,$policy,$egressReason,$egressData,$egressDestinationClass,$egressDestination,$egressAuthorityKind,$egressAuthorityRef,$egressGrantGeneration,$egressContent,$decisionDetail);";
        command.Parameters.AddWithValue("$event", GuidText(eventId));
        command.Parameters.AddWithValue("$seconds", occurredAt.UnixSeconds);
        command.Parameters.AddWithValue("$nanoseconds", (long)occurredAt.Nanoseconds);
        command.Parameters.AddWithValue("$year", partition.Year);
        command.Parameters.AddWithValue("$month", partition.Month);
        command.Parameters.AddWithValue("$type", (int)auditEvent.EventType);
        command.Parameters.AddWithValue("$actor", ActorChainSnapshot.Encode(auditEvent.ActorChain));
        command.Parameters.AddWithValue("$software", auditEvent.SoftwareIdentity.Value);
        command.Parameters.AddWithValue("$capability", auditEvent.Capability.Value);
        command.Parameters.AddWithValue("$executor", GuidText(auditEvent.Executor.Value));
        command.Parameters.AddWithValue("$resourceKind", (int)auditEvent.Resource.Kind);
        command.Parameters.AddWithValue("$resourceId", auditEvent.Resource == default ? string.Empty : GuidText(auditEvent.Resource.Id));
        command.Parameters.AddWithValue("$risk", (int)auditEvent.Risk);
        command.Parameters.AddWithValue("$decision", (int)auditEvent.Decision);
        command.Parameters.AddWithValue("$reason", (int)auditEvent.Reason);
        command.Parameters.AddWithValue("$origin", (int)auditEvent.Origin);
        command.Parameters.AddWithValue("$workspace", auditEvent.Workspace is { } workspace ? GuidText(workspace.Value) : DBNull.Value);
        command.Parameters.AddWithValue("$task", auditEvent.Task is { } task ? GuidText(task.Value) : DBNull.Value);
        command.Parameters.AddWithValue("$correlation", auditEvent.Correlation is { } correlation ? GuidText(correlation.Value) : DBNull.Value);
        command.Parameters.AddWithValue("$hash", hash);
        command.Parameters.AddWithValue("$policy", GuidText(policyId));
        var egress = auditEvent.Egress;
        command.Parameters.AddWithValue("$egressReason", egress is null ? DBNull.Value : (int)egress.Reason);
        command.Parameters.AddWithValue("$egressData", egress is null ? DBNull.Value : (int)egress.DataClass);
        command.Parameters.AddWithValue("$egressDestinationClass", egress is null ? DBNull.Value : (int)egress.DestinationClass);
        command.Parameters.AddWithValue("$egressDestination", egress?.Destination is { } destination ? destination.Value : DBNull.Value);
        command.Parameters.AddWithValue("$egressAuthorityKind", egress is null ? DBNull.Value : (int)egress.AuthorityKind);
        command.Parameters.AddWithValue("$egressAuthorityRef", egress?.AuthorityReference is { } reference ? reference.Value : DBNull.Value);
        command.Parameters.AddWithValue("$egressGrantGeneration", egress?.GrantGeneration is { } generation ? generation.Value : DBNull.Value);
        command.Parameters.AddWithValue("$egressContent", egress is null ? DBNull.Value : egress.Content.Value);
        command.Parameters.AddWithValue("$decisionDetail", auditEvent.DecisionDetail is { } detail ? DecisionAuditCodec.Encode(detail) : DBNull.Value);
        command.ExecuteNonQuery();
    }

    private AuditEventRecord ReadAndVerifyEvent(SqliteDataReader reader)
    {
        var record = DecodeEvent(reader, retentionPolicy.PolicyId);
        EnsureOwner(record.Event.ActorChain.Owner.Realm, record.Event.ActorChain.Owner.Id);
        return record;
    }

    /// <summary>Decode and verify one stored row: executor, policy, stored partition, typed egress detail and digest.</summary>
    private static AuditEventRecord DecodeEvent(SqliteDataReader reader, Guid expectedPolicyId)
    {
        try
        {
            return DecodeEventCore(reader, expectedPolicyId);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException
            or InvalidCastException or InvalidOperationException)
        {
            // A stored row that no longer satisfies the closed typed shapes is corrupt, not a caller error.
            throw new InvalidDataException("A stored audit row is malformed or violates its closed event shape.", ex);
        }
    }

    private static AuditEventRecord DecodeEventCore(SqliteDataReader reader, Guid expectedPolicyId)
    {
        var sequence = reader.GetInt64(0);
        var eventId = ParseGuid(reader.GetString(1));
        var occurredAt = new Instant(reader.GetInt64(2), checked((uint)reader.GetInt64(3)));
        var actorChain = ActorChainSnapshot.Decode((byte[])reader[5]).Chain;
        var software = new AuditSoftwareIdentity(reader.GetString(6));
        var capability = new AuditCapabilityId(reader.GetString(7));
        var executor = new InstanceId(ParseGuid(reader.GetString(8)));
        var workspace = reader.IsDBNull(15) ? (WorkspaceId?)null : new WorkspaceId(ParseGuid(reader.GetString(15)));
        var task = reader.IsDBNull(16) ? (TaskId?)null : new TaskId(ParseGuid(reader.GetString(16)));
        var correlation = reader.IsDBNull(17) ? (CorrelationId?)null : new CorrelationId(ParseGuid(reader.GetString(17)));
        AuditEgressDetail? egress = null;
        if (!reader.IsDBNull(22))
        {
            egress = new AuditEgressDetail((AuditEgressReason)reader.GetInt32(22), (AuditEgressDataClass)reader.GetInt32(23),
                (AuditEgressDestinationClass)reader.GetInt32(24),
                reader.IsDBNull(25) ? null : new AuditEgressDestinationId(reader.GetString(25)),
                (AuditEgressAuthorityKind)reader.GetInt32(26),
                reader.IsDBNull(27) ? null : new AuditReferenceText(reader.GetString(27)),
                reader.IsDBNull(28) ? null : new AuditReferenceText(reader.GetString(28)),
                new AuditEgressContentReference(reader.GetString(29)));
        }

        var resourceKind = (AuditResourceKind)reader.GetInt32(9);
        var resourceText = reader.GetString(10);
        var resource = egress is not null
            ? (resourceKind == AuditResourceKind.None && resourceText.Length == 0 ? default : throw new InvalidDataException("An egress row carries a resource reference."))
            : new AuditResourceReference(resourceKind, ParseGuid(resourceText));
        var auditEvent = new AuditEvent((AuditEventType)reader.GetInt32(4), actorChain, software,
            capability, resource,
            (AuditRisk)reader.GetInt32(11), (AuditDecision)reader.GetInt32(12),
            (AuditDecisionReason)reader.GetInt32(13), (AuditOrigin)reader.GetInt32(14), workspace, task, correlation, egress,
            reader.IsDBNull(30) ? null : DecisionAuditCodec.Decode((byte[])reader[30]));
        if (executor != auditEvent.Executor) throw new InvalidDataException("Stored executor does not match the preserved actor chain.");
        if (reader.GetString(19) != GuidText(expectedPolicyId)) throw new InvalidDataException("Event names an unexpected retention policy.");
        var expectedHash = ComputeEventHash(auditEvent, occurredAt, expectedPolicyId, eventId);
        var storedHash = reader.GetString(18);
        if (!StringComparer.Ordinal.Equals(expectedHash, storedHash)) throw new InvalidDataException("Audit event integrity digest does not match its stored fields.");
        var partition = AuditPartition.For(actorChain.Owner, occurredAt);
        if (partition.Year != reader.GetInt32(20) || partition.Month != reader.GetInt32(21))
            throw new InvalidDataException("Stored partition does not match the event timestamp.");
        return new AuditEventRecord(sequence, eventId, occurredAt, auditEvent, storedHash);
    }

    private static void InsertHold(SqliteConnection connection, SqliteTransaction transaction, Guid holdId,
        AuditPartition partition, AuditHoldReason reason, Instant occurredAt, bool released,
        ActorChain actorChain, AuditSoftwareIdentity softwareIdentity, AuditOrigin origin, Guid? capabilityId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"INSERT INTO {HoldTable}(hold_id,partition_year,partition_month,action,reason,occurred_unix_seconds,occurred_nanoseconds,actor_chain,software_identity,origin,capability_id) VALUES($hold,$year,$month,$action,$reason,$seconds,$nanoseconds,$actor,$software,$origin,$capability);";
        command.Parameters.AddWithValue("$hold", GuidText(holdId));
        command.Parameters.AddWithValue("$year", partition.Year);
        command.Parameters.AddWithValue("$month", partition.Month);
        command.Parameters.AddWithValue("$action", released ? 2 : 1);
        command.Parameters.AddWithValue("$reason", (int)reason);
        command.Parameters.AddWithValue("$seconds", occurredAt.UnixSeconds);
        command.Parameters.AddWithValue("$nanoseconds", (long)occurredAt.Nanoseconds);
        command.Parameters.AddWithValue("$actor", ActorChainSnapshot.Encode(actorChain));
        command.Parameters.AddWithValue("$software", softwareIdentity.Value);
        command.Parameters.AddWithValue("$origin", (int)origin);
        command.Parameters.AddWithValue("$capability", capabilityId is { } id ? GuidText(id) : DBNull.Value);
        command.ExecuteNonQuery();
    }

    private static AuditHoldRecord ReadHold(SqliteDataReader reader, AuditPartition partition, bool released)
    {
        var actor = ActorChainSnapshot.Decode((byte[])reader[8]).Chain;
        var rowPartition = new AuditPartition(actor.Owner.Realm, actor.Owner.Id, reader.GetInt32(2), reader.GetInt32(3));
        if (rowPartition != partition) throw new InvalidDataException("Stored legal hold escaped its owner/month partition.");
        var software = new AuditSoftwareIdentity(reader.GetString(9));
        ValidateSoftwareIdentity(actor, software);
        return new AuditHoldRecord(reader.GetInt64(0), ParseGuid(reader.GetString(1)), partition,
            (AuditHoldReason)reader.GetInt32(4), new Instant(reader.GetInt64(5), checked((uint)reader.GetInt64(6))),
            released, actor, software, (AuditOrigin)reader.GetInt32(10));
    }

    private static bool HasActiveHold(SqliteConnection connection, SqliteTransaction transaction, AuditPartition partition)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT EXISTS(SELECT 1 FROM {HoldTable} h WHERE h.partition_year=$year AND h.partition_month=$month AND h.action=1 AND NOT EXISTS(SELECT 1 FROM {HoldTable} r WHERE r.hold_id=h.hold_id AND r.action=2 AND r.sequence>h.sequence));";
        command.Parameters.AddWithValue("$year", partition.Year);
        command.Parameters.AddWithValue("$month", partition.Month);
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0;
    }

    private static (int Year, int Month, AuditHoldReason Reason, bool Released)? ReadLatestHold(
        SqliteConnection connection, SqliteTransaction transaction, Guid holdId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT partition_year,partition_month,reason,action FROM {HoldTable} WHERE hold_id=$hold ORDER BY sequence DESC LIMIT 1;";
        command.Parameters.AddWithValue("$hold", GuidText(holdId));
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        return (reader.GetInt32(0), reader.GetInt32(1), (AuditHoldReason)reader.GetInt32(2), reader.GetInt32(3) == 2);
    }

    private static long PartitionEventCount(SqliteConnection connection, SqliteTransaction transaction, AuditPartition partition)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT COUNT(*) FROM {EventTable} WHERE partition_year=$year AND partition_month=$month;";
        command.Parameters.AddWithValue("$year", partition.Year);
        command.Parameters.AddWithValue("$month", partition.Month);
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static bool CapabilityWasUsed(SqliteConnection connection, SqliteTransaction transaction, Guid capabilityId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT EXISTS(SELECT 1 FROM {AuthorityReceiptTable} WHERE capability_id=$capability);";
        command.Parameters.AddWithValue("$capability", GuidText(capabilityId));
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0;
    }

    private static void InsertAuthorityReceipt(SqliteConnection connection, SqliteTransaction transaction,
        AuditMaintenanceReceipt authority)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"INSERT INTO {AuthorityReceiptTable}(capability_id,action,policy_id,partition_realm,partition_owner,partition_year,partition_month,issued_unix_seconds,issued_nanoseconds,expires_unix_seconds,expires_nanoseconds,hold_id,authority_actor_chain,software_identity) VALUES($capability,$action,$policy,$realm,$owner,$year,$month,$issuedSeconds,$issuedNanoseconds,$expiresSeconds,$expiresNanoseconds,$hold,$actor,$software);";
        command.Parameters.AddWithValue("$capability", GuidText(authority.CapabilityId));
        command.Parameters.AddWithValue("$action", (int)authority.Action);
        command.Parameters.AddWithValue("$policy", GuidText(authority.PolicyId));
        command.Parameters.AddWithValue("$realm", GuidText(authority.Partition.Realm.Value));
        command.Parameters.AddWithValue("$owner", GuidText(authority.Partition.Owner.Value));
        command.Parameters.AddWithValue("$year", authority.Partition.Year);
        command.Parameters.AddWithValue("$month", authority.Partition.Month);
        command.Parameters.AddWithValue("$issuedSeconds", authority.IssuedAt.UnixSeconds);
        command.Parameters.AddWithValue("$issuedNanoseconds", (long)authority.IssuedAt.Nanoseconds);
        command.Parameters.AddWithValue("$expiresSeconds", authority.ExpiresAt.UnixSeconds);
        command.Parameters.AddWithValue("$expiresNanoseconds", (long)authority.ExpiresAt.Nanoseconds);
        command.Parameters.AddWithValue("$hold", authority.HoldId is { } hold ? GuidText(hold) : DBNull.Value);
        command.Parameters.AddWithValue("$actor", ActorChainSnapshot.Encode(authority.AuthorityActor));
        command.Parameters.AddWithValue("$software", authority.SoftwareIdentity.Value);
        command.ExecuteNonQuery();
    }

    private static void InsertPurgeReceipt(SqliteConnection connection, SqliteTransaction transaction,
        AuditMaintenanceReceipt authority, Instant purgedAt, PartitionDigest evidence)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"INSERT INTO {PurgeReceiptTable}(capability_id,partition_realm,partition_owner,partition_year,partition_month,purged_unix_seconds,purged_nanoseconds,event_count,first_event_sequence,last_event_sequence,events_sha256) VALUES($capability,$realm,$owner,$year,$month,$purgedSeconds,$purgedNanoseconds,$count,$first,$last,$hash);";
        command.Parameters.AddWithValue("$capability", GuidText(authority.CapabilityId));
        command.Parameters.AddWithValue("$realm", GuidText(authority.Partition.Realm.Value));
        command.Parameters.AddWithValue("$owner", GuidText(authority.Partition.Owner.Value));
        command.Parameters.AddWithValue("$year", authority.Partition.Year);
        command.Parameters.AddWithValue("$month", authority.Partition.Month);
        command.Parameters.AddWithValue("$purgedSeconds", purgedAt.UnixSeconds);
        command.Parameters.AddWithValue("$purgedNanoseconds", (long)purgedAt.Nanoseconds);
        command.Parameters.AddWithValue("$count", evidence.Count);
        command.Parameters.AddWithValue("$first", evidence.FirstSequence);
        command.Parameters.AddWithValue("$last", evidence.LastSequence);
        command.Parameters.AddWithValue("$hash", evidence.Digest);
        command.ExecuteNonQuery();
    }

    private AuditPurgeReceipt ReadPurgeReceipt(SqliteDataReader reader)
    {
        var partition = new AuditPartition(new RealmId(ParseGuid(reader.GetString(2))),
            new UserId(ParseGuid(reader.GetString(3))), reader.GetInt32(4), reader.GetInt32(5));
        EnsurePartition(partition);
        var authority = new AuditMaintenanceReceipt(ParseGuid(reader.GetString(1)),
            (AuditMaintenanceAction)reader.GetInt32(12), ParseGuid(reader.GetString(13)), partition,
            new Instant(reader.GetInt64(14), checked((uint)reader.GetInt64(15))),
            new Instant(reader.GetInt64(16), checked((uint)reader.GetInt64(17))),
            reader.IsDBNull(18) ? null : ParseGuid(reader.GetString(18)),
            ActorChainSnapshot.Decode((byte[])reader[19]).Chain, new AuditSoftwareIdentity(reader.GetString(20)));
        EnsureOwner(authority.AuthorityActor.Owner.Realm, authority.AuthorityActor.Owner.Id);
        ValidateSoftwareIdentity(authority.AuthorityActor, authority.SoftwareIdentity);
        if (authority.Action != AuditMaintenanceAction.PurgeExpiredPartition || authority.PolicyId != retentionPolicy.PolicyId)
            throw new InvalidDataException("A purge receipt references a non-purge authority action.");
        return new AuditPurgeReceipt(reader.GetInt64(0), authority, partition,
            new Instant(reader.GetInt64(6), checked((uint)reader.GetInt64(7))), reader.GetInt64(8), reader.GetInt64(9),
            reader.GetInt64(10), reader.GetString(11));
    }

    private AuditMaintenanceReceipt ReadMaintenanceReceipt(SqliteDataReader reader)
    {
        var partition = new AuditPartition(new RealmId(ParseGuid(reader.GetString(3))),
            new UserId(ParseGuid(reader.GetString(4))), reader.GetInt32(5), reader.GetInt32(6));
        EnsurePartition(partition);
        var actor = ActorChainSnapshot.Decode((byte[])reader[12]).Chain;
        EnsureOwner(actor.Owner.Realm, actor.Owner.Id);
        var software = new AuditSoftwareIdentity(reader.GetString(13));
        ValidateSoftwareIdentity(actor, software);
        var receipt = new AuditMaintenanceReceipt(ParseGuid(reader.GetString(0)),
            (AuditMaintenanceAction)reader.GetInt32(1), ParseGuid(reader.GetString(2)), partition,
            new Instant(reader.GetInt64(7), checked((uint)reader.GetInt64(8))),
            new Instant(reader.GetInt64(9), checked((uint)reader.GetInt64(10))),
            reader.IsDBNull(11) ? null : ParseGuid(reader.GetString(11)), actor, software);
        if (receipt.PolicyId != retentionPolicy.PolicyId)
            throw new InvalidDataException("Stored maintenance receipt names an unexpected retention policy.");
        return receipt;
    }

    private PartitionDigest CalculatePartitionDigest(SqliteConnection connection, SqliteTransaction transaction, AuditPartition partition)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT {EventColumns} FROM {EventTable} WHERE partition_year=$year AND partition_month=$month ORDER BY sequence;";
        command.Parameters.AddWithValue("$year", partition.Year);
        command.Parameters.AddWithValue("$month", partition.Month);
        using var reader = command.ExecuteReader();
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long count = 0;
        long first = 0;
        long last = 0;
        Span<byte> sequenceBytes = stackalloc byte[sizeof(long)];
        while (reader.Read())
        {
            var record = ReadAndVerifyEventForPurge(reader, partition, retentionPolicy.PolicyId);
            count++;
            if (first == 0) first = record.Sequence;
            last = record.Sequence;
            BinaryPrimitives.WriteInt64BigEndian(sequenceBytes, record.Sequence);
            aggregate.AppendData(sequenceBytes);
            aggregate.AppendData(Convert.FromHexString(record.IntegritySha256));
        }

        return count == 0
            ? new PartitionDigest(0, 0, 0, string.Empty)
            : new PartitionDigest(count, first, last, Convert.ToHexStringLower(aggregate.GetHashAndReset()));
    }

    private static AuditEventRecord ReadAndVerifyEventForPurge(SqliteDataReader reader, AuditPartition expectedPartition, Guid expectedPolicyId)
    {
        // The shared decoder verifies every field and digest; this method also binds each row to the approved owner month.
        var record = DecodeEvent(reader, expectedPolicyId);
        if (AuditPartition.For(record.Event.ActorChain.Owner, record.OccurredAt) != expectedPartition)
        {
            throw new InvalidDataException("Stored event is outside its owner partition.");
        }

        return record;
    }

    private static string ComputeEventHash(AuditEvent auditEvent, Instant occurredAt, Guid policyId, Guid eventId)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(auditEvent.DecisionDetail is null ? "ArcForges.local_audit.event.v4" : "ArcForges.local_audit.event.v5");
            writer.Write(GuidText(policyId));
            writer.Write(eventId.ToByteArray());
            writer.Write((int)auditEvent.EventType);
            writer.Write(occurredAt.UnixSeconds);
            writer.Write(occurredAt.Nanoseconds);
            var actor = ActorChainSnapshot.Encode(auditEvent.ActorChain);
            writer.Write(actor.Length);
            writer.Write(actor);
            writer.Write(auditEvent.SoftwareIdentity.Value);
            writer.Write(auditEvent.Capability.Value);
            writer.Write(auditEvent.Executor.Value.ToByteArray());
            writer.Write((int)auditEvent.Resource.Kind);
            writer.Write(auditEvent.Resource.Id.ToByteArray());
            writer.Write((int)auditEvent.Risk);
            writer.Write((int)auditEvent.Decision);
            writer.Write((int)auditEvent.Reason);
            writer.Write((int)auditEvent.Origin);
            WriteOptionalGuid(writer, auditEvent.Workspace?.Value);
            WriteOptionalGuid(writer, auditEvent.Task?.Value);
            WriteOptionalGuid(writer, auditEvent.Correlation?.Value);
            WriteOptionalEgress(writer, auditEvent.Egress);
            if (auditEvent.DecisionDetail is { } detail)
            {
                var bytes = DecisionAuditCodec.Encode(detail);
                writer.Write(bytes.Length);
                writer.Write(bytes);
            }
        }

        return Convert.ToHexStringLower(SHA256.HashData(stream.ToArray()));
    }

    private static void WriteOptionalEgress(BinaryWriter writer, AuditEgressDetail? egress)
    {
        writer.Write(egress is not null);
        if (egress is null) return;
        writer.Write((int)egress.Reason);
        writer.Write((int)egress.DataClass);
        writer.Write((int)egress.DestinationClass);
        writer.Write(egress.Destination is not null);
        if (egress.Destination is not null) writer.Write(egress.Destination.Value);
        writer.Write((int)egress.AuthorityKind);
        writer.Write(egress.AuthorityReference is not null);
        if (egress.AuthorityReference is not null) writer.Write(egress.AuthorityReference.Value);
        writer.Write(egress.GrantGeneration is not null);
        if (egress.GrantGeneration is not null) writer.Write(egress.GrantGeneration.Value);
        writer.Write(egress.Content.Value);
    }

    private static void WriteOptionalGuid(BinaryWriter writer, Guid? value)
    {
        writer.Write(value.HasValue);
        if (value is { } id) writer.Write(id.ToByteArray());
    }

    private static void SetPurgeGate(SqliteConnection connection, SqliteTransaction transaction, bool enabled)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"UPDATE {GateTable} SET enabled=$enabled WHERE singleton=1;";
        command.Parameters.AddWithValue("$enabled", enabled ? 1 : 0);
        if (command.ExecuteNonQuery() != 1) throw new InvalidDataException("The local audit maintenance gate is missing.");
    }

    private static long LastInsertSequence(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT last_insert_rowid();";
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Every call site supplies a fixed schema query; all external values use SQLite parameters.")]
    private static long ScalarLong(SqliteConnection connection, SqliteTransaction transaction, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
        Justification = "Only fixed schema statements are passed here during the internal schema-creation transaction; all runtime values are parameters.")]
    private static void Execute(SqliteConnection connection, SqliteTransaction transaction, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static string GuidText(Guid value) => value.ToString("N", System.Globalization.CultureInfo.InvariantCulture);
    private static Guid ParseGuid(string value) => Guid.ParseExact(value, "N");

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    }

    private static void SetAuthorizer(SqliteConnection connection, AuthorizerState state) =>
        SetConnectionAuthorization(connection, state);

    private static void SetConnectionAuthorization(SqliteConnection connection, AuthorizerState state)
    {
        connection.CreateFunction("arcforges_audit_retention_authorized", () => state.IsMaintenance ? 1 : 0);
        raw.sqlite3_set_authorizer(connection.Handle!, DatabaseAuthorizer, state);
    }

    private static void ClearAuthorizer(SqliteConnection connection) =>
        raw.sqlite3_set_authorizer(connection.Handle!, (strdelegate_authorizer)null!, null!);

    private static int AuthorizeDatabase(object state, int action, string first, string second, string database, string source)
    {
        if (state is not AuthorizerState authorization) return raw.SQLITE_DENY;
        if (action is raw.SQLITE_CREATE_INDEX or raw.SQLITE_CREATE_TABLE or raw.SQLITE_CREATE_TRIGGER or raw.SQLITE_CREATE_VIEW
            or raw.SQLITE_DROP_INDEX or raw.SQLITE_DROP_TABLE or raw.SQLITE_DROP_TRIGGER or raw.SQLITE_DROP_VIEW or raw.SQLITE_ALTER_TABLE)
        {
            return authorization.IsInitializing ? raw.SQLITE_OK : raw.SQLITE_DENY;
        }

        var table = first;
        if (action == raw.SQLITE_INSERT)
        {
            if (table == "sqlite_sequence") return raw.SQLITE_OK;
            if (table == EventTable || table == HoldTable) return raw.SQLITE_OK;
            if (table == AuthorityReceiptTable || table == PurgeReceiptTable) return authorization.IsMaintenance ? raw.SQLITE_OK : raw.SQLITE_DENY;
            if (table == $"{EventTable}_store" || table == GateTable) return authorization.IsInitializing ? raw.SQLITE_OK : raw.SQLITE_DENY;
        }

        if (action == raw.SQLITE_UPDATE)
        {
            if (table == $"{EventTable}_store" && authorization.IsInitializing) return raw.SQLITE_OK;
            if (table == GateTable && authorization.IsMaintenance) return raw.SQLITE_OK;
            return IsProtectedAuditTable(table) ? raw.SQLITE_DENY : raw.SQLITE_OK;
        }

        if (action == raw.SQLITE_DELETE)
        {
            if (table == EventTable && authorization.IsPurging) return raw.SQLITE_OK;
            return IsProtectedAuditTable(table) ? raw.SQLITE_DENY : raw.SQLITE_OK;
        }

        return raw.SQLITE_OK;
    }

    private static bool IsProtectedAuditTable(string table) => table == EventTable || table == HoldTable
        || table == AuthorityReceiptTable || table == PurgeReceiptTable || table == $"{EventTable}_store" || table == GateTable;

    private sealed class AuthorizerState
    {
        public bool IsInitializing { get; init; }
        public bool IsMaintenance { get; set; }
        public bool IsPurging { get; set; }
    }

    private readonly record struct PartitionDigest(long Count, long FirstSequence, long LastSequence, string Digest);
}
