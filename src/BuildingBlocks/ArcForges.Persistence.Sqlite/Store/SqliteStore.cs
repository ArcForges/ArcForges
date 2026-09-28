// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Persistence.Sqlite.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Persistence.Sqlite;

/// <summary>One atomic write path for payload, origin, journal, version, outbox and durable receipt.</summary>
public sealed class SqliteStore : IStore
{
    private readonly StoreDatabase database;
    private readonly IStoreAuthorization authorization;
    private readonly SqliteJournal journal;
    private readonly SqliteSnapshotCoordinator snapshots;
    private readonly Action<CommitStage>? fault;
    private readonly bool runSnapshotPolicy;

    public SqliteStore(string path, Guid storeId, IStoreAuthorization authorization)
        : this(path, storeId, authorization, null, null, performRecovery: true, runSnapshotPolicy: true) { }

    internal SqliteStore(string path, Guid storeId, IStoreAuthorization authorization, Action<CommitStage>? fault)
        : this(path, storeId, authorization, fault, null, performRecovery: true, runSnapshotPolicy: true) { }

    internal SqliteStore(string path, Guid storeId, IStoreAuthorization authorization, Action<CommitStage>? fault,
        JournalSnapshotPolicy? snapshotPolicy, bool performRecovery, bool runSnapshotPolicy,
        Action<SnapshotStage>? snapshotFault = null)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        this.authorization = authorization;
        this.fault = fault;
        this.runSnapshotPolicy = runSnapshotPolicy;
        snapshots = new(path, storeId, snapshotFault);
        Recovery = performRecovery
            ? snapshots.PrepareForOpen()
            : new(StoreRecoveryOutcome.Clean, 0, 0, null, "Recovery is disabled for this internal replay session.");
        journal = new(snapshots, snapshotPolicy);
        database = new(path, storeId);
        database.WithTransaction(context =>
        {
            using var command = context.CreateCommand("""
                CREATE TABLE IF NOT EXISTS store_identity(id TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS store_content(kind TEXT NOT NULL,id TEXT NOT NULL,version TEXT NOT NULL,payload BLOB NOT NULL,origin BLOB NOT NULL,PRIMARY KEY(kind,id));
                CREATE TABLE IF NOT EXISTS store_origins(id TEXT PRIMARY KEY,record BLOB NOT NULL,refs INTEGER NOT NULL CHECK(refs>=0));
                CREATE INDEX IF NOT EXISTS store_origins_refs ON store_origins(refs,id);
                CREATE TABLE IF NOT EXISTS store_origin_pending_refs(id TEXT PRIMARY KEY,refs INTEGER NOT NULL CHECK(refs>0));
                CREATE TABLE IF NOT EXISTS store_origin_edges(child TEXT NOT NULL,parent TEXT NOT NULL,PRIMARY KEY(child,parent));
                CREATE TABLE IF NOT EXISTS store_origin_identity(id TEXT PRIMARY KEY,checksum BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS store_local_heads(kind TEXT NOT NULL,id TEXT NOT NULL,head INTEGER NOT NULL,PRIMARY KEY(kind,id));
                CREATE TABLE IF NOT EXISTS store_history(kind TEXT NOT NULL,id TEXT NOT NULL,sequence INTEGER NOT NULL,version TEXT NOT NULL,payload BLOB NOT NULL,origin BLOB NOT NULL,PRIMARY KEY(kind,id,sequence));
                CREATE TABLE IF NOT EXISTS command_log(command_id TEXT PRIMARY KEY,fingerprint BLOB NOT NULL,version TEXT NOT NULL,sequence INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS sync_outbox(sequence INTEGER PRIMARY KEY,command_id TEXT NOT NULL UNIQUE,payload BLOB NOT NULL);
                """);
            command.ExecuteNonQuery();
            using var identity = context.CreateCommand("SELECT id FROM store_identity");
            var stored = identity.ExecuteScalar();
            if (stored is not null && (string)stored != storeId.ToString("D"))
                throw new InvalidOperationException("The file belongs to another store identity.");
            if (stored is null)
            {
                using var insert = context.CreateCommand("INSERT INTO store_identity(id) VALUES($id)");
                insert.Parameters.AddWithValue("$id", storeId.ToString("D")); insert.ExecuteNonQuery();
            }
            journal.Initialize(context);
            return 0;
        });
        Migrations = new(database);
    }
    public MigrationRunner Migrations { get; }
    public StoreRecoveryReport Recovery { get; }
    /// <summary>The most recently published policy snapshot, if one was produced by this open instance.</summary>
    public JournalSnapshotReceipt? LastSnapshot { get; private set; }
    /// <summary>Diagnostic for a post-commit policy snapshot failure; the write receipt remains authoritative.</summary>
    public string? LastSnapshotFailure { get; private set; }
    public event EventHandler<StoreCommittedEventArgs>? Committed;
    public StoredContent? Read(string aggregateKind, Guid aggregateId) => database.Read(context => ReadContent(context, aggregateKind, aggregateId));
    public IReadOnlyList<JournalEntry> ReadJournal(JournalSequence? after, int limit) => database.Read(context => journal.Read(context, after, limit));

    /// <summary>Creates a durable verified snapshot and truncates only the journal prefix it binds.</summary>
    public JournalSnapshotReceipt? CreateSnapshot()
    {
        EnsureWritableRecoveryState();
        var receipt = snapshots.CreateSnapshot(database, journal);
        LastSnapshot = receipt;
        LastSnapshotFailure = null;
        return receipt;
    }

    public CommitReceipt Write(WriteCommand command)
    {
        EnsureWritableRecoveryState();
        ArgumentNullException.ThrowIfNull(command);
        command.Content.ValidateForWrite();
        if (!command.Content.Version.IsSuccessorOf(command.Expected)) throw new ArgumentException("The next version must advance the materialized source token.", nameof(command));
        if (!authorization.CanWrite(command)) throw new UnauthorizedAccessException("The owner refused this write.");
        var fingerprint = Fingerprint(command);
        var receipt = database.WithTransaction(context =>
        {
            var unit = new CommitUnit(context);
            using (var previous = unit.Context.CreateCommand("SELECT fingerprint,version,sequence FROM command_log WHERE command_id=$command"))
            {
                previous.Parameters.AddWithValue("$command", command.CommandId.Value.ToString("D"));
                using var row = previous.ExecuteReader();
                if (row.Read())
                {
                    if (!CryptographicOperations.FixedTimeEquals(fingerprint, (byte[])row.GetValue(0)))
                        throw new InvalidOperationException("A command identity cannot be reused for different semantic content.");
                    return new CommitReceipt(command.CommandId, StoreVersion.ParseCanonicalText(row.GetString(1)), new(context.StoreId, row.GetInt64(2)), EffectCertainty.Happened, true);
                }
            }
            var current = ReadContent(context, command.AggregateKind, command.AggregateId);
            if ((current?.Version ?? StoreVersion.NewRoot) != command.Expected)
                throw new InvalidOperationException("The materialized source token changed; stale work cannot commit.");
            if (command.LocalSequence is { } localSequence)
            {
                if (command.Content.Version.Kind != StoreVersionKind.Native)
                    throw new ArgumentException("Explicit local identities apply only to native owner commits.", nameof(command));
                using var local = context.CreateCommand("SELECT head FROM store_local_heads WHERE kind=$kind AND id=$id");
                local.Parameters.AddWithValue("$kind", command.AggregateKind); local.Parameters.AddWithValue("$id", command.AggregateId.ToString("D"));
                if (local.ExecuteScalar() is long head && localSequence <= head)
                    throw new InvalidOperationException("The owner local identity must advance its durable high watermark.");
                using var advanceLocal = context.CreateCommand("INSERT INTO store_local_heads(kind,id,head) VALUES($kind,$id,$head) ON CONFLICT(kind,id) DO UPDATE SET head=excluded.head");
                advanceLocal.Parameters.AddWithValue("$kind", command.AggregateKind); advanceLocal.Parameters.AddWithValue("$id", command.AggregateId.ToString("D"));
                advanceLocal.Parameters.AddWithValue("$head", localSequence); advanceLocal.ExecuteNonQuery();
            }
            // Preserve unfamiliar existing origin versions instead of destructively rewriting them.
            if (current is not null && current.Origin.Profile != "arcforges.content-origin.v1")
                throw new InvalidOperationException("The existing content-origin profile is read-only.");
            if (current is not null && current.Origin.Kinds.Except(command.Content.Origin.Kinds, StringComparer.Ordinal).Any())
                throw new InvalidOperationException("An edit must retain the inherited content-origin kind union.");
            using (var origin = context.CreateCommand("SELECT checksum FROM store_origin_identity WHERE id=$id"))
            {
                origin.Parameters.AddWithValue("$id", ContentOriginId.FromWire(command.Content.Origin.OriginId).Value.ToString("D"));
                if (origin.ExecuteScalar() is byte[] prior && !CryptographicOperations.FixedTimeEquals(prior, SHA256.HashData(command.Content.OriginBytes)))
                    throw new InvalidOperationException("An immutable origin identity cannot be rewritten.");
            }
            using (var apply = context.CreateCommand("INSERT INTO store_content(kind,id,version,payload,origin) VALUES($kind,$id,$version,$payload,$origin) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload,origin=excluded.origin"))
            {
                BindContent(apply, command, command.Expected); apply.ExecuteNonQuery();
            }
            RegisterOrigin(context, command.Content);
            ChangeOriginReference(context, ContentOriginId.FromWire(command.Content.Origin.OriginId).Value.ToString("D"), 2);
            if (current is not null) ChangeOriginReference(context, ContentOriginId.FromWire(current.Origin.OriginId).Value.ToString("D"), -1);
            using (var identity = context.CreateCommand("INSERT OR IGNORE INTO store_origin_identity(id,checksum) VALUES($id,$checksum)"))
            {
                identity.Parameters.AddWithValue("$id", ContentOriginId.FromWire(command.Content.Origin.OriginId).Value.ToString("D"));
                identity.Parameters.AddWithValue("$checksum", SHA256.HashData(command.Content.OriginBytes)); identity.ExecuteNonQuery();
            }
            fault?.Invoke(CommitStage.Applied);
            var sequence = journal.GetNextSequence(context);
            var replay = EncodeContent(command.Content);
            journal.Append(context, JournalEntry.Create(sequence, command.AggregateKind, command.AggregateId,
                command.Expected, command.Content.Version, command.CommandId, command.Operation, 1, replay, null,
                command.Actor, command.CorrelationId, null, command.CommittedAt,
                command.Content.Version.Kind == StoreVersionKind.LocalProjection
                    ? (command.Content.Version.LocalVersion!.Value.HeadLocalSequence > (command.Expected.LocalVersion?.HeadLocalSequence ?? 0)
                        ? command.Content.Version.LocalVersion.Value.HeadLocalSequence : null)
                    : command.LocalSequence));
            fault?.Invoke(CommitStage.Journaled);
            using (var advance = context.CreateCommand("UPDATE store_content SET version=$version WHERE kind=$kind AND id=$id"))
            {
                advance.Parameters.AddWithValue("$version", command.Content.Version.CanonicalText);
                advance.Parameters.AddWithValue("$kind", command.AggregateKind); advance.Parameters.AddWithValue("$id", command.AggregateId.ToString("D"));
                if (advance.ExecuteNonQuery() != 1) throw new InvalidDataException("The version must advance exactly once.");
            }
            using (var history = context.CreateCommand("INSERT INTO store_history(kind,id,sequence,version,payload,origin) VALUES($kind,$id,$sequence,$version,$payload,$origin)"))
            {
                BindContent(history, command, command.Content.Version); history.Parameters.AddWithValue("$sequence", sequence.Value); history.ExecuteNonQuery();
            }
            CollectUnpinnedHistory(context, command);
            fault?.Invoke(CommitStage.RevisionAdvanced);
            using (var outbox = context.CreateCommand("INSERT INTO sync_outbox(sequence,command_id,payload) VALUES($sequence,$command,$payload)"))
            {
                outbox.Parameters.AddWithValue("$sequence", sequence.Value); outbox.Parameters.AddWithValue("$command", command.CommandId.Value.ToString("D"));
                outbox.Parameters.AddWithValue("$payload", replay); outbox.ExecuteNonQuery();
            }
            fault?.Invoke(CommitStage.OutboxEnqueued);
            using (var record = context.CreateCommand("INSERT INTO command_log(command_id,fingerprint,version,sequence) VALUES($command,$fingerprint,$version,$sequence)"))
            {
                record.Parameters.AddWithValue("$command", command.CommandId.Value.ToString("D")); record.Parameters.AddWithValue("$fingerprint", fingerprint);
                record.Parameters.AddWithValue("$version", command.Content.Version.CanonicalText); record.Parameters.AddWithValue("$sequence", sequence.Value); record.ExecuteNonQuery();
            }
            fault?.Invoke(CommitStage.ReceiptRecorded);
            return new CommitReceipt(command.CommandId, command.Content.Version, sequence, EffectCertainty.Happened, false);
        });
        if (!receipt.Replayed) TryPolicySnapshot();
        fault?.Invoke(CommitStage.Committed);
        // A failed notification leaves the durable receipt intact. The caller reconciles by retrying
        // the same command; the replay path never repeats the effect or its notification.
        if (!receipt.Replayed) Committed?.Invoke(this, new(receipt));
        return receipt;
    }

    private void EnsureWritableRecoveryState()
    {
        if (Recovery.RequiresSafeStart)
            throw new InvalidOperationException("The owner store is in read-first safe start after recovery; canonical writes are disabled until its evidence is resolved.");
    }

    private void TryPolicySnapshot()
    {
        if (!runSnapshotPolicy) return;
        try
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (!SqliteSnapshotCoordinator.RequiresSnapshot(database, journal, new ArcForges.Foundation.Instant(now, 0)))
            {
                LastSnapshotFailure = null;
                return;
            }
            LastSnapshot = snapshots.CreateSnapshot(database, journal);
            LastSnapshotFailure = null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException or
            InvalidDataException or InvalidOperationException)
        {
            // The write and its receipt are already durable. Snapshot failure is reported separately and
            // leaves the journal prefix untouched, so callers must not retry the write as if it rolled back.
            LastSnapshotFailure = exception.Message;
        }
    }

    private static StoredContent? ReadContent(SqliteReadContext context, string kind, Guid id)
    {
        using var command = context.CreateCommand("SELECT version,payload,origin FROM store_content WHERE kind=$kind AND id=$id");
        command.Parameters.AddWithValue("$kind", kind); command.Parameters.AddWithValue("$id", id.ToString("D"));
        using var row = command.ExecuteReader();
        return row.Read() ? new(StoreVersion.ParseCanonicalText(row.GetString(0)), (byte[])row.GetValue(1), ContentOrigin.Parser.ParseFrom((byte[])row.GetValue(2))) : null;
    }
    private static void RegisterOrigin(SqliteCommitContext context, StoredContent content)
    {
        var value = content.Origin;
        var id = ContentOriginId.FromWire(value.OriginId).Value.ToString("D");
        using var insert = context.CreateCommand("INSERT OR IGNORE INTO store_origins(id,record,refs) VALUES($id,$record,COALESCE((SELECT refs FROM store_origin_pending_refs WHERE id=$id),0))");
        insert.Parameters.AddWithValue("$id", id); insert.Parameters.AddWithValue("$record", content.OriginBytes);
        if (insert.ExecuteNonQuery() == 0) return;
        using (var pending = context.CreateCommand("DELETE FROM store_origin_pending_refs WHERE id=$id"))
        { pending.Parameters.AddWithValue("$id", id); pending.ExecuteNonQuery(); }
        foreach (var parent in value.ParentOriginIds)
        {
            var parentId = ContentOriginId.FromWire(parent).Value.ToString("D");
            using (var inherited = context.CreateCommand("SELECT record FROM store_origins WHERE id=$id"))
            {
                inherited.Parameters.AddWithValue("$id", parentId);
                if (inherited.ExecuteScalar() is byte[] record &&
                    ContentOrigin.Parser.ParseFrom(record).Kinds.Except(value.Kinds, StringComparer.Ordinal).Any())
                    throw new InvalidOperationException("The declared kind union omits a retained contributing origin.");
            }
            using var edge = context.CreateCommand("INSERT INTO store_origin_edges(child,parent) VALUES($child,$parent)");
            edge.Parameters.AddWithValue("$child", id); edge.Parameters.AddWithValue("$parent", parentId); edge.ExecuteNonQuery();
            ChangeOriginReference(context, parentId, 1);
        }
    }
    private static void ChangeOriginReference(SqliteCommitContext context, string id, int delta)
    {
        using var update = context.CreateCommand("UPDATE store_origins SET refs=refs+$delta WHERE id=$id");
        update.Parameters.AddWithValue("$id", id); update.Parameters.AddWithValue("$delta", delta);
        if (update.ExecuteNonQuery() == 1) return;
        using var read = context.CreateCommand("SELECT refs FROM store_origin_pending_refs WHERE id=$id");
        read.Parameters.AddWithValue("$id", id);
        var next = checked((read.ExecuteScalar() is long refs ? refs : 0) + delta);
        if (next < 0) throw new InvalidDataException("Origin reference accounting underflow.");
        if (next == 0)
        {
            using var remove = context.CreateCommand("DELETE FROM store_origin_pending_refs WHERE id=$id");
            remove.Parameters.AddWithValue("$id", id); remove.ExecuteNonQuery();
        }
        else
        {
            using var pending = context.CreateCommand("INSERT INTO store_origin_pending_refs(id,refs) VALUES($id,$refs) ON CONFLICT(id) DO UPDATE SET refs=excluded.refs");
            pending.Parameters.AddWithValue("$id", id); pending.Parameters.AddWithValue("$refs", next); pending.ExecuteNonQuery();
        }
    }
    // Fixed budgets: 64 history roots and 64 zero-reference origins; each origin has at most 32 edges.
    // Indexed reference counts avoid scanning unrelated roots or traversing retained lineage.
    private static void CollectUnpinnedHistory(SqliteCommitContext context, WriteCommand command)
    {
        var expired = new List<(long Sequence, string Origin)>();
        using (var query = context.CreateCommand("SELECT sequence,origin FROM store_history WHERE kind=$kind AND id=$id ORDER BY sequence DESC LIMIT 64 OFFSET 64"))
        {
            query.Parameters.AddWithValue("$kind", command.AggregateKind); query.Parameters.AddWithValue("$id", command.AggregateId.ToString("D"));
            using var rows = query.ExecuteReader();
            while (rows.Read()) expired.Add((rows.GetInt64(0), ContentOriginId.FromWire(ContentOrigin.Parser.ParseFrom((byte[])rows.GetValue(1)).OriginId).Value.ToString("D")));
        }
        foreach (var item in expired)
        {
            using var remove = context.CreateCommand("DELETE FROM store_history WHERE kind=$kind AND id=$id AND sequence=$sequence");
            remove.Parameters.AddWithValue("$kind", command.AggregateKind); remove.Parameters.AddWithValue("$id", command.AggregateId.ToString("D"));
            remove.Parameters.AddWithValue("$sequence", item.Sequence); remove.ExecuteNonQuery();
            ChangeOriginReference(context, item.Origin, -1);
        }
        for (var count = 0; count < 64; count++)
        {
            using var candidate = context.CreateCommand("SELECT id FROM store_origins WHERE refs=0 ORDER BY id LIMIT 1");
            if (candidate.ExecuteScalar() is not string id) break;
            var parents = new List<string>();
            using (var edges = context.CreateCommand("SELECT parent FROM store_origin_edges WHERE child=$id LIMIT 32"))
            {
                edges.Parameters.AddWithValue("$id", id); using var rows = edges.ExecuteReader();
                while (rows.Read()) parents.Add(rows.GetString(0));
            }
            foreach (var parent in parents) ChangeOriginReference(context, parent, -1);
            using var removeEdges = context.CreateCommand("DELETE FROM store_origin_edges WHERE child=$id");
            removeEdges.Parameters.AddWithValue("$id", id); removeEdges.ExecuteNonQuery();
            using var remove = context.CreateCommand("DELETE FROM store_origins WHERE id=$id");
            remove.Parameters.AddWithValue("$id", id); remove.ExecuteNonQuery();
        }
    }
    private static void BindContent(SqliteCommand sql, WriteCommand command, StoreVersion version)
    {
        sql.Parameters.AddWithValue("$kind", command.AggregateKind); sql.Parameters.AddWithValue("$id", command.AggregateId.ToString("D"));
        sql.Parameters.AddWithValue("$version", version.CanonicalText); sql.Parameters.AddWithValue("$payload", command.Content.Payload.ToArray());
        sql.Parameters.AddWithValue("$origin", command.Content.OriginBytes);
    }
    private static byte[] EncodeContent(StoredContent content)
    {
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream, Encoding.UTF8, true);
        writer.Write("ArcForges.StoreContent.v1"); writer.Write(content.Payload.Length); writer.Write(content.Payload.Span);
        writer.Write(content.OriginBytes.Length); writer.Write(content.OriginBytes); writer.Flush(); return stream.ToArray();
    }
    private static byte[] Fingerprint(WriteCommand command)
    {
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream, Encoding.UTF8, true);
        writer.Write(command.AggregateKind); writer.Write(command.AggregateId.ToString("D")); writer.Write(command.Actor.Value.ToString("D"));
        writer.Write(command.Operation); writer.Write(command.Expected.CanonicalText); writer.Write(command.Content.Version.CanonicalText);
        writer.Write(command.LocalSequence.HasValue); if (command.LocalSequence.HasValue) writer.Write(command.LocalSequence.Value);
        writer.Write(EncodeContent(command.Content)); writer.Flush(); return SHA256.HashData(stream.ToArray());
    }
    public void Dispose() => database.Dispose();
}
