// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Node.Store;

internal sealed record DurableCapacity(int MaximumReceipts = 4096, int SafetyReceipts = 8,
    int MaximumResponseBytes = 1048576, long MaximumJournalBytes = 67108864);

internal sealed record DurableIntent(byte[] CommandId, byte[] OwnerEpoch, string Method, string? AggregateKind,
    string? AggregateId, byte[] CanonicalBody, long? ExpectedSandboxRevision = null, byte[]? SafetyParent = null);

internal enum DurableDecision { Execute, Replay, InProgress, Compacted, Conflict, EpochRetired, RevisionConflict, Capacity, Maintenance }

internal sealed record DurableReceipt(string CommandId, string Method, string? AggregateKind, string? AggregateId,
    string State, int Effect, string? ResponseJson, bool Compacted);

internal sealed record DurableAdmission(DurableDecision Decision, DurableReceipt? Receipt);

/// <summary>
/// V2 owner-epoch durable commands. The host supplies the protected backend, and authorizes the caller before disclosing
/// results. Only short SQLite metadata changes run inside its FULL transaction; no native/network effect runs here.
/// </summary>
internal sealed partial class DurableCommandStore : IDisposable
{
    private readonly NodeStore _store;
    private readonly string _owner;
    private readonly NodeSecretStore _secrets;
    private DurableCapacity _capacity;
    private readonly DurableCapacity? _requestedCapacity;
    private readonly Lock _gate = new();
    private readonly string _fencePath;
    private readonly FileStream _ownerLock;
    private byte[] _key = [];
    private DurableEpochFence _fence = null!;
    private bool _disposed;

    internal bool MaintenanceRequired { get; private set; }
    internal ReadOnlyMemory<byte> OwnerEpoch => _fence.Epoch;

    internal DurableCommandStore(NodeStore store, string owner, NodeSecretStore secrets, DurableCapacity? capacity = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentException.ThrowIfNullOrWhiteSpace(owner);
        if (Encoding.UTF8.GetByteCount(owner) > 256) throw new ArgumentOutOfRangeException(nameof(owner));
        _store = store;
        _owner = owner;
        _secrets = secrets;
        _capacity = capacity ?? new();
        _requestedCapacity = capacity;
        if (_capacity.MaximumReceipts <= _capacity.SafetyReceipts || _capacity.SafetyReceipts < 1
            || _capacity.MaximumResponseBytes is < 1024 or > 1048576
            || _capacity.MaximumJournalBytes < (long)(_capacity.SafetyReceipts + 2) * _capacity.MaximumResponseBytes)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        if (store.Metadata.SchemaVersion < 16) throw new StoreIncompatibleException("V2 commands require schema16.");
        _fencePath = DurableEpochFence.PathFor(store.DataRoot, owner);
        _ownerLock = DurableEpochFence.OpenPrivate(_fencePath + ".lock", FileMode.OpenOrCreate);
        try
        {
            using var catalogue = DurableEpochFence.OpenCatalogueLock(store.DataRoot);
            OpenEpoch();
        }
        catch { _ownerLock.Dispose(); CryptographicOperations.ZeroMemory(_key); throw; }
    }

    private void OpenEpoch()
    {
        var epoch = _store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT owner_epoch,digest_key_ref,state,admission_sequence,history_hmac_sha256 FROM owner_epoch WHERE owner_id=$owner;");
            command.Parameters.AddWithValue("$owner", _owner);
            using var row = command.ExecuteReader();
            if (!row.Read()) return ((DurableEpochFence?)null, false);
            var value = new DurableEpochFence(_owner, (byte[])row[0], row.GetString(1), row.GetInt64(3), Convert.FromHexString(row.GetString(4)));
            bool active = row.GetString(2) == "ACTIVE";
            if (row.Read()) throw new DurableStoreMaintenanceException(); // Never select/rotate among retired authorities.
            return (value, active);
        });
        if (epoch.Item1 is null)
        {
            if (File.Exists(_fencePath)) throw new DurableStoreMaintenanceException();
            byte[] id = RandomNumberGenerator.GetBytes(16);
            string target = NodeDataKeyRing.TargetName(_store.Metadata.NodeId.Span, "v2-owner-" + Convert.ToHexStringLower(id));
            _key = RandomNumberGenerator.GetBytes(32);
            _secrets.Store.Write(target, _key);
            _fence = new(_owner, id, _secrets.Backend + "|" + target, 0, new byte[32]);
            _fence.Write(_fencePath, _key);
            _store.Write(tx =>
            {
                tx.Execute("INSERT INTO owner_epoch(owner_id,owner_epoch,digest_key_ref,state,created_utc) VALUES($o,$e,$k,'ACTIVE',$now);",
                    ("$o", _owner), ("$e", id), ("$k", _fence.KeyReference), ("$now", Now()));
                tx.Execute("INSERT INTO owner_epoch_capacity(owner_id,owner_epoch,maximum_receipts,safety_receipts,maximum_response_bytes,maximum_journal_bytes,reserve_storage) VALUES($o,$e,$m,$s,$b,$budget,zeroblob($r));",
                    ("$o", _owner), ("$e", id), ("$m", _capacity.MaximumReceipts), ("$s", _capacity.SafetyReceipts),
                    ("$b", _capacity.MaximumResponseBytes), ("$budget", _capacity.MaximumJournalBytes),
                    ("$r", checked(_capacity.SafetyReceipts * _capacity.MaximumResponseBytes)));
            }, CommitDurability.Full);
            return;
        }
        _fence = epoch.Item1;
        _capacity = _store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT maximum_receipts,safety_receipts,maximum_response_bytes,maximum_journal_bytes FROM owner_epoch_capacity WHERE owner_id=$o AND owner_epoch=$e;");
            command.Parameters.AddWithValue("$o", _owner); command.Parameters.AddWithValue("$e", _fence.Epoch);
            using var row = command.ExecuteReader();
            return row.Read() ? new DurableCapacity(row.GetInt32(0), row.GetInt32(1), row.GetInt32(2), row.GetInt64(3))
                : throw new DurableStoreMaintenanceException();
        });
        if (_requestedCapacity is not null && _requestedCapacity != _capacity)
            throw new InvalidOperationException("Changing persisted owner capacity requires explicit maintenance.");
        string prefix = _secrets.Backend + "|";
        if (!epoch.Item2 || !_fence.KeyReference.StartsWith(prefix, StringComparison.Ordinal))
        {
            MaintenanceRequired = true;
            return;
        }
        _key = _secrets.Store.Read(_fence.KeyReference[prefix.Length..]) ?? [];
        if (_key.Length != 32) { MaintenanceRequired = true; return; }
        try
        {
            var recorded = DurableEpochFence.Read(_fencePath, _key);
            MaintenanceRequired = recorded.Owner != _owner || !recorded.Epoch.AsSpan().SequenceEqual(_fence.Epoch)
                || recorded.KeyReference != _fence.KeyReference || recorded.Sequence != _fence.Sequence
                || !CryptographicOperations.FixedTimeEquals(recorded.History, _fence.History);
        }
        catch (DurableStoreMaintenanceException) { MaintenanceRequired = true; }
    }

    internal DurableAdmission Admit(DurableIntent intent, Action<StoreTransaction>? metadataChanges = null)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Validate(intent);
            if (!intent.OwnerEpoch.AsSpan().SequenceEqual(_fence.Epoch)) return new(DurableDecision.EpochRetired, null);
            if (!Equals(_store.Read(reader => reader.Scalar("SELECT state FROM owner_epoch WHERE owner_id=$o AND owner_epoch=$e;",
                ("$o", _owner), ("$e", _fence.Epoch))), "ACTIVE")) return new(DurableDecision.EpochRetired, null);
            if (MaintenanceRequired) return new(DurableDecision.Maintenance, null);
            byte[] digest = IntentDigest(intent);
            string id = Convert.ToHexStringLower(intent.CommandId);
            if (intent.SafetyParent is not null)
            {
                string? held = _store.Read(reader => reader.Scalar("SELECT command_id FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND safety_parent_command_id=$p AND method=$m;",
                    ("$o", _owner), ("$e", _fence.Epoch), ("$p", Convert.ToHexStringLower(intent.SafetyParent)), ("$m", intent.Method)) as string);
                if (held is not null) id = held;
            }
            var existing = _store.Read(reader => ReadReceipt(reader, id));
            if (existing is not null)
            {
                bool matches = existing.Method == intent.Method && _store.Read(reader =>
                    CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString((string)reader.Scalar(
                        "SELECT request_hmac_sha256 FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c;",
                        ("$o", _owner), ("$e", _fence.Epoch), ("$c", id))!)));
                return new(!matches ? DurableDecision.Conflict : existing.Compacted ? DurableDecision.Compacted
                    : existing.State is "ACCEPTED" or "UNKNOWN" ? DurableDecision.InProgress : DurableDecision.Replay, existing);
            }
            var precondition = _store.Read(reader => CanAdmit(reader, intent));
            if (precondition != DurableDecision.Execute) return new(precondition, null);
            Advance("admit", id, digest, tx =>
            {
                if (CanAdmit(tx, intent) != DurableDecision.Execute) throw new DurableStoreMaintenanceException();
                string? parent = intent.SafetyParent is null ? null : Convert.ToHexStringLower(intent.SafetyParent);
                if (parent is not null)
                    tx.Execute("UPDATE owner_epoch_capacity SET reserve_storage=substr(reserve_storage,1,length(reserve_storage)-$n) WHERE owner_id=$o AND owner_epoch=$e;",
                        ("$n", _capacity.MaximumResponseBytes), ("$o", _owner), ("$e", _fence.Epoch));
                tx.Execute("""
                    INSERT INTO command_receipt(owner_id,owner_epoch,command_id,method,request_hmac_sha256,aggregate_kind,aggregate_id,
                      state,effect_certainty,response_json,created_utc,updated_utc,admission_sequence,safety_parent_command_id,reserved_response)
                    VALUES($o,$e,$c,$m,$h,$ak,$ai,'ACCEPTED',3,'{}',$now,$now,$seq,$parent,zeroblob($reserve));
                    """, ("$o", _owner), ("$e", _fence.Epoch), ("$c", id), ("$m", intent.Method),
                    ("$h", Convert.ToHexStringLower(digest)), ("$ak", intent.AggregateKind), ("$ai", intent.AggregateId),
                    ("$now", Now()), ("$seq", _fence.Sequence), ("$parent", parent), ("$reserve", _capacity.MaximumResponseBytes));
                metadataChanges?.Invoke(tx);
            });
            return new(DurableDecision.Execute, _store.Read(reader => ReadReceipt(reader, id)));
        }
    }

    private DurableDecision CanAdmit(StoreReader reader, DurableIntent intent)
    {
        if (intent.ExpectedSandboxRevision is { } revision &&
            !Equals(reader.Scalar("SELECT revision FROM sandbox WHERE owner_id=$o AND sandbox_id=$id;",
                ("$o", _owner), ("$id", intent.AggregateId)), revision)) return DurableDecision.RevisionConflict;
        long count = (long)reader.Scalar("SELECT count(*) FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e;",
            ("$o", _owner), ("$e", _fence.Epoch))!;
        bool safety = intent.SafetyParent is not null;
        long reserve = (long)reader.Scalar("SELECT length(reserve_storage) FROM owner_epoch_capacity WHERE owner_id=$o AND owner_epoch=$e;",
            ("$o", _owner), ("$e", _fence.Epoch))!;
        if (reserve < _capacity.MaximumResponseBytes) return DurableDecision.Capacity;
        if (!safety)
        {
            long active = (long)reader.Scalar("""
                SELECT count(*) FROM command_receipt p WHERE p.owner_id=$o AND p.owner_epoch=$e AND p.safety_parent_command_id IS NULL
                  AND NOT(p.state IN ('SUCCEEDED','FAILED') AND p.effect_certainty=1)
                  AND NOT EXISTS(SELECT 1 FROM command_receipt s WHERE s.owner_id=p.owner_id AND s.owner_epoch=p.owner_epoch AND s.safety_parent_command_id=p.command_id);
                """, ("$o", _owner), ("$e", _fence.Epoch))!;
            if ((active + 1) * _capacity.MaximumResponseBytes > reserve) return DurableDecision.Capacity;
            if (count + active + 2 > _capacity.MaximumReceipts) return DurableDecision.Capacity;
        }
        if (safety)
        {
            string parent = Convert.ToHexStringLower(intent.SafetyParent!);
            if (!Equals(reader.Scalar("SELECT count(*) FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND command_id=$p AND aggregate_kind IS $k AND aggregate_id IS $id AND safety_parent_command_id IS NULL;",
                ("$o", _owner), ("$e", _fence.Epoch), ("$p", parent), ("$k", intent.AggregateKind), ("$id", intent.AggregateId)), 1L))
                return DurableDecision.Conflict;
            if (!Equals(reader.Scalar("SELECT count(*) FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND safety_parent_command_id=$p;",
                ("$o", _owner), ("$e", _fence.Epoch), ("$p", parent)), 0L)) return DurableDecision.Conflict;
        }
        long bytes = (long)reader.Scalar("SELECT coalesce(sum(coalesce(length(CAST(response_json AS BLOB)),0)+length(reserved_response)+2048),0) FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e;",
            ("$o", _owner), ("$e", _fence.Epoch))!;
        return count >= _capacity.MaximumReceipts
            || bytes + reserve + (safety ? 0 : _capacity.MaximumResponseBytes) + 2048 > _capacity.MaximumJournalBytes
            ? DurableDecision.Capacity : DurableDecision.Execute;
    }

    internal DurableReceipt? Inspect(ReadOnlySpan<byte> commandId)
    {
        StoreIds.Validate(commandId, nameof(commandId));
        string id = Convert.ToHexStringLower(commandId);
        return _store.Read(reader => ReadReceipt(reader, id));
    }

    private DurableReceipt? ReadReceipt(StoreReader reader, string id)
    {
        using var command = reader.CreateCommand("SELECT command_id,method,aggregate_kind,aggregate_id,state,effect_certainty,response_json,response_compacted_utc FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c;");
        command.Parameters.AddWithValue("$o", _owner); command.Parameters.AddWithValue("$e", _fence.Epoch); command.Parameters.AddWithValue("$c", id);
        using var row = command.ExecuteReader();
        return !row.Read() ? null : new(row.GetString(0), row.GetString(1), row.IsDBNull(2) ? null : row.GetString(2),
            row.IsDBNull(3) ? null : row.GetString(3), row.GetString(4), row.GetInt32(5), row.IsDBNull(6) ? null : row.GetString(6), !row.IsDBNull(7));
    }

    private void Advance(string kind, string command, ReadOnlySpan<byte> content, Action<StoreTransaction> write)
    {
        byte[] historyInput = [.. _fence.History, .. Encoding.UTF8.GetBytes(kind + "|" + command), .. content];
        byte[] history = HMACSHA256.HashData(_key, historyInput);
        var next = _fence with { Sequence = checked(_fence.Sequence + 1), History = history };
        next.Write(_fencePath, _key);
        long previous = _fence.Sequence;
        _fence = next;
        try
        {
            _store.Write(tx =>
            {
                if (tx.Execute("UPDATE owner_epoch SET admission_sequence=$next,history_hmac_sha256=$hash WHERE owner_id=$o AND owner_epoch=$e AND state='ACTIVE' AND admission_sequence=$previous;",
                    ("$next", next.Sequence), ("$hash", Convert.ToHexStringLower(history)), ("$o", _owner), ("$e", next.Epoch), ("$previous", previous)) != 1)
                    throw new DurableStoreMaintenanceException();
                write(tx);
            }, CommitDurability.Full);
        }
        catch { MaintenanceRequired = true; throw; }
    }

    private byte[] IntentDigest(DurableIntent intent)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(1); writer.Write(_owner); writer.Write(_fence.Epoch); writer.Write(intent.Method);
            writer.Write(intent.AggregateKind ?? ""); writer.Write(intent.AggregateId ?? "");
            writer.Write(intent.SafetyParent?.Length ?? 0); writer.Write(intent.SafetyParent ?? []);
            writer.Write(intent.ExpectedSandboxRevision ?? 0); writer.Write(intent.CanonicalBody.Length); writer.Write(intent.CanonicalBody);
        }
        return HMACSHA256.HashData(_key, stream.ToArray());
    }

    private static void Validate(DurableIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        StoreIds.Validate(intent.CommandId, nameof(intent)); StoreIds.Validate(intent.OwnerEpoch, nameof(intent));
        ArgumentNullException.ThrowIfNull(intent.CanonicalBody);
        if (intent.SafetyParent is not null) StoreIds.Validate(intent.SafetyParent, nameof(intent));
        ArgumentException.ThrowIfNullOrWhiteSpace(intent.Method);
        int separator = intent.Method.IndexOf('.');
        if (separator < 1 || separator != intent.Method.LastIndexOf('.') || separator == intent.Method.Length - 1
            || !intent.Method[..separator].EndsWith("Service", StringComparison.Ordinal)
            || !intent.Method.Where(character => character != '.').All(char.IsAsciiLetterOrDigit))
            throw new ArgumentException("A durable method uses its canonical Service.Method identity.", nameof(intent));
        if (intent.Method is "RunService.AcquireTerminal" or "RunService.WriteTerminal" or "RunService.ResizeTerminal" or "RunService.DetachTerminal"
            || intent.Method.Contains("/AcquireTerminal", StringComparison.Ordinal) || intent.Method.Contains("/WriteTerminal", StringComparison.Ordinal)
            || intent.Method.Contains("/ResizeTerminal", StringComparison.Ordinal) || intent.Method.Contains("/DetachTerminal", StringComparison.Ordinal)
            || intent.CanonicalBody.Length > 1048576 || (intent.AggregateKind is null) != (intent.AggregateId is null)
            || intent.AggregateKind is not null && (string.IsNullOrWhiteSpace(intent.AggregateKind) || string.IsNullOrWhiteSpace(intent.AggregateId)))
            throw new ArgumentException("Invalid durable command shape.", nameof(intent));
    }

    private string Now() => _store.Clock.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            CryptographicOperations.ZeroMemory(_key);
            _ownerLock.Dispose();
        }
    }
}
