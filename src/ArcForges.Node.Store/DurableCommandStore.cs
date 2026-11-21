// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ArcForges.Node.Store;

internal sealed record DurableCapacity(int MaximumReceipts = 4096, int SafetyReceipts = 8,
    int MaximumResponseBytes = 1048576, long MaximumJournalBytes = 67108864);

internal enum DurableGrantAction { Replace, Revoke }

internal sealed record DurableGrantPrecondition(long ExpectedRevision, DurableGrantAction Action);

internal sealed record DurableProvisionBinding(string ParentGrantId, long ParentGrantRevision, string DerivedGrantId);

internal sealed record DurableDeletionBinding(string OriginalCommandId, string DeletionId);

internal sealed record DurableIntent(byte[] CommandId, byte[] OwnerEpoch, string Method, string? AggregateKind,
    string? AggregateId, byte[] CanonicalBody, long? ExpectedSandboxRevision = null, byte[]? SafetyParent = null,
    string? ExpectedSandboxId = null, DurableGrantPrecondition? Grant = null, int AdditionalSafetyReservations = 0,
    DurableProvisionBinding? Provision = null, DurableRemoteBinding? Remote = null, DurableDeletionBinding? Deletion = null);

internal enum DurableDecision { Execute, Replay, InProgress, Compacted, Conflict, EpochRetired, RevisionConflict, Capacity, Maintenance }

internal sealed record DurableReceipt(string CommandId, string Method, string? AggregateKind, string? AggregateId,
    string State, int Effect, string? ResponseJson, bool Compacted, string? SafetyParentCommandId = null,
    DurableProvisionBinding? Provision = null, DurableRemoteBinding? Remote = null, DurableDeletionBinding? Deletion = null);

internal sealed record DurableAdmission(DurableDecision Decision, DurableReceipt? Receipt);

/// <summary>
/// V2 owner-epoch durable commands. The host supplies the protected backend, and authorizes the caller before disclosing
/// results. Only short SQLite metadata changes run inside its FULL transaction; no native/network effect runs here.
/// </summary>
internal sealed partial class DurableCommandStore : IDisposable
{
    private const string GrantAggregate = "grant";
    private const string SetGrantMethod = "NodeService.SetRemoteGrant";
    private const string RevokeGrantMethod = "NodeService.RevokeRemoteGrant";
    private const string SandboxCreateMethod = "SandboxService.Create";
    private const string ResourcePolicyMethod = "ResourceService.SetPolicy";
    private const int ReceiptIdentityBytes = 2048;
    private const int PendingReceiptBodyBytes = 2;
    private const int ReservedSafetyIdentityBytes = ReceiptIdentityBytes + PendingReceiptBodyBytes;
    private const string ImportCloseAnchor = """
        FROM transfer AS t
        JOIN sandbox AS s ON s.sandbox_id=t.sandbox_id AND s.owner_id=t.owner_id
        JOIN command_receipt AS b ON b.owner_id=t.owner_id AND b.owner_epoch=t.owner_epoch AND b.command_id=t.command_id
        LEFT JOIN remote_command_binding AS rb ON rb.owner_id=b.owner_id AND rb.owner_epoch=b.owner_epoch AND rb.command_id=b.command_id
        WHERE t.direction='import' AND t.state IN (1,2,5) AND t.closed_utc IS NULL
          AND t.staging_identity<>$unbound AND length(t.staging_identity)>0
          AND ((rb.command_id IS NULL AND json_extract(t.manifest_json,'$.actorId')=t.owner_id
                  AND json_extract(t.manifest_json,'$.grantId') IS NULL)
               OR (rb.scope_kind='sandbox' AND rb.sandbox_id=t.sandbox_id
                  AND rb.actor_id=json_extract(t.manifest_json,'$.actorId')
                  AND rb.grant_id=json_extract(t.manifest_json,'$.grantId')
                  AND rb.grant_revision=json_extract(t.manifest_json,'$.grantRevision')
                  AND rb.enrollment_id=json_extract(t.manifest_json,'$.enrollmentId')))
          AND b.method=$beginImport AND b.aggregate_kind='transfer' AND b.aggregate_id=t.transfer_id
          AND b.state='SUCCEEDED' AND b.effect_certainty=2 AND b.safety_parent_command_id IS NULL
          AND NOT EXISTS(SELECT 1 FROM command_receipt AS child
            WHERE child.owner_id=b.owner_id AND child.owner_epoch=b.owner_epoch AND child.safety_parent_command_id=b.command_id)
        """;

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

    internal static bool HasExistingAuthority(NodeStore store, string owner)
    {
        VerifyRestorePublication(store.DataRoot);
        string fence = DurableEpochFence.PathFor(store.DataRoot, owner);
        bool hasFence = File.Exists(fence);
        var (hasEpoch, hasAnyEpoch) = store.Read(reader => (
            Equals(reader.Scalar("SELECT EXISTS(SELECT 1 FROM owner_epoch WHERE owner_id=$o);", ("$o", owner)), 1L),
            Equals(reader.Scalar("SELECT EXISTS(SELECT 1 FROM owner_epoch);"), 1L)));
        if (hasFence != hasEpoch)
        {
            throw new DurableStoreMaintenanceException();
        }

        if (!hasEpoch && (hasAnyEpoch || Directory.EnumerateFiles(Path.GetDirectoryName(fence)!, "v2-owner-*.fence").Any()))
        {
            throw new DurableStoreMaintenanceException();
        }

        return hasEpoch;
    }

    internal byte[] DeriveRunControlKey(string runId, string launchSha256)
    {
        if (!IsGrantIdentity(runId) || launchSha256.Length != 64 || !launchSha256.All(char.IsAsciiHexDigitLower))
        {
            throw new ArgumentException("Run control derivation requires a canonical Run ID and launch digest.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();
            ReadOnlySpan<byte> domain = "ArcForges.V2.RunControlKey.v1\0"u8;
            Span<byte> material = stackalloc byte[domain.Length + 16 + 16 + 32];
            domain.CopyTo(material);
            _fence.Epoch.CopyTo(material[domain.Length..]);
            Convert.FromHexString(runId).CopyTo(material[(domain.Length + 16)..]);
            Convert.FromHexString(launchSha256).CopyTo(material[(domain.Length + 32)..]);
            return HMACSHA256.HashData(_key, material);
        }
    }

    internal void RecordRunPreparing(byte[] startCommand, string runId, string runEpoch)
    {
        StoreIds.Validate(startCommand, nameof(startCommand));
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();
            string id = Convert.ToHexStringLower(startCommand);
            var run = _store.Read(reader =>
            {
                var receipt = ReadReceipt(reader, id);
                var candidate = RunRecords.Get(reader, _owner, runId);
                return receipt is { Method: "RunService.Start", AggregateKind: "run", State: "ACCEPTED", Effect: 3 }
                    && receipt.AggregateId == runId && candidate is { State: StoredRunState.Starting }
                    && candidate.Epoch == runEpoch && RunRecoveryRecords.Read(reader, _owner, candidate) is { PrepareStarted: false }
                    ? candidate : null;
            });
            if (run is null)
                throw new InvalidOperationException("Preparation requires the exact still-accepted original Run Start.");

            // Publish the independent witness before the SQL marker and any native launch attempt.
            byte[] identity = Encoding.UTF8.GetBytes(run.RunId + "|" + run.Epoch + "|" + run.LaunchSha256);
            Advance("run_preparing", id, identity, transaction =>
            {
                if (!RunRecoveryRecords.MarkPreparing(transaction, _owner, run.RunId, run.Epoch))
                    throw new DurableStoreMaintenanceException();
            });
        }
    }

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
        VerifyRestorePublication(store.DataRoot);
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

    internal DurableAdmission Admit(DurableIntent intent, Action<StoreTransaction>? metadataChanges = null) =>
        Admit(intent, metadataChanges, null);

    /// <summary>Atomically journals an already observed outcome and its optional metadata on first admission.</summary>
    internal DurableAdmission AdmitObserved(DurableIntent intent, string state, int effect, string redactedJson,
        Action<StoreTransaction>? observedMetadata = null) =>
        Admit(intent, observedMetadata, new(state, effect, redactedJson));

    private DurableAdmission Admit(DurableIntent intent, Action<StoreTransaction>? metadataChanges, InitialResult? observed)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Validate(intent);
            if (observed is not null)
                ValidateResult(observed.State, observed.Effect, observed.Json);
            if (!intent.OwnerEpoch.AsSpan().SequenceEqual(_fence.Epoch)) return new(DurableDecision.EpochRetired, null);
            if (!Equals(_store.Read(reader => reader.Scalar("SELECT state FROM owner_epoch WHERE owner_id=$o AND owner_epoch=$e;",
                ("$o", _owner), ("$e", _fence.Epoch))), "ACTIVE")) return new(DurableDecision.EpochRetired, null);
            if (MaintenanceRequired) return new(DurableDecision.Maintenance, null);
            byte[] digest = IntentDigest(intent);
            string id = Convert.ToHexStringLower(intent.CommandId);
            if (intent.SafetyParent is not null && intent.Method != TransferRecords.CloseMethod)
            {
                string? held = _store.Read(reader => reader.Scalar("SELECT command_id FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND safety_parent_command_id=$p AND method=$m;",
                    ("$o", _owner), ("$e", _fence.Epoch), ("$p", Convert.ToHexStringLower(intent.SafetyParent)), ("$m", intent.Method)) as string);
                if (held is not null)
                {
                    if (intent.Remote is not null && held != id) return new(DurableDecision.Conflict, null);
                    id = held;
                }
            }
            var existing = _store.Read(reader => ReadReceipt(reader, id));
            if (existing is not null)
            {
                bool matches = existing.Remote == intent.Remote && existing.Method == intent.Method
                    && (existing.Provision is null || intent.Provision is null || existing.Provision == intent.Provision)
                    && (existing.Deletion is null || intent.Deletion is null || existing.Deletion == intent.Deletion)
                    && _store.Read(reader =>
                    CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString((string)reader.Scalar(
                        "SELECT request_hmac_sha256 FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c;",
                        ("$o", _owner), ("$e", _fence.Epoch), ("$c", id))!)));
                return new(!matches ? DurableDecision.Conflict : existing.Compacted ? DurableDecision.Compacted
                    : existing.State is "ACCEPTED" or "UNKNOWN" ? DurableDecision.InProgress : DurableDecision.Replay,
                    !matches && intent.Remote is not null ? null : existing);
            }
            if (IsGrantMutation(intent) && (observed is not { State: "SUCCEEDED", Effect: 2 } || metadataChanges is null))
                throw new ArgumentException("A new grant mutation must atomically commit its observed SQLite effect.", nameof(intent));
            if (intent.Method is TransferRecords.BeginImportMethod or TransferRecords.BeginExportMethod
                && (observed is { Effect: not 1 } || observed is null && metadataChanges is null)
                || intent.Method == TransferRecords.CloseMethod && intent.SafetyParent is null && observed is null
                || IsImportStep(intent) && (observed is null or { State: "UNKNOWN" }) && metadataChanges is null)
                throw new ArgumentException("A new transfer effect requires its exact durable reservation.", nameof(intent));
            if (intent.AdditionalSafetyReservations != 0 && (observed is not null || intent.Provision is null))
                throw new ArgumentException("New provisioning must persist its exact derived grant reservation before native work.", nameof(intent));
            if (intent.Deletion is not null && (observed is not null || metadataChanges is null))
                throw new ArgumentException("A deletion successor must bind its exact journal before native work.", nameof(intent));
            string? pendingBody = intent.Provision is { } provision ? WriteProvisionReservation(null, provision)
                : intent.Deletion is { } deletion ? WriteDeletionBinding(null, deletion) : null;
            int pendingBodyBytes = pendingBody is null ? PendingReceiptBodyBytes : Encoding.UTF8.GetByteCount(pendingBody);
            var admittedAt = _store.Clock.GetUtcNow();
            var precondition = _store.Read(reader => CanAdmit(reader, intent, admittedAt, pendingBodyBytes, observed));
            if (precondition != DurableDecision.Execute) return new(precondition, null);
            // The specialized reservation participates in the owner fence without changing the
            // caller intent digest used by historical, settled, and compacted receipts.
            byte[] proof = digest;
            if (pendingBody is not null)
            {
                byte[] reservationProof = [.. digest, .. Encoding.UTF8.GetBytes(pendingBody)];
                proof = HMACSHA256.HashData(_key, reservationProof);
            }
            else if (observed is not null)
            {
                byte[] admissionProof = [.. digest, .. ObservationDigest(observed.State, observed.Effect, observed.Json)];
                proof = HMACSHA256.HashData(_key, admissionProof);
            }

            Advance(observed is null ? "admit" : "admit_observed", id, proof, tx =>
            {
                if (CanAdmit(tx, intent, admittedAt, pendingBodyBytes, observed) != DurableDecision.Execute)
                    throw new DurableStoreMaintenanceException();
                string? parent = intent.SafetyParent is null ? null : Convert.ToHexStringLower(intent.SafetyParent);
                bool grantRevoke = intent.Grant?.Action == DurableGrantAction.Revoke;
                if (parent is not null || grantRevoke || intent.Deletion is not null)
                    tx.Execute("UPDATE owner_epoch_capacity SET reserve_storage=substr(reserve_storage,1,length(reserve_storage)-$n) WHERE owner_id=$o AND owner_epoch=$e;",
                        ("$n", _capacity.MaximumResponseBytes), ("$o", _owner), ("$e", _fence.Epoch));
                string now = Now();
                tx.Execute("""
                    INSERT INTO command_receipt(owner_id,owner_epoch,command_id,method,request_hmac_sha256,aggregate_kind,aggregate_id,
                      state,effect_certainty,response_json,created_utc,updated_utc,admission_sequence,safety_parent_command_id,reserved_response)
                    VALUES($o,$e,$c,$m,$h,$ak,$ai,'ACCEPTED',3,$body,$now,$now,$seq,$parent,zeroblob($reserve));
                    """, ("$o", _owner), ("$e", _fence.Epoch), ("$c", id), ("$m", intent.Method),
                    ("$h", Convert.ToHexStringLower(digest)), ("$ak", intent.AggregateKind), ("$ai", intent.AggregateId),
                    ("$now", now), ("$seq", _fence.Sequence), ("$parent", parent), ("$reserve", _capacity.MaximumResponseBytes),
                    ("$body", pendingBody ?? "{}"));
                if (intent.Remote is { } remote)
                    RecordRemoteBinding(tx, id, remote);
                metadataChanges?.Invoke(tx);
                if (intent.Deletion is { } bound
                    && !SandboxDeletionRecords.IsBoundSuccessor(tx, _owner, _fence.Epoch, intent.AggregateId!, bound, id))
                    throw new InvalidOperationException("The deletion admission did not link its exact original receipt and journal.");
                if (IsGrantMutation(intent))
                    RequireGrantMutation(tx, intent, id);
                if (IsImportStep(intent) && (observed is null or { State: "UNKNOWN" })
                    && !HasImportCloseAnchor(tx, intent, admittedAt, id))
                    throw new InvalidOperationException("The exact import phase must share its original Close reservation.");
                if (observed is not null)
                {
                    bool uncertain = observed.State == "UNKNOWN";
                    WriteResult(tx, id, observed.State, observed.Effect, observed.Json, now,
                        uncertain ? null : now, uncertain ? null : ResultExpiry());
                    if (grantRevoke)
                        RestoreSafetyReserve(tx);
                }
            });
            var decision = observed is null ? DurableDecision.Execute
                : observed.State == "UNKNOWN" ? DurableDecision.InProgress : DurableDecision.Replay;
            return new(decision, _store.Read(reader => ReadReceipt(reader, id)));
        }
    }

    private sealed record InitialResult(string State, int Effect, string Json);

    private DurableDecision CanAdmit(StoreReader reader, DurableIntent intent, DateTimeOffset admittedAt, int pendingBodyBytes,
        InitialResult? observed)
    {
        if (intent.ExpectedSandboxRevision is { } revision &&
            !Equals(reader.Scalar("SELECT revision FROM sandbox WHERE owner_id=$o AND sandbox_id=$id;",
                ("$o", _owner), ("$id", intent.ExpectedSandboxId ?? intent.AggregateId)), revision)) return DurableDecision.RevisionConflict;
        if (intent.Remote is { } remote && !CanAdmitRemote(reader, intent, remote, admittedAt))
            return DurableDecision.RevisionConflict;
        if (intent.Grant is { } grant
            && !RemoteGrantRecords.IsActiveRevision(reader, _owner, intent.AggregateId!, grant.ExpectedRevision, admittedAt))
            return DurableDecision.RevisionConflict;
        if (IsGrantMutation(intent) && intent.Grant is null && RemoteGrantRecords.Exists(reader, intent.AggregateId!))
            return DurableDecision.Conflict;
        if (intent.Provision is { } provision)
        {
            if (RemoteGrantRecords.Get(reader, _owner, provision.ParentGrantId) is not
                { Scope: StoredRemoteGrantScope.Provision, ParentGrantId: null, State: StoredRemoteGrantState.Active } parent
                || parent.Revision != provision.ParentGrantRevision || parent.ExpiresAt is { } expiration && expiration <= admittedAt)
                return DurableDecision.RevisionConflict;
            if (RemoteGrantRecords.Exists(reader, provision.DerivedGrantId))
                return DurableDecision.Conflict;
        }
        long count = (long)reader.Scalar("SELECT count(*) FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e;",
            ("$o", _owner), ("$e", _fence.Epoch))!;
        bool coveredImport = IsImportStep(intent) && (observed is null or { State: "UNKNOWN" });
        if (coveredImport && !HasImportCloseAnchor(reader, intent, admittedAt, pendingCommand: null))
            return DurableDecision.Conflict;
        if (intent.Deletion is { } deletion
            && !SandboxDeletionRecords.CanAdmitSuccessor(reader, _owner, _fence.Epoch, intent.AggregateId!, deletion))
            return DurableDecision.Conflict;
        bool safety = intent.SafetyParent is not null || intent.Grant?.Action == DurableGrantAction.Revoke || intent.Deletion is not null;
        long reserve = (long)reader.Scalar("SELECT length(reserve_storage) FROM owner_epoch_capacity WHERE owner_id=$o AND owner_epoch=$e;",
            ("$o", _owner), ("$e", _fence.Epoch))!;
        if (reserve < _capacity.MaximumResponseBytes) return DurableDecision.Capacity;
        long futureSafety = 0;
        if (!safety)
        {
            // A known effect with no remaining boundary and an import step already covered by its Begin do not add promises.
            int newSafety = coveredImport || intent.Method == ResourcePolicyMethod || intent.Grant?.Action == DurableGrantAction.Replace
                || observed is { State: not "UNKNOWN" } && !IsGrantMutation(intent) ? 0 : 1;
            futureSafety = CountOutstandingSafetyPromises(reader) + newSafety + intent.AdditionalSafetyReservations;
            if (futureSafety * _capacity.MaximumResponseBytes > reserve) return DurableDecision.Capacity;
            if (count + futureSafety + 1 > _capacity.MaximumReceipts) return DurableDecision.Capacity;
        }
        if (intent.SafetyParent is not null)
        {
            string parent = Convert.ToHexStringLower(intent.SafetyParent);
            if (intent.Method == TransferRecords.CloseMethod
                && !TransferRecords.IsCloseSafetyParent(reader, _owner, _fence.Epoch, intent.AggregateId!, parent))
                return DurableDecision.Conflict;
            if (!Equals(reader.Scalar("SELECT count(*) FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND command_id=$p AND aggregate_kind IS $k AND aggregate_id IS $id AND safety_parent_command_id IS NULL;",
                ("$o", _owner), ("$e", _fence.Epoch), ("$p", parent), ("$k", intent.AggregateKind), ("$id", intent.AggregateId)), 1L))
                return DurableDecision.Conflict;
            if (!Equals(reader.Scalar("SELECT count(*) FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND safety_parent_command_id=$p;",
                ("$o", _owner), ("$e", _fence.Epoch), ("$p", parent)), 0L)) return DurableDecision.Conflict;
        }
        long bytes = (long)reader.Scalar("SELECT coalesce(sum(coalesce(length(CAST(response_json AS BLOB)),0)+length(reserved_response)+$identity),0) FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e;",
            ("$o", _owner), ("$e", _fence.Epoch), ("$identity", ReceiptIdentityBytes))!;
        return count >= _capacity.MaximumReceipts
            || bytes + reserve + (safety ? 0 : _capacity.MaximumResponseBytes) + ReceiptIdentityBytes
                + futureSafety * ReservedSafetyIdentityBytes + pendingBodyBytes > _capacity.MaximumJournalBytes
            ? DurableDecision.Capacity : DurableDecision.Execute;
    }

    private long CountOutstandingSafetyPromises(StoreReader reader)
    {
        // A settled remote provision keeps its owned-root reconciliation promise while
        // the exact derived authority is still active. That grant also owns its revoke.
        long active = (long)reader.Scalar($"""
            SELECT count(*) FROM command_receipt p WHERE p.owner_id=$o AND p.owner_epoch=$e AND p.safety_parent_command_id IS NULL
              AND p.aggregate_kind IS NOT 'grant' AND p.method<>$resourcePolicy
              AND NOT (p.aggregate_kind IS 'transfer' AND p.method IN ($write,$commit) AND EXISTS(
                SELECT 1 {ImportCloseAnchor}
                  AND t.owner_id=p.owner_id AND t.owner_epoch=p.owner_epoch AND t.transfer_id=p.aggregate_id
                  AND json_extract(t.manifest_json,'$.pending.commandId')=p.command_id
                  AND json_extract(t.manifest_json,'$.pending.phase')=CASE p.method WHEN $write THEN $chunk ELSE $publish END))
              AND NOT (p.method=$delete AND p.aggregate_kind IS 'sandbox' AND EXISTS(
                SELECT 1 FROM deletion_journal AS d
                JOIN command_receipt AS original ON original.owner_id=d.owner_id AND original.owner_epoch=d.owner_epoch
                    AND original.command_id=d.command_id AND original.method=$delete
                    AND original.aggregate_kind='sandbox' AND original.aggregate_id=d.sandbox_id
                WHERE d.owner_id=p.owner_id AND d.owner_epoch=p.owner_epoch AND d.sandbox_id=p.aggregate_id
                  AND (d.latest_resume_command_id=p.command_id OR (
                    d.deletion_id=json_extract(p.response_json,'$._deletionBinding.deletionId')
                    AND d.command_id=json_extract(p.response_json,'$._deletionBinding.originalCommandId')))))
              AND (
                p.state IN ('ACCEPTED','UNKNOWN')
                OR (p.method='RunService.Start' AND EXISTS(
                  SELECT 1 FROM run r JOIN sandbox b ON b.sandbox_id=r.sandbox_id
                  WHERE r.run_id=p.aggregate_id AND b.owner_id=p.owner_id AND r.state IN (1,2,3,4,7)))
                OR (p.method=$create AND p.aggregate_kind='sandbox' AND p.state='SUCCEEDED' AND EXISTS(
                  SELECT 1 FROM remote_grant g JOIN sandbox b ON b.sandbox_id=g.sandbox_id
                  WHERE b.sandbox_id=p.aggregate_id AND b.owner_id=p.owner_id AND b.state<>$deleted
                    AND g.scope_kind='sandbox' AND g.parent_grant_id IS NOT NULL AND g.state=$grantActive
                    AND json_extract(g.policy_json,'$.ownerId')=p.owner_id
                    AND json_extract(g.policy_json,'$.revocationAnchorCommandId')=p.command_id))
                OR EXISTS(SELECT 1 FROM transfer t
                  WHERE t.owner_id=p.owner_id AND t.owner_epoch=p.owner_epoch AND t.command_id=p.command_id
                    AND (t.state IN (1,2,5) OR t.effect_certainty=3 OR
                      (t.state IN (3,4) AND t.closed_utc IS NULL AND
                        (t.state=3 OR t.staging_identity<>'unbound'))))
                OR EXISTS(SELECT 1 FROM deletion_journal d
                  WHERE d.owner_id=p.owner_id AND d.owner_epoch=p.owner_epoch AND d.command_id=p.command_id
                    AND (d.phase<>'complete' OR d.effect_certainty=3))
              )
              AND NOT EXISTS(SELECT 1 FROM command_receipt s WHERE s.owner_id=p.owner_id AND s.owner_epoch=p.owner_epoch AND s.safety_parent_command_id=p.command_id);
            """, ("$o", _owner), ("$e", _fence.Epoch), ("$resourcePolicy", ResourcePolicyMethod),
            ("$create", SandboxCreateMethod), ("$deleted", (int)StoredSandboxState.Deleted),
            ("$grantActive", (int)StoredRemoteGrantState.Active), ("$unbound", TransferRecords.UnboundStage),
            ("$beginImport", TransferRecords.BeginImportMethod), ("$write", TransferRecords.WriteMethod), ("$commit", TransferRecords.CommitMethod),
            ("$chunk", (int)StoredTransferPhase.Chunk), ("$publish", (int)StoredTransferPhase.Publish),
            ("$delete", SandboxDeletionRecords.Method))!;
        long pendingGrants = (long)reader.Scalar("""
            SELECT count(*) FROM command_receipt p WHERE p.owner_id=$o AND p.owner_epoch=$e
              AND p.method=$create AND p.aggregate_kind='sandbox' AND p.state IN ('ACCEPTED','UNKNOWN')
              AND json_extract(p.response_json,$field)=1;
            """, ("$o", _owner), ("$e", _fence.Epoch), ("$create", SandboxCreateMethod), ("$field", GrantReservationPath))!;
        return active + RemoteGrantRecords.CountActive(reader, _owner) + pendingGrants;
    }

    private bool HasImportCloseAnchor(StoreReader reader, DurableIntent intent, DateTimeOffset admittedAt, string? pendingCommand) =>
        Equals(reader.Scalar($"""
            SELECT EXISTS(SELECT 1 {ImportCloseAnchor}
              AND t.owner_id=$owner AND t.owner_epoch=$epoch AND t.transfer_id=$id
              AND t.expires_utc>$now
              AND ($phase=$chunk OR t.verified_offset=t.byte_length)
              AND (($command IS NULL AND t.state IN (1,2) AND json_extract(t.manifest_json,'$.pending') IS NULL)
                   OR ($command IS NOT NULL AND json_extract(t.manifest_json,'$.pending.commandId')=$command
                       AND json_extract(t.manifest_json,'$.pending.phase')=$phase)));
            """, ("$owner", _owner), ("$epoch", _fence.Epoch), ("$id", intent.AggregateId),
            ("$now", SandboxRecords.FormatTime(admittedAt)), ("$command", pendingCommand), ("$unbound", TransferRecords.UnboundStage),
            ("$beginImport", TransferRecords.BeginImportMethod), ("$chunk", (int)StoredTransferPhase.Chunk),
            ("$phase", (int)(intent.Method == TransferRecords.WriteMethod ? StoredTransferPhase.Chunk : StoredTransferPhase.Publish))), 1L);

    private static bool IsImportStep(DurableIntent intent) =>
        intent.Method is TransferRecords.WriteMethod or TransferRecords.CommitMethod;

    private static bool IsGrantMutation(DurableIntent intent) => intent.Method is SetGrantMethod or RevokeGrantMethod;

    private void RequireGrantMutation(StoreTransaction transaction, DurableIntent intent, string commandId)
    {
        var grant = RemoteGrantRecords.Get(transaction, _owner, intent.AggregateId!);
        var known = intent.Grant switch
        {
            { Action: DurableGrantAction.Revoke } revoke => grant is { State: StoredRemoteGrantState.Revoked, RevokedAt: not null }
                && grant.Revision == revoke.ExpectedRevision + 1,
            { Action: DurableGrantAction.Replace } replace => grant is { State: StoredRemoteGrantState.Active }
                && grant.Revision == replace.ExpectedRevision + 1,
            _ => grant is { State: StoredRemoteGrantState.Active, Revision: 1 } && grant.RevocationAnchorCommandId == commandId,
        };
        if (!known)
            throw new InvalidOperationException("The observed receipt must commit the exact grant mutation.");
    }

    internal DurableReceipt? Inspect(ReadOnlySpan<byte> commandId)
    {
        StoreIds.Validate(commandId, nameof(commandId));
        string id = Convert.ToHexStringLower(commandId);
        return _store.Read(reader => ReadReceipt(reader, id));
    }

    private DurableReceipt? ReadReceipt(StoreReader reader, string id)
    {
        using var command = reader.CreateCommand("""
            SELECT c.command_id,c.method,c.aggregate_kind,c.aggregate_id,c.state,c.effect_certainty,c.response_json,
                   c.response_compacted_utc,c.safety_parent_command_id,
                   b.account_id,b.actor_id,b.enrollment_id,b.protocol_epoch,b.grant_id,b.grant_revision,b.scope_kind,b.sandbox_id
            FROM command_receipt AS c LEFT JOIN remote_command_binding AS b USING(owner_id,owner_epoch,command_id)
            WHERE c.owner_id=$o AND c.owner_epoch=$e AND c.command_id=$c;
            """);
        command.Parameters.AddWithValue("$o", _owner); command.Parameters.AddWithValue("$e", _fence.Epoch); command.Parameters.AddWithValue("$c", id);
        using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        string method = row.GetString(1);
        string? kind = row.IsDBNull(2) ? null : row.GetString(2);
        string state = row.GetString(4);
        string? body = row.IsDBNull(6) ? null : row.GetString(6);
        var provision = method == SandboxCreateMethod && kind == "sandbox" && state is ("ACCEPTED" or "UNKNOWN") && body is not null
            ? ReadProvisionReservation(body) : null;
        var remote = row.IsDBNull(9) ? null : new DurableRemoteBinding(row.GetString(9), row.GetString(10), row.GetString(11),
            row.GetString(12), row.GetString(13), row.GetInt64(14), row.GetString(15), row.IsDBNull(16) ? null : row.GetString(16));
        var deletion = method == SandboxDeletionRecords.Method && kind == "sandbox" && state is ("ACCEPTED" or "UNKNOWN") && body is not null
            ? ReadDeletionBinding(body) : null;
        return new(row.GetString(0), method, kind, row.IsDBNull(3) ? null : row.GetString(3), state, row.GetInt32(5),
            body, !row.IsDBNull(7), row.IsDBNull(8) ? null : row.GetString(8), provision, remote, deletion);
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
            // Preserve the exact existing digest for commands that use their aggregate ID for the Sandbox revision.
            if (intent.ExpectedSandboxId is { } sandboxId)
                writer.Write(sandboxId);
            if (intent.Grant is { } grant)
            {
                writer.Write("grant_precondition");
                writer.Write((int)grant.Action);
                writer.Write(grant.ExpectedRevision);
            }
            if (intent.AdditionalSafetyReservations != 0)
            {
                writer.Write("remote_grant_reservation");
                writer.Write(intent.AdditionalSafetyReservations);
            }
            if (intent.Remote is { } remote)
                WriteRemoteBinding(writer, remote);
        }
        return HMACSHA256.HashData(_key, stream.ToArray());
    }

    private static void Validate(DurableIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        StoreIds.Validate(intent.CommandId, nameof(intent)); StoreIds.Validate(intent.OwnerEpoch, nameof(intent));
        ArgumentNullException.ThrowIfNull(intent.CanonicalBody);
        if (intent.SafetyParent is not null) StoreIds.Validate(intent.SafetyParent, nameof(intent));
        if (intent.Method == TransferRecords.CloseMethod
            && (intent.AggregateKind != TransferRecords.Aggregate || !IsGrantIdentity(intent.AggregateId))
            || intent.AggregateKind == TransferRecords.Aggregate && intent.SafetyParent is not null
                && intent.Method != TransferRecords.CloseMethod
            || IsImportStep(intent) && (intent.AggregateKind != TransferRecords.Aggregate || !IsGrantIdentity(intent.AggregateId)))
            throw new ArgumentException("The transfer receipt must identify its exact owned aggregate and Close reservation.", nameof(intent));
        if (intent.ExpectedSandboxId is { } sandboxId
            && (intent.ExpectedSandboxRevision is not > 0 || sandboxId.Length != 32
                || !sandboxId.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new ArgumentException("An explicit expected Sandbox ID requires its positive revision.", nameof(intent));
        if (intent.Grant is { } grant
            && (intent.SafetyParent is not null || intent.ExpectedSandboxRevision is not null
                || grant.ExpectedRevision is < 1 or long.MaxValue
                || (grant.Action, intent.Method) is not ((DurableGrantAction.Replace, SetGrantMethod) or (DurableGrantAction.Revoke, RevokeGrantMethod))))
            throw new ArgumentException("A grant mutation requires its exact positive revision and typed method.", nameof(intent));
        if (IsGrantMutation(intent) && (intent.AggregateKind != GrantAggregate || !IsGrantIdentity(intent.AggregateId)
            || intent.SafetyParent is not null || intent.ExpectedSandboxRevision is not null
            || intent.Method == RevokeGrantMethod && intent.Grant is null)
            || !IsGrantMutation(intent) && intent.AggregateKind == GrantAggregate)
            throw new ArgumentException("A grant receipt must describe its exact owned grant.", nameof(intent));
        if (intent.AdditionalSafetyReservations != 0 && (intent.AdditionalSafetyReservations != 1
            || intent is not { Method: SandboxCreateMethod, AggregateKind: "sandbox", SafetyParent: null, ExpectedSandboxRevision: null }
            || !IsGrantIdentity(intent.AggregateId)))
            throw new ArgumentException("Only provisioning may add one derived-grant safety reservation.", nameof(intent));
        if (intent.Provision is { } provision
            && (intent.AdditionalSafetyReservations != 1 || !ValidProvisionBinding(provision)))
            throw new ArgumentException("A provision reservation binds its exact parent revision and preselected child grant.", nameof(intent));
        if (intent.Remote is { } remote)
            ValidateRemoteIntent(intent, remote);
        if (intent.Deletion is { } deletion
            && (intent is not
            {
                Method: SandboxDeletionRecords.Method, AggregateKind: "sandbox", ExpectedSandboxRevision: > 0,
                SafetyParent: null, ExpectedSandboxId: null, Grant: null, Provision: null, Remote: null
            }
                || !IsGrantIdentity(intent.AggregateId) || !IsGrantIdentity(deletion.OriginalCommandId)
                || !IsGrantIdentity(deletion.DeletionId) || deletion.OriginalCommandId == Convert.ToHexStringLower(intent.CommandId)))
            throw new ArgumentException("A deletion successor requires the exact original command, journal, and Sandbox revision.", nameof(intent));
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

    private static bool IsGrantIdentity(string? id) => id is { Length: 32 } && id.All(char.IsAsciiHexDigitLower);

    private static string WriteDeletionBinding(string? response, DurableDeletionBinding binding)
    {
        var result = response is null ? new JsonObject() : JsonNode.Parse(response)?.AsObject()
            ?? throw new InvalidOperationException("The deletion result must be a bounded JSON object.");
        result["_deletionBinding"] = new JsonObject
        {
            ["originalCommandId"] = binding.OriginalCommandId,
            ["deletionId"] = binding.DeletionId,
        };
        return result.ToJsonString();
    }

    private static DurableDeletionBinding? ReadDeletionBinding(string body)
    {
        using var value = JsonDocument.Parse(body);
        if (value.RootElement.ValueKind != JsonValueKind.Object
            || !value.RootElement.TryGetProperty("_deletionBinding", out var binding))
            return null;
        if (binding.ValueKind != JsonValueKind.Object
            || !binding.TryGetProperty("originalCommandId", out var original) || original.ValueKind != JsonValueKind.String
            || !binding.TryGetProperty("deletionId", out var deletion) || deletion.ValueKind != JsonValueKind.String
            || original.GetString() is not { } originalId || !IsGrantIdentity(originalId)
            || deletion.GetString() is not { } deletionId || !IsGrantIdentity(deletionId))
            throw new DurableStoreMaintenanceException();
        return new(originalId, deletionId);
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
