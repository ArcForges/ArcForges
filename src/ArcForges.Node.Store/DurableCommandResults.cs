// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ArcForges.Node.Store;

internal sealed partial class DurableCommandStore
{
    private const int DeletionChildResponseBytes = 1024;

    // Effect observations are supplied by the owning subsystem. This store does not infer native success.
    internal DurableReceipt SetResult(byte[] commandId, string state, int effect, string redactedJson,
        Action<StoreTransaction>? observedMetadata = null, byte[]? settledSafetyCommand = null, string? settledSafetyJson = null,
        string settledSafetyState = "SUCCEEDED")
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();
            StoreIds.Validate(commandId, nameof(commandId));
            ValidateResult(state, effect, redactedJson);
            var previous = Inspect(commandId) ?? throw new InvalidOperationException("No admitted command exists.");
            redactedJson = PreserveSandboxRemovalWitness(previous, state, redactedJson);
            redactedJson = PrepareDeletionChildResult(previous, state, redactedJson);
            string id = Convert.ToHexStringLower(commandId);
            var provision = previous.Provision;
            if (provision is not null && state == "UNKNOWN")
            {
                // Keep the future child-grant safety slot while native creation is uncertain.
                redactedJson = WriteProvisionReservation(redactedJson, provision);
                ValidateResult(state, effect, redactedJson);
            }
            bool sameResult = previous.State == state && previous.Effect == effect && previous.ResponseJson == redactedJson;
            bool retainUnknown = false;
            bool retainSafetyUnknown = false;
            int safetyEffect = settledSafetyState == "UNKNOWN" ? 3 : 2;
            string? safetyId = null;
            DurableReceipt? previousSafety = null;
            if (settledSafetyCommand is not null || settledSafetyJson is not null || settledSafetyState != "SUCCEEDED")
            {
                if (settledSafetyCommand is null || settledSafetyJson is null
                    || settledSafetyState is not ("SUCCEEDED" or "UNKNOWN")
                    || (state, effect) is not (("SUCCEEDED", 2) or ("FAILED", 1) or ("UNKNOWN", 3)))
                    throw new ArgumentException("An atomic Run settlement requires a valid Start result and a bounded Stop result.", nameof(settledSafetyJson));
                StoreIds.Validate(settledSafetyCommand, nameof(settledSafetyCommand));
                ValidateResult(settledSafetyState, safetyEffect, settledSafetyJson);
                string stopId = Convert.ToHexStringLower(settledSafetyCommand);
                safetyId = stopId;
                var sibling = _store.Read(reader => ReadRunSafetySibling(reader, previous, stopId));
                previousSafety = sibling;
                if (sibling.State == "UNKNOWN" && settledSafetyState == "UNKNOWN")
                {
                    settledSafetyJson = sibling.ResponseJson ?? throw new DurableStoreMaintenanceException();
                    retainSafetyUnknown = true;
                }

                if (state == "UNKNOWN" && previous.State == "UNKNOWN")
                {
                    redactedJson = previous.ResponseJson ?? throw new DurableStoreMaintenanceException();
                    sameResult = true;
                    retainUnknown = true;
                }

                if (sameResult && settledSafetyState == "SUCCEEDED" && sibling.State == "SUCCEEDED"
                    && sibling.Effect == safetyEffect && sibling.ResponseJson == settledSafetyJson)
                    return previous;
                if ((sameResult && !retainUnknown) || observedMetadata is null || sibling.State is not ("ACCEPTED" or "UNKNOWN"))
                    throw new InvalidOperationException("The Run terminal observation and linked unsettled Stop must commit together.");
            }

            if (sameResult && !retainUnknown) return previous;
            if (previous.State == "UNKNOWN" && state == "UNKNOWN" && !retainUnknown)
                throw new InvalidOperationException("An unresolved observation is retained until a definite effect is supplied.");
            if (previous.State is "SUCCEEDED" or "FAILED")
            {
                if (previous.State != state || previous.Effect != effect || previous.ResponseJson != redactedJson)
                    throw new InvalidOperationException("The known command outcome cannot be rewritten.");
                return previous;
            }
            string now = Now();
            string? resolved = state == "UNKNOWN" ? null : now;
            string? expires = resolved is not null || safetyId is not null && settledSafetyState == "SUCCEEDED" ? ResultExpiry() : null;
            byte[] observation = ObservationDigest(state, effect, redactedJson);
            if (safetyId is not null)
            {
                byte[] safetyProof = ObservationDigest(settledSafetyState, safetyEffect, settledSafetyJson!);
                byte[] pairProof = [.. observation, .. Convert.FromHexString(safetyId), .. safetyProof];
                observation = HMACSHA256.HashData(_key, pairProof);
            }

            if (state != "UNKNOWN" && observedMetadata is null && _store.Read(reader => BlocksKnownResult(reader, id, state, effect)))
                throw new InvalidOperationException("An unresolved effect cannot become a known settled result.");
            Advance(safetyId is null ? "observe" : "observe_run_stop", id, observation, tx =>
            {
                if (safetyId is not null && ReadRunSafetySibling(tx, previous, safetyId) != previousSafety)
                    throw new InvalidOperationException("The linked Stop changed before atomic settlement.");

                observedMetadata?.Invoke(tx);
                if (provision is not null && state != "UNKNOWN"
                    && !RemoteGrantRecords.MatchesProvisionSettlement(tx, _owner, previous.AggregateId!, id, provision,
                        succeeded: state == "SUCCEEDED" && effect == 2))
                    throw new InvalidOperationException("A provisioned Sandbox and its exact child grant must settle together.");
                if (safetyId is not null && !Equals(tx.Scalar("""
                    SELECT EXISTS(
                        SELECT 1 FROM run AS r JOIN sandbox AS s ON s.sandbox_id=r.sandbox_id
                        WHERE s.owner_id=$owner AND r.run_id=$run AND r.ended_utc IS NOT NULL AND (
                            ($startEffect=2 AND r.state=$exited AND r.payload_started<>$notStarted)
                            OR ($startEffect=1 AND r.state IN ($exited,$failed)
                                AND r.payload_started=$notStarted AND r.effect_certainty=1)
                            OR ($startEffect=3 AND r.state=$exited
                                AND r.payload_started=$unknownPayload AND r.effect_certainty=3)
                        )
                    );
                    """, ("$owner", _owner), ("$run", previous.AggregateId),
                    ("$startEffect", effect), ("$exited", (int)StoredRunState.Exited),
                    ("$failed", (int)StoredRunState.Failed), ("$notStarted", (int)StoredPayloadStart.NotStarted),
                    ("$unknownPayload", (int)StoredPayloadStart.Unknown)), 1L))
                    throw new InvalidOperationException("The linked Run boundary lacks a terminal observation.");

                if (!retainUnknown)
                    WriteResult(tx, id, state, effect, redactedJson, now, resolved, resolved is null ? null : expires, previous);
                if (safetyId is not null && !retainSafetyUnknown)
                {
                    string? resolvedSafety = settledSafetyState == "SUCCEEDED" ? now : null;
                    WriteResult(tx, safetyId, settledSafetyState, safetyEffect, settledSafetyJson!, now,
                        resolvedSafety, resolvedSafety is null ? null : expires);
                }
            });
            return Inspect(commandId)!;
        }
    }

    /// <summary>Fences the caller's observation of exact native removal before tombstone settlement.</summary>
    internal void RecordSandboxRemovalVerified(byte[] originalCommand, byte[]? successorCommand,
        Action<StoreTransaction>? validate = null)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();
            StoreIds.Validate(originalCommand, nameof(originalCommand));
            if (successorCommand is not null) StoreIds.Validate(successorCommand, nameof(successorCommand));
            string originalId = Convert.ToHexStringLower(originalCommand);
            string? successorId = successorCommand is null ? null : Convert.ToHexStringLower(successorCommand);
            var original = Inspect(originalCommand);
            if (original is not
                {
                    Method: SandboxDeletionRecords.Method, AggregateKind: "sandbox", AggregateId: { } sandboxId,
                    State: "ACCEPTED" or "UNKNOWN", Effect: 3, ResponseJson: { } existing
                })
                throw new InvalidOperationException("The removal witness requires its exact unsettled original Delete receipt.");

            var journal = _store.Read(reader => SandboxDeletionRecords.ReadOriginal(reader, _owner, _fence.Epoch, sandboxId, originalId));
            if (journal is not { Phase: "removing", QuarantineIdentity: not null, Effect: 3 }
                || journal.LatestSuccessorId != successorId
                || successorId is not null && journal.LatestSuccessorState is not ("ACCEPTED" or "UNKNOWN"))
                throw new InvalidOperationException("The removal witness requires the exact removing journal and current successor.");
            if (journal.RemovalVerified) return;

            string witness = SandboxDeletionRecords.RemovalWitness(journal, _fence.Epoch);
            string observed = WithSandboxRemovalWitness(existing, witness);
            ValidateResult("UNKNOWN", 3, observed);
            byte[] evidence = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(observed));
            Advance("record_sandbox_removal", originalId, evidence, tx =>
            {
                if (SandboxDeletionRecords.ReadOriginal(tx, _owner, _fence.Epoch, sandboxId, originalId) != journal
                    || SandboxRecords.Get(tx, _owner, sandboxId) is not
                    { State: StoredSandboxState.Deleting or StoredSandboxState.RecoveryRequired } sandbox
                    || sandbox.RootIdentity != journal.RootIdentity)
                    throw new InvalidOperationException("The held Sandbox deletion changed before recording native removal.");
                validate?.Invoke(tx);
                if (tx.Execute("""
                    UPDATE command_receipt SET response_json=$observed,reserved_response=zeroblob($reserve)
                    WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$id AND method=$method
                      AND aggregate_kind='sandbox' AND aggregate_id=$sandbox AND state=$state AND effect_certainty=3
                      AND response_json=$existing;
                    """, ("$observed", observed), ("$reserve", _capacity.MaximumResponseBytes - Encoding.UTF8.GetByteCount(observed)),
                    ("$owner", _owner), ("$epoch", _fence.Epoch), ("$id", originalId), ("$sandbox", sandboxId),
                    ("$method", SandboxDeletionRecords.Method), ("$state", original.State), ("$existing", existing)) != 1)
                    throw new DurableStoreMaintenanceException();
            });
        }
    }

    internal DurableReceipt SettleRunStop(byte[] startCommand, byte[] stopCommand, string state, int effect,
        string redactedJson, Action<StoreTransaction> observedMetadata)
    {
        ArgumentNullException.ThrowIfNull(observedMetadata);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();
            StoreIds.Validate(startCommand, nameof(startCommand));
            StoreIds.Validate(stopCommand, nameof(stopCommand));
            ValidateResult(state, effect, redactedJson);
            if ((state, effect) is not (("SUCCEEDED", 2) or ("UNKNOWN", 3)))
                throw new ArgumentException("A recovered Stop requires a known performed effect or an unresolved observation.", nameof(state));

            var start = Inspect(startCommand) ?? throw new InvalidOperationException("No original Run Start receipt exists.");
            string stopId = Convert.ToHexStringLower(stopCommand);
            var stop = _store.Read(reader => ReadRunSafetySibling(reader, start, stopId));
            if (stop.State is "SUCCEEDED" or "FAILED")
            {
                if (stop.State != state || stop.Effect != effect || stop.ResponseJson != redactedJson)
                    throw new InvalidOperationException("The known Stop outcome cannot be rewritten.");
                return stop;
            }

            // Terminal reconciliation may update the Run without rewriting its already recorded uncertainty.
            bool keepOriginal = stop.State == "UNKNOWN" && state == "UNKNOWN";
            string now = Now();
            string? resolved = state == "UNKNOWN" ? null : now;
            string? expires = resolved is null ? null : ResultExpiry();
            byte[] evidence = ObservationDigest(state, effect, redactedJson);
            Advance("observe_recovered_stop", stopId, evidence, transaction =>
            {
                if (ReadRunSafetySibling(transaction, start, stopId) != stop)
                    throw new InvalidOperationException("The linked Stop changed before recovery settlement.");
                observedMetadata(transaction);
                if (!Equals(transaction.Scalar("""
                    SELECT EXISTS(SELECT 1 FROM run r JOIN sandbox s ON s.sandbox_id=r.sandbox_id
                      WHERE s.owner_id=$owner AND r.run_id=$run AND r.ended_utc IS NOT NULL
                        AND r.state IN ($exited,$failed));
                    """, ("$owner", _owner), ("$run", start.AggregateId),
                    ("$exited", (int)StoredRunState.Exited), ("$failed", (int)StoredRunState.Failed)), 1L))
                    throw new InvalidOperationException("The recovered Run boundary lacks a terminal observation.");
                if (!keepOriginal)
                    WriteResult(transaction, stopId, state, effect, redactedJson, now, resolved, expires);
            });
            return Inspect(stopCommand)!;
        }
    }

    /// <summary>Commits the proved tombstone and the exact original and current successor together.</summary>
    internal DurableReceipt SettleSandboxDeletion(byte[] originalCommand, byte[]? successorCommand, string originalResultJson,
        string? successorResultJson, Action<StoreTransaction> observedMetadata)
    {
        ArgumentNullException.ThrowIfNull(observedMetadata);
        return ObserveSandboxDeletion(originalCommand, successorCommand, originalResultJson, successorResultJson,
            "SUCCEEDED", 2, observedMetadata);
    }

    /// <summary>Retains uncertainty without rewriting any prior unknown body.</summary>
    internal DurableReceipt MarkSandboxDeletionUnknown(byte[] originalCommand, byte[]? successorCommand, string originalResultJson,
        string? successorResultJson, Action<StoreTransaction>? observedMetadata = null) =>
        ObserveSandboxDeletion(originalCommand, successorCommand, originalResultJson, successorResultJson,
            "UNKNOWN", 3, observedMetadata);

    private DurableReceipt ObserveSandboxDeletion(byte[] originalCommand, byte[]? successorCommand, string originalResultJson,
        string? successorResultJson, string state, int effect, Action<StoreTransaction>? observedMetadata)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();
            StoreIds.Validate(originalCommand, nameof(originalCommand));
            ValidateResult(state, effect, originalResultJson);
            if ((successorCommand is null) != (successorResultJson is null))
                throw new ArgumentException("The exact deletion successor and result must be supplied together.", nameof(successorCommand));
            if (successorCommand is not null)
            {
                StoreIds.Validate(successorCommand, nameof(successorCommand));
                ValidateResult(state, effect, successorResultJson!);
            }

            var originalId = Convert.ToHexStringLower(originalCommand);
            var successorId = successorCommand is null ? null : Convert.ToHexStringLower(successorCommand);
            var original = Inspect(originalCommand);
            var successor = successorCommand is null ? null : Inspect(successorCommand);
            if (original is not { Method: SandboxDeletionRecords.Method, AggregateKind: "sandbox", AggregateId: { } sandboxId }
                || successorId is not null && (successorId == originalId || successor is not
                { Method: SandboxDeletionRecords.Method, AggregateKind: "sandbox" } || successor.AggregateId != sandboxId))
                throw new InvalidOperationException("The deletion observation lacks its exact owner-scoped receipts.");

            originalResultJson = PreserveSandboxRemovalWitness(original, state, originalResultJson);
            if (successor is not null)
                successorResultJson = PrepareDeletionChildResult(successor, state,
                    PreserveSandboxRemovalWitness(successor, state, successorResultJson!));
            bool succeeded = effect == 2;
            if (succeeded && original is { State: "SUCCEEDED", Effect: 2 } && original.ResponseJson == originalResultJson
                && (successorId is null || successor is { State: "SUCCEEDED", Effect: 2 } && successor.ResponseJson == successorResultJson)
                && _store.Read(reader => SandboxDeletionRecords.HasTombstone(
                    reader, _owner, _fence.Epoch, sandboxId, originalId, successorId)))
                return successor ?? original;

            var journal = _store.Read(reader => SandboxDeletionRecords.ReadOriginal(reader, _owner, _fence.Epoch, sandboxId, originalId));
            if (journal is null || journal.LatestSuccessorId != successorId || journal.Effect != 3
                || succeeded && !journal.RemovalVerified
                || successor is not null && successor.State is not ("ACCEPTED" or "UNKNOWN"))
                throw new InvalidOperationException("The deletion observation does not name the exact unsettled journal and latest successor.");

            var earlier = succeeded ? _store.Read(reader =>
                SandboxDeletionRecords.OlderUnsettledSuccessors(reader, _owner, _fence.Epoch, sandboxId, journal)
                    .Select(id => ReadReceipt(reader, id) ?? throw new DurableStoreMaintenanceException()).ToArray()) : [];
            var earlierResults = earlier.Select(receipt =>
                PrepareDeletionChildResult(receipt, state, successorResultJson ?? originalResultJson)).ToArray();
            bool writeOriginal = succeeded || original.State != "UNKNOWN";
            bool writeSuccessor = successor is not null && (succeeded || successor.State != "UNKNOWN");
            if (!writeOriginal && !writeSuccessor && observedMetadata is null) return successor ?? original;

            string now = Now();
            string? resolved = succeeded ? now : null;
            string? expires = succeeded ? ResultExpiry() : null;
            byte[] evidence = ObservationDigest(state, effect, writeOriginal ? originalResultJson : original.ResponseJson!);
            if (successorId is not null)
            {
                byte[] siblingProof = ObservationDigest(state, effect, writeSuccessor ? successorResultJson! : successor!.ResponseJson!);
                byte[] paired = [.. evidence, .. Convert.FromHexString(successorId), .. siblingProof];
                evidence = HMACSHA256.HashData(_key, paired);
            }
            for (int index = 0; index < earlier.Length; index++)
            {
                byte[] previousProof = ObservationDigest(state, effect, earlierResults[index]);
                byte[] linked = [.. evidence, .. Convert.FromHexString(earlier[index].CommandId), .. previousProof];
                evidence = HMACSHA256.HashData(_key, linked);
            }

            Advance(succeeded ? "observe_deleted_sandbox" : "observe_unresolved_deletion", originalId, evidence, tx =>
            {
                if (SandboxDeletionRecords.ReadOriginal(tx, _owner, _fence.Epoch, sandboxId, originalId) != journal)
                    throw new InvalidOperationException("The exact deletion journal changed before observation.");
                if (succeeded && !SandboxDeletionRecords.OlderUnsettledSuccessors(tx, _owner, _fence.Epoch, sandboxId, journal)
                    .SequenceEqual(earlier.Select(receipt => receipt.CommandId)))
                    throw new InvalidOperationException("The exact deletion lineage changed before observation.");

                observedMetadata?.Invoke(tx);
                if (succeeded && !SandboxDeletionRecords.HasTombstone(tx, _owner, _fence.Epoch, sandboxId, originalId, successorId))
                    throw new InvalidOperationException("The deletion result lacks a committed Sandbox tombstone.");
                if (writeOriginal)
                    WriteResult(tx, originalId, state, effect, originalResultJson, now, resolved, expires);
                if (writeSuccessor)
                    WriteResult(tx, successorId!, state, effect, successorResultJson!, now, resolved, expires, successor);
                for (int index = 0; index < earlier.Length; index++)
                {
                    var previous = earlier[index];
                    WriteResult(tx, previous.CommandId, state, effect, earlierResults[index], now, resolved, expires, previous);
                }
            });
            return Inspect(successorCommand ?? originalCommand)!;
        }
    }

    private DurableReceipt ReadRunSafetySibling(StoreReader reader, DurableReceipt start, string stopId)
    {
        var stop = ReadReceipt(reader, stopId);
        if (start.Method != "RunService.Start" || start.AggregateKind != "run" || start.AggregateId is null
            || stop is not { Method: "RunService.Stop", AggregateKind: "run" } || stop.AggregateId != start.AggregateId
            || stop.SafetyParentCommandId != start.CommandId)
            throw new InvalidOperationException("The safety receipt is not the Stop admitted for this Start and Run.");

        return stop;
    }

    private void ValidateResult(string state, int effect, string redactedJson)
    {
        if (state is not ("SUCCEEDED" or "FAILED" or "UNKNOWN") || effect is < 1 or > 3
            || state == "UNKNOWN" && effect != 3 || state != "UNKNOWN" && effect == 3
            || Encoding.UTF8.GetByteCount(redactedJson) > _capacity.MaximumResponseBytes)
            throw new ArgumentException("Invalid bounded effect observation.", nameof(state));
        using var json = JsonDocument.Parse(redactedJson);
    }

    private byte[] ObservationDigest(string state, int effect, string json) =>
        HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(state + "|" + effect + "|" + json));

    private string ResultExpiry() => _store.Clock.GetUtcNow().AddHours(24).UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private string PreserveSandboxRemovalWitness(DurableReceipt previous, string state, string json)
    {
        if (previous.Method != SandboxDeletionRecords.Method) return json;
        if (SandboxDeletionRecords.ReadRemovalWitness(json) is not null)
            throw new ArgumentException("Only the dedicated removal observation may add native proof.", nameof(json));
        if (state == "UNKNOWN" && SandboxDeletionRecords.ReadRemovalWitness(previous.ResponseJson) is { } witness)
        {
            json = WithSandboxRemovalWitness(json, witness);
            ValidateResult(state, 3, json);
        }

        return json;
    }

    private static string WithSandboxRemovalWitness(string json, string witness)
    {
        var result = JsonNode.Parse(json)?.AsObject()
            ?? throw new InvalidOperationException("A deletion witness requires a bounded JSON object.");
        result[SandboxDeletionRecords.RemovalWitnessField] = witness;
        return result.ToJsonString();
    }

    private static string PrepareDeletionChildResult(DurableReceipt previous, string state, string json)
    {
        if (previous.Deletion is not { } binding) return json;
        if (state == "UNKNOWN") json = WriteDeletionBinding(json, binding);
        if (Encoding.UTF8.GetByteCount(json) > DeletionChildResponseBytes)
            throw new ArgumentException("A deletion continuation has a bounded metadata response.", nameof(json));
        return json;
    }

    private void WriteResult(StoreTransaction tx, string id, string state, int effect, string json, string now, string? resolved,
        string? expires, DurableReceipt? prior = null)
    {
        if (state != "UNKNOWN" && BlocksKnownResult(tx, id, state, effect))
            throw new InvalidOperationException("An unresolved effect cannot become a known settled result.");
        if (tx.Execute("""
            UPDATE command_receipt SET state=$s,effect_certainty=$effect,response_json=$body,updated_utc=$now,
                resolved_utc=$resolved,expires_utc=$expires,reserved_response=zeroblob($reserve)
            WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c AND state IN ('ACCEPTED','UNKNOWN');
            """, ("$s", state), ("$effect", effect), ("$body", json), ("$now", now),
            ("$resolved", resolved), ("$expires", expires),
            ("$reserve", state == "UNKNOWN"
                ? (prior?.Deletion is null ? _capacity.MaximumResponseBytes : DeletionChildResponseBytes) - Encoding.UTF8.GetByteCount(json) : 0),
            ("$o", _owner), ("$e", _fence.Epoch), ("$c", id)) != 1)
            throw new DurableStoreMaintenanceException();
        if (prior is { Deletion: not null, State: "ACCEPTED" }
            || state != "UNKNOWN" && tx.Scalar("SELECT safety_parent_command_id FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c;",
                ("$o", _owner), ("$e", _fence.Epoch), ("$c", id)) is string)
            RestoreSafetyReserve(tx);
    }

    private void RestoreSafetyReserve(StoreTransaction tx)
    {
        long promised = CountOutstandingSafetyPromises(tx) * ReservedSafetyIdentityBytes;
        tx.Execute("""
            UPDATE owner_epoch_capacity SET reserve_storage=zeroblob(length(reserve_storage)+$n)
            WHERE owner_id=$o AND owner_epoch=$e AND length(reserve_storage)+$n<=safety_receipts*maximum_response_bytes
              AND length(reserve_storage)+$n+$promised+(SELECT coalesce(sum(coalesce(length(CAST(response_json AS BLOB)),0)+length(reserved_response)+$identity),0)
                FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e)<=maximum_journal_bytes;
            """, ("$n", _capacity.MaximumResponseBytes), ("$o", _owner), ("$e", _fence.Epoch),
            ("$identity", ReceiptIdentityBytes), ("$promised", promised));
    }

    private bool BlocksKnownResult(StoreReader reader, string id, string state, int effect)
    {
        // BeginImport can have a definite stage reservation while its transfer still holds managed use.
        bool readyImport = state == "SUCCEEDED" && effect == 2
            && TransferRecords.CanSettleReadyImport(reader, _owner, _fence.Epoch, id);
        return !Equals(reader.Scalar("""
            SELECT (SELECT count(*) FROM transfer WHERE owner_id=$o AND owner_epoch=$e
                       AND ((command_id=$c AND $readyImport=0 AND (state IN (1,2,5) OR effect_certainty=3))
                            OR json_extract(manifest_json,'$.pending.commandId')=$c))
              + (SELECT count(*) FROM deletion_journal WHERE owner_id=$o AND owner_epoch=$e
                       AND (command_id=$c OR latest_resume_command_id=$c) AND (phase<>'complete' OR effect_certainty=3))
              + (SELECT count(*) FROM command_receipt AS close
                 JOIN transfer AS t ON t.owner_id=close.owner_id AND t.owner_epoch=close.owner_epoch
                   AND t.command_id=close.safety_parent_command_id AND t.transfer_id=close.aggregate_id
                 WHERE $succeeded=1 AND close.owner_id=$o AND close.owner_epoch=$e AND close.command_id=$c
                   AND close.method=$close AND t.closed_utc IS NULL);
            """, ("$o", _owner), ("$e", _fence.Epoch), ("$c", id), ("$readyImport", readyImport ? 1 : 0),
            ("$succeeded", state == "SUCCEEDED" && effect == 2 ? 1 : 0), ("$close", TransferRecords.CloseMethod)), 0L);
    }

    internal int CompactKnownResponses()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();
            return _store.Write(tx => tx.Execute("""
                UPDATE command_receipt SET response_json=NULL,response_compacted_utc=$now,reserved_response=X''
                WHERE owner_id=$o AND owner_epoch=$e AND state IN ('SUCCEEDED','FAILED') AND effect_certainty IN (1,2)
                  AND expires_utc IS NOT NULL AND julianday($now)>=julianday(expires_utc) AND expires_utc<=$now
                  AND response_compacted_utc IS NULL
                  AND NOT EXISTS(SELECT 1 FROM transfer t WHERE t.owner_id=$o AND t.owner_epoch=$e AND t.command_id=command_receipt.command_id
                    AND (t.state IN (1,2,5) OR t.effect_certainty=3))
                  AND NOT EXISTS(SELECT 1 FROM deletion_journal d WHERE d.owner_id=$o AND d.owner_epoch=$e
                    AND (d.command_id=command_receipt.command_id OR d.latest_resume_command_id=command_receipt.command_id)
                    AND (d.phase<>'complete' OR d.effect_certainty=3));
                """, ("$o", _owner), ("$e", _fence.Epoch), ("$now", Now())), CommitDurability.Full);
        }
    }
}
