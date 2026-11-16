// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Node.Store;

internal sealed partial class DurableCommandStore
{
    // Effect observations are supplied by the owning subsystem. This store does not infer native success.
    internal DurableReceipt SetResult(byte[] commandId, string state, int effect, string redactedJson,
        Action<StoreTransaction>? observedMetadata = null)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();
            StoreIds.Validate(commandId, nameof(commandId));
            if (state is not ("SUCCEEDED" or "FAILED" or "UNKNOWN") || effect is < 1 or > 3
                || state == "UNKNOWN" && effect != 3 || state != "UNKNOWN" && effect == 3
                || Encoding.UTF8.GetByteCount(redactedJson) > _capacity.MaximumResponseBytes)
                throw new ArgumentException("Invalid bounded effect observation.", nameof(state));
            using var json = JsonDocument.Parse(redactedJson);
            var previous = Inspect(commandId) ?? throw new InvalidOperationException("No admitted command exists.");
            if (previous.State == state && previous.Effect == effect && previous.ResponseJson == redactedJson) return previous;
            if (previous.State == "UNKNOWN" && state == "UNKNOWN")
                throw new InvalidOperationException("An unresolved observation is retained until a definite effect is supplied.");
            if (previous.State is "SUCCEEDED" or "FAILED")
            {
                if (previous.State != state || previous.Effect != effect || previous.ResponseJson != redactedJson)
                    throw new InvalidOperationException("The known command outcome cannot be rewritten.");
                return previous;
            }
            string id = Convert.ToHexStringLower(commandId);
            string now = Now();
            string? resolved = state == "UNKNOWN" ? null : now;
            string? expires = resolved is null ? null : _store.Clock.GetUtcNow().AddHours(24).UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
            byte[] observation = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(state + "|" + effect + "|" + redactedJson));
            if (state != "UNKNOWN" && observedMetadata is null && _store.Read(reader => HasUnresolvedEffect(reader, id)))
                throw new InvalidOperationException("An unresolved effect cannot become a known settled result.");
            Advance("observe", id, observation, tx =>
            {
                observedMetadata?.Invoke(tx);
                if (state != "UNKNOWN" && HasUnresolvedEffect(tx, id))
                    throw new InvalidOperationException("An unresolved effect cannot become a known settled result.");
                tx.Execute("""
                    UPDATE command_receipt SET state=$s,effect_certainty=$effect,response_json=$body,updated_utc=$now,
                        resolved_utc=$resolved,expires_utc=$expires,reserved_response=zeroblob($reserve)
                    WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c;
                    """, ("$s", state), ("$effect", effect), ("$body", redactedJson), ("$now", now),
                    ("$resolved", resolved), ("$expires", expires),
                    ("$reserve", state == "UNKNOWN" ? _capacity.MaximumResponseBytes - Encoding.UTF8.GetByteCount(redactedJson) : 0),
                    ("$o", _owner), ("$e", _fence.Epoch), ("$c", id));
                if (state != "UNKNOWN" && tx.Scalar("SELECT safety_parent_command_id FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c;",
                    ("$o", _owner), ("$e", _fence.Epoch), ("$c", id)) is string)
                    tx.Execute("""
                        UPDATE owner_epoch_capacity SET reserve_storage=zeroblob(length(reserve_storage)+$n)
                        WHERE owner_id=$o AND owner_epoch=$e AND length(reserve_storage)+$n<=safety_receipts*maximum_response_bytes
                          AND length(reserve_storage)+$n+(SELECT coalesce(sum(coalesce(length(CAST(response_json AS BLOB)),0)+length(reserved_response)+2048),0)
                            FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e)<=maximum_journal_bytes;
                        """, ("$n", _capacity.MaximumResponseBytes), ("$o", _owner), ("$e", _fence.Epoch));
            });
            return Inspect(commandId)!;
        }
    }

    private bool HasUnresolvedEffect(StoreReader reader, string id) => !Equals(reader.Scalar("""
        SELECT (SELECT count(*) FROM transfer WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c
                   AND (state IN (1,2,5) OR effect_certainty=3))
          + (SELECT count(*) FROM deletion_journal WHERE owner_id=$o AND owner_epoch=$e
                   AND (command_id=$c OR latest_resume_command_id=$c) AND (phase<>'complete' OR effect_certainty=3));
        """, ("$o", _owner), ("$e", _fence.Epoch), ("$c", id)), 0L);

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
