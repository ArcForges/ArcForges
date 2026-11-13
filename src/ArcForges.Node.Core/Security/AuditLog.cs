// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Security;

/// <summary>One <c>audit_log</c> row.</summary>
/// <param name="Seq">The row's sequence.</param>
/// <param name="At">When (microseconds).</param>
/// <param name="Actor">Who acted.</param>
/// <param name="Operation">The matrix operation and method, for example <c>task.cancel_others TaskService.CancelTask</c>.</param>
/// <param name="TargetKind">The kind of the object acted on, if any.</param>
/// <param name="TargetId">The object's ID, if any.</param>
/// <param name="Decision">The permission decision applied.</param>
/// <param name="ApprovalId">The approval the action belongs to, if any.</param>
/// <param name="Outcome">What happened.</param>
public sealed record AuditEntry(long Seq, long At, ActorRef Actor, string Operation, string? TargetKind, byte[]? TargetId, PermissionDecision Decision,
    byte[]? ApprovalId, string Outcome);

/// <summary>
/// The local audit log (node-store.md <c>audit_log</c>; R-SEC-002): every privileged action (each operation of the permission matrix whose
/// default is not ALLOW for every local origin), every refusal of one, every approval raised, decided, withdrawn, expired and executed, and
/// every adoption and process termination. Entries are written in the transaction of the action they record, so an action and its audit
/// entry commit together; they are kept for one year. Like the store itself, the log is a record of what the node did, not a tamper-proof
/// one: a same-user process can edit the store (11 section 1).
/// </summary>
public static class AuditLog
{
    private const long YearMicroseconds = 365L * 24 * 60 * 60 * 1_000_000;

    /// <summary>Appends an entry in <paramref name="transaction"/>.</summary>
    public static void Append(StoreTransaction transaction, ActorRef actor, string operation, string? targetKind, ReadOnlySpan<byte> targetId,
        PermissionDecision decision, ReadOnlySpan<byte> approvalId, string outcome) =>
        _ = AppendRow(transaction, actor, operation, targetKind, targetId, decision, approvalId, outcome);

    /// <summary>
    /// Appends file/workspace scope and bounded observations in the same transaction as the audit entry. Values are metadata,
    /// never file contents, patterns or replacement text. Missing observations do not acquire a synthetic digest.
    /// </summary>
    public static void AppendFileWorkspace(StoreTransaction transaction, ActorRef actor, string operation, byte[]? workspaceId,
        byte[]? attemptId, string? path, PermissionDecision decision, string outcome, FileAuditMetadata? metadata)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(actor);
        if (workspaceId is { Length: not 16 } || attemptId is { Length: not 16 } || workspaceId is not null && attemptId is not null)
        {
            throw new ArgumentException("An audit scope names at most one valid workspace or attempt.");
        }

        if (path is not null && new System.Text.UTF8Encoding(false, true).GetByteCount(path) > 4096)
        {
            throw new ArgumentException("An audit path is at most 4096 UTF-8 bytes.", nameof(path));
        }

        var observations = metadata?.Observations;
        if (observations is { Count: > 4 } || observations is not null && observations.Select(item => item.Kind).Distinct().Count() != observations.Count)
        {
            throw new ArgumentException("Audit observation kinds are unique and bounded.", nameof(metadata));
        }

        if (observations is not null)
        {
            foreach (var item in observations)
            {
                if (!item.HasKind || (int)item.Kind is < 1 or > 7 ||
                    !item.HasSizeBytes || item.SizeBytes > long.MaxValue || !item.HasDigestInputBytes || item.DigestInputBytes > long.MaxValue ||
                    !item.HasSha256 || item.Sha256.Length != 32 || item.HasItemCount && item.ItemCount > 10_001)
                {
                    throw new ArgumentException("An audit observation has a valid kind, byte counts and SHA-256.", nameof(metadata));
                }
            }
        }

        var targetId = workspaceId ?? attemptId;
        var seq = AppendRow(transaction, actor, operation, workspaceId is not null ? "workspace" : attemptId is not null ? "attempt" : null,
            targetId ?? [], decision, [], outcome);
        transaction.Execute("""
            INSERT INTO file_workspace_audit (audit_seq, workspace_id, attempt_id, path)
            VALUES ($seq, $workspace, $attempt, $path);
            """, ("$seq", seq), ("$workspace", workspaceId), ("$attempt", attemptId), ("$path", path));
        RoutedFileRetention.MarkAudit(transaction, seq);
        if (observations is not null)
        {
            foreach (var item in observations)
            {
                transaction.Execute("""
                    INSERT INTO file_workspace_audit_observation (audit_seq, kind, size_bytes, digest_input_bytes, item_count, sha256)
                    VALUES ($seq, $kind, $size, $input, $items, $digest);
                    """, ("$seq", seq), ("$kind", (int)item.Kind), ("$size", (long)item.SizeBytes),
                    ("$input", (long)item.DigestInputBytes), ("$items", item.HasItemCount ? (long)item.ItemCount : null),
                    ("$digest", item.Sha256.ToByteArray()));
            }
        }
    }

    private static long AppendRow(StoreTransaction transaction, ActorRef actor, string operation, string? targetKind, ReadOnlySpan<byte> targetId,
        PermissionDecision decision, ReadOnlySpan<byte> approvalId, string outcome)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(actor);
        return (long)transaction.Scalar(
            """
            INSERT INTO audit_log (at, actor, operation, target_kind, target_id, decision, approval_id, remote_command_id, outcome_summary)
            VALUES ($at, $actor, $operation, $kind, $target, $decision, $approval, $remote, $outcome)
            RETURNING seq;
            """,
            ("$at", transaction.NowMicroseconds), ("$actor", actor.ToByteArray()), ("$operation", operation), ("$kind", targetKind),
            ("$target", targetId.Length > 0 ? targetId.ToArray() : null), ("$decision", (int)decision),
            ("$approval", approvalId.Length == 16 ? approvalId.ToArray() : null),
            ("$remote", actor.RemoteCommandId is { Value.Length: 16 } remote ? remote.Value.ToByteArray() : null),
            ("$outcome", outcome.Length <= 500 ? outcome : outcome[..500]))!;
    }

    /// <summary>The newest entries first (tests and diagnosis; no API lists the local audit log in release 1).</summary>
    public static List<AuditEntry> Recent(StoreReader reader, int limit = 500)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var entries = new List<AuditEntry>();
        using var command = reader.CreateCommand(
            "SELECT seq, at, actor, operation, target_kind, target_id, decision, approval_id, outcome_summary FROM audit_log ORDER BY seq DESC LIMIT $limit;");
        command.Parameters.AddWithValue("$limit", limit);
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            entries.Add(new AuditEntry(rows.GetInt64(0), rows.GetInt64(1), ActorRef.Parser.ParseFrom((byte[])rows.GetValue(2)), rows.GetString(3),
                rows.IsDBNull(4) ? null : rows.GetString(4), rows.IsDBNull(5) ? null : (byte[])rows.GetValue(5), (PermissionDecision)rows.GetInt32(6),
                rows.IsDBNull(7) ? null : (byte[])rows.GetValue(7), rows.GetString(8)));
        }

        return entries;
    }

    /// <summary>Retention (housekeeping): entries older than one year are deleted.</summary>
    public static int Prune(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        // A wall-clock jump must not remove the ownership of a dedup row that is still live. Both lookups use existing time/ID indexes.
        var now = transaction.NowMicroseconds;
        return transaction.Execute("""
            DELETE FROM audit_log WHERE at < $cutoff AND (target_kind IS NOT $kind OR NOT EXISTS (
                SELECT 1 FROM command_dedup d WHERE d.command_id = audit_log.remote_command_id
                  AND d.created_at = audit_log.at AND d.expires_at > $now));
            """, ("$cutoff", now - YearMicroseconds), ("$kind", RoutedCommandOwnership.TargetKind), ("$now", now));
    }
}
