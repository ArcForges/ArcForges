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
        PermissionDecision decision, ReadOnlySpan<byte> approvalId, string outcome)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(actor);
        transaction.Execute(
            """
            INSERT INTO audit_log (at, actor, operation, target_kind, target_id, decision, approval_id, remote_command_id, outcome_summary)
            VALUES ($at, $actor, $operation, $kind, $target, $decision, $approval, NULL, $outcome);
            """,
            ("$at", transaction.NowMicroseconds), ("$actor", actor.ToByteArray()), ("$operation", operation), ("$kind", targetKind),
            ("$target", targetId.Length > 0 ? targetId.ToArray() : null), ("$decision", (int)decision),
            ("$approval", approvalId.Length == 16 ? approvalId.ToArray() : null), ("$outcome", outcome.Length <= 500 ? outcome : outcome[..500]));
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
        return transaction.Execute("DELETE FROM audit_log WHERE at < $cutoff;", ("$cutoff", transaction.NowMicroseconds - YearMicroseconds));
    }
}
