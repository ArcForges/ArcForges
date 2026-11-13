// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Security;

/// <summary>
/// Associates a routed command outcome with the caller class that actually recorded it. The marker is written in the same FULL transaction
/// as command_dedup, at that row's exact created_at, and contains no request or outcome bytes. A missing or malformed marker fails closed.
/// </summary>
public static class RoutedCommandOwnership
{
    /// <summary>The distinct audit target reserved for an outcome ownership marker, not a policy refusal.</summary>
    public const string TargetKind = "routed_command_owner";

    /// <summary>True when existing approval and live dedup records may be used by this caller class.</summary>
    public static bool MayUse(StoreReader reader, ReadOnlySpan<byte> commandId, CenterCaller? caller)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var id = commandId.ToArray();
        if (Approvals.ByCommand(reader, id) is { } approval)
        {
            var requester = approval.View.Requester?.CenterCaller;
            if ((caller is not null || requester is not null) && !CenterRouting.SameClass(caller, requester))
            {
                return false;
            }
        }

        long createdAt;
        long expiresAt;
        Origin origin;
        using (var command = reader.CreateCommand("SELECT origin, created_at, expires_at FROM command_dedup WHERE command_id = $id;"))
        {
            command.Parameters.AddWithValue("$id", id);
            using var row = command.ExecuteReader();
            if (!row.Read())
            {
                return true;
            }

            origin = (Origin)row.GetInt32(0);
            createdAt = row.GetInt64(1);
            expiresAt = row.GetInt64(2);
        }

        if (expiresAt <= reader.NowMicroseconds && !RoutedFileRetention.IsHeld(reader, id))
        {
            return true;
        }

        if (origin != Origin.Remote)
        {
            return caller is null;
        }

        if (caller is null)
        {
            return false;
        }

        // at is indexed; matching the command's exact creation instant avoids an unrelated earlier receipt or expired generation.
        using var marker = reader.CreateCommand("""
            SELECT actor FROM audit_log WHERE at = $at AND target_kind = $kind AND remote_command_id = $id ORDER BY seq DESC LIMIT 1;
            """);
        marker.Parameters.AddWithValue("$at", createdAt);
        marker.Parameters.AddWithValue("$kind", TargetKind);
        marker.Parameters.AddWithValue("$id", id);
        try
        {
            return marker.ExecuteScalar() is byte[] actor && CenterRouting.SameClass(ActorRef.Parser.ParseFrom(actor).CenterCaller, caller);
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }
    }

    /// <summary>Also prevents a routed approval's command ID being reused for another method or request before its outcome exists.</summary>
    public static bool MayExecute(StoreReader reader, ReadOnlySpan<byte> commandId, CenterCaller? caller, string operation, ReadOnlySpan<byte> digest)
    {
        if (!MayUse(reader, commandId, caller))
        {
            return false;
        }

        if (Approvals.ByCommand(reader, commandId) is not { } approval
            || (caller is null && approval.View.Requester?.CenterCaller is null))
        {
            return true;
        }

        return approval.View.Operation == operation && approval.RequestDigest.AsSpan().SequenceEqual(digest);
    }

    /// <summary>Records the original routed requester's class alongside a newly recorded command outcome.</summary>
    public static void Record(StoreTransaction transaction, ReadOnlySpan<byte> commandId, ActorRef actor)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(actor);
        if (actor.CenterCaller is null)
        {
            return;
        }

        var id = commandId.ToArray();
        using var row = transaction.CreateCommand("SELECT created_at FROM command_dedup WHERE command_id = $id;");
        row.Parameters.AddWithValue("$id", id);
        var at = row.ExecuteScalar() is long value ? value : throw new InvalidOperationException("The routed outcome has no deduplication row.");

        // If a clock adjustment recreated a generation at an identical timestamp, remove only an exact stale marker before replacing it.
        transaction.Execute("DELETE FROM audit_log WHERE at = $at AND target_kind = $kind AND remote_command_id = $id;",
            ("$at", at), ("$kind", TargetKind), ("$id", id));
        var seq = (long)transaction.Scalar("""
            INSERT INTO audit_log (at, actor, operation, target_kind, target_id, decision, approval_id, remote_command_id, outcome_summary)
            VALUES ($at, $actor, 'routed.command.outcome', $kind, NULL, $decision, NULL, $id, 'routed command outcome recorded') RETURNING seq;
            """, ("$at", at), ("$actor", actor.ToByteArray()), ("$kind", TargetKind), ("$decision", (int)PermissionDecision.Unspecified), ("$id", id))!;
        if (RoutedFileRetention.IsHeld(transaction, id))
        {
            RoutedFileRetention.MarkAudit(transaction, seq);
        }
    }
}
