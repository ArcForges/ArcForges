// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

internal static partial class FileMutationJournal
{
    private const string RemovalIntentPrefix = "removal-intent-v1:";

    internal static bool IsRemoval(StoreReader reader, ReadOnlySpan<byte> id) =>
        reader.Scalar("SELECT 1 FROM file_operation_journal WHERE command_id = $id AND kind = 3;", ("$id", id.ToArray())) is not null;

    internal static void PrepareRemoval(StoreTransaction tx, byte[] command, byte[] correlation, byte[] digest, CenterCaller caller,
        byte[]? workspace, byte[]? attempt, string? path, RegisteredWorkspaces.RootIdentity root,
        RegisteredWorkspaces.RootIdentity parent, RegisteredWorkspaces.RootIdentity target, byte[] plan, string destination)
    {
        RequireFull(tx);
        StoreIds.Validate(command, nameof(command));
        StoreIds.Validate(correlation, nameof(correlation));
        if (digest.Length != 32 || CenterRouting.Shape(caller) is not null || root.Platform != parent.Platform || root.Platform != target.Platform ||
            (workspace is null) == (attempt is null) || tx.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", command)) is not null)
            throw new InvalidOperationException("A removal requires its exact reserved command and native target.");
        tx.Execute("""
            INSERT INTO file_operation_journal
              (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path, attempt_id,
               identity_platform, root_identity, parent_identity, target_identity, expected_absent, created_at, updated_at, held, acknowledged)
            VALUES ($command, 3, 1, $digest, $caller, $correlation, $workspace, $path, $attempt,
                    $platform, $root, $parent, $target, 0, $now, $now, 1, 0);
            """, ("$command", command), ("$digest", digest), ("$caller", Sanitize(caller).ToByteArray()),
            ("$correlation", correlation), ("$workspace", workspace), ("$path", path), ("$attempt", attempt),
            ("$platform", root.Platform), ("$root", root.Bytes), ("$parent", parent.Bytes), ("$target", target.Bytes), ("$now", tx.NowMicroseconds));
        var detail = RemovalIntentPrefix + Convert.ToHexString(command) + ":" + Convert.ToBase64String(Encoding.UTF8.GetBytes(destination));
        if (tx.Execute("UPDATE cleanup_plan SET state = 3, rev = rev + 1 WHERE plan_id = $plan AND state IN (1, 2);", ("$plan", plan)) != 1)
            throw new InvalidOperationException("The removal plan is no longer available.");
        tx.Execute("UPDATE cleanup_item SET outcome_detail = $detail WHERE plan_id = $plan;",
            ("$detail", detail), ("$plan", plan));
    }

    internal static FileOperation? RemovalOperation(StoreReader reader, ReadOnlySpan<byte> command, CenterCaller? caller)
    {
        using var query = reader.CreateCommand("""
            SELECT j.request_sha256, j.caller, j.correlation_id, j.workspace_id, j.relative_path, j.attempt_id,
                   j.phase, j.created_at, j.updated_at, j.held, j.acknowledged, d.outcome
            FROM file_operation_journal j JOIN command_dedup d ON d.command_id = j.command_id
            WHERE j.command_id = $id AND j.kind = 3;
            """);
        query.Parameters.AddWithValue("$id", command.ToArray());
        using var row = query.ExecuteReader();
        if (!row.Read()) return null;
        var owner = CenterCaller.Parser.ParseFrom((byte[])row.GetValue(1));
        if (caller is not null && !CenterRouting.SameFileCaller(owner, caller)) return null;
        var result = new FileOperation
        {
            CommandId = new Id { Value = ByteString.CopyFrom(command) },
            Kind = FileOperationKind.Removal,
            State = (FileOperationState)row.GetInt32(6),
            RequestSha256 = ByteString.CopyFrom((byte[])row.GetValue(0)),
            CreatedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(row.GetInt64(7))),
            UpdatedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(row.GetInt64(8))),
            Held = row.GetInt32(9) != 0,
            Acknowledged = row.GetInt32(10) != 0,
        };
        if (!row.IsDBNull(3))
            result.WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom((byte[])row.GetValue(3)) }, Path = row.GetString(4) };
        else result.AttemptId = new Id { Value = ByteString.CopyFrom((byte[])row.GetValue(5)) };
        if (!row.IsDBNull(11))
        {
            var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom((byte[])row.GetValue(11));
            if (!NodeShapes.IsValid(response) || !response.Meta.CorrelationId.Value.Span.SequenceEqual((byte[])row.GetValue(2)))
                throw new InvalidDataException("Invalid recorded removal outcome.");
            if (response.Error is { } error) result.Error = error.Clone();
            else if (response.Value?.Result is { } removal) result.Removal = removal.Clone();
            else throw new InvalidDataException("A removal outcome is missing.");
        }
        if (!NodeShapes.IsValid(result)) throw new InvalidDataException("Invalid removal journal.");
        return result;
    }

    internal static byte[] CompleteRemoval(StoreTransaction tx, byte[] command, byte[] plan,
        FileServiceExecuteRemovalResponse response, string? originalPath = null, string? destination = null, byte[]? quarantine = null,
        long? purgeAfter = null, long? quarantinedAt = null)
    {
        RequireFull(tx);
        var current = RemovalOperation(tx, command, null) ?? throw new InvalidOperationException("Missing removal journal.");
        if (current.State != FileOperationState.Prepared || !NodeShapes.IsValid(response))
            throw new InvalidOperationException("Only a checked prepared removal can settle.");
        if (response.Value?.Result is { Quarantined: true } moved)
        {
            if (originalPath is null || destination is null || quarantine is null || purgeAfter is null || quarantinedAt is null ||
                !moved.PlanId.Value.Span.SequenceEqual(plan) || !moved.QuarantineId.Value.Span.SequenceEqual(quarantine))
                throw new InvalidOperationException("The actual quarantine evidence is required.");
            // The selected root is the physically moved object. Descendant rows remain linked to that root.
            tx.Execute("""
                INSERT INTO quarantine_entry (plan_id, item_id, original_path, quarantine_path, size_bytes, quarantined_at, purge_at)
                SELECT i.plan_id, i.item_id, $original, $destination, $size, $now, $purge
                FROM cleanup_item i JOIN file_removal_plan_item p ON p.plan_id = i.plan_id AND p.item_id = i.item_id
                WHERE p.plan_id = $plan AND p.ordinal = 0;
                """, ("$plan", plan), ("$original", originalPath), ("$destination", destination), ("$size", checked((long)moved.TotalBytes)),
                ("$now", quarantinedAt.Value), ("$purge", purgeAfter.Value));
        }
        tx.Execute("UPDATE file_operation_journal SET phase = 2, held = 0, updated_at = max(updated_at, $now) WHERE command_id = $id AND phase = 1;",
            ("$id", command), ("$now", tx.NowMicroseconds));
        tx.Execute("UPDATE cleanup_plan SET state = $state, executed_at = $now, rev = rev + 1 WHERE plan_id = $plan AND state = 3;",
            ("$state", response.Error is null ? 4 : 5), ("$now", tx.NowMicroseconds), ("$plan", plan));
        tx.Execute("UPDATE cleanup_item SET outcome = $outcome, acted_at = $now WHERE plan_id = $plan;",
            ("$outcome", response.Error is null ? 2 : 7), ("$now", tx.NowMicroseconds), ("$plan", plan));
        if (response.Error is null && current.AttemptId is { } attempt)
            tx.Execute("""
                UPDATE managed_directory SET state = 4, last_used_at = $now, rev = rev + 1
                WHERE directory_id = (SELECT directory_id FROM file_attempt_temp_identity WHERE attempt_id = $attempt);
                """, ("$attempt", attempt.Value.ToByteArray()), ("$now", tx.NowMicroseconds));
        var bytes = response.ToByteArray();
        CommandDeduplication.Complete(tx, command, bytes);
        AuditLog.AppendFileWorkspace(tx, RemovalActor(tx, command), "file.remove FileService.ExecuteRemoval",
            current.WorkspacePath?.WorkspaceId.Value.ToByteArray(), current.AttemptId?.Value.ToByteArray(), current.WorkspacePath?.Path,
            response.Error is null ? PermissionDecision.Allow : PermissionDecision.Deny,
            response.Error is null ? "completed: quarantined" : "refused: " + response.Error.Code, null);
        return bytes;
    }

    private static ActorRef RemovalActor(StoreReader reader, ReadOnlySpan<byte> id) => new()
    {
        Origin = Origin.Remote,
        CenterCaller = CenterCaller.Parser.ParseFrom((byte[])reader.Scalar("SELECT caller FROM file_operation_journal WHERE command_id = $id;", ("$id", id.ToArray()))!),
        RemoteCommandId = new Id { Value = ByteString.CopyFrom(id) },
    };

    internal static string? RemovalRecoveryLocation(StoreReader reader, ReadOnlySpan<byte> command)
    {
        var prefix = RemovalIntentPrefix + Convert.ToHexString(command) + ":";
        var value = reader.Scalar("SELECT outcome_detail FROM cleanup_item WHERE outcome_detail LIKE $prefix LIMIT 1;",
            ("$prefix", prefix + "%")) as string;
        return value is not null && value.StartsWith(prefix, StringComparison.Ordinal)
            ? StrictUtf8.GetString(Convert.FromBase64String(value[prefix.Length..])) : null;
    }

    private static byte[] MarkRemovalUnknown(StoreTransaction tx, ReadOnlySpan<byte> command)
    {
        var operation = RemovalOperation(tx, command, null) ?? throw new InvalidOperationException("Missing removal journal.");
        var correlation = (byte[])tx.Scalar("SELECT correlation_id FROM file_operation_journal WHERE command_id = $id;", ("$id", command.ToArray()))!;
        var response = new FileServiceExecuteRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(correlation) } },
            Error = new ArcError
            {
                Category = ErrorCategory.Execution,
                Code = "operation_failed",
                MessageKey = "error.execution.operation_failed",
                Effect = EffectCertainty.Unknown,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                CorrelationId = new Id { Value = ByteString.CopyFrom(correlation) },
                Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "file_outcome_unknown" } },
            },
        };
        if (operation.State != FileOperationState.Prepared || !NodeShapes.IsValid(response))
            throw new InvalidOperationException("Only an unresolved removal can become unknown.");
        tx.Execute("UPDATE file_operation_journal SET phase = 3, updated_at = max(updated_at, $now) WHERE command_id = $id AND phase = 1;",
            ("$id", command.ToArray()), ("$now", tx.NowMicroseconds));
        var bytes = response.ToByteArray(); CommandDeduplication.Complete(tx, command, bytes);
        AuditLog.AppendFileWorkspace(tx, RemovalActor(tx, command), "file.recovery FileService.GetFileOperation",
            operation.WorkspacePath?.WorkspaceId.Value.ToByteArray(), operation.AttemptId?.Value.ToByteArray(), operation.WorkspacePath?.Path,
            PermissionDecision.Allow, "recovered: file_outcome_unknown", null);
        return bytes;
    }

    private static FileJournalAcknowledgment AcknowledgeRemoval(StoreTransaction tx, ReadOnlySpan<byte> command, ReadOnlySpan<byte> digest, ActorRef actor)
    {
        var row = RemovalOperation(tx, command, null)!;
        void Audit(PermissionDecision decision, string outcome) => AuditLog.AppendFileWorkspace(tx, actor,
            "file.acknowledge FileService.AcknowledgeFileOperation", row.WorkspacePath?.WorkspaceId.Value.ToByteArray(),
            row.AttemptId?.Value.ToByteArray(), row.WorkspacePath?.Path, decision, outcome, null);
        if (!CryptographicOperations.FixedTimeEquals(row.RequestSha256.Span, digest))
        {
            Audit(PermissionDecision.Deny, "refused: digest_mismatch");
            return FileJournalAcknowledgment.DigestMismatch;
        }
        if (row.State != FileOperationState.Unknown || !row.Held)
        {
            Audit(PermissionDecision.Deny, "refused: invalid_state");
            return FileJournalAcknowledgment.InvalidState;
        }
        tx.Execute("UPDATE file_operation_journal SET held = 0, acknowledged = 1, updated_at = max(updated_at, $now) WHERE command_id = $id AND phase = 3 AND held = 1;",
            ("$id", command.ToArray()), ("$now", tx.NowMicroseconds));
        // No removal child is launched. The in-process move callback ended before status/ack can enter the command writer.
        var prefix = RemovalIntentPrefix + Convert.ToHexString(command) + ":%";
        tx.Execute("UPDATE cleanup_plan SET state = 5, rev = rev + 1 WHERE state = 3 AND plan_id IN (SELECT plan_id FROM cleanup_item WHERE outcome_detail LIKE $prefix);", ("$prefix", prefix));
        AuditLog.AppendFileWorkspace(tx, actor, "file.acknowledge FileService.AcknowledgeFileOperation",
            row.WorkspacePath?.WorkspaceId.Value.ToByteArray(), row.AttemptId?.Value.ToByteArray(), row.WorkspacePath?.Path,
            PermissionDecision.Allow, "acknowledged: file_outcome_unknown", null);
        return FileJournalAcknowledgment.Acknowledged;
    }
}
