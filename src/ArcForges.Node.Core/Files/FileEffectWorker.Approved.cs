// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Files;

internal static partial class FileEffectWorker
{
    /// <summary>
    /// Registers the actual owned effect child against the already FULL PREPARED, genuinely APPROVED reference.
    /// The original transmitted digest is read from durable metadata; no body request or caller proof is synthesized.
    /// </summary>
    internal static PrivateStageApprovedPlan RecordApprovedChild(StoreTransaction transaction, ReadOnlySpan<byte> approvalId,
        ReadOnlySpan<byte> commandId, CenterCaller caller, LinuxOwnedPidfd worker)
    {
        RequireFull(transaction);
        if (!OperatingSystem.IsLinux() || !HasSchema(transaction))
            throw new InvalidOperationException("The Linux worker lifetime fence is unavailable.");
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId);
        if (plan is null || !plan.Active || !plan.Intent.CommandId.AsSpan().SequenceEqual(commandId) ||
            !CenterRouting.SameFileCaller(plan.Intent.Caller, caller))
            throw new InvalidOperationException("The original approved caller binding is unavailable.");
        var intent = plan.Intent;
        if (transaction.Scalar("""
                SELECT 1 FROM file_operation_journal j JOIN command_dedup d ON d.command_id = j.command_id
                WHERE j.command_id = $id AND j.kind = $kind AND j.phase = 1 AND j.held = 1 AND j.acknowledged = 0
                  AND d.outcome IS NULL AND d.origin = $origin AND d.payload_digest = $digest
                  AND j.request_sha256 = $digest AND j.caller = $caller AND j.correlation_id = $correlation
                  AND j.workspace_id = $workspace AND j.relative_path = $path AND j.identity_platform = $platform
                  AND j.root_identity = $root AND j.parent_identity = $parent AND j.target_identity IS $target
                  AND j.expected_absent = $absent AND j.original_size IS $original_size
                  AND j.original_sha256 IS $original_hash AND j.original_stage_identity IS $original_stage
                  AND j.intended_size = $intended_size AND j.intended_sha256 = $intended_hash
                  AND j.intended_stage_identity = $intended_stage;
                """, ("$id", intent.CommandId), ("$kind", (int)intent.Kind), ("$origin", (int)Origin.Remote),
                ("$digest", plan.RequestSha256), ("$caller", FileMutationJournal.Sanitize(intent.Caller).ToByteArray()),
                ("$correlation", intent.CorrelationId), ("$workspace", intent.WorkspaceId), ("$path", intent.RelativePath),
                ("$platform", intent.IdentityPlatform), ("$root", intent.RootIdentity), ("$parent", intent.ParentIdentity),
                ("$target", intent.TargetIdentity), ("$absent", intent.TargetIdentity is null ? 1 : 0),
                ("$original_size", intent.OriginalSize), ("$original_hash", intent.OriginalSha256),
                ("$original_stage", intent.OriginalStageIdentity), ("$intended_size", intent.IntendedSize),
                ("$intended_hash", intent.IntendedSha256), ("$intended_stage", intent.IntendedStageIdentity)) is null)
            throw new InvalidOperationException("The actual child does not bind the approved PREPARED intent.");
        var identity = worker.SealedIdentity();
        transaction.Execute("""
            INSERT INTO file_effect_worker (command_id, boot_id, pid_namespace, process_id, start_ticks, ended)
            VALUES ($id, $boot, $namespace, $pid, $start, 0);
            """, ("$id", intent.CommandId), ("$boot", identity.BootId.ToString("D")),
            ("$namespace", identity.PidNamespace), ("$pid", identity.ProcessId), ("$start", identity.StartTicks));
        return plan;
    }
}
