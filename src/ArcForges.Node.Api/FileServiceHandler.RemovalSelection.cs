// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    internal Task<byte[]?> ExecuteApprovedRemovalReferenceAsync(byte[] reference, Caller caller)
    {
        if (reference.Length != 17 || reference[0] != 2 || !caller.Approved || caller.Routed is not null ||
            caller.ApprovalId is not { } approvalId || caller.CenterCaller is not { } center ||
            caller.RemoteCommandId?.Value.Span.SequenceEqual(reference.AsSpan(1)) != true || node.Stopping.IsCancellationRequested)
            return Task.FromResult<byte[]?>(null);

        try
        {
            return Task.FromResult(node.Store.Read(reader => ReadApprovedRemovalOutcome(reader, caller.RemoteCommandId, approvalId, center)));
        }
        catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
        {
            node.Log.Error("api.file.removal.approval_deferred");
            return Task.FromResult<byte[]?>(null);
        }
    }

    private static byte[]? ReadApprovedRemovalOutcome(StoreReader reader, Id command, byte[] approvalId, CenterCaller center)
    {
        var id = command.Value.ToByteArray();
        var approval = Approvals.ByCommand(reader, id);
        if (approval is not { State: ApprovalState.Approved } ||
            !approval.Id.AsSpan().SequenceEqual(approvalId) ||
            !MatchesRemovalApproval(approval, id, center))
            return null;
        var receipt = CommandDeduplication.ReadRetained(reader, id, RemovalExecutionMethod, approval.RequestDigest, reader.NowMicroseconds);
        if (receipt is not { Status: DedupStatus.Replay, Outcome: { } bytes } ||
            !RemovalCallerMayUse(reader, id, center, retained: true))
            return null;

        string Detail(string name) => approval.View.Details.Single(item => item.Name == name).Value;
        var planId = Convert.FromHexString(Detail("plan_id"));
        var planDigest = Convert.FromHexString(Detail("plan_digest"));
        var correlation = new Id { Value = ByteString.CopyFrom(Convert.FromHexString(Detail("correlation_id"))) };
        var strict = Detail("delete_without_quarantine");
        if (planId.Length != 16 || planDigest.Length != 32 || strict is not ("true" or "false") ||
            reader.Scalar("SELECT 1 FROM cleanup_plan WHERE plan_id = $plan AND approval_id = $approval;",
                ("$plan", planId), ("$approval", approvalId)) is null ||
            ReadRemovalExecutionPlan(reader, planId, center) is not { } plan ||
            !CryptographicOperations.FixedTimeEquals(plan.Digest, planDigest))
            return null;

        var request = new FileServiceExecuteRemovalRequest
        {
            Meta = new RequestMeta { CommandId = command.Clone(), CorrelationId = correlation },
            PlanId = new Id { Value = ByteString.CopyFrom(planId) },
            PlanDigest = ByteString.CopyFrom(planDigest),
            DeleteWithoutQuarantine = strict == "true",
        };
        if (ParseRemovalOutcome(request, bytes) is not { } replay ||
            replay.Error is { Effect: EffectCertainty.Unknown } or { Code: "approval_required" })
            return null;

        return RemovalOutcomeMatchesCustody(reader, id, center, approval.RequestDigest, replay.Error) ? bytes.ToArray() : null;
    }
}
