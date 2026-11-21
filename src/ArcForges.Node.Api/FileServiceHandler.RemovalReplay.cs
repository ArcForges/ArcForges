// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    private const string RemovalPlanMethod = "arcforges.node.v1.FileService/PlanRemoval";
    private const string RemovalExecutionMethod = "arcforges.node.v1.FileService/ExecuteRemoval";
    private const string RemovalApprovalOperation = "FileService.ExecuteRemoval";

    internal sealed record RemovalReplay(IMessage Response, ArcError? Error, ReadOnlyMemory<byte>? Retained = null);

    internal RemovalReplay ReadRoutedRemoval(Caller caller, IMessage request, CancellationToken cancellationToken)
    {
        var plan = request as FileServicePlanRemovalRequest;
        var execution = request as FileServiceExecuteRemovalRequest;
        var planning = plan is not null;
        var meta = plan?.Meta ?? execution?.Meta;
        var routed = caller.Routed ?? throw new InvalidOperationException("Removal requires a verified route.");
        var correlation = routed.Correlation(meta);
        var replyMeta = new ResponseMeta { CorrelationId = correlation.Clone() };
        var raw = caller.RawRequest ?? throw new InvalidOperationException("Removal requires the exact routed request.");
        var operation = planning ? PermissionMatrix.CleanupPlan : PermissionMatrix.FileRemove;
        var method = planning ? RemovalPlanMethod : RemovalExecutionMethod;
        var authorization = planning ? "FileService.PlanRemoval" : RemovalApprovalOperation;

        RemovalReplay Refusal(ArcError error) =>
            new(planning ? new FileServicePlanRemovalResponse { Meta = replyMeta, Error = error } :
                new FileServiceExecuteRemovalResponse { Meta = replyMeta, Error = error }, error);

        ArcError Unknown()
        {
            var error = planning
                ? Error(ErrorCategory.Internal, "internal", "legacy_removal_plan_outcome_unavailable", correlation)
                : Error(ErrorCategory.Execution, "operation_failed", "file_outcome_unknown", correlation);
            error.Effect = EffectCertainty.Unknown;
            return error;
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (routed.RemainingFileOperation() <= TimeSpan.Zero)
                throw new OperationCanceledException(cancellationToken);
            if (plan?.WorkspacePath is { HasPath: true } oversized && StrictUtf8.GetByteCount(oversized.Path) > 4096)
            {
                var bounded = plan.Clone();
                bounded.WorkspacePath.Path = "x";
                return Refusal(NodeShapes.IsValid(bounded) ? RemovalLimit(correlation, "path_bytes", "4096") :
                    Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
            }

            if (!(planning ? NodeShapes.IsValid(plan!) : execution is not null && NodeShapes.IsValid(execution)) ||
                Validation.CommandId(meta) is not null || caller.CenterCaller is not { } center || CenterRouting.Shape(center) is not null)
                return Refusal(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));

            var id = meta!.CommandId.Value.ToByteArray();
            var digest = SHA256.HashData(raw);
            var result = node.Store.Read(reader =>
            {
                routed.BeforeReplay();
                var receipt = CommandDeduplication.ReadRetained(reader, id, method, digest, reader.NowMicroseconds);
                if (!RemovalCallerMayUse(reader, id, center, retained: receipt is not null) ||
                    receipt is null && !RoutedCommandOwnership.MayExecute(reader, id, center, authorization, digest, retainedDedup: false))
                    return Refusal(StoreErrors.CommandIdReused());

                var approval = planning ? null : Approvals.ByCommand(reader, id);
                if (approval is not null && (!MatchesRemovalApproval(approval, id, center) ||
                    !CryptographicOperations.FixedTimeEquals(approval.RequestDigest, digest)))
                    return Refusal(StoreErrors.CommandIdReused());

                if (receipt?.Status == DedupStatus.Conflict)
                    return Refusal(StoreErrors.CommandIdReused());
                if (receipt is { Status: DedupStatus.Replay, Outcome: { } bytes })
                {
                    var replay = ParseRemovalOutcome(request, bytes);
                    if (replay is null)
                        return Refusal(Unknown());
                    if (!planning && !RemovalOutcomeMatchesCustody(reader, id, center, digest, replay.Error))
                        return Refusal(Unknown());
                    if (replay.Error is { Category: ErrorCategory.Authorization })
                    {
                        var reason = reader.Scalar("SELECT policy_reason FROM file_removal_command_owner WHERE command_id = $id;",
                            ("$id", id)) as string;
                        if (reason is null)
                            return Refusal(Unknown());
                        routed.Refused(operation, reason);
                        return replay with { Retained = null };
                    }
                    return replay;
                }

                if (receipt?.Status == DedupStatus.InProgress || approval is not null)
                    return Refusal(Unknown());
                if (planning)
                {
                    CheckPlanAuthority(reader, caller);
                }
                else
                {
                    CheckRemovalPreflightAuthority(reader, caller);
                    var selected = ReadRemovalExecutionPlan(reader, execution!.PlanId.Value.ToByteArray(), center);
                    if (selected is null)
                        return Refusal(NodeErrors.NotFound("cleanup_plan", execution.PlanId.Value.Span));
                    if (!CryptographicOperations.FixedTimeEquals(selected.Digest, execution.PlanDigest.Span))
                        return Refusal(Error(ErrorCategory.Conflict, "digest_mismatch", "plan_digest_mismatch", correlation));
                }
                return Refusal(Unknown());
            });
            cancellationToken.ThrowIfCancellationRequested();
            if (routed.RemainingFileOperation() <= TimeSpan.Zero)
                throw new OperationCanceledException(cancellationToken);
            routed.BeforeReplay();
            return result;
        }
        catch (EncoderFallbackException)
        {
            return Refusal(Error(ErrorCategory.Validation, "invalid_argument", "path: utf8", correlation));
        }
        catch (FilePolicyException refusal)
        {
            routed.Refused(operation, refusal.Reason);
            return Refusal(Error(ErrorCategory.Authorization, "permission_denied", operation, correlation));
        }
        catch (Exception failure) when (failure is not OperationCanceledException and not RoutedAbortException and
            not OutOfMemoryException and not StackOverflowException)
        {
            node.Log.Warning("api.file.removal.replay_unavailable");
            return Refusal(Unknown());
        }
    }

    private static bool MatchesRemovalApproval(StoredApproval approval, byte[] commandId, CenterCaller caller) =>
        approval.View.Operation == RemovalApprovalOperation && approval.Request.Length == 17 && approval.Request[0] == 2 &&
        approval.Request.AsSpan(1).SequenceEqual(commandId) &&
        CenterRouting.SameFileCaller(approval.View.Requester?.CenterCaller, caller);

    private static bool RemovalOutcomeMatchesCustody(StoreReader reader, byte[] command, CenterCaller caller, byte[] digest, ArcError? error)
    {
        if (!FileMutationJournal.IsRemoval(reader, command))
            return error is { Effect: EffectCertainty.DidNotHappen, Code: not "approval_required" };

        var required = error?.Effect == EffectCertainty.Unknown ? FileOperationState.Unknown : FileOperationState.Completed;
        return FileMutationJournal.RemovalOperation(reader, command, caller) is { } recorded && recorded.State == required &&
            CryptographicOperations.FixedTimeEquals(recorded.RequestSha256.Span, digest);
    }

    private static RemovalReplay? ParseRemovalOutcome(IMessage request, ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is < 1 or > ResultSigner.MaxPayloadBytes)
            return null;
        if (request is FileServicePlanRemovalRequest plan)
        {
            var response = FileServicePlanRemovalResponse.Parser.ParseFrom(bytes.Span);
            return RoutedFileResponseValidation.RemovalPlanOutcome(response, plan) ? new(response, response.Error, bytes) : null;
        }

        var executed = FileServiceExecuteRemovalResponse.Parser.ParseFrom(bytes.Span);
        return RoutedFileResponseValidation.RemovalExecutionOutcome(executed, (FileServiceExecuteRemovalRequest)request)
            ? new(executed, executed.Error, bytes) : null;
    }
}
