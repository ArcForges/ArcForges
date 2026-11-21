// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    private static MutationPreparation? PreviousFileApproval(StoreTransaction transaction, Caller caller, MutationRequest request,
        byte[] raw, Id correlation)
    {
        var id = request.Meta!.CommandId.Value.Span;
        var previous = Approvals.ByCommand(transaction, id);
        if (previous is null) return null;
        caller.Routed!.BeforeEffect(transaction);
        var method = request.Kind == FileOperationKind.Write ? "FileService.WriteFile" : "FileService.EditFile";
        if (previous.View.Operation != method || previous.Request.Length != 17 || previous.Request[0] != 1 ||
            !previous.Request.AsSpan(1).SequenceEqual(id) || previous.RequestDigest.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(previous.RequestDigest, SHA256.HashData(raw)) ||
            !CenterRouting.SameFileCaller(previous.View.Requester?.CenterCaller, caller.CenterCaller))
            return FileApprovalRefusal(request, Error(ErrorCategory.Conflict, "command_id_reused", "command_id_reused", correlation));
        if (previous.State == ApprovalState.Pending)
        {
            var sample = RoutedFileValidationTime.Advance(transaction);
            if (!sample.Healthy) return new MutationPreparation();
            var expiry = transaction.Scalar("SELECT expires_at FROM approval WHERE approval_id = $id;", ("$id", previous.Id));
            if (expiry is not long until || until <= sample.BoundaryMicroseconds)
                return FileApprovalRefusal(request, Error(ErrorCategory.State, "invalid_state", "approval_expired", correlation));
            return PendingFileApproval(request, previous, correlation);
        }
        if (previous.State == ApprovalState.Approved) return new MutationPreparation();
        if (previous.State is ApprovalState.Denied or ApprovalState.Cancelled)
            return FileApprovalRefusal(request, Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileWrite, correlation), "denied");
        if (previous.State == ApprovalState.Expired)
            return FileApprovalRefusal(request, Error(ErrorCategory.State, "invalid_state", "approval_expired", correlation));
        // A terminal approval without a journal receipt is not sufficient evidence of the file result.
        return new MutationPreparation();
    }

    private static MutationPreparation PendingFileApproval(MutationRequest request, StoredApproval approval, Id correlation)
    {
        var error = RoutedRefusals.ApprovalRequired(PermissionMatrix.FileWrite, approval.View.ApprovalId, correlation);
        return FileApprovalRefusal(request, error, "approval_required");
    }

    private static MutationPreparation FileApprovalRefusal(MutationRequest request, ArcError error, string? policyReason = null)
    {
        var meta = new ResponseMeta { CorrelationId = error.CorrelationId.Clone() };
        if (request.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("The file approval refusal is invalid.");
            return new MutationPreparation(response.ToByteArray(), policyReason);
        }
        var edit = new FileServiceEditFileResponse { Meta = meta, Error = error };
        if (!NodeShapes.IsValid(edit)) throw new InvalidDataException("The file approval refusal is invalid.");
        return new MutationPreparation(edit.ToByteArray(), policyReason);
    }
}
