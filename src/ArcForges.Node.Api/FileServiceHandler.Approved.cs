// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    /// <summary>Replays only a settled, bound legacy approval result. An unfinished approval stays deferred.</summary>
    internal Task<byte[]?> ExecuteApprovedReferenceAsync(byte[] reference, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(caller);
        if (reference.Length != 17 || reference[0] != 1 || caller.ApprovalId is not { Length: 16 } approvalId ||
            caller.CenterCaller is null || caller.RemoteCommandId?.Value.Span.SequenceEqual(reference.AsSpan(1)) != true ||
            !caller.Approved || caller.Routed is not null || node.Stopping.IsCancellationRequested)
            return Task.FromResult<byte[]?>(null);

        try
        {
            return Task.FromResult(node.Store.Read<byte[]?>(reader =>
            {
                if (node.Stopping.IsCancellationRequested)
                    return null;
                var plan = PrivateStageApprovedPlans.Read(reader, approvalId);
                if (plan is null || !plan.Intent.CommandId.AsSpan().SequenceEqual(reference.AsSpan(1)) ||
                    !CenterRouting.SameFileCaller(plan.Intent.Caller, caller.CenterCaller))
                    return null;

                return FileMutationJournal.GetForCaller(reader, plan.Intent.CommandId, plan.Intent.Caller)
                    is { State: FileOperationState.Completed }
                    ? FileMutationJournal.ReplayApproved(reader, approvalId)
                    : null;
            }));
        }
        catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
        {
            node.Log.Error("api.file.approval.execution_deferred");
            return Task.FromResult<byte[]?>(null);
        }
    }
}
