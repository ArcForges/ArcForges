// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    private void CheckPlanAuthority(StoreReader reader, Caller caller)
    {
        if (caller.CenterCaller is not { } center || caller.Routed is null) throw new FilePolicyException("center_caller_incomplete");
        try
        {
            var policy = PolicyRules.Current(reader);
            if (!CryptographicOperations.FixedTimeEquals(policy.Digest, PolicyDocuments.Digest(policy.Document)) ||
                policy.Document.Permissions.Any(item => PermissionMatrix.Valid(item) is not null) ||
                policy.Document.CenterRouted is { HasRelayedFrom: true } route &&
                    route.RelayedFrom is not (RelayedFrom.Unspecified or RelayedFrom.OwnNode or RelayedFrom.Account))
                throw new FilePolicyException("policy_invalid");
            if (CenterRouting.Refusal(center, node.NodeId.Span, policy.Document.CenterRouted) is { } reason)
                throw new FilePolicyException(reason);
            if (PermissionMatrix.DecideRouted(PermissionMatrix.CleanupPlan, caller.CellsOrigin, policy.Document.Permissions).Decision != PermissionDecision.Allow)
                throw new FilePolicyException("denied");
            caller.Routed.BeforeEffect(reader);
        }
        catch (FilePolicyException) { throw; }
        catch (Exception exception) when (exception is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new FilePolicyException("policy_invalid");
        }
    }

    private static bool RemovalCallerMayUse(StoreReader reader, byte[] commandId, CenterCaller caller, bool retained)
    {
        if (!retained) return true;
        using var owner = reader.CreateCommand("SELECT caller FROM file_removal_command_owner WHERE command_id = $id;");
        owner.Parameters.AddWithValue("$id", commandId);
        try
        {
            return owner.ExecuteScalar() is byte[] encoded && CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom(encoded), caller);
        }
        catch (InvalidProtocolBufferException) { return false; }
    }

    private static ArcError RemovalLimit(Id correlation, string name, string maximum) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails
        {
            Limit = new LimitFailure
            {
                LimitName = name,
                Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = maximum },
            }
        },
    };
}
