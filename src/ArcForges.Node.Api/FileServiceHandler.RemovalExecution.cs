// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    private void CheckRemovalPreflightAuthority(StoreReader reader, Caller caller)
    {
        if (caller.CenterCaller is not { } center || caller.Routed is null && !caller.Approved) throw new FilePolicyException("center_caller_incomplete");
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
            if (PermissionMatrix.DecideRouted(PermissionMatrix.FileRemove, caller.CellsOrigin, policy.Document.Permissions).Decision == PermissionDecision.Deny ||
                PermissionMatrix.DecideRouted(PermissionMatrix.CleanupExecute, caller.CellsOrigin, policy.Document.Permissions).Decision == PermissionDecision.Deny)
                throw new FilePolicyException("denied");
            caller.Routed?.BeforeEffect(reader);
        }
        catch (FilePolicyException) { throw; }
        catch (Exception exception) when (exception is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new FilePolicyException("policy_invalid");
        }
    }

    private static RemovalExecutionPlan? ReadRemovalExecutionPlan(StoreReader reader, byte[] id, CenterCaller caller)
    {
        using var command = reader.CreateCommand("""
            SELECT p.caller, c.digest, c.state, c.expires_at, p.target_kind, p.workspace_id, p.workspace_path,
                   p.attempt_id, p.root_platform, p.root_identity, c.total_bytes, c.item_count
            FROM file_removal_plan p JOIN cleanup_plan c ON c.plan_id = p.plan_id WHERE p.plan_id = $id;
            """);
        command.Parameters.AddWithValue("$id", id);
        using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        try
        {
            if (!CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom((byte[])row.GetValue(0)), caller)) return null;
        }
        catch (InvalidProtocolBufferException) { return null; }
        return new RemovalExecutionPlan((byte[])row.GetValue(1), row.GetInt32(2), row.GetInt64(3), row.GetInt32(4),
            row.IsDBNull(5) ? null : (byte[])row.GetValue(5), row.IsDBNull(6) ? null : row.GetString(6),
            row.IsDBNull(7) ? null : (byte[])row.GetValue(7), row.GetInt32(8), (byte[])row.GetValue(9),
            checked((ulong)row.GetInt64(10)), row.GetInt32(11));
    }

    private sealed record RemovalExecutionPlan(byte[] Digest, int State, long Expires, int TargetKind,
        byte[]? Workspace, string? Path, byte[]? Attempt, int RootPlatform, byte[] RootIdentity, ulong TotalBytes, int Count);
}
