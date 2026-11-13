// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed class RemovalExecutionResponseUnavailableException : Exception { }

internal sealed partial class FileServiceHandler
{
    // Exercises the real FULL commit return boundary against exclusively test-owned metadata.
    internal Action? AfterRemovalExecutionCommitForTests { get; set; }
    // Coordinates a native replacement of a test-owned target after the metadata snapshot.
    internal Action? AfterRemovalExecutionCaptureForTests { get; set; }

    internal Task<FileServiceExecuteRemovalResponse> ExecuteRemovalAsync(Caller caller,
        FileServiceExecuteRemovalRequest request, CancellationToken cancellationToken) =>
        ExecuteCoordinatedRemovalAsync(caller, request, cancellationToken);

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

    private static void VerifyRemovalExecutionTarget(StoreReader reader, WorkspacePath root, byte[] id, string path)
    {
        using var command = reader.CreateCommand("""
            SELECT relative_path, entry_kind, native_platform, native_identity, stamp_size, stamp_mtime,
                   stamp_mtime_nsec, stamp_change, stamp_change_nsec, mode, link_count
            FROM file_removal_plan_item WHERE plan_id = $id AND ordinal = 0;
            """);
        command.Parameters.AddWithValue("$id", id);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetString(0) != path)
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
        var current = root.InspectEntry(path);
        var expectedKind = (WorkspaceEntryType)row.GetInt32(1);
        if (current.Kind != expectedKind || expectedKind is not (WorkspaceEntryType.File or WorkspaceEntryType.Directory))
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
        var expectedStamp = new WorkspaceFileStamp(row.GetInt64(4), row.GetInt64(5), checked((uint)row.GetInt64(6)),
            row.GetInt64(7), checked((uint)row.GetInt64(8)));
        // Compare observed changes before the encoder requires the planned single-link file shape.
        if (current.Stamp != expectedStamp || current.Identity.Mode != checked((uint)row.GetInt64(9)) ||
            current.Identity.Links != checked((uint)row.GetInt64(10)))
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
        var identity = RegisteredWorkspaces.RootIdentity.Encode(current.Identity, directory: expectedKind == WorkspaceEntryType.Directory);
        if (identity.Platform != row.GetInt32(2) ||
            !CryptographicOperations.FixedTimeEquals(identity.Bytes, (byte[])row.GetValue(3)))
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
    }

    private static void MatchRemovalExecutionSnapshot(StoreReader reader, byte[] id, RemovalExecutionPlan plan,
        WorkspaceRemovalSnapshot snapshot)
    {
        if (snapshot.RootIdentity.Platform != plan.RootPlatform ||
            !CryptographicOperations.FixedTimeEquals(snapshot.RootIdentity.Bytes, plan.RootIdentity) ||
            snapshot.TotalBytes != plan.TotalBytes || snapshot.Entries.Count != plan.Count)
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
        using var command = reader.CreateCommand("""
            SELECT ordinal, relative_path, entry_kind, fingerprint_sha256 FROM file_removal_plan_item
            WHERE plan_id = $id ORDER BY ordinal;
            """);
        command.Parameters.AddWithValue("$id", id);
        using var row = command.ExecuteReader();
        var index = 0;
        while (row.Read())
        {
            if (index >= snapshot.Entries.Count || row.GetInt32(0) != index ||
                row.GetString(1) != snapshot.Entries[index].Path || row.GetInt32(2) != (int)snapshot.Entries[index].Kind ||
                !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(3), snapshot.Entries[index].FingerprintSha256))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            index++;
        }
        if (index != snapshot.Entries.Count) throw new WorkspaceRemovalPlanException("planned_tree_changed");
    }

    private sealed record RemovalExecutionPlan(byte[] Digest, int State, long Expires, int TargetKind,
        byte[]? Workspace, string? Path, byte[]? Attempt, int RootPlatform, byte[] RootIdentity, ulong TotalBytes, int Count);
}
