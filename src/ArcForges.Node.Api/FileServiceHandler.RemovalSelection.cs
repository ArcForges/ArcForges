// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    private void CaptureRemovalForEffect(StoreTransaction tx, Caller caller, FileServiceExecuteRemovalRequest request,
        RemovalEffectLease lease, CancellationToken token)
    {
        var plan = lease.Plan!;
        if (plan.TargetKind == 1 && plan.Workspace is { } workspace && plan.Path is { } path)
        {
            lease.Use = _workspaces.OpenForUse(tx, workspace, selected => CheckRemovalPreflightAuthority(selected, caller), token);
            lease.Source = path;
        }
        else if (plan.TargetKind == 2 && plan.Attempt is { } attempt)
        {
            var (target, refusal) = ResolveAttemptPlanTarget(tx, caller, attempt, request.Meta.CorrelationId);
            if (refusal is not null || target is null) throw new WorkspaceRemovalPlanException("planned_tree_changed");
            if (AttemptHasDirectReferences(tx, target, attempt)) throw new WorkspaceRemovalPlanException("managed_file_in_use");
            lease.TemporaryRoot = OpenAttemptPlanRoot(target);
            lease.Source = target.Name;
            lease.AttemptRoot = lease.TemporaryRoot.OpenWindowsHeldChildRoot(target.Name);
            WorkspaceRemovalPlan.VerifyCheckedRoot(lease.AttemptRoot, target.Platform, target.DirectoryIdentity);
            var references = QualifyAttemptReferences(tx, lease.TemporaryRoot, lease.AttemptRoot, () => token.ThrowIfCancellationRequested());
            if (references == AttemptReferenceState.InUse) throw new WorkspaceRemovalPlanException("managed_file_in_use");
            if (references == AttemptReferenceState.Unknown) throw new WorkspaceRemovalPlanException("attempt_references_unverified");
        }
        else throw new WorkspaceRemovalPlanException("planned_tree_changed");
        if (tx.Scalar("SELECT 1 FROM file_private_stage_object WHERE native_identity IS NULL LIMIT 1;") is not null)
            throw new WorkspaceRemovalPlanException("file_access_denied");
        // Registered workspace uses already install protection and retain a lookup across writer transactions.
        if (plan.TargetKind == 2)
        {
            var protectedStages = PrivateStageRegistry.TryLoadIdentitiesForUse(tx);
            if (protectedStages is null) lease.Root.ProtectPrivateStageFiles(identity => node.Store.Read(reader => PrivateStageRegistry.ContainsIdentity(reader, identity)));
            else lease.Root.ProtectPrivateStageFiles(protectedStages);
        }
        if (plan.TargetKind == 1) VerifyRemovalExecutionTarget(tx, lease.Root, request.PlanId.Value.ToByteArray(), lease.Source);
        WorkspaceRemovalSnapshot snapshot;
        try
        {
            snapshot = lease.Snapshot = CaptureSelectedRemoval(lease, token);
            AfterRemovalExecutionCaptureForTests?.Invoke();
            MatchRemovalExecutionSnapshot(tx, request.PlanId.Value.ToByteArray(), plan, snapshot);
            RecheckRemovalOwnership(tx, caller, request, lease.Root, snapshot, token);
        }
        finally
        {
            if (plan.TargetKind == 1) VerifyRemovalExecutionTarget(tx, lease.Root, request.PlanId.Value.ToByteArray(), lease.Source);
        }
        if (tx.Scalar("SELECT 1 FROM file_operation_journal WHERE held = 1 LIMIT 1;") is not null)
            throw new WorkspaceRemovalPlanException("managed_file_in_use");
        lease.Target = lease.Root.InspectEntry(lease.Source).Identity;
        var actual = RegisteredWorkspaces.RootIdentity.Encode(lease.Target, directory: lease.Target.IsDirectory);
        if (actual.Platform != snapshot.Entries[0].NativeIdentity.Platform ||
            !CryptographicOperations.FixedTimeEquals(actual.Bytes, snapshot.Entries[0].NativeIdentity.Bytes))
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
    }

    private static WorkspaceRemovalSnapshot CaptureSelectedRemoval(RemovalEffectLease lease, CancellationToken token)
    {
        var snapshot = WorkspaceRemovalPlan.Capture(lease.Root, lease.Source, token);
        if (lease.Plan!.TargetKind == 2)
            snapshot = snapshot with
            {
                Entries = snapshot.Entries.Select(entry => entry with
                { Path = AttemptRelativePath(lease.Source, entry.Path) }).ToArray()
            };
        return snapshot;
    }

    private static void RecheckRemovalOwnership(StoreReader tx, Caller caller, FileServiceExecuteRemovalRequest request,
        WorkspacePath root, WorkspaceRemovalSnapshot snapshot, CancellationToken token)
    {
        if (snapshot.Entries.Count == 0) throw new WorkspaceRemovalPlanException("planned_tree_changed");
        using var select = tx.CreateCommand("SELECT relative_path, owner_verified FROM file_removal_plan_item WHERE plan_id = $id ORDER BY ordinal;");
        select.Parameters.AddWithValue("$id", request.PlanId.Value.ToByteArray());
        using var rows = select.ExecuteReader();
        var index = 0;
        while (rows.Read())
        {
            token.ThrowIfCancellationRequested();
            if (index >= snapshot.Entries.Count || snapshot.Entries[index].Path != rows.GetString(0))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            // Attempt-root ownership was re-derived from actual task/temp provenance above.
            if (caller.CenterCaller is null) throw new WorkspaceRemovalPlanException("planned_tree_changed");
            if (rows.GetInt32(1) != 0 && snapshot.Entries[index].Path.Length != 0 &&
                tx.Scalar("SELECT target_kind FROM file_removal_plan WHERE plan_id = $id;", ("$id", request.PlanId.Value.ToByteArray())) is long kind && kind == 1 &&
                !FileCreationOwnership.IsVerifiedAgent(tx, caller.CenterCaller,
                    (byte[])tx.Scalar("SELECT workspace_id FROM file_removal_plan WHERE plan_id = $id;", ("$id", request.PlanId.Value.ToByteArray()))!,
                    root, snapshot.Entries[index], token,
                    preparedRemoval: tx is StoreTransaction && FileMutationJournal.IsRemoval(tx, request.Meta.CommandId.Value.Span)
                        ? request.Meta.CommandId.Value.ToByteArray() : null))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            index++;
        }
        if (index != snapshot.Entries.Count) throw new WorkspaceRemovalPlanException("planned_tree_changed");
    }

    private string? RemovalQuarantineRoot(StoreReader reader, WorkspaceObjectIdentity source)
    {
        var staging = reader.Scalar("SELECT path FROM root_location WHERE root_class = 'staging';") as string;
        var dataPath = staging ?? node.DataRoot;
        using (var data = WorkspacePath.OpenRoot(dataPath))
        {
            if (data.RootIdentity.Volume == source.Volume)
                return staging ?? Path.Combine(node.DataRoot, "staging");
        }
        var policy = PolicyRules.Current(reader).Document;
        foreach (var configured in policy.Storage.QuarantineRoots.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            using var candidate = WorkspacePath.OpenRoot(configured.Value);
            if (candidate.RootIdentity.Volume == source.Volume) return configured.Value;
        }
        return null;
    }

    private bool RemovalQuarantineAvailable(StoreReader reader, WorkspaceObjectIdentity source) => RemovalQuarantineRoot(reader, source) is not null;

    private void PrepareRemovalDestination(StoreTransaction tx, FileServiceExecuteRemovalRequest request, RemovalEffectLease lease)
    {
        var selected = RemovalQuarantineRoot(tx, lease.Target) ?? throw new WorkspaceRemovalPlanException("strict_cleanup_guard_unavailable");
        // The default managed staging root is created through its existing checked data-root parent.
        WorkspacePath baseRoot;
        if (selected == Path.Combine(node.DataRoot, "staging"))
        {
            using var data = WorkspacePath.OpenRoot(node.DataRoot);
            baseRoot = data.EnsureRemovalDirectory("staging");
        }
        else baseRoot = WorkspacePath.OpenRoot(selected);
        using (baseRoot)
        {
            var staging = tx.Scalar("SELECT path FROM root_location WHERE root_class = 'staging';") as string
                ?? Path.Combine(node.DataRoot, "staging");
            if (selected == staging)
            {
                using var quarantine = baseRoot.EnsureRemovalDirectory("quarantine");
                lease.Destination = quarantine.EnsureRemovalDirectory(Convert.ToHexStringLower(request.PlanId.Value.Span));
            }
            else lease.Destination = baseRoot.EnsureRemovalDirectory(Convert.ToHexStringLower(request.PlanId.Value.Span));
        }
        lease.Item = (byte[])tx.Scalar("SELECT item_id FROM file_removal_plan_item WHERE plan_id = $plan AND ordinal = 0;",
            ("$plan", request.PlanId.Value.ToByteArray()))!;
        lease.DestinationName = Convert.ToHexStringLower(lease.Item);
        lease.DestinationPath = Path.Combine(lease.Destination.RootPath, lease.DestinationName);
        if (lease.Destination.RootIdentity.Volume != lease.Target.Volume) throw new WorkspaceRemovalPlanException("strict_cleanup_guard_unavailable");
        if (!lease.Destination.InspectRemovalAbsent(lease.DestinationName)) throw new WorkspaceRemovalPlanException("planned_tree_changed");
    }

    private static List<KeyValue> DescribeRemovalApproval(StoreReader tx, FileServiceExecuteRemovalRequest request, Id correlation,
        RemovalEffectLease lease)
    {
        var details = new List<KeyValue>
        {
            new() { Name = "plan_id", Value = Convert.ToHexStringLower(request.PlanId.Value.Span) },
            new() { Name = "plan_digest", Value = Convert.ToHexStringLower(request.PlanDigest.Span) },
            new() { Name = "correlation_id", Value = Convert.ToHexStringLower(correlation.Value.Span) },
            new() { Name = "delete_without_quarantine", Value = request.DeleteWithoutQuarantine ? "true" : "false" },
        };
        // The exact plan/digest remains the authority; preserve every selected path/size/risk in bounded display chunks.
        var description = new StringBuilder();
        foreach (var item in lease.Snapshot!.Entries)
            description.Append(item.Path.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(item.Path)
                .Append(' ').Append(item.Size.ToString(CultureInfo.InvariantCulture)).Append(" bytes; requires plan approval\n");
        var value = description.ToString();
        for (var index = 0; index < value.Length;)
        {
            var count = Math.Min(480, value.Length - index);
            if (index + count < value.Length && char.IsHighSurrogate(value[index + count - 1])) count--;
            details.Add(new KeyValue { Name = "plan_items_" + details.Count.ToString("D2", CultureInfo.InvariantCulture), Value = value.Substring(index, count) });
            index += count;
        }
        if (details.Count > 32) throw new WorkspaceRemovalPlanException("strict_cleanup_guard_unavailable");
        return details;
    }

    internal async Task<byte[]?> ExecuteApprovedRemovalReferenceAsync(byte[] reference, Caller caller)
    {
        if (reference.Length != 17 || reference[0] != 2 || !caller.Approved || caller.Routed is not null ||
            caller.ApprovalId is null || caller.CenterCaller is null || caller.RemoteCommandId?.Value.Span.SequenceEqual(reference.AsSpan(1)) != true)
            return null;
        var binding = node.Store.Read<(FileServiceExecuteRemovalRequest Request, byte[] Digest)?>(reader =>
        {
            var approval = Approvals.Get(reader, caller.ApprovalId);
            if (approval is null || approval.State != ApprovalState.Approved || approval.View.Operation != "FileService.ExecuteRemoval" ||
                !approval.Request.AsSpan().SequenceEqual(reference) || !CenterRouting.SameFileCaller(approval.View.Requester.CenterCaller, caller.CenterCaller))
                return null;
            using var sql = reader.CreateCommand("SELECT plan_id, digest FROM cleanup_plan WHERE approval_id = $approval;");
            sql.Parameters.AddWithValue("$approval", caller.ApprovalId);
            using var row = sql.ExecuteReader();
            if (!row.Read()) return null;
            var correlation = approval.View.Details.Single(item => item.Name == "correlation_id").Value;
            var request = new FileServiceExecuteRemovalRequest
            {
                Meta = new RequestMeta
                {
                    CommandId = caller.RemoteCommandId.Clone(),
                    CorrelationId = new Id { Value = ByteString.CopyFrom(Convert.FromHexString(correlation)) }
                },
                PlanId = new Id { Value = ByteString.CopyFrom((byte[])row.GetValue(0)) },
                PlanDigest = ByteString.CopyFrom((byte[])row.GetValue(1)),
                DeleteWithoutQuarantine = approval.View.Details.Single(item => item.Name == "delete_without_quarantine").Value == "true",
            };
            return (Request: request, Digest: approval.RequestDigest);
        });
        if (binding is null) return null;
        try
        {
            var response = await ExecuteCoordinatedRemovalAsync(caller, binding.Value.Request, node.Stopping, binding.Value.Digest).ConfigureAwait(false);
            return response.ToByteArray();
        }
        catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
        {
            node.Log.Error("api.file.removal.approval_deferred");
            return null;
        }
    }
}
