// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Store;

/// <summary>Content-free authority at first admission. The associated receipt retains the original owner epoch.</summary>
internal sealed record DurableRemoteBinding(string AccountId, string ActorId, string EnrollmentId, string ProtocolEpoch,
    string GrantId, long GrantRevision, string ScopeKind, string? SandboxId);

internal sealed partial class DurableCommandStore
{
    private const string StartRunMethod = "RunService.Start";
    private const string StopRunMethod = "RunService.Stop";

    /// <summary>Reads only the exact original association. The caller authorizes the current remote read separately.</summary>
    internal DurableReceipt? InspectRemote(ReadOnlySpan<byte> originalOwnerEpoch, ReadOnlySpan<byte> commandId,
        DurableRemoteBinding originalBinding)
    {
        StoreIds.Validate(originalOwnerEpoch, nameof(originalOwnerEpoch));
        StoreIds.Validate(commandId, nameof(commandId));
        ValidateRemoteBinding(originalBinding);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired || !originalOwnerEpoch.SequenceEqual(_fence.Epoch)) return null;
            string id = StoreIds.ToHex(commandId);
            var receipt = _store.Read(reader => ReadReceipt(reader, id));
            return receipt?.Remote == originalBinding ? receipt : null;
        }
    }

    private bool CanAdmitRemote(StoreReader reader, DurableIntent intent, DurableRemoteBinding binding, DateTimeOffset now)
    {
        if (RemoteGrantRecords.Get(reader, _owner, binding.GrantId) is not { State: StoredRemoteGrantState.Active } grant
            || grant.Revision != binding.GrantRevision || grant.EnrollmentId != binding.EnrollmentId
            || grant.SandboxId != binding.SandboxId || (grant.Scope == StoredRemoteGrantScope.Sandbox) != (binding.ScopeKind == "sandbox")
            || grant.ExpiresAt is { } expiration && expiration <= now
            || grant.ParentGrantId is { } parent && (grant.ParentGrantRevision is not { } revision
                || !RemoteGrantRecords.IsActiveRevision(reader, _owner, parent, revision, now)))
            return false;

        if (intent.AggregateKind == "run" && intent.Method != StartRunMethod
            && RunRecords.Get(reader, _owner, intent.AggregateId!)?.SandboxId != binding.SandboxId)
            return false;
        return intent.Method != StopRunMethod || intent.SafetyParent is null || Equals(reader.Scalar("""
            SELECT method FROM command_receipt WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$parent;
            """, ("$owner", _owner), ("$epoch", _fence.Epoch), ("$parent", StoreIds.ToHex(intent.SafetyParent))), StartRunMethod);
    }

    private void RecordRemoteBinding(StoreTransaction transaction, string commandId, DurableRemoteBinding binding)
    {
        transaction.Execute("""
            INSERT INTO remote_command_binding(owner_id,owner_epoch,command_id,account_id,actor_id,enrollment_id,
                protocol_epoch,grant_id,grant_revision,scope_kind,sandbox_id)
            VALUES($owner,$epoch,$id,$account,$actor,$enrollment,$protocol,$grant,$revision,$scope,$sandbox);
            """, ("$owner", _owner), ("$epoch", _fence.Epoch), ("$id", commandId), ("$account", binding.AccountId),
            ("$actor", binding.ActorId), ("$enrollment", binding.EnrollmentId), ("$protocol", binding.ProtocolEpoch),
            ("$grant", binding.GrantId), ("$revision", binding.GrantRevision), ("$scope", binding.ScopeKind), ("$sandbox", binding.SandboxId));
    }

    private static void WriteRemoteBinding(BinaryWriter writer, DurableRemoteBinding binding)
    {
        writer.Write("remote_command_binding_v1");
        writer.Write(binding.AccountId);
        writer.Write(binding.ActorId);
        writer.Write(binding.EnrollmentId);
        writer.Write(binding.ProtocolEpoch);
        writer.Write(binding.GrantId);
        writer.Write(binding.GrantRevision);
        writer.Write(binding.ScopeKind);
        writer.Write(binding.SandboxId ?? "");
    }

    private static void ValidateRemoteBinding(DurableRemoteBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (!IsRemoteIdentity(binding.AccountId) || !IsRemoteIdentity(binding.ActorId) || !IsRemoteIdentity(binding.EnrollmentId)
            || !IsRemoteIdentity(binding.ProtocolEpoch) || !IsRemoteIdentity(binding.GrantId) || binding.GrantRevision <= 0
            || binding.ScopeKind is not ("sandbox" or "provision")
            || (binding.ScopeKind == "sandbox" ? !IsRemoteIdentity(binding.SandboxId) : binding.SandboxId is not null))
            throw new ArgumentException("A durable remote binding requires exact authenticated identities and scope.", nameof(binding));
    }

    private static void ValidateRemoteIntent(DurableIntent intent, DurableRemoteBinding binding)
    {
        ValidateRemoteBinding(binding);
        bool valid = intent.Method switch
        {
            RevokeGrantMethod => intent.AggregateKind == GrantAggregate && intent.AggregateId == binding.GrantId
                && intent.Grant is { Action: DurableGrantAction.Revoke } revoke && revoke.ExpectedRevision == binding.GrantRevision,
            _ when intent.Grant is not null => false,
            SandboxCreateMethod when binding.ScopeKind == "provision" =>
                intent is { AggregateKind: "sandbox", AdditionalSafetyReservations: 1 }
                && (intent.Provision is null || intent.Provision.ParentGrantId == binding.GrantId
                    && intent.Provision.ParentGrantRevision == binding.GrantRevision),
            _ when binding.ScopeKind != "sandbox" => false,
            StartRunMethod => intent.AggregateKind == "run" && intent.ExpectedSandboxId == binding.SandboxId,
            StopRunMethod => intent.AggregateKind == "run",
            ResourcePolicyMethod when intent.AggregateKind == "run" => intent.SafetyParent is null,
            _ => intent.AggregateKind == "sandbox" && intent.AggregateId == binding.SandboxId,
        };
        if (!valid || !IsRemoteIdentity(intent.AggregateId)
            || !intent.CommandId.AsSpan().ContainsAnyExcept((byte)0) || !intent.OwnerEpoch.AsSpan().ContainsAnyExcept((byte)0))
            throw new ArgumentException("A durable remote intent requires the exact authorized target.", nameof(intent));
    }

    private static bool IsRemoteIdentity(string? id) => IsGrantIdentity(id) && id.AsSpan().ContainsAnyExcept('0');
}
