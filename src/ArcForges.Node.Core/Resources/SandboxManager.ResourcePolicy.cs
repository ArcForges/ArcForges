// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Shape = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const string SetResourcePolicyMethod = "ResourceService.SetPolicy";

    internal ResourceServiceSetPolicyResponse SetResourcePolicy(ResourceServiceSetPolicyRequest request,
        CancellationToken cancellationToken) => SetResourcePolicy(request, null, cancellationToken);

    internal ResourceServiceSetPolicyResponse SetResourcePolicyFromCenter(ResourceServiceSetPolicyRequest request,
        VerifiedRemoteGrantCall verified, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        return SetResourcePolicy(request, verified, cancellationToken);
    }

    private ResourceServiceSetPolicyResponse SetResourcePolicy(ResourceServiceSetPolicyRequest request,
        VerifiedRemoteGrantCall? remote, CancellationToken cancellationToken)
    {
        var meta = request.Meta;
        string scope = request.ScopeKind;
        if (meta is not { ExpectedNative: null, ExpectedRev.Value: > 0 and < long.MaxValue }
            || !ValidGrantId(meta.CommandId) || !ValidGrantId(request.OwnerEpoch)
            || scope is not ("node" or "sandbox" or "run")
            || (scope == "node" ? request.ScopeId is not null : !ValidGrantId(request.ScopeId))
            || !ValidResourceEdit(scope, request.Policy)
            || remote is not null && (!Shape.IsValid(request) || !MatchesRemoteOwnerEpoch(remote, request.OwnerEpoch)
                || !KnownRemoteFields(request, ResourceServiceSetPolicyRequest.Parser)))
        {
            return ResourceEditError(meta, Error(meta, ErrorCategory.Validation, "invalid_argument", "resource_policy_invalid"));
        }

        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return SetResourcePolicyLocked(request, remote, cancellationToken);
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return ResourceEditError(meta, StorageFailure(meta));
            }
        }
    }

    private ResourceServiceSetPolicyResponse SetResourcePolicyLocked(ResourceServiceSetPolicyRequest request,
        VerifiedRemoteGrantCall? remote, CancellationToken cancellationToken)
    {
        var meta = request.Meta;
        string scope = request.ScopeKind;
        string? id = request.ScopeId is null ? null : ToHex(request.ScopeId);
        long expected = meta.ExpectedRev.Value;
        byte[] commandId = meta.CommandId.Value.ToByteArray();
        var grantTime = remote is null ? default : ObserveGrantTime();
        var grant = remote is not null && id is not null
            ? AuthorizeRemoteTarget(remote, request, RemoteGrantAction.ResourceSetPolicy, scope, id, grantTime) : null;
        var remoteCeiling = grant is null ? null : GrantView(grant, grantTime).ResourceCeiling;
        if (remote is not null && (grant is null || remoteCeiling is null))
        {
            return ResourceEditError(meta, GrantDenied(meta));
        }

        var canonical = new ResourceServiceSetPolicyRequest
        {
            ScopeKind = scope,
            ScopeId = request.ScopeId,
            Policy = request.Policy,
            Meta = new() { ExpectedRev = meta.ExpectedRev },
        };
        var bodyBytes = canonical.ToByteArray();
        var intent = new DurableIntent(commandId, request.OwnerEpoch.Value.ToByteArray(), SetResourcePolicyMethod,
            scope, id ?? OwnerId, remote is null ? bodyBytes : RemoteSandboxIntent(bodyBytes, remote),
            Remote: remote is null ? null : RemoteReceiptBinding(remote, grant!));
        var prior = EpochMatches(request.OwnerEpoch) ? Receipts.Inspect(commandId) : null;
        if (!EpochMatches(request.OwnerEpoch) || prior is not null)
        {
            if (remote is not null && prior is not null && !CanReplayRemoteMutation(prior, intent.Remote, grant!, grantTime))
            {
                return ResourceEditError(meta, GrantDenied(meta));
            }

            return ResourceEditAdmission(Receipts.Admit(intent), request);
        }

        if (remoteCeiling is not null && !RemoteResourceCapsWithin(request.Policy, remoteCeiling))
        {
            return ResourceEditError(meta, GrantDenied(meta));
        }

        var frame = _resourceMonitor?.Latest;
        var view = GetResourceBudgetLocked(new() { Meta = meta, ScopeKind = scope, ScopeId = request.ScopeId }, frame);
        if (view.Error is { } viewError)
        {
            return ResourceEditError(meta, viewError);
        }

        var previous = ReadResourcePolicy(scope, id);
        long current = previous?.Revision ?? 1;
        if (current != expected)
        {
            return ResourceEditError(meta, RevisionError(meta, expected, current));
        }

        var policy = request.Policy;
        var snapshot = view.Value.Snapshot;
        var desired = new StoredResourcePolicy(scope, id, checked(current + 1), JsonFormatter.Default.Format(policy));
        if (scope == "run")
        {
            return ApplyRunResourceEdit(request, intent, previous, desired, snapshot, frame, remote, grant, cancellationToken);
        }

        if (CheckResourcePolicyCeiling(scope, id, policy, meta, frame) is { } refused)
        {
            return ResourceEditError(meta, refused);
        }

        if (scope == "node")
        {
            snapshot = NodeResourceSnapshot(frame, policy);
        }
        else
        {
            var sandbox = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, id!));
            if (sandbox is null)
            {
                return ResourceEditError(meta, NotFound(meta));
            }

            if (remoteCeiling is not null)
            {
                // Transient host capacity must not authorize a broader persisted policy.
                var unbounded = PolicyHardGrant(null, defaultRuns: ulong.MaxValue);
                var proposed = SandboxHardGrant(sandbox, policy, unbounded);
                var currentCeiling = SandboxHardGrant(sandbox, DecodeResourcePolicy(previous), unbounded);
                var delegatedCeiling = PolicyHardGrant(remoteCeiling, defaultRuns: ulong.MaxValue);
                if (proposed.Exceeded(currentCeiling.Limit(delegatedCeiling)) is not null)
                {
                    return ResourceEditError(meta, GrantDenied(meta));
                }
            }

            ApplySandboxGrantCeiling(snapshot, sandbox, policy, frame);
        }

        snapshot.PolicyRevision = new() { Value = desired.Revision };
        string body = ResourceEditResult(snapshot, _clock.GetUtcNow());
        cancellationToken.ThrowIfCancellationRequested();
        if (remote is not null)
        {
            grantTime = ObserveGrantTime();
            if (!RemoteSandboxAdmissionCurrent(remote, grant!, grantTime))
            {
                return ResourceEditError(meta, GrantDenied(meta));
            }
        }

        return ResourceEditAdmission(Receipts.AdmitObserved(intent, "SUCCEEDED", (int)EffectCertainty.Happened, body,
            transaction =>
            {
                RequireChanged(ResourceStateRecords.TryWritePolicy(transaction, OwnerId, desired, previous?.Revision));
                if (remote is not null)
                {
                    RecordRemoteAdmission(transaction, meta, SetResourcePolicyMethod, id!, desired.Revision, remote,
                        EffectCertainty.Happened, "sandbox_resource_policy_committed", grantTime);
                }
            }), request);
    }

    private ResourceServiceSetPolicyResponse ApplyRunResourceEdit(ResourceServiceSetPolicyRequest request, DurableIntent intent,
        StoredResourcePolicy? previous, StoredResourcePolicy desired, ResourceSnapshot snapshot, SandboxResourceFrame? frame,
        VerifiedRemoteGrantCall? remote, StoredRemoteGrant? grant, CancellationToken cancellationToken)
    {
        var meta = request.Meta;
        string runId = desired.ScopeId!;
        var (row, limits) = _store.Read(reader => (RunRecords.Get(reader, OwnerId, runId),
            ResourceStateRecords.ReadLimits(reader, OwnerId, runId)));
        if (row is null)
        {
            return ResourceEditError(meta, NotFound(meta));
        }

        if (row.State != StoredRunState.Running || !_liveRuns.TryGetValue(runId, out var live)
            || live.Epoch != row.Epoch || live.OwnerLease is not IRunResourceControl control
            || live.OwnerLease.Identity.ControlEpoch != row.Epoch)
        {
            return ResourceEditError(meta, Error(meta, ErrorCategory.State, "busy", "run_resource_scope_not_live"));
        }

        string boundary = live.OwnerLease.Identity.BoundaryIdentity;
        if (ReadOwnedResourceLimits(control, boundary) is not { } initial)
        {
            return ResourceEditError(meta, Error(meta, ErrorCategory.State, "busy", "run_resource_scope_unconfirmed"));
        }

        var policy = request.Policy;
        var oldPolicy = DecodeResourcePolicy(previous);
        var launch = ReadRunSnapshot(row);
        var admittedPolicy = policy.Clone();
        var changes = new List<RunLimitEdit>(2);
        if (policy.HasCpuMaxMillicores || oldPolicy?.HasCpuMaxMillicores == true)
        {
            admittedPolicy.CpuMaxMillicores = policy.HasCpuMaxMillicores ? policy.CpuMaxMillicores : launch.CpuMillicores;
            AddRunLimitEdit(changes, limits, initial, control, RunResourceDimension.Cpu, "cpu", admittedPolicy.CpuMaxMillicores);
        }

        if (policy.HasMemoryMaxBytes || oldPolicy?.HasMemoryMaxBytes == true)
        {
            admittedPolicy.MemoryMaxBytes = policy.HasMemoryMaxBytes ? policy.MemoryMaxBytes : launch.MemoryMaxBytes;
            AddRunLimitEdit(changes, limits, initial, control, RunResourceDimension.Memory, "memory", admittedPolicy.MemoryMaxBytes);
        }

        var grantTime = remote is null ? default : ObserveGrantTime();
        if (grant is not null)
        {
            var ceiling = GrantView(grant, grantTime).ResourceCeiling;
            var currentCeiling = new HardGrant(
                oldPolicy?.HasCpuMaxMillicores == true ? oldPolicy.CpuMaxMillicores : launch.CpuCeilingMillicores,
                oldPolicy?.HasMemoryMaxBytes == true ? oldPolicy.MemoryMaxBytes : launch.MemoryMaxBytes,
                ulong.MaxValue);
            if (ceiling is null)
            {
                return ResourceEditError(meta, GrantDenied(meta));
            }

            var delegated = currentCeiling.Limit(PolicyHardGrant(ceiling, defaultRuns: ulong.MaxValue));
            if (changes.Any(change =>
                {
                    var allowed = delegated.Amount(change.Name);
                    return change.Requested > allowed || change.Target > allowed;
                }))
            {
                return ResourceEditError(meta, GrantDenied(meta));
            }
        }

        if (changes.Any(change => change.Previous is null || change.Previous.BoundaryIdentity != boundary
            || change.Previous.Status == StoredRunLimitStatus.Pending))
        {
            return ResourceEditError(meta, Error(meta, ErrorCategory.State, "busy", "run_limit_evidence_unavailable"));
        }

        if (CheckResourcePolicyCeiling("run", runId, admittedPolicy, meta, frame) is { } refused)
        {
            return ResourceEditError(meta, refused);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (remote is not null)
        {
            grantTime = ObserveGrantTime();
            if (!RemoteSandboxAdmissionCurrent(remote, grant!, grantTime))
            {
                return ResourceEditError(meta, GrantDenied(meta));
            }
        }

        var admission = Receipts.Admit(intent, transaction =>
        {
            RequireChanged(ResourceStateRecords.TryWritePolicy(transaction, OwnerId, desired, previous?.Revision));
            foreach (var change in changes)
            {
                var prior = change.Previous!;
                RequireChanged(ResourceStateRecords.TrySetLimitDesired(transaction, OwnerId, runId, row.Epoch,
                    boundary, prior.DesiredRevision, new(prior.Dimension, prior.Unit, desired.Revision, LimitText(change.Requested))));
            }

            if (remote is not null)
            {
                RecordRemoteAdmission(transaction, meta, SetResourcePolicyMethod, runId, desired.Revision, remote,
                    EffectCertainty.Unknown, "run_resource_policy_admitted", grantTime);
            }
        });
        if (admission.Decision != DurableDecision.Execute)
        {
            return ResourceEditAdmission(admission, request);
        }

        // After admission the local RPC deadline cannot leave an accepted mutation halfway through its settlement.
        var observations = ApplyRunLimitEdits(control, boundary, changes);
        snapshot.PolicyRevision = new() { Value = desired.Revision };
        for (int index = 0; index < snapshot.Limits.Count; index++)
        {
            string dimension = snapshot.Limits[index].Dimension;
            if (observations.TryGetValue(dimension, out var result))
            {
                var prior = limits.Single(limit => limit.Dimension == dimension);
                snapshot.Limits[index] = ProjectStoredRunLimit(ProjectResourceObservation(prior, desired.Revision, result));
            }
        }

        bool uncertain = observations.Values.Any(result => result.Uncertain);
        string state = uncertain ? "UNKNOWN" : "SUCCEEDED";
        var effect = uncertain ? EffectCertainty.Unknown : EffectCertainty.Happened;
        string retained = ResourceEditResult(snapshot, _clock.GetUtcNow(), uncertain ? "native_limit_outcome_unconfirmed" : null);
        var receipt = Receipts.SetResult(intent.CommandId, state, (int)effect, retained, transaction =>
        {
            foreach (var (dimension, result) in observations)
            {
                RequireChanged(ResourceStateRecords.TryObserveLimit(transaction, OwnerId, runId, row.Epoch,
                    boundary, dimension, desired.Revision, result.Facts));
            }

            if (remote is not null)
            {
                RecordRemoteAdmission(transaction, meta, SetResourcePolicyMethod, runId, desired.Revision, remote, effect,
                    uncertain ? "run_resource_policy_unconfirmed" : "run_resource_policy_observed", _clock.GetUtcNow());
            }
        });
        return ResourceEditReceipt(receipt, request);
    }

    private static void AddRunLimitEdit(List<RunLimitEdit> edits, IReadOnlyList<StoredRunLimit> limits,
        RunResourceLimitReading initial, IRunResourceControl control, RunResourceDimension dimension, string name, ulong requested)
    {
        var previous = limits.FirstOrDefault(limit => limit.Dimension == name);
        edits.Add(new(dimension, name, requested, control.NormalizeRunLimit(dimension, requested), initial.Value(dimension), previous));
    }

    private Dictionary<string, RunLimitEditResult> ApplyRunLimitEdits(IRunResourceControl control, string boundary,
        List<RunLimitEdit> changes)
    {
        var results = new Dictionary<string, RunLimitEditResult>(changes.Count, StringComparer.Ordinal);
        bool unconfirmedReduction = false;
        // Confirm reductions before any escalation of the original native budget.
        foreach (var change in changes.OrderBy(change => change.Increase)
            .ThenBy(change => change.Dimension != RunResourceDimension.Memory))
        {
            var result = change.Increase && unconfirmedReduction
                ? new RunLimitEditResult(change.Requested, new(StoredRunLimitStatus.Failed, "increase_blocked_by_unconfirmed_reduction"))
                : ApplyRunLimitEdit(control, boundary, change);
            results.Add(change.Name, result);
            unconfirmedReduction |= !change.Increase && result.Facts.Status != StoredRunLimitStatus.Effective;
        }

        return results;
    }

    private RunLimitEditResult ApplyRunLimitEdit(IRunResourceControl control, string boundary, RunLimitEdit change)
    {
        if (change.Target is not ulong expected)
        {
            return new(change.Requested, new(StoredRunLimitStatus.Unsupported, "native_limit_unsupported"));
        }

        var before = ReadOwnedResourceLimits(control, boundary)?.Value(change.Dimension);
        if (before is not ulong current)
        {
            return new(change.Requested, new(StoredRunLimitStatus.Failed, "native_scope_readback_unavailable"));
        }

        if (!change.Increase && expected > current)
        {
            return new(change.Requested, new(StoredRunLimitStatus.Failed, "native_limit_changed_before_apply",
                ReadbackValue: LimitText(current), ReadbackAt: _clock.GetUtcNow()));
        }

        RunResourceWriteResult write;
        try
        {
            write = control.ApplyRunLimit(change.Dimension, change.Requested);
        }
        catch (Exception failure) when (IsNativeResourceFailure(failure))
        {
            write = new(RunResourceWriteStatus.Failed);
        }

        var appliedAt = _clock.GetUtcNow();
        ulong? actual = ReadOwnedResourceLimits(control, boundary)?.Value(change.Dimension);
        var readAt = _clock.GetUtcNow();
        string? readValue = actual is ulong value ? LimitText(value) : null;
        if (write.Status == RunResourceWriteStatus.Applied)
        {
            string? applied = write.AppliedValue is ulong accepted ? LimitText(accepted) : null;
            bool effective = actual == expected && write.AppliedValue == expected;
            string reason = effective ? "native_limit_verified" : actual is null
                ? "native_scope_readback_unavailable" : "native_limit_readback_mismatch";
            return new(change.Requested,
                new(effective ? StoredRunLimitStatus.Effective : StoredRunLimitStatus.Degraded, reason,
                    applied, readValue, applied is null ? null : appliedAt, readValue is null ? null : readAt), !effective);
        }

        // A refused setter and an unchanged readback establish that the existing limit is still enforced.
        bool unchanged = actual == current;
        var status = unchanged && write.Status == RunResourceWriteStatus.Unsupported ? StoredRunLimitStatus.Unsupported
            : unchanged ? StoredRunLimitStatus.Failed : StoredRunLimitStatus.Degraded;
        string refusal = NativeResourceRefusal(write.Reason) ?? (!unchanged ? "native_limit_outcome_unconfirmed"
            : status == StoredRunLimitStatus.Unsupported ? "native_limit_unsupported" : "native_limit_setter_failed");
        return new(change.Requested, new(status, refusal, ReadbackValue: readValue,
            ReadbackAt: readValue is null ? null : readAt), !unchanged);
    }

    private static string? NativeResourceRefusal(string? reason)
    {
        if (reason is "windows_commit_reduction_unverified" or "windows_run_limit_dimension_unsupported"
            or "windows_run_limit_unrepresentable" or "windows_run_resource_scope_lost"
            or "windows_run_resource_owner_not_running" or "windows_cpu_topology_changed" or "windows_run_job_limits_unverified"
            or "linux_live_memory_reduction_unsafe" or "linux_memory_limit_read_unavailable" or "linux_limit_unavailable"
            or "linux_control_write_failed" or "linux_resource_scope_lost" or "linux_resource_scope_not_released")
        {
            return reason;
        }

        int prefixLength = reason switch
        {
            not null when reason.StartsWith("win32:", StringComparison.Ordinal) => "win32:".Length,
            not null when reason.StartsWith("linux_errno_", StringComparison.Ordinal) => "linux_errno_".Length,
            _ => 0,
        };
        return prefixLength > 0
            && int.TryParse(reason.AsSpan(prefixLength), NumberStyles.None, CultureInfo.InvariantCulture, out _)
            ? reason : null;
    }

    private static RunResourceLimitReading? ReadOwnedResourceLimits(IRunResourceControl control, string boundary)
    {
        try
        {
            var reading = control.ReadRunLimits();
            return reading?.BoundaryIdentity == boundary ? reading : null;
        }
        catch (Exception failure) when (IsNativeResourceFailure(failure))
        {
            return null;
        }
    }

    private static bool IsNativeResourceFailure(Exception failure) =>
        failure is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception;

    private static StoredRunLimit ProjectResourceObservation(StoredRunLimit previous, long revision, RunLimitEditResult result) =>
        previous with
        {
            DesiredRevision = revision,
            DesiredValue = LimitText(result.Requested),
            AppliedValue = result.Facts.AppliedValue ?? previous.AppliedValue,
            AppliedAt = result.Facts.AppliedAt ?? previous.AppliedAt,
            ReadbackValue = result.Facts.ReadbackValue ?? previous.ReadbackValue,
            ReadbackAt = result.Facts.ReadbackAt ?? previous.ReadbackAt,
            Status = result.Facts.Status,
            Reason = result.Facts.Reason,
        };

    private static LimitState ProjectStoredRunLimit(StoredRunLimit limit)
    {
        var view = new LimitState
        {
            Dimension = limit.Dimension,
            Unit = limit.Unit,
            DesiredRevision = new() { Value = limit.DesiredRevision },
            DesiredValue = limit.DesiredValue,
            Status = (LimitStatus)limit.Status,
            Reason = limit.Reason,
        };
        if (limit.BoundaryIdentity is { } boundary) view.Scope = Hash(boundary);
        if (limit.AppliedValue is { } applied) view.AppliedValue = applied;
        if (limit.ReadbackValue is { } readback) view.ReadbackValue = readback;
        if (limit.AppliedAt is { } appliedAt) view.AppliedAt = ProtoTime.ToInstant(appliedAt);
        if (limit.ReadbackAt is { } readbackAt) view.ReadbackAt = ProtoTime.ToInstant(readbackAt);
        return view;
    }

    private StoredResourcePolicy? ReadResourcePolicy(string scopeKind, string? scopeId) =>
        _store.Read(reader => ResourceStateRecords.GetPolicy(reader, OwnerId, scopeKind, scopeId));

    private static ResourcePolicy? DecodeResourcePolicy(StoredResourcePolicy? policy) => policy is null
        ? null : JsonParser.Default.Parse<ResourcePolicy>(policy.PolicyJson);

    private long ResourcePolicyRevision(string scopeKind, string? scopeId) => ReadResourcePolicy(scopeKind, scopeId)?.Revision ?? 1;

    private static bool ValidResourceEdit(string scope, ResourcePolicy? policy) => policy is not null
        && policy.PressureAction == PressureAction.Throttle
        && !policy.HasWeight && !policy.HasPriority && !policy.HasPreemptible && !policy.HasExpectedMemoryBytes
        && (!policy.HasCpuMaxMillicores || policy.CpuMaxMillicores > 0)
        && (!policy.HasMemoryMaxBytes || policy.MemoryMaxBytes > 0)
        && (!policy.HasMaxConcurrentRuns || scope != "run" && policy.MaxConcurrentRuns is > 0 and <= 1024)
        && (scope == "node" || !policy.HasHostReserveBytes && !policy.HasHostReserveMillicores);

    private static string ResourceEditResult(ResourceSnapshot snapshot, DateTimeOffset settled, string? reason = null) =>
        new JsonObject
        {
            ["revision"] = snapshot.PolicyRevision.Value,
            ["snapshot"] = Convert.ToBase64String(snapshot.ToByteArray()),
            ["updatedAt"] = settled.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
            ["reason"] = reason,
        }.ToJsonString();

    private ResourceServiceSetPolicyResponse ResourceEditAdmission(DurableAdmission admitted, ResourceServiceSetPolicyRequest request)
    {
        if (admitted is { Decision: DurableDecision.Replay, Receipt.ResponseJson: not null }
            or { Decision: DurableDecision.InProgress, Receipt: { State: "UNKNOWN", ResponseJson: not null } })
        {
            return ResourceEditReceipt(admitted.Receipt, request);
        }

        return ResourceEditError(request.Meta, Resolve(admitted, request.Meta).Error ?? StorageFailure(request.Meta));
    }

    private static ResourceServiceSetPolicyResponse ResourceEditReceipt(DurableReceipt receipt, ResourceServiceSetPolicyRequest request)
    {
        using var body = JsonDocument.Parse(receipt.ResponseJson ?? throw new InvalidDataException("The resource receipt has no result."));
        var json = body.RootElement;
        if (receipt.State == "UNKNOWN")
        {
            return ResourceEditError(request.Meta, Error(request.Meta, ErrorCategory.Execution, "outcome_unknown",
                GetString(json, "reason") ?? "original_operation_unresolved", EffectCertainty.Unknown));
        }

        if (receipt.State != "SUCCEEDED" || receipt.Effect != (int)EffectCertainty.Happened)
        {
            throw new InvalidDataException("The resource receipt has an invalid outcome.");
        }

        if (!json.TryGetProperty("snapshot", out var bytes) || !json.TryGetProperty("updatedAt", out var storedTime))
        {
            throw new InvalidDataException("The settled resource receipt has an invalid response.");
        }

        var snapshot = ResourceSnapshot.Parser.ParseFrom(bytes.GetBytesFromBase64());
        var operation = new Operation
        {
            CommandId = request.Meta.CommandId.Clone(),
            OwnerEpoch = request.OwnerEpoch.Clone(),
            Method = SetResourcePolicyMethod,
            AggregateId = request.ScopeId?.Clone(),
            Revision = snapshot.PolicyRevision.Clone(),
            State = OperationState.Succeeded,
            Effect = EffectCertainty.Happened,
            UpdatedAt = ProtoTime.ToInstant(DateTimeOffset.Parse(storedTime.GetString()!, CultureInfo.InvariantCulture)),
        };

        return new() { Meta = Response(request.Meta, operation.Revision.Value), Value = new() { Snapshot = snapshot, Operation = operation } };
    }

    private static ResourceServiceSetPolicyResponse ResourceEditError(RequestMeta? meta, ArcError error) =>
        new() { Meta = Response(meta), Error = error };

    private sealed record RunLimitEdit(RunResourceDimension Dimension, string Name, ulong Requested, ulong? Target,
        ulong? Original, StoredRunLimit? Previous)
    {
        internal bool Increase => Target is ulong target && Original is ulong current && target > current;
    }

    private sealed record RunLimitEditResult(ulong Requested, StoredRunLimitObservation Facts, bool Uncertain = false);
}
