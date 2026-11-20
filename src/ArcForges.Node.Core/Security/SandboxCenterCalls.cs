// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Shape = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    internal SandboxServiceListResponse ListFromCenter(SandboxServiceListRequest request, VerifiedRemoteGrantCall verified,
        CancellationToken cancellationToken) => ReadFromCenter(request, request.Meta, verified, RemoteGrantAction.SandboxList,
        SandboxServiceListRequest.Parser, Shape.IsValid(request),
        (grant, _) =>
        {
            if (grant.SandboxId is not { } id || !CoversRemoteTarget(grant, "sandbox", id))
            {
                return new() { Meta = Response(request.Meta), Error = GrantDenied(request.Meta) };
            }

            if (request.Cursor.Length != 0)
            {
                return new() { Meta = Response(request.Meta), Error = GrantCursorError(request.Meta) };
            }

            var sandbox = _store.Read(reader =>
            {
                var row = SandboxRecords.Get(reader, OwnerId, id);
                if (row is null || row.State == StoredSandboxState.Deleted)
                {
                    return null;
                }

                var value = RedactRemoteSandbox(View(row));
                value.ActiveRunIds.AddRange(SandboxRecords.ListNonterminalRunIds(reader, id).Select(FromHex));
                return value;
            });
            var page = new SandboxServiceListValue { Page = new() { NextCursor = "" } };
            if (sandbox is not null)
            {
                page.Sandboxes.Add(sandbox);
            }

            return new() { Meta = Response(request.Meta), Value = page };
        }, error => new SandboxServiceListResponse { Meta = Response(request.Meta), Error = error }, cancellationToken);

    internal SandboxServiceInspectResponse InspectFromCenter(SandboxServiceInspectRequest request, VerifiedRemoteGrantCall verified,
        CancellationToken cancellationToken) => ReadFromCenter(request, request.Meta, verified, RemoteGrantAction.SandboxInspect,
        SandboxServiceInspectRequest.Parser, Shape.IsValid(request) && ValidGrantId(request.SandboxId),
        (grant, _) =>
        {
            if (!CoversRemoteTarget(grant, "sandbox", ToHex(request.SandboxId)))
            {
                return new() { Meta = Response(request.Meta), Error = GrantDenied(request.Meta) };
            }

            var response = Inspect(request, cancellationToken);
            if (response.Value?.Sandbox is { } sandbox)
            {
                RedactRemoteSandbox(sandbox);
            }

            return response;
        }, error => new SandboxServiceInspectResponse { Meta = Response(request.Meta), Error = error }, cancellationToken);

    internal RunServiceListResponse ListRunsFromCenter(RunServiceListRequest request, VerifiedRemoteGrantCall verified,
        CancellationToken cancellationToken) => ReadFromCenter(request, request.Meta, verified, RemoteGrantAction.RunList,
        RunServiceListRequest.Parser, Shape.IsValid(request) && ValidGrantId(request.SandboxId),
        (grant, _) => CoversRemoteTarget(grant, "sandbox", ToHex(request.SandboxId)) ? ListRuns(request, cancellationToken)
            : new() { Meta = Response(request.Meta), Error = GrantDenied(request.Meta) },
        error => new RunServiceListResponse { Meta = Response(request.Meta), Error = error }, cancellationToken);

    internal RunServiceInspectResponse InspectRunFromCenter(RunServiceInspectRequest request, VerifiedRemoteGrantCall verified,
        CancellationToken cancellationToken) => ReadFromCenter(request, request.Meta, verified, RemoteGrantAction.RunInspect,
        RunServiceInspectRequest.Parser, Shape.IsValid(request) && ValidGrantId(request.RunId),
        (grant, _) => CoversRemoteTarget(grant, "run", ToHex(request.RunId)) ? InspectRun(request, cancellationToken)
            : new() { Meta = Response(request.Meta), Error = GrantDenied(request.Meta) },
        error => new RunServiceInspectResponse { Meta = Response(request.Meta), Error = error }, cancellationToken);

    internal ResourceServiceGetBudgetResponse GetResourceBudgetFromCenter(ResourceServiceGetBudgetRequest request,
        VerifiedRemoteGrantCall verified, CancellationToken cancellationToken) => ReadFromCenter(request, request.Meta, verified,
        RemoteGrantAction.ResourceGetBudget, ResourceServiceGetBudgetRequest.Parser, Shape.IsValid(request),
        (grant, _) => ValidGrantId(request.ScopeId) && CoversRemoteTarget(grant, request.ScopeKind, ToHex(request.ScopeId))
            ? GetResourceBudgetLocked(request, _resourceMonitor?.Latest)
            : new() { Meta = Response(request.Meta), Error = GrantDenied(request.Meta) },
        error => new ResourceServiceGetBudgetResponse { Meta = Response(request.Meta), Error = error }, cancellationToken);

    internal NodeServiceGetOperationResponse GetOperationFromCenter(NodeServiceGetOperationRequest request,
        VerifiedRemoteGrantCall verified, CancellationToken cancellationToken) => ReadFromCenter(request, request.Meta, verified,
        RemoteGrantAction.GetOperation, NodeServiceGetOperationRequest.Parser,
        Shape.IsValid(request) && MatchesRemoteOwnerEpoch(verified, request.OwnerEpoch) && ValidGrantId(request.CommandId),
        (grant, now) =>
        {
            var retained = Receipts.InspectRemote(request.OwnerEpoch.Value.Span, request.CommandId.Value.Span,
                RemoteReceiptBinding(verified, grant));
            if (retained is null || !RemoteReceiptVisible(retained, grant, now))
            {
                return new() { Meta = Response(request.Meta), Error = NotFound(request.Meta) };
            }

            return GetOperation(request, cancellationToken);
        }, error => new NodeServiceGetOperationResponse { Meta = Response(request.Meta), Error = error }, cancellationToken);

    private TResponse ReadFromCenter<TRequest, TResponse>(TRequest request, RequestMeta? meta, VerifiedRemoteGrantCall remote,
        RemoteGrantAction action, MessageParser<TRequest> parser, bool valid,
        Func<StoredRemoteGrant, DateTimeOffset, TResponse> read, Func<ArcError, TResponse> refused,
        CancellationToken cancellationToken)
        where TRequest : class, IMessage<TRequest>
    {
        ArgumentNullException.ThrowIfNull(remote);
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!valid || !KnownRemoteFields(request, parser))
            {
                return refused(InvalidGrant(meta, "remote_read_shape_invalid"));
            }

            try
            {
                var now = ObserveGrantTime();
                var grant = _store.Read(reader => AuthorizedGrant(reader, remote, request, action, remote.GrantId, now));
                if (grant is null)
                {
                    return refused(GrantDenied(meta));
                }

                return CurrentRemoteOwnerEpoch(remote) ? read(grant, now) : refused(RetiredRunEpoch(meta));
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return refused(StorageFailure(meta));
            }
        }
    }

    private StoredRemoteGrant? AuthorizeRemoteTarget(VerifiedRemoteGrantCall remote, IMessage request, RemoteGrantAction action,
        string scope, string id, DateTimeOffset now)
    {
        var grant = _store.Read(reader => AuthorizedGrant(reader, remote, request, action, remote.GrantId, now));
        return grant is not null && CoversRemoteTarget(grant, scope, id) ? grant : null;
    }

    private bool CoversRemoteTarget(StoredRemoteGrant grant, string scope, string id)
    {
        if (grant.Scope != StoredRemoteGrantScope.Sandbox || grant.SandboxId is not { } sandbox)
        {
            return false;
        }

        return scope switch
        {
            "sandbox" => id == sandbox,
            "run" => _store.Read(reader => RunRecords.Get(reader, OwnerId, id))?.SandboxId == sandbox,
            _ => false,
        };
    }

    private bool RemoteReceiptVisible(DurableReceipt receipt, StoredRemoteGrant grant, DateTimeOffset now)
    {
        if (receipt.AggregateId is not { } id)
        {
            return false;
        }

        return receipt.AggregateKind switch
        {
            "sandbox" when grant.Scope == StoredRemoteGrantScope.Provision => CanReplayRemoteSandbox(receipt, grant, now),
            "sandbox" => CoversRemoteTarget(grant, "sandbox", id),
            // A budget refusal can retain a Start receipt without creating a Run row.
            "run" when receipt.Method == StartRunMethod && receipt.State == "FAILED"
                && receipt.Effect == (int)EffectCertainty.DidNotHappen =>
                grant.SandboxId is { } sandbox && receipt.Remote?.SandboxId == sandbox,
            "run" => CoversRemoteTarget(grant, "run", id),
            "grant" => grant.GrantId == id,
            _ => false,
        };
    }

    private bool CanReplayRemoteMutation(DurableReceipt receipt, DurableRemoteBinding? binding, StoredRemoteGrant grant,
        DateTimeOffset now) => receipt.Remote == binding && RemoteGrantPolicy.IsAllowed(GrantView(grant, now), RemoteGrantAction.GetOperation)
            && RemoteReceiptVisible(receipt, grant, now);

    private static bool RemoteResourceCapsWithin(ResourcePolicy policy, ResourcePolicy ceiling) =>
        !policy.HasHostReserveBytes && !policy.HasHostReserveMillicores
        && (!policy.HasCpuMaxMillicores || !ceiling.HasCpuMaxMillicores || policy.CpuMaxMillicores <= ceiling.CpuMaxMillicores)
        && (!policy.HasMemoryMaxBytes || !ceiling.HasMemoryMaxBytes || policy.MemoryMaxBytes <= ceiling.MemoryMaxBytes)
        && (!policy.HasMaxConcurrentRuns || !ceiling.HasMaxConcurrentRuns || policy.MaxConcurrentRuns <= ceiling.MaxConcurrentRuns);

    private static bool RemoteResourceRequestWithin(ResourcePolicy? policy, ResourcePolicy ceiling) => policy is null
        || (RemoteResourceCapsWithin(policy, ceiling)
            && (!policy.HasWeight || ceiling.HasWeight && policy.Weight == ceiling.Weight)
            && (!policy.HasPriority || ceiling.HasPriority && policy.Priority == ceiling.Priority)
            && (!policy.HasExpectedMemoryBytes || ceiling.HasExpectedMemoryBytes && policy.ExpectedMemoryBytes == ceiling.ExpectedMemoryBytes)
            && (!policy.HasPressureAction || ceiling.HasPressureAction && policy.PressureAction == ceiling.PressureAction)
            && (!policy.HasPreemptible || policy.Preemptible == ceiling.Preemptible));

    private void RecordRemoteAdmission(StoreTransaction transaction, RequestMeta meta, string method, string aggregateId,
        long revision, VerifiedRemoteGrantCall remote, EffectCertainty effect, string reason, DateTimeOffset now) =>
        _ = RemoteGrantRecords.AppendAudit(transaction, OwnerId, remote.ActorId, "remote", ToHex(meta.CommandId), method, aggregateId,
            remote.Enrollment.EnrollmentId, ValidGrantId(meta.CorrelationId) ? ToHex(meta.CorrelationId) : ToHex(meta.CommandId),
            revision, (int)effect, reason, now);
}
