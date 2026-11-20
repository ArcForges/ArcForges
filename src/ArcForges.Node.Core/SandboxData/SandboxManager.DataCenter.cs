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
    private const int RemoteDataRequestBytes = 1_052_672;

    private sealed record RemoteDataCall(VerifiedRemoteGrantCall Caller, IMessage Request, RemoteGrantAction Action)
    {
        internal StoredRemoteGrant? Grant { get; set; }
        internal DurableRemoteBinding? Binding { get; set; }
        internal bool EffectMayHaveHappened { get; set; }
    }

    internal DataServiceBeginImportResponse BeginDataImportFromCenter(DataServiceBeginImportRequest request,
        VerifiedRemoteGrantCall remote, CancellationToken token) => CallRemoteData(request, request.Meta, request.OwnerEpoch,
        remote, RemoteGrantAction.DataBeginImport, DataServiceBeginImportRequest.Parser, Shape.IsValid(request),
        call => BeginDataImport(request, call, token), error => new() { Meta = Response(request.Meta), Error = error }, token);

    internal DataServiceWriteImportResponse WriteDataImportFromCenter(DataServiceWriteImportRequest request,
        VerifiedRemoteGrantCall remote, CancellationToken token) => CallRemoteData(request, request.Meta, request.OwnerEpoch,
        remote, RemoteGrantAction.DataWriteImport, DataServiceWriteImportRequest.Parser, Shape.IsValid(request),
        call => WriteDataImport(request, call, token), error => new() { Meta = Response(request.Meta), Error = error }, token);

    internal DataServiceCommitImportResponse CommitDataImportFromCenter(DataServiceCommitImportRequest request,
        VerifiedRemoteGrantCall remote, CancellationToken token) => CallRemoteData(request, request.Meta, request.OwnerEpoch,
        remote, RemoteGrantAction.DataCommitImport, DataServiceCommitImportRequest.Parser, Shape.IsValid(request),
        call => CommitDataImport(request, call, token), error => new() { Meta = Response(request.Meta), Error = error }, token);

    internal DataServiceBeginExportResponse BeginDataExportFromCenter(DataServiceBeginExportRequest request,
        VerifiedRemoteGrantCall remote, CancellationToken token) => CallRemoteData(request, request.Meta, request.OwnerEpoch,
        remote, RemoteGrantAction.DataBeginExport, DataServiceBeginExportRequest.Parser, Shape.IsValid(request),
        call => BeginDataExport(request, call, token), error => new() { Meta = Response(request.Meta), Error = error }, token);

    internal DataServiceReadExportResponse ReadDataExportFromCenter(DataServiceReadExportRequest request,
        VerifiedRemoteGrantCall remote, CancellationToken token) => CallRemoteData(request, request.Meta, null,
        remote, RemoteGrantAction.DataReadExport, DataServiceReadExportRequest.Parser, Shape.IsValid(request),
        call => ReadDataExport(request, call, token), error => new() { Meta = Response(request.Meta), Error = error }, token);

    internal DataServiceInspectTransferResponse InspectDataTransferFromCenter(DataServiceInspectTransferRequest request,
        VerifiedRemoteGrantCall remote, CancellationToken token) => CallRemoteData(request, request.Meta, null,
        remote, RemoteGrantAction.DataInspectTransfer, DataServiceInspectTransferRequest.Parser, Shape.IsValid(request),
        call => InspectDataTransfer(request, call, token), error => new() { Meta = Response(request.Meta), Error = error }, token);

    internal DataServiceCloseTransferResponse CloseDataTransferFromCenter(DataServiceCloseTransferRequest request,
        VerifiedRemoteGrantCall remote, CancellationToken token) => CallRemoteData(request, request.Meta, request.OwnerEpoch,
        remote, RemoteGrantAction.DataCloseTransfer, DataServiceCloseTransferRequest.Parser, Shape.IsValid(request),
        call => CloseDataTransfer(request, call, token), error => new() { Meta = Response(request.Meta), Error = error }, token);

    private TResponse CallRemoteData<TRequest, TResponse>(TRequest request, RequestMeta? meta, Id? epoch,
        VerifiedRemoteGrantCall remote, RemoteGrantAction action, MessageParser<TRequest> parser, bool shape,
        Func<RemoteDataCall, TResponse> execute, Func<ArcError, TResponse> fail, CancellationToken cancellationToken)
        where TRequest : class, IMessage<TRequest>
    {
        ArgumentNullException.ThrowIfNull(remote);
        cancellationToken.ThrowIfCancellationRequested();
        bool mutation = action is not (RemoteGrantAction.DataReadExport or RemoteGrantAction.DataInspectTransfer);
        if (!shape || meta is not { ExpectedNative: null, WorkspaceId: null, ApplicationScope: null, HasRecoveryGeneration: false }
            || (mutation ? !ValidGrantId(meta.CommandId) || meta.ExpectedRev is not { Value: > 0 }
                    || !MatchesRemoteOwnerEpoch(remote, epoch) : meta.ExpectedRev is not null)
            || request.CalculateSize() > RemoteDataRequestBytes || !KnownRemoteFields(request, parser))
        {
            return fail(InvalidGrant(meta, "remote_data_shape_invalid"));
        }

        var call = new RemoteDataCall(remote, request, action);
        try
        {
            var response = execute(call);
            return call.Grant is null || RemoteDataCallCurrent(call) ? response : fail(call.EffectMayHaveHappened
                ? DataAuthorityLostAfterAdmission(meta)
                : GrantDenied(meta));
        }
        catch (Exception failure) when (IsStorageFailure(failure))
        {
            return fail(call.EffectMayHaveHappened ? Error(meta, ErrorCategory.Execution, "outcome_unknown",
                "data_admission_outcome_unavailable", EffectCertainty.Unknown) : StorageFailure(meta));
        }
    }

    private static ArcError DataAuthorityLostAfterAdmission(RequestMeta? meta) => Error(meta, ErrorCategory.Execution,
        "outcome_unknown", "remote_data_authority_unavailable_after_admission", EffectCertainty.Unknown);

    private static DurableAdmission TrackDataAdmission(RemoteDataCall? call, Func<DurableAdmission> admit)
    {
        if (call is null) return admit();

        // The reservation may have committed if returning its observation fails.
        call.EffectMayHaveHappened = true;
        var admission = admit();
        call.EffectMayHaveHappened = admission.Receipt is { Effect: (int)EffectCertainty.Happened or (int)EffectCertainty.Unknown };
        return admission;
    }

    // Called with OwnershipGate held. A transfer phase already owns its transfer stripe.
    private bool AuthorizeRemoteData(RemoteDataCall call, string sandboxId, StoredTransfer? transfer = null)
    {
        if (!CurrentRemoteOwnerEpoch(call.Caller)) return false;

        var now = ObserveGrantTime();
        var grant = _store.Read(reader => AuthorizedGrant(reader, call.Caller, call.Request, call.Action, call.Caller.GrantId,
            now, maximumRequestBytes: RemoteDataRequestBytes));
        if (grant is not { Scope: StoredRemoteGrantScope.Sandbox } || grant.SandboxId != sandboxId) return false;

        var binding = RemoteReceiptBinding(call.Caller, grant);
        if (transfer is not null && (!RemoteDataTransferMatches(transfer, call.Caller.OriginalOwnerEpoch.Span, binding)
            || !RemoteGrantPolicy.IsAllowed(GrantView(grant, now), DataBeginAction(transfer.Direction)))) return false;

        call.Grant = grant;
        call.Binding = binding;
        return true;
    }

    private bool RemoteDataCallCurrent(RemoteDataCall call)
    {
        lock (OwnershipGate)
        {
            return call.Grant is { } grant && CurrentRemoteOwnerEpoch(call.Caller)
                && RemoteSandboxAdmissionCurrent(call.Caller, grant, ObserveGrantTime());
        }
    }

    private void RequireRemoteDataCallCurrent(RemoteDataCall? call)
    {
        if (call is not null && !RemoteDataCallCurrent(call))
            throw new DataEffectException(ErrorCategory.Authorization, "permission_denied", "remote_grant_authority_unavailable");
    }

    private StoredTransfer? FindDataTransferForCall(Id id, RemoteDataCall? remote)
    {
        if (remote is null) return FindDataTransfer(id);

        lock (OwnershipGate)
        {
            var row = _store.Read(reader => TransferRecords.Get(reader, OwnerId, ToHex(id)));
            return row is not null && AuthorizeRemoteData(remote, row.SandboxId, row) ? row : null;
        }
    }

    private StoredTransfer? FindRemoteDataTransfer(string id, DurableRemoteBinding binding)
    {
        var row = _store.Read(reader => TransferRecords.Get(reader, OwnerId, id));
        return row is not null && RemoteDataTransferMatches(row, Receipts.OwnerEpoch.Span, binding) ? row : null;
    }

    private bool RemoteDataTransferMatches(StoredTransfer row, ReadOnlySpan<byte> ownerEpoch, DurableRemoteBinding binding) =>
        TransferRecords.MatchesRemote(row, ownerEpoch, binding)
        && Receipts.InspectRemote(row.OwnerEpoch, Convert.FromHexString(row.BeginCommandId), binding) is
        { AggregateKind: TransferRecords.Aggregate, AggregateId: { } id } begin
        && id == row.TransferId && begin.Method == (row.Direction == StoredTransferDirection.Import
            ? TransferRecords.BeginImportMethod : TransferRecords.BeginExportMethod);

    private bool RemoteDataReceiptVisible(DurableReceipt receipt, StoredRemoteGrant grant)
    {
        if (receipt is not { AggregateId: { } id, Remote: { } binding }) return false;

        var row = FindRemoteDataTransfer(id, binding);
        return row is not null && grant.SandboxId == row.SandboxId && grant.GrantId == binding.GrantId
            && grant.Revision == binding.GrantRevision
            && RemoteGrantPolicy.IsAllowed(GrantView(grant, _clock.GetUtcNow()), DataBeginAction(row.Direction));
    }

    private static RemoteGrantAction DataBeginAction(StoredTransferDirection direction) => direction == StoredTransferDirection.Import
        ? RemoteGrantAction.DataBeginImport : RemoteGrantAction.DataBeginExport;

    private void RequireDataWorkerGrant(StoredTransfer row, DurableRemoteBinding? binding)
    {
        if (binding is null) return;

        lock (OwnershipGate)
        {
            var now = ObserveGrantTime();
            if (RemoteDataTransferMatches(row, Receipts.OwnerEpoch.Span, binding) && _store.Read(reader =>
                RemoteGrantRecords.Get(reader, OwnerId, binding.GrantId) is { Scope: StoredRemoteGrantScope.Sandbox } grant
                && grant.Revision == binding.GrantRevision && grant.SandboxId == row.SandboxId
                && grant.EnrollmentId == binding.EnrollmentId && IsActiveGrant(grant, now)
                && MatchesDataWorkerEnrollment(ReadGrantBinding(grant), binding)
                && RemoteGrantPolicy.IsAllowed(GrantView(grant, now), DataBeginAction(row.Direction))
                && (grant.ParentGrantId is null || (grant.ParentGrantRevision is { } revision
                    && RemoteGrantRecords.IsActiveRevision(reader, OwnerId, grant.ParentGrantId, revision, now))))) return;

            throw new DataEffectException(ErrorCategory.Authorization, "permission_denied", "remote_grant_authority_unavailable");
        }
    }

    private bool MatchesDataWorkerEnrollment(ActiveRemoteEnrollment enrollment, DurableRemoteBinding binding) =>
        enrollment.OwnerId == OwnerId && enrollment.EnrollmentId == binding.EnrollmentId
        && enrollment.AccountId == binding.AccountId && enrollment.Epoch == binding.ProtocolEpoch
        && (_activeEnrollment is null || _activeEnrollment == enrollment);
}
