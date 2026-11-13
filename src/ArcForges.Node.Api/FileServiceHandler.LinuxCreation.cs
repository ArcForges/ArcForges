// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    private byte[]? ApplyLinuxCreation(StoreTransaction transaction, Caller caller, MutationRequest request, byte[] raw,
        MutationLease lease, LinuxFileCreationBinding binding, long started, TimeSpan limit, CancellationToken token)
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("The Linux worker is unavailable.");
        var worker = lease.Worker ?? throw new InvalidOperationException("The owned worker is unavailable.");
        var root = lease.Use?.Root ?? throw new InvalidOperationException("The workspace is unavailable.");
        var source = lease.Stages?.Intended ?? throw new InvalidOperationException("The intended stage is unavailable.");
        var selection = lease.CreationSelection ?? throw new InvalidOperationException("The original parent chain is unavailable.");
        try
        {
            void BeforeEffect()
            {
                BeforeMutationEffectForTests?.Invoke();
                if (Expired(started, limit, token)) throw new OperationCanceledException(token);
                CheckWriteCandidateAuthority(transaction, caller);
                if (Expired(started, limit, token)) throw new OperationCanceledException(token);
            }
            BeforeEffect();
            var result = worker.ExecuteCreation(binding, root, request.Path!.Path, selection, source, BeforeEffect,
                BeforeCreateForTests, AfterCreateForTests, token);
            lease.Created = result.Target;
            if (!FileEffectWorker.MarkEndedIfObserved(transaction, request.Meta!.CommandId.Value.Span))
                return FileMutationJournal.MarkUnknown(transaction, request.Meta.CommandId.Value.Span);
            BeforeEffect();
            lease.Created.Guard.CheckIntact();
            var completed = FileMutationJournal.CompleteVerifiedEffect(transaction, request.Meta.CommandId.Value.Span,
                raw, result.Content.Size, result.Content.Sha256, null, result.Ownership);
            AfterCreationSettlementForTests?.Invoke();
            lease.Created.Guard.CheckIntact();
            return completed;
        }
        catch (WorkspaceCreateCollisionException collision)
        {
            if (!worker.PossibleEffect && worker.WaitForActualExit(2000) &&
                FileEffectWorker.MarkEndedIfObserved(transaction, request.Meta!.CommandId.Value.Span))
                return FileMutationJournal.CompleteKnownExpectedAbsentConflict(transaction, request.Meta.CommandId.Value.Span,
                    caller.CenterCaller!, raw, collision);
            return FileMutationJournal.MarkUnknown(transaction, request.Meta!.CommandId.Value.Span);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            worker.Stop();
            if (!worker.PossibleEffect && worker.WaitForActualExit(2000) &&
                FileEffectWorker.MarkEndedIfObserved(transaction, request.Meta!.CommandId.Value.Span))
            {
                if (exception is RoutedAbortException or OperationCanceledException) throw;
                if (exception is FilePolicyException)
                    return FileMutationJournal.CompleteKnownAuthorityRefusal(transaction, request.Kind,
                        request.Meta.CommandId.Value.Span, caller.CenterCaller!, raw, approvalUnavailable: false);
                if (exception is FileApprovalNotImplementedException)
                    return FileMutationJournal.CompleteKnownAuthorityRefusal(transaction, request.Kind,
                        request.Meta.CommandId.Value.Span, caller.CenterCaller!, raw, approvalUnavailable: true);
                return FileMutationJournal.CompleteKnownGuardUnavailable(transaction, request.Kind,
                    request.Meta.CommandId.Value.Span, caller.CenterCaller!, raw);
            }
            var uncertain = FileMutationJournal.MarkUnknown(transaction, request.Meta!.CommandId.Value.Span);
            return exception is RoutedAbortException or OperationCanceledException ? null : uncertain;
        }
    }
}
