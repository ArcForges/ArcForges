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
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using WireDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    // Legacy WriteFile and EditFile admit only the reconciliation of prior commands.
    private readonly FileStageBudget _writeStageBudget = node.FileStages;

    // Test-only callbacks coordinate a real competing create and an interruption after the actual creation effect.
    internal Action? BeforeCreateForTests { get; set; }
    internal Action? AfterCreateForTests { get; set; }
    // A test can force a real SQLite rollback after the native create and tentative settlement.
    internal Action? AfterCreationSettlementForTests { get; set; }
    internal Action? BeforeMutationEffectForTests { get; set; }
    internal Action? AfterStageBeforeJournalForTests { get; set; }
    internal Func<Task>? AfterPreparationForTests { get; set; }

    internal Task<byte[]?> WriteExistingCandidateAsync(Caller caller, CancellationToken cancellationToken)
    {
        var raw = caller.RawRequest ?? throw new InvalidOperationException("The exact transmitted request is required.");
        var request = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
        var admission = WriteAdmission(request);
        return MutateExistingCandidateAsync(caller, raw, new MutationRequest(FileOperationKind.Write, request.Meta, request.Path,
            admission.Valid, admission.Limit, request.HasExpectedSha256, request.ExpectedSha256, request.Data, null, null, 0), cancellationToken);
    }

    internal Task<byte[]?> EditExistingCandidateAsync(Caller caller, CancellationToken cancellationToken)
    {
        var raw = caller.RawRequest ?? throw new InvalidOperationException("The exact transmitted request is required.");
        var request = FileServiceEditFileRequest.Parser.ParseFrom(raw);
        var admission = EditAdmission(request);
        return MutateExistingCandidateAsync(caller, raw, new MutationRequest(FileOperationKind.Edit, request.Meta, request.Path,
            admission.Valid, admission.Limit, request.HasExpectedSha256, request.ExpectedSha256, ByteString.Empty,
            request.OldText, request.NewText, request.ExpectedOccurrences), cancellationToken);
    }

    // The published shape validator includes resource maxima. Validate all other rules against a bounded clone while
    // measuring the original values; otherwise a valid oversized value would be mislabeled invalid_argument.
    private static (bool Valid, string? Limit) WriteAdmission(FileServiceWriteFileRequest original)
    {
        try
        {
            var bounded = original.Clone();
            var pathLimit = NormalizeOversizedPath(bounded.Path);
            var writeLimit = bounded.HasData && bounded.Data.Length > 196_608;
            if (writeLimit) bounded.Data = ByteString.Empty;
            return (NodeShapes.IsValid(bounded), pathLimit ? "path_bytes" : writeLimit ? "file_write_bytes" : null);
        }
        catch (Exception exception) when (exception is System.Text.EncoderFallbackException or WorkspacePathException)
        {
            return (false, null);
        }
    }

    private static (bool Valid, string? Limit) EditAdmission(FileServiceEditFileRequest original)
    {
        try
        {
            var bounded = original.Clone();
            var pathLimit = NormalizeOversizedPath(bounded.Path);
            var oldLimit = bounded.HasOldText && StrictUtf8.GetByteCount(bounded.OldText) > 65_536;
            var newLimit = bounded.HasNewText && StrictUtf8.GetByteCount(bounded.NewText) > 65_536;
            if (oldLimit) bounded.OldText = "x";
            if (newLimit) bounded.NewText = string.Empty;
            return (NodeShapes.IsValid(bounded), pathLimit ? "path_bytes" : oldLimit || newLimit ? "file_edit_text_bytes" : null);
        }
        catch (Exception exception) when (exception is System.Text.EncoderFallbackException or WorkspacePathException)
        {
            return (false, null);
        }
    }

    private static bool NormalizeOversizedPath(FilePath? path)
    {
        if (path is not { HasPath: true } || StrictUtf8.GetByteCount(path.Path) <= 4096) return false;
        // Do not erase traversal, platform-reserved names or other path errors when classifying an oversized path.
        _ = WorkspacePath.ComponentsIgnoringSize(path.Path);
        path.Path = "x";
        return true;
    }

    private async Task<byte[]?> MutateExistingCandidateAsync(Caller caller, byte[] raw, MutationRequest request, CancellationToken cancellationToken)
    {
        var routed = caller.Routed ?? throw new InvalidOperationException("A file mutation requires a verified routed caller.");
        // Sample the native clock before computing the remaining call budget. A pause here cannot extend the worker deadline.
        var nativeStarted = OperatingSystem.IsLinux() ? LinuxFatalDeadline.MonotonicNanoseconds() : System.Diagnostics.Stopwatch.GetTimestamp();
        var limit = routed.RemainingFileOperation();
        if (limit <= TimeSpan.Zero) throw new OperationCanceledException(cancellationToken);
        var started = node.Clock.GetTimestamp();
        var producerDeadline = OperatingSystem.IsLinux()
            ? checked(nativeStarted + limit.Ticks * 100)
            : checked(nativeStarted + limit.Ticks * System.Diagnostics.Stopwatch.Frequency / TimeSpan.TicksPerSecond);
        var linuxDeadline = OperatingSystem.IsLinux() ? producerDeadline : 0;
        using var deadline = new CancellationTokenSource(limit, node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, node.Stopping, routed.Link.EffectEnding);
        var token = linked.Token;
        var lease = new MutationLease();
        Task<MutationPreparation>? preparation = null;
        var ownsLease = true;
        try
        {
            preparation = node.Processor.ExecuteAsync(command => PrepareMutation(command.Transaction, caller, request, raw, started, limit, token),
                CommitDurability.Full);
            MutationPreparation prepared;
            try
            {
                prepared = await preparation.WaitAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                ownsLease = false;
                _ = ObserveMutationAndDisposeAsync(preparation, lease);
                throw;
            }

            if (prepared.PolicyReason is { } reason)
            {
                routed.Refused(PermissionMatrix.FileWrite, reason);
                routed.MarkAudited();
            }

            if (prepared.NeedsApproval)
            {
                // Dispose an earlier anonymous attempt before making a separately durable named approval stage.
                lease.Dispose();
                ownsLease = false;
                var pendingApproval = Task.Run(() => ProduceApprovalAsync(caller, request, raw, producerDeadline, started, limit, token));
                if (AfterApprovalReservationForTests is not null) LastApprovalProducerForTests = pendingApproval;
                MutationPreparation approval;
                try { approval = await pendingApproval.WaitAsync(token).ConfigureAwait(false); }
                catch (OperationCanceledException)
                {
                    _ = ObserveApprovalProducerAsync(pendingApproval);
                    throw;
                }
                if (approval.PolicyReason is { } approvalReason)
                {
                    routed.Refused(PermissionMatrix.FileWrite, approvalReason);
                    routed.MarkAudited();
                }
                return approval.Response;
            }
            if (!prepared.Ready) return prepared.Response;
            if (AfterPreparationForTests is { } afterPreparation) await afterPreparation().ConfigureAwait(false);
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);

            LinuxWorkerRegistration? linuxRegistration = null;
            if (OperatingSystem.IsLinux())
            {
                try
                {
                    lease.Worker = await LinuxFileEffectController.StartAsync(node.Settings.TestMode, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
                {
                    // No worker was given an operation or descriptor: this is a proven pre-effect refusal.
                    var refusal = node.Processor.ExecuteAsync(command => FileMutationJournal.CompleteKnownGuardUnavailable(
                        command.Transaction, request.Kind, request.Meta!.CommandId.Value.Span, caller.CenterCaller!, raw), CommitDurability.Full);
                    var result = await refusal.WaitAsync(token).ConfigureAwait(false);
                    if (Expired(started, limit, token)) throw new OperationCanceledException(token);
                    return result;
                }
                var registration = node.Processor.ExecuteAsync(command => RegisterLinuxWorker(command.Transaction, caller,
                    request, raw, lease, linuxDeadline, started, limit, token), CommitDurability.Full);
                LinuxWorkerRegistration registered;
                try { registered = await registration.WaitAsync(token).ConfigureAwait(false); }
                catch (OperationCanceledException)
                {
                    ownsLease = false;
                    _ = ObserveMutationAndDisposeAsync(registration, lease);
                    throw;
                }
                if (registered.Refusal is not null) return registered.Refusal;
                linuxRegistration = registered;
                if (registered.Binding is null && registered.Creation is null)
                    throw new InvalidOperationException("The worker operation was not registered.");
            }

            // PREPARED and the Linux worker fence committed before this transaction can permit a target effect.
            Task<byte[]?> effect;
            try
            {
                effect = node.Processor.ExecuteAsync(command => OperatingSystem.IsLinux()
                    ? linuxRegistration!.Creation is { } creation
                        ? ApplyLinuxCreation(command.Transaction, caller, request, raw, lease, creation, started, limit, token)
                        : ApplyLinuxMutation(command.Transaction, caller, request, raw, lease, linuxRegistration.Binding!, started, limit, token)
                    : ApplyMutation(command.Transaction, caller, request, raw, lease, started, limit, token), CommitDurability.Full);
            }
            catch (CommandQueueFullException)
            {
                // No target syscall was started. Keep the committed PREPARED journal for recovery and send no reply.
                return null;
            }

            try
            {
                var outcome = await effect.WaitAsync(token).ConfigureAwait(false);
                if (Expired(started, limit, token)) throw new OperationCanceledException(token);
                return outcome;
            }
            catch (OperationCanceledException)
            {
                // Never close a guard or stage while the real effect callback may still be running.
                ownsLease = false;
                _ = ObserveMutationAndDisposeAsync(effect, lease);
                throw;
            }
        }
        finally
        {
            if (ownsLease) lease.Dispose();
        }
    }

    private MutationPreparation PrepareMutation(StoreTransaction transaction, Caller caller, MutationRequest request, byte[] raw,
        long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        var method = request.Kind == FileOperationKind.Write ? "WriteFile" : "EditFile";
        var auditOperation = request.Kind == FileOperationKind.Write ? "file.write" : "file.edit";
        byte[]? workspace = null;
        string? path = null;
        void Audit(PermissionDecision decision, string outcome) => AuditLog.AppendFileWorkspace(transaction, caller.Actor,
            auditOperation + " FileService." + method, workspace, null, path, decision, outcome, null);
        MutationPreparation Refuse(ArcError error, string? policyReason = null)
        {
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            Audit(PermissionDecision.Deny, "refused: " + error.Code);
            var bytes = request.Kind == FileOperationKind.Write
                ? new FileServiceWriteFileResponse { Meta = meta, Error = error }.ToByteArray()
                : new FileServiceEditFileResponse { Meta = meta, Error = error }.ToByteArray();
            return new MutationPreparation(false, bytes, policyReason);
        }
        void CheckBudget()
        {
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        }
        MutationPreparation Unavailable()
        {
            var error = Error(ErrorCategory.Execution, "operation_failed", "file_outcome_unknown", correlation);
            error.Effect = EffectCertainty.Unknown;
            return Refuse(error);
        }

        try
        {
            CheckBudget();
            if (!request.ShapeValid || Validation.CommandId(request.Meta) is not null ||
                request.Meta!.CommandId is null || caller.RemoteCommandId is null || !request.Meta.CommandId.Equals(caller.RemoteCommandId) ||
                request.Path?.WorkspaceId is not { Value.Length: 16 } selected || !request.Path.HasPath ||
                caller.CenterCaller is null || raw.Length is < 1 or > 245_760)
                return Refuse(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
            workspace = selected.Value.ToByteArray();
            path = request.Limit == "path_bytes" ? null : request.Path.Path;
            if (request.Limit is { } resource)
                return Refuse(TooLargeFile(resource, resource switch
                {
                    "path_bytes" => "4096",
                    "file_write_bytes" => "196608",
                    "file_edit_text_bytes" => "65536",
                    _ => throw new InvalidOperationException("Unknown mutation request limit."),
                }, correlation));
            path = request.Path.Path;
            // A recorded command is replayed only to the original caller with the exact transmitted bytes. Like the
            // existing workspace mutation flow, replay still requires a live, non-stopping link, but does not execute
            // another effect or depend on the current write matrix or the target remaining available.
            routed.BeforeReplay();
            CheckBudget();
            var id = request.Meta.CommandId.Value.ToByteArray();
            var binding = FindRetainedMutation(transaction, request.Kind, id, caller.CenterCaller, SHA256.HashData(raw));
            if (binding == RetainedMutation.Conflict)
                return Refuse(Error(ErrorCategory.Conflict, "command_id_reused", "command_id_reused", correlation));
            if (binding == RetainedMutation.Unavailable)
                return Unavailable();
            if (binding == RetainedMutation.Receipt)
            {
                byte[]? cached;
                ArcError? replayError;
                try
                {
                    cached = FileMutationJournal.Replay(transaction, request.Kind, id, caller.CenterCaller, raw);
                    if (cached is null) return new MutationPreparation(false);
                    replayError = request.Kind == FileOperationKind.Write
                        ? FileServiceWriteFileResponse.Parser.ParseFrom(cached).Error
                        : FileServiceEditFileResponse.Parser.ParseFrom(cached).Error;
                }
                catch (Exception failure) when (failure is InvalidDataException or InvalidProtocolBufferException)
                {
                    return Unavailable();
                }
                Audit(replayError is null ? PermissionDecision.Allow : PermissionDecision.Deny,
                    replayError is null ? "replayed" : "replayed: " + replayError.Code);
                return new MutationPreparation(false, cached);
            }

            if (binding == RetainedMutation.PendingStage)
            {
                MutationPreparation? previous;
                try { previous = PreviousFileApproval(transaction, caller, request, raw, correlation); }
                catch (Exception failure) when (failure is InvalidDataException or InvalidProtocolBufferException)
                {
                    return Unavailable();
                }
                if (previous is null) return new MutationPreparation(false); // Preserve an unsettled producer.
                if (previous.PolicyReason == "approval_required")
                    Audit(PermissionDecision.Approval, "refused: approval_required");
                else if (previous.Response is not null)
                    Audit(PermissionDecision.Deny, "refused: existing_approval");
                return previous;
            }

            CheckWriteCandidateAuthority(transaction, caller);
            CheckBudget();
            // An absent receipt cannot establish the effect of an earlier submission. This path cannot open
            // a target, reserve a journal, stage new data, or ask for a new approval.
            return Unavailable();
        }
        catch (FilePolicyException refusal)
        {
            return Refuse(Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileWrite, correlation), refusal.Reason);
        }
        catch (FileApprovalNotImplementedException)
        {
            return Unavailable();
        }
    }

    private enum RetainedMutation { None, Conflict, Unavailable, Receipt, PendingStage }

    private static RetainedMutation FindRetainedMutation(StoreReader reader, FileOperationKind kind, byte[] id, CenterCaller caller,
        byte[] digest)
    {
        // Match the journal or stage binding before reading retained outcomes or approval data.
        using var query = reader.CreateCommand("""
            SELECT coalesce(j.kind, r.kind), coalesce(j.request_sha256, r.request_sha256), coalesce(j.caller, r.caller),
                   j.command_id IS NOT NULL, r.active, t.command_id IS NOT NULL,
                   d.method, d.payload_digest, d.origin, d.outcome IS NULL
            FROM command_dedup d
            LEFT JOIN file_operation_journal j ON j.command_id = d.command_id
            LEFT JOIN file_private_stage_reservation r ON r.command_id = d.command_id
            LEFT JOIN file_private_stage_terminal t ON t.command_id = r.command_id
            WHERE d.command_id = $id;
            """);
        query.Parameters.AddWithValue("$id", id);
        using var row = query.ExecuteReader();
        if (!row.Read()) return RetainedMutation.None;
        if (row.IsDBNull(0) || row.GetInt32(0) != (int)kind ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(1), digest))
            return RetainedMutation.Conflict;

        CenterCaller saved;
        try { saved = CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)); }
        catch (InvalidProtocolBufferException) { return RetainedMutation.None; }
        if (CenterRouting.Shape(saved) is not null) return RetainedMutation.None;
        if (!CenterRouting.SameFileCaller(saved, caller)) return RetainedMutation.Conflict;

        var method = kind == FileOperationKind.Write ? "WriteFile" : "EditFile";
        if (row.GetString(6) != "arcforges.node.v1.FileService/" + method || row.GetInt32(8) != (int)Origin.Remote ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(7), digest))
            return RetainedMutation.Unavailable;
        if (row.GetBoolean(3)) return RetainedMutation.Receipt;
        var outcomeMissing = row.GetBoolean(9);
        if (row.GetBoolean(5)) return outcomeMissing ? RetainedMutation.Unavailable : RetainedMutation.Receipt;
        return row.GetInt32(4) == 1 && outcomeMissing ? RetainedMutation.PendingStage : RetainedMutation.Unavailable;
    }

    private LinuxWorkerRegistration RegisterLinuxWorker(StoreTransaction transaction, Caller caller, MutationRequest request, byte[] raw,
        MutationLease lease, long linuxDeadline, long started, TimeSpan limit, CancellationToken token)
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("The Linux worker is unavailable.");
        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        try { CheckWriteCandidateAuthority(transaction, caller); }
        catch (FilePolicyException)
        {
            return new LinuxWorkerRegistration(null, FileMutationJournal.CompleteKnownAuthorityRefusal(transaction, request.Kind,
                request.Meta!.CommandId.Value.Span, caller.CenterCaller!, raw, approvalUnavailable: false));
        }
        catch (FileApprovalNotImplementedException)
        {
            return new LinuxWorkerRegistration(null, FileMutationJournal.CompleteKnownAuthorityRefusal(transaction, request.Kind,
                request.Meta!.CommandId.Value.Span, caller.CenterCaller!, raw, approvalUnavailable: true));
        }
        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        // Take the monotonic point first so the expiry conversion cannot extend the signed validity window.
        var beforeSample = LinuxFatalDeadline.MonotonicNanoseconds();
        var sample = RoutedFileValidationTime.Sample(transaction);
        if (!sample.Healthy) throw new RoutedAbortException(RoutedAbort.ClockUncertain);
        var expiry = caller.Routed!.FileExpiryMicroseconds;
        if (sample.BoundaryMicroseconds >= expiry) throw new RoutedAbortException(RoutedAbort.Expired);
        var untilExpiry = checked((expiry - sample.BoundaryMicroseconds) * 1_000);
        var effectDeadline = Math.Min(linuxDeadline, checked(beforeSample + untilExpiry));
        if (lease.Intent!.TargetIdentity is null)
        {
            FileEffectWorker.RecordPreparedChild(transaction, lease.Intent, raw, lease.Worker!.SealedWorker);
            return new LinuxWorkerRegistration(null, null,
                LinuxFileCreationBinding.FromPrepared(lease.Intent, raw, effectDeadline, expiry));
        }
        var binding = FileEffectWorker.BindPreparedChild(transaction, lease.Intent, raw, lease.Worker!.SealedWorker,
            effectDeadline, expiry);
        return new LinuxWorkerRegistration(binding, null);
    }

    private byte[]? ApplyLinuxMutation(StoreTransaction transaction, Caller caller, MutationRequest request, byte[] raw,
        MutationLease lease, LinuxFileEffectBinding binding, long started, TimeSpan limit, CancellationToken token)
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("The Linux worker is unavailable.");
        var worker = lease.Worker ?? throw new InvalidOperationException("The owned worker is unavailable.");
        var guard = lease.Guard ?? throw new InvalidOperationException("The guarded target is unavailable.");
        var original = lease.Stages?.Original ?? throw new InvalidOperationException("The original stage is unavailable.");
        var intended = lease.Stages.Intended;
        var root = lease.Use?.Root ?? throw new InvalidOperationException("The workspace is unavailable.");
        try
        {
            var checkNames = lease.CheckNames ?? throw new InvalidOperationException("The captured parent chain is unavailable.");
            void BeforeEffect()
            {
                BeforeMutationEffectForTests?.Invoke();
                if (Expired(started, limit, token)) throw new OperationCanceledException(token);
                CheckWriteCandidateAuthority(transaction, caller);
                if (Expired(started, limit, token)) throw new OperationCanceledException(token);
            }
            var ownership = FileCreationOwnership.PrepareUpdate(transaction, caller.CenterCaller!,
                request.Path!.WorkspaceId.Value.Span, root, request.Path.Path, guard, request.ExpectedSha256.Span, token);
            BeforeEffect();
            var result = worker.Execute(binding, root, guard, original, intended, BeforeEffect, checkNames, token);
            lease.Guard = result.Guard;
            if (!FileEffectWorker.MarkEndedIfObserved(transaction, request.Meta!.CommandId.Value.Span))
                return FileMutationJournal.MarkUnknown(transaction, request.Meta.CommandId.Value.Span);
            BeforeEffect();
            if (ownership is not null && !FileCreationOwnership.ConfirmUpdate(ownership, root, result.Guard,
                result.Content.Size, result.Content.Sha256, token)) ownership = null;
            var replacements = request.Kind == FileOperationKind.Edit ? request.ExpectedOccurrences : (uint?)null;
            var completed = FileMutationJournal.CompleteVerifiedEffect(transaction, request.Meta.CommandId.Value.Span, raw,
                result.Content.Size, result.Content.Sha256, replacements, ownershipUpdate: ownership);
            result.Guard.CheckIntact();
            return completed;
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
                if (exception is WorkspacePathException native && native.Reason is
                    "hash_mismatch" or "file_identity_changed" or "directory_identity_changed" or "root_changed")
                    return FileMutationJournal.CompleteKnownTargetChanged(transaction, request.Kind,
                        request.Meta.CommandId.Value.Span, caller.CenterCaller!, raw, native.Reason);
                return FileMutationJournal.CompleteKnownGuardUnavailable(transaction, request.Kind,
                    request.Meta.CommandId.Value.Span, caller.CenterCaller!, raw);
            }
            // A permission may have reached the worker, or its actual termination is not established.
            var uncertain = FileMutationJournal.MarkUnknown(transaction, request.Meta!.CommandId.Value.Span);
            return exception is RoutedAbortException or OperationCanceledException ? null : uncertain;
        }
    }

    private byte[] ApplyMutation(StoreTransaction transaction, Caller caller, MutationRequest request, byte[] raw, MutationLease lease,
        long started, TimeSpan limit, CancellationToken token)
    {
        void CheckEffect()
        {
            BeforeMutationEffectForTests?.Invoke();
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);
            CheckWriteCandidateAuthority(transaction, caller);
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        }

        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        try
        {
            CheckWriteCandidateAuthority(transaction, caller);
        }
        catch (FilePolicyException)
        {
            return FileMutationJournal.CompleteKnownAuthorityRefusal(transaction, request.Kind,
                request.Meta!.CommandId.Value.Span, caller.CenterCaller!, raw, approvalUnavailable: false);
        }
        catch (FileApprovalNotImplementedException)
        {
            return FileMutationJournal.CompleteKnownAuthorityRefusal(transaction, request.Kind,
                request.Meta!.CommandId.Value.Span, caller.CenterCaller!, raw, approvalUnavailable: true);
        }
        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        if (!request.HasExpectedSha256)
        {
            try
            {
                lease.Created = lease.Use!.Root.CreateWindowsNewTarget(request.Path!.Path, lease.ParentIdentity!.Value,
                    lease.Stages!.Intended, BeforeCreateForTests, CheckEffect, token);
            }
            catch (WorkspaceCreateCollisionException collision)
            {
                return FileMutationJournal.CompleteKnownExpectedAbsentConflict(transaction, request.Meta!.CommandId.Value.Span,
                    caller.CenterCaller!, raw, collision);
            }
            catch (WorkspaceCreateUncertainException)
            {
                return FileMutationJournal.MarkUnknown(transaction, request.Meta!.CommandId.Value.Span);
            }

            WorkspaceGuardedMutationResult actual;
            WorkspaceCreatedOwnership? ownership;
            try
            {
                AfterCreateForTests?.Invoke();
                actual = lease.Use!.Root.ApplyExistingGuardedStage(request.Path!.Path, lease.Created.Guard,
                    lease.Stages!.Intended, SHA256.HashData(ReadOnlySpan<byte>.Empty), afterFirstEffect: null, beforeEachEffect: CheckEffect, token);
                ownership = lease.Use.Root.MarkCreatedTarget(request.Path.Path, lease.Created, actual.Size, actual.Sha256, CheckEffect, token);
            }
            catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
            {
                // Creation itself was an effect, even when no later content write began.
                return FileMutationJournal.MarkUnknown(transaction, request.Meta!.CommandId.Value.Span);
            }
            var completed = FileMutationJournal.CompleteVerifiedEffect(transaction, request.Meta!.CommandId.Value.Span,
                raw, actual.Size, actual.Sha256, null, ownership);
            AfterCreationSettlementForTests?.Invoke();
            return completed;
        }

        try
        {
            var ownership = FileCreationOwnership.PrepareUpdate(transaction, caller.CenterCaller!,
                request.Path!.WorkspaceId.Value.Span, lease.Use!.Root, request.Path.Path, lease.Guard!,
                request.ExpectedSha256.Span, token);
            var actual = lease.Use.Root.ApplyExistingGuardedStage(request.Path.Path, lease.Guard!, lease.Stages!.Intended,
                request.ExpectedSha256.Span, afterFirstEffect: null, beforeEachEffect: CheckEffect, token);
            if (ownership is not null && !FileCreationOwnership.ConfirmUpdate(ownership, lease.Use.Root, lease.Guard!,
                actual.Size, actual.Sha256, token)) ownership = null;
            var replacements = request.Kind == FileOperationKind.Edit ? request.ExpectedOccurrences : (uint?)null;
            return FileMutationJournal.CompleteVerifiedEffect(transaction, request.Meta!.CommandId.Value.Span, raw, actual.Size,
                actual.Sha256, replacements, ownershipUpdate: ownership);
        }
        catch (WorkspaceGuardedMutationException failure) when (failure.PossibleEffect)
        {
            return FileMutationJournal.MarkUnknown(transaction, request.Meta!.CommandId.Value.Span);
        }
        catch (WorkspaceGuardedMutationException failure) when (failure.InnerException is WorkspacePathException { Reason: "file_too_large" })
        {
            return FileMutationJournal.CompleteKnownExistingFileTooLarge(transaction, request.Kind,
                request.Meta!.CommandId.Value.Span, caller.CenterCaller!, raw, lease.Guard!, token);
        }
    }

    private void CheckWriteCandidateAuthority(StoreReader reader, Caller caller)
    {
        if (caller.CenterCaller is not { } center || caller.Routed is null)
            throw new FilePolicyException("center_caller_incomplete");
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
            var verdict = PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, caller.CellsOrigin, policy.Document.Permissions);
            if (verdict.Decision == PermissionDecision.Approval)
                throw new FileApprovalNotImplementedException();
            if (verdict.Decision != PermissionDecision.Allow)
                throw new FilePolicyException("denied");
            caller.Routed.BeforeEffect(reader);
        }
        catch (FilePolicyException) { throw; }
        catch (FileApprovalNotImplementedException) { throw; }
        catch (Exception exception) when (exception is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new FilePolicyException("policy_invalid");
        }
    }

    // An actual approval cannot be inferred from this exception.
    private sealed class FileApprovalNotImplementedException() : NotSupportedException("Durable file approval is not implemented.");

    private static ArcError TooLargeFile(string name, string maximum, Id correlation) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails { Limit = new LimitFailure { LimitName = name, Maximum = new WireDecimal { Value = maximum } } },
    };

    private async Task ObserveMutationAndDisposeAsync<T>(Task<T> pending, MutationLease lease)
    {
        try { _ = await pending.ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { node.Log.Error("api.file.mutation.pending_failed"); }
        finally { lease.Dispose(); }
    }

    private sealed record MutationRequest(FileOperationKind Kind, RequestMeta? Meta, FilePath? Path, bool ShapeValid, string? Limit,
        bool HasExpectedSha256, ByteString ExpectedSha256, ByteString Data, string? OldText, string? NewText, uint ExpectedOccurrences);

    private sealed record MutationPreparation(bool Ready, byte[]? Response = null, string? PolicyReason = null, bool NeedsApproval = false);

    private sealed record LinuxWorkerRegistration(LinuxFileEffectBinding? Binding, byte[]? Refusal, LinuxFileCreationBinding? Creation = null);

    private sealed class MutationLease : IDisposable
    {
        internal RegisteredWorkspaceUse? Use { get; set; }
        internal WorkspaceWriteGuard? Guard { get; set; }
        internal WorkspaceCreatedTarget? Created { get; set; }
        internal WorkspaceObjectIdentity? ParentIdentity { get; set; }
        internal Action? CheckNames { get; set; }
        internal WorkspaceLinuxCreationSelection? CreationSelection { get; set; }
        internal WorkspaceStagePair? Stages { get; set; }
        internal FileJournalIntent? Intent { get; set; }
        internal LinuxFileEffectController? Worker { get; set; }

        public void Dispose()
        {
            if (OperatingSystem.IsLinux() && Worker is { } worker)
            {
                Worker = null;
                worker.Shutdown(DisposeResources);
                return;
            }
            DisposeResources();
        }

        private void DisposeResources()
        {
            try { Stages?.Dispose(); }
            finally
            {
                try { Guard?.Dispose(); }
                finally
                {
                    try { Created?.Dispose(); }
                    finally { Use?.Dispose(); }
                }
            }
        }
    }
}
