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
    // The routed mutation path remains unadvertised until approval, settlement and both native platform paths are complete.
    // It executes the guarded existing-file protocol only for an authorized caller.
    private readonly FileStageBudget _writeStageBudget = new();

    // Test-only callbacks coordinate a real competing create and an interruption after the actual creation effect.
    internal Action? BeforeCreateForTests { get; set; }
    internal Action? AfterCreateForTests { get; set; }
    internal Action? BeforeMutationEffectForTests { get; set; }
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
        var limit = routed.RemainingFileOperation();
        if (limit <= TimeSpan.Zero) throw new OperationCanceledException(cancellationToken);
        var started = node.Clock.GetTimestamp();
        using var deadline = new CancellationTokenSource(limit, node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var token = linked.Token;
        var lease = new MutationLease();
        Task<MutationPreparation>? preparation = null;
        var ownsLease = true;
        try
        {
            preparation = node.Processor.ExecuteAsync(command => PrepareMutation(command.Transaction, caller, request, raw, lease, started, limit, token),
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

            if (!prepared.Ready) return prepared.Response;
            if (AfterPreparationForTests is { } afterPreparation) await afterPreparation().ConfigureAwait(false);
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);

            // PREPARED committed before this second transaction can write the target.
            Task<byte[]> effect;
            try
            {
                effect = node.Processor.ExecuteAsync(command => ApplyMutation(command.Transaction, caller, request, raw, lease, started, limit, token),
                    CommitDurability.Full);
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
        MutationLease lease, long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        var method = request.Kind == FileOperationKind.Write ? "WriteFile" : "EditFile";
        var auditOperation = request.Kind == FileOperationKind.Write ? "file.write" : "file.edit";
        byte[]? workspace = null;
        string? path = null;
        FileAuditMetadata? observed = null;
        void Audit(PermissionDecision decision, string outcome) => AuditLog.AppendFileWorkspace(transaction, caller.Actor,
            auditOperation + " FileService." + method, workspace, null, path, decision, outcome, observed);
        MutationPreparation Refuse(ArcError error, string? policyReason = null)
        {
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            Audit(PermissionDecision.Deny, "refused: " + error.Code);
            var bytes = request.Kind == FileOperationKind.Write
                ? new FileServiceWriteFileResponse { Meta = meta, Error = error, Audit = observed }.ToByteArray()
                : new FileServiceEditFileResponse { Meta = meta, Error = error, Audit = observed }.ToByteArray();
            return new MutationPreparation(false, bytes, policyReason);
        }
        void CheckBudget()
        {
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        }
        MutationPreparation Reserve(FileJournalIntent intent)
        {
            CheckWriteCandidateAuthority(transaction, caller);
            CheckBudget();
            return FileMutationJournal.Prepare(transaction, intent, raw) switch
            {
                FileJournalPreparation.Prepared => new MutationPreparation(true),
                FileJournalPreparation.Conflict => Refuse(Error(ErrorCategory.Conflict, "command_id_reused", "command_id_reused", correlation)),
                FileJournalPreparation.WorkspaceHeld => Refuse(Error(ErrorCategory.State, "invalid_state", "file_recovery_pending", correlation)),
                FileJournalPreparation.Capacity => Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "file_stage_capacity", correlation)),
                _ => new MutationPreparation(false),
            };
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
            var existing = FileMutationJournal.FindExisting(transaction, request.Kind, request.Meta.CommandId.Value.Span, caller.CenterCaller, raw);
            if (existing == FileJournalPreparation.Conflict)
                return Refuse(Error(ErrorCategory.Conflict, "command_id_reused", "command_id_reused", correlation));
            if (existing == FileJournalPreparation.Existing)
            {
                var cached = FileMutationJournal.Replay(transaction, request.Kind, request.Meta.CommandId.Value.Span, caller.CenterCaller, raw);
                if (cached is not null) Audit(PermissionDecision.Allow, "replayed");
                return new MutationPreparation(false, cached);
            }

            CheckWriteCandidateAuthority(transaction, caller);
            CheckBudget();
            // Linux remains unavailable until its lease coordinator is proven. A new AGENT-owned target also waits
            // for durable per-creation ownership markers; this internal candidate does not claim unattended ownership.
            if (!OperatingSystem.IsWindows())
                return Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "file_guard_unavailable", correlation));
            if (!request.HasExpectedSha256 && caller.CellsOrigin == Origin.Agent)
                return Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "file_ownership_unavailable", correlation));
            _ = WorkspacePath.Components(path);
            lease.Use = _workspaces.OpenForUse(transaction, workspace, beforeUse: selectedTx =>
                CheckWriteCandidateAuthority(selectedTx, caller), token);
            CheckBudget();
            var durableStages = PrivateStageRegistry.Usage(transaction);
            if (!request.HasExpectedSha256)
            {
                lease.Stages = WorkspaceStagePair.TryCreate(lease.Use.Root, _writeStageBudget, original: null, request.Data.Memory, token,
                    durableStages.Mutations, durableStages.Bytes);
                if (lease.Stages is null)
                    return Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "file_stage_capacity", correlation));
                var slashAt = path.LastIndexOf('/');
                var parentHandle = lease.Use.Root.OpenDirectory(slashAt < 0 ? "" : path[..slashAt]);
                var rootId = RegisteredWorkspaces.RootIdentity.Encode(lease.Use.Root.RootIdentity);
                var newParentIdentity = WorkspacePath.Identity(parentHandle);
                lease.ParentIdentity = newParentIdentity;
                var parentId = RegisteredWorkspaces.RootIdentity.Encode(newParentIdentity);
                var stage = lease.Stages.Intended;
                var absentIntent = new FileJournalIntent(FileOperationKind.Write, request.Meta.CommandId.Value.ToByteArray(),
                    correlation.Value.ToByteArray(), caller.CenterCaller, workspace, path, rootId.Platform, rootId.Bytes,
                    parentId.Bytes, null, null, null, null, stage.Length, stage.Sha256.ToArray(), stage.Identity.Bytes);
                return Reserve(absentIntent);
            }
            lease.Guard = lease.Use.Root.OpenExistingWriteGuard(path);
            using var original = lease.Guard.ReadForMutation(token);
            observed = new FileAuditMetadata
            {
                Observations =
                {
                    new FileAuditObservation
                    {
                        Kind = FileAuditKind.InputBytes,
                        SizeBytes = checked((ulong)original.Bytes.Length),
                        DigestInputBytes = checked((ulong)original.Bytes.Length),
                        Sha256 = ByteString.CopyFrom(original.Sha256.Span),
                    },
                },
            };
            if (!CryptographicOperations.FixedTimeEquals(request.ExpectedSha256.Span, original.Sha256.Span))
                return Refuse(Error(ErrorCategory.Conflict, "file_changed", "hash_mismatch", correlation));
            CheckBudget();
            using var edit = request.Kind == FileOperationKind.Edit
                ? WorkspaceFileEdit.Plan(original.Bytes.Span, request.ExpectedSha256.Span, request.OldText!, request.NewText!,
                    request.ExpectedOccurrences, token) : null;
            var intended = edit is null ? request.Data.ToByteArray() : edit.Bytes.ToArray();
            try
            {
                lease.Stages = WorkspaceStagePair.TryCreate(lease.Use.Root, _writeStageBudget, original.Bytes, intended, token,
                durableStages.Mutations, durableStages.Bytes);
            }
            finally { CryptographicOperations.ZeroMemory(intended); }
            if (lease.Stages is null)
                return Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "file_stage_capacity", correlation));
            var slash = path.LastIndexOf('/');
            var parent = lease.Use.Root.OpenDirectory(slash < 0 ? "" : path[..slash]);
            var rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(lease.Use.Root.RootIdentity);
            var parentIdentity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(parent));
            var targetIdentity = RegisteredWorkspaces.RootIdentity.Encode(lease.Guard.ObjectIdentity, directory: false);
            var originalStage = lease.Stages.Original ?? throw new InvalidOperationException("An existing file needs a preimage stage.");
            var intent = new FileJournalIntent(request.Kind, request.Meta.CommandId.Value.ToByteArray(),
                correlation.Value.ToByteArray(), caller.CenterCaller, workspace, path, rootIdentity.Platform, rootIdentity.Bytes,
                parentIdentity.Bytes, targetIdentity.Bytes, original.Bytes.Length, original.Sha256.ToArray(), originalStage.Identity.Bytes,
                lease.Stages.Intended.Length, lease.Stages.Intended.Sha256.ToArray(), lease.Stages.Intended.Identity.Bytes);
            return Reserve(intent);
        }
        catch (FilePolicyException refusal)
        {
            return Refuse(Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileWrite, correlation), refusal.Reason);
        }
        catch (FileApprovalNotImplementedException)
        {
            // This remains an honest pre-effect refusal until the real durable HUMAN approval path is implemented.
            return Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "file_approval_unavailable", correlation));
        }
        catch (WorkspaceFileEditException failure)
        {
            return failure.Reason switch
            {
                "occurrence_mismatch" => Refuse(Error(ErrorCategory.Conflict, "occurrence_mismatch", "occurrence_mismatch", correlation)),
                "file_existing_bytes" or "file_edit_result_bytes" => Refuse(TooLargeFile(failure.Reason, "4194304", correlation)),
                "file_edit_text_bytes" => Refuse(TooLargeFile(failure.Reason, "65536", correlation)),
                "hash_mismatch" => Refuse(Error(ErrorCategory.Conflict, "file_changed", "hash_mismatch", correlation)),
                _ => Refuse(Error(ErrorCategory.Validation, "invalid_argument", "content: invalid_utf8", correlation)),
            };
        }
        catch (WorkspacePathException exception) when (exception.Reason == "file_too_large")
        {
            return Refuse(TooLargeFile("file_existing_bytes", "4194304", correlation));
        }
        catch (Exception exception) when (exception is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or IOException)
        {
            return Refuse(Failure(exception, correlation));
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
            try
            {
                AfterCreateForTests?.Invoke();
                actual = lease.Use!.Root.ApplyExistingGuardedStage(request.Path!.Path, lease.Created.Guard,
                    lease.Stages!.Intended, SHA256.HashData(ReadOnlySpan<byte>.Empty), afterFirstEffect: null, beforeEachEffect: CheckEffect, token);
            }
            catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
            {
                // Creation itself was an effect, even when no later content write began.
                return FileMutationJournal.MarkUnknown(transaction, request.Meta!.CommandId.Value.Span);
            }
            return FileMutationJournal.CompleteVerifiedEffect(transaction, request.Meta!.CommandId.Value.Span, raw, actual.Size, actual.Sha256, null);
        }

        try
        {
            var actual = lease.Use!.Root.ApplyExistingGuardedStage(request.Path!.Path, lease.Guard!, lease.Stages!.Intended,
                request.ExpectedSha256.Span, afterFirstEffect: null, beforeEachEffect: CheckEffect, token);
            var replacements = request.Kind == FileOperationKind.Edit ? request.ExpectedOccurrences : (uint?)null;
            return FileMutationJournal.CompleteVerifiedEffect(transaction, request.Meta!.CommandId.Value.Span, raw, actual.Size, actual.Sha256, replacements);
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

    private sealed record MutationPreparation(bool Ready, byte[]? Response = null, string? PolicyReason = null);

    private sealed class MutationLease : IDisposable
    {
        internal RegisteredWorkspaceUse? Use { get; set; }
        internal WorkspaceWriteGuard? Guard { get; set; }
        internal WorkspaceCreatedTarget? Created { get; set; }
        internal WorkspaceObjectIdentity? ParentIdentity { get; set; }
        internal WorkspaceStagePair? Stages { get; set; }

        public void Dispose()
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
