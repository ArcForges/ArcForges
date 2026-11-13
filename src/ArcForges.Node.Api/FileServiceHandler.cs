// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
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

namespace ArcForges.Node.Api;

/// <summary>Read-only target-node file operation for an already verified center caller.</summary>
internal sealed partial class FileServiceHandler(NodeRuntime node) : IDisposable
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly RegisteredWorkspaces _workspaces = new(node.Store);

    // Test-only coordination changes the real policy before the usage transaction.
    internal Func<CancellationToken, Task>? BeforeReadUseForTests { get; set; }

    // Test-only checkpoints coordinate real I/O and the writer's held transaction.
    internal Action<WorkspaceReadCheckpoint>? ReadCheckpointForTests { get; set; }

    internal Action? AfterNativeReadForTests { get; set; }

    // A test holds the real writer transaction after the private-stage identity snapshot, before native I/O.
    internal Action? AfterWorkspaceSnapshotForTests { get; set; }

    internal async Task<FileServiceReadFileResponse> ReadAsync(Caller caller, FileServiceReadFileRequest request,
        CancellationToken cancellationToken)
    {
        var routed = caller.Routed ?? throw new InvalidOperationException("A file operation requires a verified routed caller.");
        var limit = routed.RemainingFileOperation();
        if (limit <= TimeSpan.Zero)
        {
            // No verified reply is emitted when there is no budget to perform and audit the read.
            throw new OperationCanceledException(cancellationToken);
        }

        var started = node.Clock.GetTimestamp();
        using var deadline = new CancellationTokenSource(limit, node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var token = linked.Token;
        if (BeforeReadUseForTests is { } beforeRead)
        {
            await beforeRead(token).WaitAsync(token).ConfigureAwait(false);
        }

        // The bounded command processor owns and drains the work even if the caller times out while it is queued.
        // Its transaction encloses both the actual native read and its audit, so there is no post-read audit queue gap.
        var pending = node.Processor.ExecuteAsync(command => ReadInTransaction(command.Transaction, caller, request, started, limit, token),
            CommitDurability.Full);
        ReadOutcome result;
        try
        {
            result = await pending.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = ObservePendingAsync(pending);
            throw;
        }

        if (Expired(started, limit, token))
        {
            throw new OperationCanceledException(token);
        }

        if (result.Abort is RoutedAbortException routedAbort)
        {
            throw routedAbort;
        }

        if (result.Abort is OperationCanceledException cancelled)
        {
            throw cancelled;
        }

        if (result.PolicyReason is { } reason)
        {
            routed.Refused(PermissionMatrix.FileRead, reason);
            routed.MarkAudited();
        }

        return result.Response!;
    }

    private ReadOutcome ReadInTransaction(StoreTransaction transaction, Caller caller, FileServiceReadFileRequest request,
        long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        byte[]? workspace = request.Path?.WorkspaceId is { Value.Length: 16 } id &&
            id.Value.Span.IndexOfAnyExcept((byte)0) >= 0 ? id.Value.ToByteArray() : null;
        string? path = null;
        FileAuditMetadata? observation = null;

        void Audit(PermissionDecision decision, string outcome) => AuditLog.AppendFileWorkspace(transaction, caller.Actor,
            PermissionMatrix.FileRead + " FileService.ReadFile", workspace, null, path, decision, outcome, observation);
        ReadOutcome Refusal(ArcError error)
        {
            Audit(PermissionDecision.Deny, "refused: " + error.Code);
            return new ReadOutcome(new FileServiceReadFileResponse { Meta = meta, Error = error, Audit = observation });
        }

        void CheckBudget()
        {
            if (Expired(started, limit, token))
            {
                throw new OperationCanceledException(token);
            }
        }

        try
        {
            if (request.Path is { HasPath: true } attempted && StrictUtf8.GetByteCount(attempted.Path) <= 4096)
            {
                path = attempted.Path;
            }

            CheckBudget();
            if (request.Path is { HasPath: true } providedPath)
            {
                if (StrictUtf8.GetByteCount(providedPath.Path) > 4096)
                {
                    var bounded = request.Clone();
                    bounded.Path.Path = "x";
                    return Refusal(workspace is not null && request.Meta?.CommandId is null && request.HasOffset &&
                        request.HasLength && request.Length > 0 && NodeShapes.IsValid(bounded)
                        ? TooLarge(correlation)
                        : Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
                }
            }

            if (!NodeShapes.IsValid(request) || request.Meta?.CommandId is not null || workspace is null ||
                request.Path is not { HasPath: true } filePath || !request.HasOffset || !request.HasLength || request.Length == 0)
            {
                return Refusal(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
            }

            path = filePath.Path;
            CheckAuthority(transaction, caller);
            CheckBudget();
            using var use = _workspaces.OpenForQuery(transaction, workspace, beforeUse: selected => CheckAuthority(selected, caller), token);
            AfterWorkspaceSnapshotForTests?.Invoke();
            CheckBudget();
            var selected = use.Root.InspectEntry(path);
            if (selected.Kind == WorkspaceEntryType.Directory)
            {
                throw new WorkspacePathException("file_not_regular");
            }

            if (selected.Kind != WorkspaceEntryType.File || selected.Identity.Links != 1)
            {
                throw new WorkspacePathException(selected.Kind == WorkspaceEntryType.File ? "file_hard_link" : "path_link_or_special");
            }

            var value = WorkspaceFileReader.Read(use.Root, path, request.Offset, request.Length, ReadCheckpointForTests, token);
            observation = ReadObservation(value.Bytes.Length, value.Sha256.Span);
            WorkspaceEntryMetadata named;
            try
            {
                named = use.Root.InspectEntry(path);
            }
            catch (WorkspacePathException exception) when (exception.Reason is "native_2" or "native_3" or "native_20")
            {
                throw new WorkspaceReadException("file_changed_while_reading", value.Bytes.Length, value.Sha256, exception);
            }

            if (named.Kind != WorkspaceEntryType.File || !selected.Identity.SameObject(named.Identity) ||
                selected.Stamp != named.Stamp || named.Identity.Links != 1)
            {
                throw new WorkspaceReadException("file_changed_while_reading", value.Bytes.Length, value.Sha256);
            }

            AfterNativeReadForTests?.Invoke();
            CheckBudget();
            CheckAuthority(transaction, caller);
            Audit(PermissionDecision.Allow, "read");
            return new ReadOutcome(new FileServiceReadFileResponse
            {
                Meta = meta,
                Value = new FileServiceReadFileValue
                {
                    Data = ByteString.CopyFrom(value.Bytes.Span),
                    Offset = value.Offset,
                    NextOffset = value.NextOffset,
                    FileSize = value.FileSize,
                    Eof = value.Eof,
                    Sha256 = ByteString.CopyFrom(value.Sha256.Span),
                },
                Audit = observation,
            });
        }
        catch (EncoderFallbackException)
        {
            path = null;
            return Refusal(Error(ErrorCategory.Validation, "invalid_argument", "path: utf8", correlation));
        }
        catch (FilePolicyException refusal)
        {
            Audit(PermissionDecision.Deny, "refused: " + refusal.Reason);
            return new ReadOutcome(new FileServiceReadFileResponse
            {
                Meta = meta,
                Error = Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileRead, correlation),
                Audit = observation,
            }, PolicyReason: refusal.Reason);
        }
        catch (WorkspaceReadException failure)
        {
            if (failure.ObservedSha256 is { } hash)
            {
                observation = ReadObservation(failure.ObservedBytes, hash.Span);
            }

            Audit(PermissionDecision.Deny, "refused: " + failure.Reason);
            if (failure.Reason == "file_read_cancelled")
            {
                return new ReadOutcome(Abort: new OperationCanceledException(token));
            }

            return new ReadOutcome(new FileServiceReadFileResponse { Meta = meta, Error = Failure(failure, correlation), Audit = observation });
        }
        catch (RoutedAbortException abort)
        {
            Audit(PermissionDecision.Deny, "refused: routed_call_ended");
            return new ReadOutcome(Abort: abort);
        }
        catch (OperationCanceledException cancelled)
        {
            Audit(PermissionDecision.Deny, "refused: cancelled");
            return new ReadOutcome(Abort: cancelled);
        }
        catch (Exception exception) when (exception is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or IOException or ArgumentException)
        {
            return Refusal(Failure(exception, correlation));
        }
    }

    private bool Expired(long started, TimeSpan limit, CancellationToken token) => token.IsCancellationRequested || node.Clock.GetElapsedTime(started) >= limit;

    private async Task ObservePendingAsync(Task<ReadOutcome> pending)
    {
        try
        {
            _ = await pending.ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Do not log an exception message: paths and file bytes are sensitive.
            node.Log.Error("api.file.read.audit_failed");
        }
    }

    private sealed record ReadOutcome(FileServiceReadFileResponse? Response = null, Exception? Abort = null, string? PolicyReason = null);

    private void CheckAuthority(StoreReader reader, Caller caller)
    {
        if (caller.CenterCaller is not { } center || caller.Routed is null)
        {
            throw new FilePolicyException("center_caller_incomplete");
        }

        try
        {
            var policy = PolicyRules.Current(reader);
            if (!CryptographicOperations.FixedTimeEquals(policy.Digest, PolicyDocuments.Digest(policy.Document)) ||
                policy.Document.Permissions.Any(item => PermissionMatrix.Valid(item) is not null) ||
                policy.Document.CenterRouted is { HasRelayedFrom: true } route &&
                route.RelayedFrom is not (RelayedFrom.Unspecified or RelayedFrom.OwnNode or RelayedFrom.Account))
            {
                throw new FilePolicyException("policy_invalid");
            }

            if (CenterRouting.Refusal(center, node.NodeId.Span, policy.Document.CenterRouted) is { } reason)
            {
                throw new FilePolicyException(reason);
            }

            if (PermissionMatrix.DecideRouted(PermissionMatrix.FileRead, caller.CellsOrigin, policy.Document.Permissions).Decision != PermissionDecision.Allow)
            {
                throw new FilePolicyException("denied");
            }

            caller.Routed.BeforeEffect(reader);
        }
        catch (FilePolicyException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new FilePolicyException("policy_invalid");
        }
    }

    private static FileAuditMetadata ReadObservation(int count, ReadOnlySpan<byte> digest) => new()
    {
        Observations =
        {
            new FileAuditObservation
            {
                Kind = FileAuditKind.ReadBytes,
                SizeBytes = checked((ulong)count),
                DigestInputBytes = checked((ulong)count),
                Sha256 = ByteString.CopyFrom(digest),
            },
        },
    };

    private static ArcError Error(ErrorCategory category, string code, string reason, Id correlation) => new()
    {
        Category = category,
        Code = code,
        MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = reason } },
    };

    private static ArcError TooLarge(Id correlation) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails
        {
            Limit = new LimitFailure { LimitName = "path_bytes", Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = "4096" } },
        },
    };

    private static ArcError Failure(Exception exception, Id correlation)
    {
        if (exception is RegisteredWorkspaceException registered)
        {
            if (registered.Reason == "workspace_not_found")
            {
                return Error(ErrorCategory.Validation, "invalid_argument", "workspace_id.registered: required", correlation);
            }

            if (registered.Reason == "workspace_root_changed" ||
                registered.Reason == "workspace_root_unavailable" &&
                registered.InnerException is WorkspacePathException { Reason: "native_2" or "native_3" or "native_20" or "root_not_directory" })
            {
                return Error(ErrorCategory.Conflict, "file_changed", "workspace_root_changed", correlation);
            }

            return Error(ErrorCategory.State, "file_access_denied", "file_access_denied", correlation);
        }

        var reason = exception switch
        {
            WorkspacePathException native => native.Reason,
            WorkspaceReadException read => read.Reason,
            _ => "file_access_denied",
        };
        if (reason is "native_2" or "native_3" or "native_20" or "file_not_regular")
        {
            return Error(ErrorCategory.Validation, "path_not_found", "path", correlation);
        }

        if (reason is "path_invalid" or "path_reserved" or "root_operation_refused" or "path_utf8_invalid")
        {
            return Error(ErrorCategory.Validation, "invalid_argument", "path: " + reason, correlation);
        }

        if (reason is "file_identity_changed" or "directory_identity_changed" or "root_changed" or "file_changed_while_reading")
        {
            return Error(ErrorCategory.Conflict, "file_changed", reason, correlation);
        }

        var closed = reason switch
        {
            "file_hard_link" or "file_metadata_unavailable" or "path_link_or_special" or "mount_crossing" or
            "canonical_path_unavailable" or "case_semantics_unavailable" or "directory_entry_invalid" or
            "directory_enumeration_failed" or "directory_enumeration_unavailable" or "file_guard_unavailable" or
            "path_enforcement_unavailable" or "identity_filesystem_unavailable" or "identity_handle_unavailable" or
            "identity_unavailable" or "identity_unavailable_or_reparse" or "procfs_unavailable" or "root_not_supported" => reason,
            _ => "file_access_denied",
        };
        return Error(ErrorCategory.State, "file_access_denied", closed, correlation);
    }

    private sealed class FilePolicyException(string reason) : Exception(reason)
    {
        internal string Reason { get; } = reason;
    }
}
