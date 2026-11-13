// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
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

/// <summary>
/// Target-node workspace operations for already verified center callers. Mutations and their exact response, requester
/// ownership and content-free audit share the node's FULL SQLite transaction. This class is not a local submission endpoint.
/// </summary>
internal sealed class WorkspaceServiceHandler(NodeRuntime node) : IDisposable
{
    private const string Service = "arcforges.node.v1.WorkspaceService";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly RegisteredWorkspaces _workspaces = new(node.Store);
    private readonly byte[] _pageKey = RandomNumberGenerator.GetBytes(32);

    public void Dispose() => CryptographicOperations.ZeroMemory(_pageKey);

    // A test may coordinate real policy changes after preparation; production never sets this callback.
    internal Func<CancellationToken, Task>? AfterPrepareForTests { get; set; }

    // A test may change real policy after the first check and before the transactional usage update.
    internal Func<CancellationToken, Task>? BeforeReadUseForTests { get; set; }

    internal async Task<WorkspaceServiceRegisterWorkspaceResponse> RegisterAsync(Caller caller, WorkspaceServiceRegisterWorkspaceRequest request,
        CancellationToken cancellationToken)
    {
        var meta = ApiCommands.Meta(request.Meta);
        if (caller.Routed is { } responseRouting)
        {
            meta.CorrelationId = responseRouting.Correlation(request.Meta);
        }
        try
        {
            if (request.HasPath && StrictUtf8.GetByteCount(request.Path) > 4096)
            {
                var bounded = request.Clone();
                bounded.Path = OperatingSystem.IsWindows() ? @"C:\x" : "/x";
                if (NodeShapes.IsValid(bounded))
                {
                    var correlation = caller.Routed?.Correlation(request.Meta) ?? throw new InvalidOperationException("A workspace registration requires a routed caller.");
                    var error = new ArcError
                    {
                        Category = ErrorCategory.Resource,
                        Code = "too_large",
                        MessageKey = "error.resource.too_large",
                        Effect = EffectCertainty.DidNotHappen,
                        Retry = new RetryAdvice { Mode = RetryMode.Never },
                        CorrelationId = correlation,
                        Details = new ErrorDetails
                        {
                            Limit = new LimitFailure { LimitName = "workspace_root_path_bytes", Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = "4096" } },
                        },
                    };
                    await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceRegister, "RegisterWorkspace", null, null, error.Code).ConfigureAwait(false);
                    return new WorkspaceServiceRegisterWorkspaceResponse { Meta = meta, Error = error };
                }
            }
        }
        catch (EncoderFallbackException)
        {
            await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceRegister, "RegisterWorkspace", null, null, "invalid_argument").ConfigureAwait(false);
            return new WorkspaceServiceRegisterWorkspaceResponse { Meta = meta, Error = NodeErrors.InvalidArgument("path: utf8") };
        }

        if (!NodeShapes.IsValid(request))
        {
            var error = NodeErrors.InvalidArgument("workspace registration request");
            await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceRegister, "RegisterWorkspace", null, null, "invalid_argument").ConfigureAwait(false);
            return new WorkspaceServiceRegisterWorkspaceResponse { Meta = meta, Error = error };
        }

        try
        {
            node.Store.Read(reader => { CheckAuthority(reader, caller, PermissionMatrix.WorkspaceRegister); return 0; });
        }
        catch (WorkspacePolicyException refusal)
        {
            await PolicyRefusalAsync(caller, PermissionMatrix.WorkspaceRegister, "RegisterWorkspace", null, refusal.Reason).ConfigureAwait(false);
            return new WorkspaceServiceRegisterWorkspaceResponse { Meta = meta, Error = NodeErrors.PermissionDenied(PermissionMatrix.WorkspaceRegister) };
        }

        RegisteredWorkspaces.PreparedRegistration? prepared = null;
        GitStatusSummary? summary = null;
        ArcError? prepareError = null;
        try
        {
            prepared = _workspaces.PrepareRegistration(request.Path, request.HasName ? request.Name : null, cancellationToken: cancellationToken);
            summary = await WorkspaceGitStatus.ObserveAsync(prepared.Opened, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or ArgumentException)
        {
            prepareError = Failure(exception, null);
        }

        using (prepared)
        {
            if (AfterPrepareForTests is { } coordinate)
            {
                await coordinate(cancellationToken).ConfigureAwait(false);
            }

            return await MutationAsync(caller, request, request.Meta, "RegisterWorkspace", PermissionMatrix.WorkspaceRegister,
                WorkspaceServiceRegisterWorkspaceResponse.Parser, error => new WorkspaceServiceRegisterWorkspaceResponse { Meta = meta, Error = error },
                command =>
                {
                    var response = new WorkspaceServiceRegisterWorkspaceResponse { Meta = meta };
                    try
                    {
                        CheckAuthority(command.Transaction, caller, PermissionMatrix.WorkspaceRegister);
                        if (prepareError is not null)
                        {
                            response.Error = prepareError;
                        }
                        else
                        {
                            var record = _workspaces.RegisterPreparedFromVerifiedHuman(command.Transaction, prepared!,
                                () => CheckAuthority(command.Transaction, caller, PermissionMatrix.WorkspaceRegister), cancellationToken);
                            var workspace = Projection(record, summary);
                            response.Value = new WorkspaceServiceRegisterWorkspaceValue { Workspace = workspace };
                            response.Audit = WorkspaceAuditMetadata.ForRecords([workspace]);
                        }
                    }
                    catch (Exception exception) when (exception is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException)
                    {
                        response.Error = Failure(exception, null);
                    }

                    var id = response.Value?.Workspace?.WorkspaceId?.Value.ToByteArray();
                    AuditLog.AppendFileWorkspace(command.Transaction, caller.Actor, "workspace.register WorkspaceService.RegisterWorkspace",
                        id, null, response.Value?.Workspace?.RootPath, response.Error is null ? PermissionDecision.Allow : PermissionDecision.Deny,
                        response.Error is null ? "registered" : "refused: " + response.Error.Code, response.Audit);
                    return response;
                }).ConfigureAwait(false);
        }
    }

    internal async Task<WorkspaceServiceUnregisterWorkspaceResponse> UnregisterAsync(Caller caller, WorkspaceServiceUnregisterWorkspaceRequest request,
        CancellationToken cancellationToken)
    {
        var meta = ApiCommands.Meta(request.Meta);
        if (caller.Routed is { } responseRouting)
        {
            meta.CorrelationId = responseRouting.Correlation(request.Meta);
        }
        if (!NodeShapes.IsValid(request))
        {
            await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceUnregister, "UnregisterWorkspace", null, null, "invalid_argument").ConfigureAwait(false);
            return new WorkspaceServiceUnregisterWorkspaceResponse { Meta = meta, Error = NodeErrors.InvalidArgument("workspace unregistration request") };
        }

        var id = request.WorkspaceId.Value.ToByteArray();
        return await MutationAsync(caller, request, request.Meta, "UnregisterWorkspace", PermissionMatrix.WorkspaceUnregister,
            WorkspaceServiceUnregisterWorkspaceResponse.Parser, error => new WorkspaceServiceUnregisterWorkspaceResponse { Meta = meta, Error = error },
            command =>
            {
                var response = new WorkspaceServiceUnregisterWorkspaceResponse { Meta = meta };
                try
                {
                    CheckAuthority(command.Transaction, caller, PermissionMatrix.WorkspaceUnregister);
                    _workspaces.UnregisterPreparedFromVerifiedHuman(command.Transaction, id,
                        () => CheckAuthority(command.Transaction, caller, PermissionMatrix.WorkspaceUnregister), cancellationToken);
                    response.Value = new WorkspaceServiceUnregisterWorkspaceValue
                    {
                        Receipt = new Receipt { CommandId = request.Meta.CommandId.Clone(), Effect = EffectCertainty.Happened },
                    };
                }
                catch (RegisteredWorkspaceException exception)
                {
                    response.Error = Failure(exception, id);
                }

                AuditLog.AppendFileWorkspace(command.Transaction, caller.Actor, "workspace.unregister WorkspaceService.UnregisterWorkspace",
                    id, null, null, response.Error is null ? PermissionDecision.Allow : PermissionDecision.Deny,
                    response.Error is null ? "unregistered" : "refused: " + response.Error.Code, null);
                return response;
            }, id).ConfigureAwait(false);
    }

    internal async Task<WorkspaceServiceGetWorkspaceResponse> GetAsync(Caller caller, WorkspaceServiceGetWorkspaceRequest request,
        CancellationToken cancellationToken)
    {
        var meta = ApiCommands.Meta(request.Meta);
        if (caller.Routed is { } responseRouting)
        {
            meta.CorrelationId = responseRouting.Correlation(request.Meta);
        }
        if (!NodeShapes.IsValid(request))
        {
            await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceRead, "GetWorkspace", null, null, "invalid_argument").ConfigureAwait(false);
            return new WorkspaceServiceGetWorkspaceResponse { Meta = meta, Error = NodeErrors.InvalidArgument("workspace get request") };
        }

        var id = request.WorkspaceId.Value.ToByteArray();
        try
        {
            node.Store.Read(reader => { CheckAuthority(reader, caller, PermissionMatrix.WorkspaceRead); return 0; });
            var workspace = node.Store.Read(reader => WorkspaceCatalog.Get(reader, id))
                ?? throw new RegisteredWorkspaceException("workspace_not_found");
            if (BeforeReadUseForTests is { } coordinate) await coordinate(cancellationToken).ConfigureAwait(false);
            if (workspace.Kind == WorkspaceKind.Registered)
            {
                using var use = _workspaces.OpenForUse(id,
                    transaction => CheckAuthority(transaction, caller, PermissionMatrix.WorkspaceRead), cancellationToken);
                workspace.Git = await WorkspaceGitStatus.ObserveAsync(use.Root, cancellationToken).ConfigureAwait(false);
                var record = _workspaces.Get(id, cancellationToken);
                workspace.LastUsedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(record.LastUsedAt));
            }
            else
            {
                // A non-registered record is not a registered root and has no registration identity to reopen.
                workspace.Git = new GitStatusSummary { Quality = GitStatusQuality.Unknown };
            }

            var audit = WorkspaceAuditMetadata.ForRecords([workspace]);
            await AuditSuccessAsync(caller, "GetWorkspace", id, workspace.RootPath, audit).ConfigureAwait(false);
            return new WorkspaceServiceGetWorkspaceResponse { Meta = meta, Value = new WorkspaceServiceGetWorkspaceValue { Workspace = workspace }, Audit = audit };
        }
        catch (WorkspacePolicyException refusal)
        {
            await PolicyRefusalAsync(caller, PermissionMatrix.WorkspaceRead, "GetWorkspace", id, refusal.Reason).ConfigureAwait(false);
            return new WorkspaceServiceGetWorkspaceResponse { Meta = meta, Error = NodeErrors.PermissionDenied(PermissionMatrix.WorkspaceRead) };
        }
        catch (Exception exception) when (exception is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException)
        {
            var error = Failure(exception, id);
            await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceRead, "GetWorkspace", id, null, error.Code).ConfigureAwait(false);
            return new WorkspaceServiceGetWorkspaceResponse { Meta = meta, Error = error };
        }
    }

    internal async Task<WorkspaceServiceListWorkspacesResponse> ListAsync(Caller caller, WorkspaceServiceListWorkspacesRequest request,
        CancellationToken cancellationToken)
    {
        var meta = ApiCommands.Meta(request.Meta);
        if (caller.Routed is { } responseRouting)
        {
            meta.CorrelationId = responseRouting.Correlation(request.Meta);
        }
        if (!NodeShapes.IsValid(request))
        {
            await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceRead, "ListWorkspaces", null, null, "invalid_argument").ConfigureAwait(false);
            return new WorkspaceServiceListWorkspacesResponse { Meta = meta, Error = NodeErrors.InvalidArgument("workspace list request") };
        }

        var kinds = request.Kinds.Count == 0 ? (byte)7 :
            (byte)request.Kinds.Aggregate(0, (bits, kind) => bits | (1 << ((int)kind - 1)));
        var limit = request.Page is { HasLimit: true } page ? page.Limit : 100;
        byte[]? after = null;
        long cursorRevision = -1;
        if (request.Page is { HasCursor: true } requested &&
            !WorkspacePageBuilder.TryCursor(requested.Cursor, node.NodeId.Span, kinds, _pageKey, out after, out cursorRevision))
        {
            await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceRead, "ListWorkspaces", null, null, "invalid_cursor").ConfigureAwait(false);
            return new WorkspaceServiceListWorkspacesResponse { Meta = meta, Error = NodeErrors.InvalidCursor() };
        }

        try
        {
            node.Store.Read(reader => { CheckAuthority(reader, caller, PermissionMatrix.WorkspaceRead); return 0; });
            var pageData = node.Store.Read(reader => WorkspaceCatalog.ReadPage(reader, limit, kinds, after));
            if (after is not null && cursorRevision != pageData.Revision)
            {
                throw new WorkspaceInventoryChangedException();
            }

            var projected = new List<Workspace>(pageData.Records.Count);
            var remaining = false;
            foreach (var workspace in pageData.Records)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (projected.Count > 0 && caller.Routed is { } routed && routed.Remaining() < TimeSpan.FromSeconds(2.25))
                {
                    remaining = true;
                    break;
                }

                if (BeforeReadUseForTests is { } coordinate) await coordinate(cancellationToken).ConfigureAwait(false);
                if (workspace.Kind == WorkspaceKind.Registered)
                {
                    try
                    {
                        // A catalogue page always retains the recorded registration. Only a verified root may
                        // be inspected for Git; an unavailable or replaced root is explicitly UNKNOWN.
                        using var use = _workspaces.OpenForUse(workspace.WorkspaceId.Value.Span,
                            transaction => CheckAuthority(transaction, caller, PermissionMatrix.WorkspaceRead), cancellationToken);
                        workspace.Git = await WorkspaceGitStatus.ObserveAsync(use.Root, cancellationToken).ConfigureAwait(false);
                        var record = _workspaces.Get(workspace.WorkspaceId.Value.Span, cancellationToken);
                        workspace.LastUsedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(record.LastUsedAt));
                    }
                    catch (Exception exception) when (exception is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException)
                    {
                        workspace.Git = new GitStatusSummary { Quality = GitStatusQuality.Unknown };
                    }
                }
                else
                {
                    workspace.Git = new GitStatusSummary { Quality = GitStatusQuality.Unknown };
                }

                projected.Add(workspace);
            }

            var response = WorkspacePageBuilder.Build(meta, projected, remaining || pageData.More,
                node.NodeId.Span, kinds, pageData.Revision, _pageKey);
            await AuditSuccessAsync(caller, "ListWorkspaces", null, null, response.Audit, pageData.Revision).ConfigureAwait(false);
            return response;
        }
        catch (WorkspaceInventoryChangedException)
        {
            await AuditRefusalAsync(caller, PermissionMatrix.WorkspaceRead, "ListWorkspaces", null, null, "invalid_cursor").ConfigureAwait(false);
            return new WorkspaceServiceListWorkspacesResponse { Meta = meta, Error = NodeErrors.InvalidCursor() };
        }
        catch (WorkspacePolicyException refusal)
        {
            await PolicyRefusalAsync(caller, PermissionMatrix.WorkspaceRead, "ListWorkspaces", null, refusal.Reason).ConfigureAwait(false);
            return new WorkspaceServiceListWorkspacesResponse { Meta = meta, Error = NodeErrors.PermissionDenied(PermissionMatrix.WorkspaceRead) };
        }
    }

    private async Task<T> MutationAsync<T>(Caller caller, IMessage request, RequestMeta meta, string method, string operation,
        MessageParser<T> parser, Func<ArcError, T> fail, Func<CommandContext, T> effect, byte[]? workspaceId = null)
        where T : class, IMessage<T>
    {
        var digest = ApiCommands.Digest(caller, request);
        try
        {
            var result = await node.Processor.ExecuteIdempotentAsync(meta.CommandId.Value.Memory, Service + "/" + method, digest, Origin.Remote,
                command =>
                {
                    var outcome = effect(command);
                    var error = outcome switch
                    {
                        WorkspaceServiceRegisterWorkspaceResponse response => response.Error,
                        WorkspaceServiceUnregisterWorkspaceResponse response => response.Error,
                        _ => null,
                    };
                    if (error is not null && caller.Routed is { } routed)
                    {
                        RoutedFileErrors.Complete(error, meta, routed.CallId, node.Clock);
                    }

                    return outcome.ToByteArray();
                },
                beforeDedup: command =>
                {
                    caller.Routed?.BeforeReplay();
                    return RoutedCommandOwnership.MayExecute(command.Transaction, meta.CommandId.Value.Span, caller.CenterCaller,
                        "WorkspaceService." + method, digest) ? null : StoreErrors.CommandIdReused();
                },
                afterComplete: command => RoutedCommandOwnership.Record(command.Transaction, meta.CommandId.Value.Span, caller.Actor)).ConfigureAwait(false);
            if (result.Error is { } error)
            {
                await AuditRefusalAsync(caller, operation, method, workspaceId, null, error.Code).ConfigureAwait(false);
                return fail(error);
            }

            return parser.ParseFrom(result.Outcome);
        }
        catch (WorkspacePolicyException refusal)
        {
            await PolicyRefusalAsync(caller, operation, method, workspaceId, refusal.Reason).ConfigureAwait(false);
            return fail(NodeErrors.PermissionDenied(operation));
        }
        catch (CommandQueueFullException)
        {
            return fail(NodeErrors.Overloaded(node.Clock.GetUtcNow()));
        }
    }

    private void CheckAuthority(StoreReader reader, Caller caller, string operation)
    {
        if (caller.CenterCaller is not { } center || caller.Routed is null)
        {
            throw new WorkspacePolicyException("center_caller_incomplete");
        }

        try
        {
            var policy = PolicyRules.Current(reader);
            if (!CryptographicOperations.FixedTimeEquals(policy.Digest, PolicyDocuments.Digest(policy.Document)) ||
                policy.Document.Permissions.Any(item => PermissionMatrix.Valid(item) is not null) ||
                policy.Document.CenterRouted is { HasRelayedFrom: true } route && route.RelayedFrom is not (RelayedFrom.Unspecified or RelayedFrom.OwnNode or RelayedFrom.Account))
            {
                throw new WorkspacePolicyException("policy_invalid");
            }

            if (CenterRouting.Refusal(center, node.NodeId.Span, policy.Document.CenterRouted) is { } reason)
            {
                throw new WorkspacePolicyException(reason);
            }

            if (PermissionMatrix.DecideRouted(operation, caller.CellsOrigin, policy.Document.Permissions).Decision != PermissionDecision.Allow)
            {
                throw new WorkspacePolicyException("denied");
            }

            caller.Routed.BeforeEffect(reader);
        }
        catch (WorkspacePolicyException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new WorkspacePolicyException("policy_invalid");
        }
    }

    private Task<int> AuditSuccessAsync(Caller caller, string method, byte[]? id, string? path, FileAuditMetadata metadata, long? inventoryRevision = null) =>
        node.Processor.ExecuteAsync(command =>
        {
            CheckAuthority(command.Transaction, caller, PermissionMatrix.WorkspaceRead);
            if (inventoryRevision is { } expected)
            {
                if (command.Transaction.Scalar("SELECT revision FROM workspace_inventory_revision WHERE singleton = 1;") is not long actual || actual != expected)
                {
                    throw new WorkspaceInventoryChangedException();
                }
            }
            AuditLog.AppendFileWorkspace(command.Transaction, caller.Actor, "workspace.read WorkspaceService." + method, id, null, path,
                PermissionDecision.Allow, "read", metadata);
            return 0;
        }, CommitDurability.Full);

    private Task<int> AuditRefusalAsync(Caller caller, string operation, string method, byte[]? id, string? path, string reason) =>
        node.Processor.ExecuteAsync(command =>
        {
            AuditLog.AppendFileWorkspace(command.Transaction, caller.Actor, operation + " WorkspaceService." + method, id, null, path,
                PermissionDecision.Deny, "refused: " + reason, null);
            return 0;
        }, CommitDurability.Full);

    private async Task PolicyRefusalAsync(Caller caller, string operation, string method, byte[]? id, string reason)
    {
        caller.Routed?.Refused(operation, reason);
        await AuditRefusalAsync(caller, operation, method, id, null, reason).ConfigureAwait(false);
        caller.Routed?.MarkAudited();
    }

    private static Workspace Projection(RegisteredWorkspace record, GitStatusSummary? summary) => new()
    {
        WorkspaceId = new Id { Value = ByteString.CopyFrom(record.Id) },
        Kind = WorkspaceKind.Registered,
        State = WorkspaceState.Active,
        Name = record.Name,
        RootPath = record.RootPath,
        CreatedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(record.CreatedAt)),
        LastUsedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(record.LastUsedAt)),
        Git = summary,
    };

    private static ArcError Failure(Exception exception, byte[]? id)
    {
        if (exception is RegisteredWorkspaceException { Reason: "workspace_root_unavailable", InnerException: WorkspacePathException native } &&
            native.Reason is "native_2" or "native_3" or "native_20" or "root_not_directory")
        {
            return ClosedError(ErrorCategory.Conflict, "file_changed", "workspace_root_changed");
        }

        var reason = exception switch
        {
            RegisteredWorkspaceException registered => registered.Reason,
            WorkspacePathException path => path.Reason,
            UnauthorizedAccessException => "file_access_denied",
            _ => "workspace_path_invalid",
        };
        if (reason == "workspace_not_found")
        {
            return NodeErrors.NotFound("workspace", id ?? []);
        }

        if (reason == "workspace_in_use")
        {
            return NodeErrors.InUse(reason);
        }

        if (reason is "native_2" or "native_3")
        {
            return NodeErrors.Validation("path_not_found", "workspace_root");
        }

        if (reason is "workspace_path_invalid" or "workspace_name_invalid" or "path_invalid" or "root_not_absolute" or "path_reserved")
        {
            return NodeErrors.InvalidArgument(reason);
        }

        if (reason is "workspace_root_changed" or "workspace_path_conflict" or "workspace_identity_conflict" or
            "workspace_registration_changed" or "legacy_snapshot_changed")
        {
            return ClosedError(ErrorCategory.Conflict, "file_changed", reason);
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
        return ClosedError(ErrorCategory.State, "file_access_denied", closed);
    }

    private static ArcError ClosedError(ErrorCategory category, string code, string reason) => new()
    {
        Category = category,
        Code = code,
        MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = reason } },
    };

    private sealed class WorkspaceInventoryChangedException : Exception;

    private sealed class WorkspacePolicyException(string reason) : Exception(reason)
    {
        internal string Reason { get; } = reason;
    }
}
