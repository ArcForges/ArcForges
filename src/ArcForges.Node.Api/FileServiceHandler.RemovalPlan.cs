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
using Microsoft.Data.Sqlite;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed class RemovalPlanResponseUnavailableException : Exception { }

internal sealed partial class FileServiceHandler
{
    // Coordinates a test-owned transactional failure after actual plan inserts; production never sets this callback.
    internal Action? AfterRemovalPlanInsertForTests { get; set; }

    // In-process tests alone inject failures before or at the return from the real FULL commit.
    internal Action<StoreTransaction>? AfterRemovalSizeRefusalForTests { get; set; }
    internal Action? AfterRemovalSizeCommitForTests { get; set; }

    // Coordinates test-owned file changes and repeated real ownership checks; production sets neither callback.
    internal Action? AfterRemovalOwnershipReadForTests { get; set; }
    internal Action<WorkspaceRemovalEntry, Action>? AfterRemovalOwnershipCheckForTests { get; set; }

    internal async Task<FileServicePlanRemovalResponse> PlanRemovalAsync(Caller caller, FileServicePlanRemovalRequest request,
        CancellationToken cancellationToken)
    {
        var routed = caller.Routed ?? throw new InvalidOperationException("A removal plan requires a verified routed caller.");
        var raw = caller.RawRequest ?? throw new InvalidOperationException("The original transmitted request is required.");
        var limit = routed.RemainingFileOperation();
        if (limit <= TimeSpan.Zero) throw new OperationCanceledException(cancellationToken);
        var started = node.Clock.GetTimestamp();
        using var deadline = new CancellationTokenSource(limit, node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var token = linked.Token;
        var pending = node.Processor.ExecuteAsync(command => PlanRemovalInTransaction(command.Transaction, caller, request,
            SHA256.HashData(raw), started, limit, token), CommitDurability.Full);
        RemovalPlanOutcome outcome;
        try
        {
            outcome = await pending.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = ObserveRemovalPlanPendingAsync(pending);
            throw;
        }
        catch (SqliteException)
        {
            // The COMMIT may have taken effect even when its completion was not returned. Do not fabricate a
            // size refusal or a rollback; only a subsequently recovered exact receipt can establish the outcome.
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);
            var uncertain = NodeErrors.Internal(node.Clock.GetUtcNow());
            uncertain.Retry = new RetryAdvice { Mode = RetryMode.Never };
            RoutedFileErrors.Complete(uncertain, request.Meta, routed.CallId, node.Clock);
            return new FileServicePlanRemovalResponse
            {
                Meta = new ResponseMeta { CorrelationId = uncertain.CorrelationId.Clone() },
                Error = uncertain,
            };
        }

        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        if (outcome.Abort is { } abort) throw abort;
        if (outcome.PolicyReason is { } reason)
        {
            routed.Refused(PermissionMatrix.CleanupPlan, reason);
            routed.MarkAudited();
        }

        return outcome.Response!;
    }

    private RemovalPlanOutcome PlanRemovalInTransaction(StoreTransaction transaction, Caller caller,
        FileServicePlanRemovalRequest request, byte[] rawDigest, long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        var workspace = request.WorkspacePath?.WorkspaceId is { Value.Length: 16 } id &&
            id.Value.Span.IndexOfAnyExcept((byte)0) >= 0 ? id.Value.ToByteArray() : null;
        var attempt = request.AttemptId is { Value.Length: 16 } attemptId &&
            attemptId.Value.Span.IndexOfAnyExcept((byte)0) >= 0 ? attemptId.Value.ToByteArray() : null;
        string? path = null;
        using var inputAudit = new WorkspaceOwnershipInputAudit { AfterReadForTests = AfterRemovalOwnershipReadForTests };

        void CheckBudget()
        {
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        }

        void Audit(PermissionDecision decision, string outcome) => AuditLog.AppendFileWorkspace(transaction, caller.Actor,
            "cleanup.plan FileService.PlanRemoval", workspace, attempt, path, decision, outcome, inputAudit.Snapshot());

        FileServicePlanRemovalResponse Refusal(ArcError error)
        {
            RoutedFileErrors.Complete(error, request.Meta, routed.CallId, node.Clock);
            Audit(PermissionDecision.Deny, "refused: " + error.Code);
            return new FileServicePlanRemovalResponse { Meta = meta.Clone(), Error = error, Audit = inputAudit.Snapshot() };
        }

        try
        {
            CheckBudget();
            if (request.WorkspacePath is { HasPath: true } selected && StrictUtf8.GetByteCount(selected.Path) <= 4096)
                path = selected.Path;
            if (request.WorkspacePath is { HasPath: true } oversized && StrictUtf8.GetByteCount(oversized.Path) > 4096)
            {
                var bounded = request.Clone();
                bounded.WorkspacePath.Path = "x";
                return new RemovalPlanOutcome(Refusal(NodeShapes.IsValid(bounded)
                    ? RemovalLimit(correlation, "path_bytes", "4096")
                    : Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation)));
            }

            if (!NodeShapes.IsValid(request) || request.Meta?.CommandId is not { Value.Length: 16 } command ||
                caller.CenterCaller is null || CenterRouting.Shape(caller.CenterCaller) is not null)
                return new RemovalPlanOutcome(Refusal(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation)));

            var commandId = command.Value.ToByteArray();
            routed.BeforeReplay();
            var liveReceipt = RemovalHasLiveReceipt(transaction, commandId);
            if (!RemovalCallerMayUse(transaction, commandId, caller.CenterCaller) ||
                !liveReceipt && !RoutedCommandOwnership.MayExecute(transaction, commandId, caller.CenterCaller, "FileService.PlanRemoval", rawDigest))
                return new RemovalPlanOutcome(Refusal(StoreErrors.CommandIdReused()));

            var decision = CommandDeduplication.Begin(transaction, commandId,
                "arcforges.node.v1.FileService/PlanRemoval", rawDigest, Origin.Remote);
            if (decision.Status == DedupStatus.Replay)
            {
                var replay = FileServicePlanRemovalResponse.Parser.ParseFrom(decision.Outcome!.Value.Span);
                var replayPolicyReason = transaction.Scalar(
                    "SELECT policy_reason FROM file_removal_command_owner WHERE command_id = $id;", ("$id", commandId)) as string;
                if (replay.Error is { Category: ErrorCategory.Authorization } && replayPolicyReason is null)
                    throw new InvalidDataException("The recorded plan policy reason is unavailable.");
                Audit(replay.Error is null ? PermissionDecision.Allow : PermissionDecision.Deny,
                    replay.Error is null ? "replayed: planned" : "replayed: " + replay.Error.Code);
                return new RemovalPlanOutcome(replay, PolicyReason: replayPolicyReason);
            }
            if (decision.Status is DedupStatus.Conflict or DedupStatus.InProgress)
                return new RemovalPlanOutcome(Refusal(decision.Error ?? NodeErrors.Internal(node.Clock.GetUtcNow())));

            FileServicePlanRemovalResponse response;
            string? policyReason = null;
            var planInsertionStarted = false;
            try
            {
                CheckPlanAuthority(transaction, caller);
                CheckBudget();
                if (attempt is not null)
                {
                    // A terminal attempt needs durable managed-directory provenance and all live-use checks.
                    // Until those producers are wired, distinguish unknown/foreign IDs from a real unavailable identity.
                    response = Refusal(AttemptRefusal(transaction, caller, attempt, correlation));
                }
                else if (workspace is null || request.WorkspacePath is not { HasPath: true } target)
                {
                    response = Refusal(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
                }
                else
                {
                    // A separate known, unresolved protection gap means this new endpoint cannot establish that a
                    // recorded private object is outside the proposed tree. Refuse rather than disclose its metadata.
                    using var use = _workspaces.OpenForUse(transaction, workspace,
                        beforeUse: selected => CheckPlanAuthority(selected, caller), token);
                    if (transaction.Scalar("SELECT 1 FROM file_private_stage_object LIMIT 1;") is not null)
                        throw new WorkspaceRemovalPlanException("file_access_denied");
                    var snapshot = WorkspaceRemovalPlan.Capture(use.Root, target.Path, token);
                    var verifiedOwners = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var entry in snapshot.Entries)
                    {
                        CheckBudget();
                        bool CheckOwner() => FileCreationOwnership.IsVerifiedAgent(transaction, caller.CenterCaller, workspace,
                            use.Root, entry, token, inputAudit);
                        if (CheckOwner()) verifiedOwners.Add(entry.Path);
                        AfterRemovalOwnershipCheckForTests?.Invoke(entry, () => _ = CheckOwner());
                    }
                    if (verifiedOwners.Count != 0)
                    {
                        // Ownership readback may take time. Re-observe the entire plan before recording a positive item.
                        var rechecked = WorkspaceRemovalPlan.Capture(use.Root, target.Path, token);
                        if (rechecked.Entries.Count != snapshot.Entries.Count || rechecked.TotalBytes != snapshot.TotalBytes ||
                            !rechecked.RootIdentity.Bytes.AsSpan().SequenceEqual(snapshot.RootIdentity.Bytes) ||
                            rechecked.Entries.Where((entry, index) =>
                                !entry.FingerprintSha256.AsSpan().SequenceEqual(snapshot.Entries[index].FingerprintSha256)).Any())
                            throw new WorkspaceRemovalPlanException("planned_tree_changed");
                    }
                    CheckBudget();
                    CheckPlanAuthority(transaction, caller);
                    var sample = RoutedFileValidationTime.Sample(transaction);
                    if (!sample.Healthy) throw new RoutedAbortException(RoutedAbort.ClockUncertain);
                    var prepared = FileRemovalPlans.PrepareWorkspace(transaction, commandId, rawDigest, caller.CenterCaller,
                        caller.Actor, target, use.Root.RootPath, snapshot, sample.BoundaryMicroseconds, verifiedOwners);
                    response = new FileServicePlanRemovalResponse
                    {
                        Meta = meta,
                        Value = new FileServicePlanRemovalValue { Plan = prepared.Plan },
                        Audit = inputAudit.Snapshot(),
                    };
                    // A different malformed candidate cannot be misreported as an observed response-size limit.
                    if (!NodeShapes.IsValid(meta) || !NodeShapes.IsValid(prepared.Plan)) throw new RemovalPlanResponseUnavailableException();
                    // Size the entire exact signed inner response before inserting any plan, item or successful receipt.
                    if (!RemovalPlanResponseFits(response))
                    {
                        response = Refusal(RemovalLimit(correlation, "removal_plan_response_bytes", "1040384"));
                        AfterRemovalSizeRefusalForTests?.Invoke(transaction);
                        transaction.AfterCommitForTests = AfterRemovalSizeCommitForTests;
                    }
                    else
                    {
                        if (!NodeShapes.IsValid(response)) throw new RemovalPlanResponseUnavailableException();
                        planInsertionStarted = true;
                        FileRemovalPlans.RecordWorkspace(transaction, prepared);
                        AfterRemovalPlanInsertForTests?.Invoke();
                        Audit(PermissionDecision.Allow, "planned");
                    }
                }
            }
            catch (FilePolicyException denied)
            {
                policyReason = denied.Reason;
                response = Refusal(Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.CleanupPlan, correlation));
            }
            catch (RegisteredWorkspaceException failure) when (!planInsertionStarted && failure.Reason == "workspace_not_found")
            {
                response = Refusal(NodeErrors.NotFound("workspace", workspace ?? []));
            }
            catch (WorkspaceRemovalPlanException failure) when (!planInsertionStarted)
            {
                var error = failure.Reason switch
                {
                    "removal_descendants" => RemovalLimit(correlation, "removal_descendants", "1000"),
                    "removal_total_bytes" => RemovalLimit(correlation, "removal_total_bytes", "67108864"),
                    "removal_ownership_input_bytes" => RemovalLimit(correlation, "removal_ownership_input_bytes", "67108864"),
                    "planned_tree_changed" => Error(ErrorCategory.Conflict, "file_changed", "planned_tree_changed", correlation),
                    "path_link_or_special" => Error(ErrorCategory.State, "file_access_denied", "path_link_or_special", correlation),
                    "path_enforcement_unavailable" => Error(ErrorCategory.State, "file_access_denied", "path_enforcement_unavailable", correlation),
                    _ => Error(ErrorCategory.State, "file_access_denied", "file_access_denied", correlation),
                };
                response = Refusal(error);
                if (failure.Reason == "removal_ownership_input_bytes")
                {
                    AfterRemovalSizeRefusalForTests?.Invoke(transaction);
                    transaction.AfterCommitForTests = AfterRemovalSizeCommitForTests;
                }
            }
            catch (WorkspacePathException failure) when (!planInsertionStarted && (failure.Reason is "directory_changed" or "directory_identity_changed" or "file_identity_changed"))
            {
                response = Refusal(Error(ErrorCategory.Conflict, "file_changed", "planned_tree_changed", correlation));
            }
            catch (Exception failure) when (!planInsertionStarted && (failure is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or IOException or ArgumentException))
            {
                response = Refusal(Failure(failure, correlation));
            }

            CheckBudget();
            routed.BeforeEffect(transaction);
            CheckBudget();
            CommandDeduplication.Complete(transaction, commandId, response.ToByteArray());
            transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller, policy_reason) VALUES ($id, $caller, $reason);",
                ("$id", commandId), ("$caller", caller.CenterCaller.ToByteArray()), ("$reason", policyReason));
            return new RemovalPlanOutcome(response, PolicyReason: policyReason);
        }
        catch (EncoderFallbackException)
        {
            path = null;
            return new RemovalPlanOutcome(Refusal(Error(ErrorCategory.Validation, "invalid_argument", "path: utf8", correlation)));
        }
    }

    private void CheckPlanAuthority(StoreReader reader, Caller caller)
    {
        if (caller.CenterCaller is not { } center || caller.Routed is null) throw new FilePolicyException("center_caller_incomplete");
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
            if (PermissionMatrix.DecideRouted(PermissionMatrix.CleanupPlan, caller.CellsOrigin, policy.Document.Permissions).Decision != PermissionDecision.Allow)
                throw new FilePolicyException("denied");
            caller.Routed.BeforeEffect(reader);
        }
        catch (FilePolicyException) { throw; }
        catch (Exception exception) when (exception is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new FilePolicyException("policy_invalid");
        }
    }

    private static bool RemovalHasLiveReceipt(StoreReader reader, byte[] commandId)
    {
        using var command = reader.CreateCommand("SELECT expires_at FROM command_dedup WHERE command_id = $id;");
        command.Parameters.AddWithValue("$id", commandId);
        return command.ExecuteScalar() is long expires &&
            (expires > reader.NowMicroseconds || RoutedFileRetention.IsHeld(reader, commandId));
    }

    private static bool RemovalCallerMayUse(StoreReader reader, byte[] commandId, CenterCaller caller)
    {
        if (!RemovalHasLiveReceipt(reader, commandId)) return true;
        using var owner = reader.CreateCommand("SELECT caller FROM file_removal_command_owner WHERE command_id = $id;");
        owner.Parameters.AddWithValue("$id", commandId);
        try
        {
            return owner.ExecuteScalar() is byte[] encoded && CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom(encoded), caller);
        }
        catch (InvalidProtocolBufferException) { return false; }
    }

    private static ArcError AttemptRefusal(StoreReader reader, Caller caller, byte[] attempt, Id correlation)
    {
        using (var command = reader.CreateCommand("""
            SELECT a.state, t.state, t.owner, t.pinned
            FROM attempt a JOIN task t ON t.task_id = a.task_id WHERE a.attempt_id = $id;
            """))
        {
            command.Parameters.AddWithValue("$id", attempt);
            using var row = command.ExecuteReader();
            if (!row.Read()) return NodeErrors.NotFound("attempt", attempt);
            ActorRef owner;
            try { owner = ActorRef.Parser.ParseFrom((byte[])row.GetValue(2)); }
            catch (InvalidProtocolBufferException) { return NodeErrors.NotFound("attempt", attempt); }
            if (!CenterRouting.SameFileCaller(owner.CenterCaller, caller.CenterCaller)) return NodeErrors.NotFound("attempt", attempt);
            if (row.GetInt32(0) != 9 || row.GetInt32(1) is < 7 or > 10 || row.GetInt32(3) != 0)
                return NodeErrors.InUse("attempt_in_use");
        }

        using (var directories = reader.CreateCommand("""
            SELECT state, pinned FROM managed_directory
            WHERE owner_kind = 1 AND owner_id = $id AND root_class = 'tmp' AND state <> 5;
            """))
        {
            directories.Parameters.AddWithValue("$id", attempt);
            using var row = directories.ExecuteReader();
            if (!row.Read()) return Error(ErrorCategory.State, "file_access_denied", "identity_unavailable", correlation);
            var state = row.GetInt32(0);
            var pinned = row.GetInt32(1);
            if (row.Read()) return Error(ErrorCategory.State, "file_access_denied", "identity_unavailable", correlation);
            if (state == 1 || pinned != 0) return NodeErrors.InUse("managed_directory_in_use");
            if (state is not (2 or 3)) return NodeErrors.NotFound("attempt", attempt);
        }

        // A Windows-created attempt may now have a provenance record, but this endpoint does not yet re-open and
        // verify that identity or establish all live-reference and lease conditions. Never infer those facts from
        // a terminal row or accept a caller-provided path as a substitute.
        return Error(ErrorCategory.State, "file_access_denied", "identity_unavailable", correlation);
    }

    internal static bool RemovalPlanResponseFits(FileServicePlanRemovalResponse response) =>
        response.CalculateSize() <= ArcForges.Node.CloudLink.ResultSigner.MaxPayloadBytes;

    private static ArcError RemovalLimit(Id correlation, string name, string maximum) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails
        {
            Limit = new LimitFailure
            {
                LimitName = name,
                Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = maximum },
            }
        },
    };

    private async Task ObserveRemovalPlanPendingAsync(Task<RemovalPlanOutcome> pending)
    {
        try { _ = await pending.ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { node.Log.Error("api.file.removal_plan.audit_failed"); }
    }

    private sealed record RemovalPlanOutcome(FileServicePlanRemovalResponse? Response = null, Exception? Abort = null, string? PolicyReason = null);
}
