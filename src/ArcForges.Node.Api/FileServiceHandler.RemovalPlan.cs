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
                    var (attemptTarget, refusal) = ResolveAttemptPlanTarget(transaction, caller, attempt, correlation);
                    if (refusal is not null)
                    {
                        response = Refusal(refusal);
                    }
                    else
                    {
                        if (node.Execution is null)
                            response = Refusal(Error(ErrorCategory.State, "file_access_denied", "identity_unavailable", correlation));
                        else if (AttemptHasDirectReferences(transaction, attemptTarget!, attempt))
                            response = Refusal(NodeErrors.InUse("attempt_in_use"));
                        else
                        {
                            var target = attemptTarget ?? throw new InvalidDataException("Attempt provenance is unavailable.");
                            // Preserve the existing private-stage fail-closed boundary; an unbound reservation is
                            // also ambiguous. This does not establish privacy of other file endpoints.
                            if (transaction.Scalar("SELECT 1 FROM file_private_stage_object LIMIT 1;") is not null ||
                                transaction.Scalar("SELECT 1 FROM file_private_stage_reservation LIMIT 1;") is not null)
                                throw new WorkspaceRemovalPlanException("file_access_denied");

                            using var temporaryRoot = OpenAttemptPlanRoot(target);
                            var snapshot = WorkspaceRemovalPlan.Capture(temporaryRoot, target.Name, token);
                            if (snapshot.Entries.Count == 0 ||
                                !snapshot.Entries[0].NativeIdentity.Bytes.AsSpan().SequenceEqual(target.DirectoryIdentity) ||
                                snapshot.Entries[0].NativeIdentity.Platform != target.Platform)
                                throw new WorkspaceRemovalPlanException("planned_tree_changed");
                            if (AttemptTreeHasHold(transaction, temporaryRoot, snapshot, token) ||
                                AttemptHasPathReferences(transaction, temporaryRoot, target, CheckBudget))
                                response = Refusal(NodeErrors.InUse("attempt_in_use"));
                            else
                            {
                                var relativeEntries = snapshot.Entries.Select(entry => entry with
                                {
                                    Path = AttemptRelativePath(target.Name, entry.Path),
                                }).ToArray();
                                var relativeSnapshot = snapshot with { Entries = relativeEntries };
                                CheckBudget();
                                if (AttemptHasDirectReferences(transaction, target, attempt))
                                {
                                    response = Refusal(NodeErrors.InUse("attempt_in_use"));
                                }
                                else
                                {
                                    CheckPlanAuthority(transaction, caller);
                                    var sample = RoutedFileValidationTime.Sample(transaction);
                                    if (!sample.Healthy) throw new RoutedAbortException(RoutedAbort.ClockUncertain);
                                    var prepared = FileRemovalPlans.PrepareAttempt(transaction, commandId, rawDigest, caller.CenterCaller,
                                        caller.Actor, request.AttemptId!, Path.Combine(temporaryRoot.RootPath, target.Name),
                                        relativeSnapshot, sample.BoundaryMicroseconds);
                                    response = new FileServicePlanRemovalResponse
                                    {
                                        Meta = meta,
                                        Value = new FileServicePlanRemovalValue { Plan = prepared.Plan },
                                        Audit = inputAudit.Snapshot(),
                                    };
                                    if (!NodeShapes.IsValid(meta) || !NodeShapes.IsValid(prepared.Plan))
                                        throw new RemovalPlanResponseUnavailableException();
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
                                        FileRemovalPlans.RecordAttempt(transaction, prepared);
                                        AfterRemovalPlanInsertForTests?.Invoke();
                                        Audit(PermissionDecision.Allow, "planned");
                                    }
                                }
                            }
                        }
                    }
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
                    "identity_unavailable" => Error(ErrorCategory.State, "file_access_denied", "identity_unavailable", correlation),
                    _ => Error(ErrorCategory.State, "file_access_denied", "file_access_denied", correlation),
                };
                response = Refusal(error);
                if (failure.Reason == "removal_ownership_input_bytes")
                {
                    AfterRemovalSizeRefusalForTests?.Invoke(transaction);
                    transaction.AfterCommitForTests = AfterRemovalSizeCommitForTests;
                }
            }
            catch (WorkspacePathException failure) when (!planInsertionStarted && attempt is not null && OperatingSystem.IsWindows() &&
                (failure.Reason is "native_32" or "native_33"))
            {
                response = Refusal(NodeErrors.InUse("attempt_in_use"));
            }
            catch (WorkspacePathException failure) when (!planInsertionStarted && attempt is not null &&
                (failure.Reason is "native_2" or "native_3" or "native_20" or "root_changed" or "root_not_directory"))
            {
                response = Refusal(Error(ErrorCategory.Conflict, "file_changed", "planned_tree_changed", correlation));
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

    private sealed record AttemptPlanTarget(string Name, string RootPath, int Platform, byte[] RootIdentity,
        byte[] DirectoryIdentity, byte[] TaskId);

    private static (AttemptPlanTarget? Target, ArcError? Error) ResolveAttemptPlanTarget(
        StoreReader reader, Caller caller, byte[] attempt, Id correlation)
    {
        byte[] taskId;
        byte[] taskOwner;
        using (var command = reader.CreateCommand("""
            SELECT a.state, t.state, t.owner, t.pinned, a.task_id, a.finished_at, a.termination_reason, a.leftover_count
            FROM attempt a JOIN task t ON t.task_id = a.task_id WHERE a.attempt_id = $id;
            """))
        {
            command.Parameters.AddWithValue("$id", attempt);
            using var row = command.ExecuteReader();
            if (!row.Read()) return (null, NodeErrors.NotFound("attempt", attempt));
            taskOwner = (byte[])row.GetValue(2);
            ActorRef owner;
            try { owner = ActorRef.Parser.ParseFrom(taskOwner); }
            catch (InvalidProtocolBufferException) { return (null, NodeErrors.NotFound("attempt", attempt)); }
            if (!CenterRouting.SameFileCaller(owner.CenterCaller, caller.CenterCaller))
                return (null, NodeErrors.NotFound("attempt", attempt));
            if (row.GetInt32(0) != 9 || row.GetInt32(1) is < 7 or > 10 || row.GetInt32(3) != 0 ||
                row.IsDBNull(5) || row.IsDBNull(6) || row.GetInt32(7) != 0 ||
                row.GetInt32(6) is (int)TerminationReason.Lost or (int)TerminationReason.TerminationIncomplete)
                return (null, NodeErrors.InUse("attempt_in_use"));
            taskId = (byte[])row.GetValue(4);
        }

        using var directories = reader.CreateCommand("""
            SELECT m.state, m.pinned, m.relative_path, p.task_id, p.owner, p.root_platform,
                   p.root_identity, p.directory_identity, r.path
            FROM managed_directory m
            LEFT JOIN file_attempt_temp_identity p ON p.directory_id = m.directory_id AND p.attempt_id = $id
            LEFT JOIN root_location r ON r.root_class = m.root_class
            WHERE m.owner_kind = 1 AND m.owner_id = $id AND m.root_class = 'tmp'
              AND m.relative_path = $name AND m.state <> 5;
            """);
        directories.Parameters.AddWithValue("$id", attempt);
        directories.Parameters.AddWithValue("$name", ArcForges.Client.IdText.Format(attempt));
        using var selected = directories.ExecuteReader();
        ArcError unavailable() => Error(ErrorCategory.State, "file_access_denied", "identity_unavailable", correlation);
        if (!selected.Read()) return (null, unavailable());
        var state = selected.GetInt32(0);
        var pinned = selected.GetInt32(1);
        if (state == 1 || pinned != 0) return (null, NodeErrors.InUse("managed_directory_in_use"));
        // QUARANTINED is not an available attempt-temp planning target. This state does not prove a move occurred.
        if (state is not (2 or 3)) return (null, NodeErrors.NotFound("attempt_temp", attempt));
        if (Enumerable.Range(3, 6).Any(selected.IsDBNull) ||
            selected.GetString(2) != ArcForges.Client.IdText.Format(attempt) ||
            !((byte[])selected.GetValue(3)).AsSpan().SequenceEqual(taskId) ||
            !((byte[])selected.GetValue(4)).AsSpan().SequenceEqual(taskOwner) ||
            selected.GetInt32(5) != 1 || !OperatingSystem.IsWindows())
            return (null, unavailable());
        var target = new AttemptPlanTarget(selected.GetString(2), selected.GetString(8), selected.GetInt32(5),
            (byte[])selected.GetValue(6), (byte[])selected.GetValue(7), taskId);
        if (selected.Read()) return (null, unavailable());
        return (target, null);
    }

    private WorkspacePath OpenAttemptPlanRoot(AttemptPlanTarget target)
    {
        // The stored path is evidence, never an authority for an arbitrary root.
        var root = WorkspacePath.OpenRoot(Path.Combine(node.DataRoot, "tmp"));
        try
        {
            var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            if (!string.Equals(root.RootPath, target.RootPath, StringComparison.OrdinalIgnoreCase) ||
                identity.Platform != target.Platform || !identity.Bytes.AsSpan().SequenceEqual(target.RootIdentity))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            return root;
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }

    private bool AttemptHasDirectReferences(StoreReader reader, AttemptPlanTarget target, byte[] attempt)
    {
        // These records directly bind the selected task or attempt. An unrelated active row is not evidence
        // that this particular tree is in use.
        if (node.Execution is null || node.Execution.Running(target.Name) is not null) return true;
        return reader.Scalar("""
            SELECT 1 WHERE EXISTS(SELECT 1 FROM workspace WHERE leased_by_attempt_id = $attempt)
                OR EXISTS(SELECT 1 FROM task_concurrency_key WHERE task_id = $task AND released_at IS NULL)
                OR EXISTS(SELECT 1 FROM remote_attempt WHERE released_at IS NULL AND
                    (local_task_id = $task OR (origin_node_id = $node AND origin_attempt_id = $attempt)));
            """, ("$attempt", attempt), ("$task", target.TaskId), ("$node", node.NodeId.ToArray())) is not null;
    }

    private static bool AttemptHasPathReferences(StoreReader reader, WorkspacePath temporaryRoot,
        AttemptPlanTarget target, Action checkBudget)
    {
        // Compare native identities of checked paths and their retained ancestors, never textual prefixes.
        // These observations cover the persisted paths below; they do not establish that an external process
        // has no open handle or that an unrecorded reference does not exist.
        var targetKey = FileCreationOwnership.StableKey(target.Platform, target.DirectoryIdentity)
            ?? throw new WorkspacePathException("identity_unavailable");
        var targetAncestors = temporaryRoot.WindowsRootAncestors().Select(WindowsDirectoryKey).ToArray();
        var observations = new Dictionary<string, (RegisteredWorkspaces.RootIdentity Identity, bool Overlaps)>(StringComparer.Ordinal);

        bool Overlaps(string? path, int? expectedPlatform = null, byte[]? expectedIdentity = null)
        {
            checkBudget();
            if (string.IsNullOrEmpty(path)) return false;
            if (!observations.TryGetValue(path, out var observation))
            {
                try
                {
                    using var reference = WorkspacePath.OpenRoot(Path.TrimEndingDirectorySeparator(path));
                    var identity = RegisteredWorkspaces.RootIdentity.Encode(reference.RootIdentity);
                    var referenceKey = WindowsDirectoryKey(reference.RootIdentity);
                    var overlaps = targetAncestors.Any(item => item.AsSpan().SequenceEqual(referenceKey)) ||
                        reference.WindowsRootAncestors().Any(item => WindowsDirectoryKey(item).AsSpan().SequenceEqual(targetKey));
                    observation = (identity, overlaps);
                    observations.Add(path, observation);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    // A persisted reference path could not be safely opened/identified; this is not an observed
                    // change to the target and is not proof that the reference is unrelated.
                    throw new WorkspaceRemovalPlanException("identity_unavailable", exception);
                }
            }

            // A registered workspace has a stronger stored root binding. Use the full identity for that binding;
            // the overlap comparison above deliberately ignores the mutable creation-time part of the ID.
            if (expectedPlatform is { } platform &&
                (expectedIdentity is null || platform != observation.Identity.Platform ||
                 !CryptographicOperations.FixedTimeEquals(expectedIdentity, observation.Identity.Bytes)))
                throw new WorkspaceRemovalPlanException("identity_unavailable");
            return observation.Overlaps;
        }

        using (var sessions = reader.CreateCommand("""
            SELECT s.cwd, w.root_path, i.platform, i.native_identity FROM session s
            LEFT JOIN workspace w ON w.workspace_id = s.workspace_id
            LEFT JOIN workspace_root_identity i ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE s.state IN (1, 2) OR EXISTS
                (SELECT 1 FROM session_subagent a WHERE a.session_id = s.session_id AND a.stopped_at IS NULL);
            """))
        using (var rows = sessions.ExecuteReader())
        {
            while (rows.Read())
                if (Overlaps(rows.IsDBNull(0) ? null : rows.GetString(0)) ||
                    Overlaps(rows.IsDBNull(1) ? null : rows.GetString(1),
                        rows.IsDBNull(2) ? null : rows.GetInt32(2), rows.IsDBNull(3) ? null : (byte[])rows.GetValue(3))) return true;
        }

        using (var tasks = reader.CreateCommand("""
            SELECT t.spec, w.root_path, i.platform, i.native_identity FROM task t
            LEFT JOIN workspace w ON w.workspace_id = t.workspace_id
            LEFT JOIN workspace_root_identity i ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE t.state BETWEEN 1 AND 6;
            """))
        using (var rows = tasks.ExecuteReader())
        {
            while (rows.Read())
                if (Overlaps(StoredTaskWorkingDirectory((byte[])rows.GetValue(0))) ||
                    Overlaps(rows.IsDBNull(1) ? null : rows.GetString(1),
                        rows.IsDBNull(2) ? null : rows.GetInt32(2), rows.IsDBNull(3) ? null : (byte[])rows.GetValue(3))) return true;
        }

        using (var references = reader.CreateCommand("""
            SELECT path, NULL, NULL FROM cache_instance
            WHERE maintenance_lease_holder IS NOT NULL
            UNION ALL
            SELECT w.root_path, i.platform, i.native_identity FROM workspace w
            LEFT JOIN workspace_root_identity i ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE w.leased_by_attempt_id IS NOT NULL OR EXISTS
                (SELECT 1 FROM remote_attempt r WHERE r.remote_workspace_id = w.workspace_id AND r.released_at IS NULL);
            """))
        using (var rows = references.ExecuteReader())
        {
            while (rows.Read())
                if (Overlaps(rows.GetString(0), rows.IsDBNull(1) ? null : rows.GetInt32(1),
                    rows.IsDBNull(2) ? null : (byte[])rows.GetValue(2))) return true;
        }

        using (var pinned = reader.CreateCommand("""
            SELECT r.path, m.relative_path FROM managed_directory m
            LEFT JOIN root_location r ON r.root_class = m.root_class
            WHERE m.pinned = 1 AND m.state <> 5;
            """))
        using (var rows = pinned.ExecuteReader())
        {
            while (rows.Read())
            {
                checkBudget();
                if (rows.IsDBNull(0) || rows.GetString(0).Length == 0) continue;
                try
                {
                    var components = WorkspacePath.Components(rows.GetString(1), allowRoot: true);
                    var candidate = components.Length == 0 ? rows.GetString(0) :
                        Path.Combine(rows.GetString(0), string.Join(Path.DirectorySeparatorChar, components));
                    if (Overlaps(candidate)) return true;
                }
                catch (WorkspacePathException exception)
                {
                    throw new WorkspaceRemovalPlanException("identity_unavailable", exception);
                }
            }
        }
        checkBudget();
        return false;
    }

    private static byte[] WindowsDirectoryKey(WorkspaceObjectIdentity identity)
    {
        var encoded = RegisteredWorkspaces.RootIdentity.Encode(identity);
        return encoded.Platform == 1 && FileCreationOwnership.StableKey(encoded.Platform, encoded.Bytes) is { } key
            ? key : throw new WorkspacePathException("identity_unavailable");
    }

    private static string? StoredTaskWorkingDirectory(byte[] encoded)
    {
        // Extract field 2 only; command, argument and environment fields remain opaque and are never logged.
        var input = new CodedInputStream(encoded);
        string? directory = null;
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            if (tag == 18) directory = input.ReadString();
            else input.SkipLastField();
        }
        return directory;
    }

    private static bool AttemptTreeHasHold(StoreReader reader, WorkspacePath root, WorkspaceRemovalSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        if (reader.Scalar("SELECT 1 FROM file_operation_journal WHERE held = 1 LIMIT 1;") is null) return false;
        foreach (var entry in snapshot.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var separator = entry.Path.LastIndexOf('/');
            var parentPath = separator < 0 ? "" : entry.Path[..separator];
            var parent = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(root.OpenDirectory(parentPath)));
            if (parent.Platform != entry.NativeIdentity.Platform ||
                FileMutationJournal.HasTargetHold(reader, parent.Platform, parent.Bytes, entry.NativeIdentity.Bytes, entry.Path, root))
                return true;
        }

        return false;
    }

    private static string AttemptRelativePath(string attemptName, string path)
    {
        if (string.Equals(path, attemptName, StringComparison.Ordinal)) return "";
        if (!path.StartsWith(attemptName + "/", StringComparison.Ordinal))
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
        return path[(attemptName.Length + 1)..];
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
