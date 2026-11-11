// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Api;

/// <summary>Why a routed call stopped immediately before its effect (<see cref="RoutedContext.BeforeEffect"/>).</summary>
internal enum RoutedAbort
{
    /// <summary>The link ended under the call (switched off, signed out, the session ending): the call is dropped unanswered.</summary>
    Dropped,

    /// <summary>The node's stop began: answered <c>STATE/node_stopping</c> (DID_NOT_HAPPEN).</summary>
    Stopping,

    /// <summary>Past <c>expires_at</c> plus the 120 s skew (Plan PN-15): answered EXPIRED (decision 4).</summary>
    Expired,

    /// <summary>The file/workspace wall and monotonic clocks do not establish a safe validation time.</summary>
    ClockUncertain,
}

/// <summary>Thrown inside a routed call's effect transaction when <see cref="RoutedContext.BeforeEffect"/> fails: nothing is stored.</summary>
internal sealed class RoutedAbortException : Exception
{
    public RoutedAbortException()
    {
    }

    public RoutedAbortException(string message)
        : base(message)
    {
    }

    public RoutedAbortException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public RoutedAbortException(RoutedAbort kind)
        : base("The routed call stopped before its effect: " + kind)
    {
        Kind = kind;
    }

    /// <summary>Why.</summary>
    public RoutedAbort Kind { get; }
}

/// <summary>
/// The context of one center-routed call on its way through a TaskService body (AF-CTR-05 N2b): the link it arrived on, its expiry, its
/// wait budget on the local monotonic clock, and the closed operation and reason of a refusal the body made (the dispatcher signs it).
/// </summary>
internal sealed class RoutedContext(IRoutedLink link, NodeLifecycle lifecycle, DateTimeOffset expiresAt, TimeSpan lifetime, TimeProvider clock, long receivedAt, Id callId, bool fileWorkspace)
{
    /// <summary>The margin a routed answer keeps before the call's deadline.</summary>
    public static readonly TimeSpan Margin = TimeSpan.FromSeconds(1);

    /// <summary>The verified call ID, used only when no valid request correlation was supplied.</summary>
    public Id CallId { get; } = callId.Clone();

    /// <summary>The correlation supplied by the request, otherwise the verified call ID.</summary>
    public Id Correlation(RequestMeta? meta) => RoutedFileErrors.Correlation(meta, CallId);

    /// <summary>The link of the call.</summary>
    public IRoutedLink Link { get; } = link;

    /// <summary>The matrix operation of the body's refusal, for its closed <c>state.state</c>.</summary>
    public string? Operation { get; private set; }

    /// <summary>The closed reason of the body's refusal.</summary>
    public string? Reason { get; private set; }

    /// <summary>True once this call's policy refusal has a committed audit entry.</summary>
    public bool Audited { get; private set; }

    /// <summary>Marks a committed refusal or approval audit.</summary>
    public void MarkAudited() => Audited = true;

    /// <summary>Records the closed operation and reason of a refusal the body made.</summary>
    public void Refused(string operation, string reason)
    {
        Operation = operation;
        Reason = reason;
    }

    /// <summary>
    /// The time left for a wait: the call's lifetime from <c>issued_at</c> to its deadline, counted from its receipt on the local monotonic clock,
    /// less <see cref="Margin"/> (verifier N-9: never the wall-clock difference, which the 120 s skew could distort).
    /// </summary>
    public TimeSpan Remaining()
    {
        var left = lifetime - clock.GetElapsedTime(receivedAt) - Margin;
        return left > TimeSpan.Zero ? left : TimeSpan.Zero;
    }

    /// <summary>The file operation budget also includes time since this verified call was received.</summary>
    public TimeSpan RemainingFileOperation()
    {
        var fromReceipt = TimeSpan.FromSeconds(10) - clock.GetElapsedTime(receivedAt);
        var left = Remaining();
        return fromReceipt <= TimeSpan.Zero ? TimeSpan.Zero : fromReceipt < left ? fromReceipt : left;
    }

    /// <summary>
    /// Inside the writer, a replay or new effect requires a usable link and a node that has not begun stopping (decisions B-2 and B-3).
    /// </summary>
    public void BeforeReplay()
    {
        if (!Link.Usable)
        {
            throw new RoutedAbortException(RoutedAbort.Dropped);
        }

        if (Link.Stopping || lifecycle.IsStopping)
        {
            throw new RoutedAbortException(RoutedAbort.Stopping);
        }
    }

    /// <summary>Also requires a still-valid expiry immediately before a new effect.</summary>
    public void BeforeEffect() => BeforeEffect(null);

    /// <summary>Rechecks file/workspace time against the store snapshot or its FULL effect transaction.</summary>
    public void BeforeEffect(StoreReader? reader)
    {
        BeforeReplay();
        if (fileWorkspace)
        {
            if (reader is null)
            {
                throw new RoutedAbortException(RoutedAbort.ClockUncertain);
            }

            var sample = reader is StoreTransaction { Durability: CommitDurability.Full } transaction
                ? RoutedFileValidationTime.Advance(transaction) : RoutedFileValidationTime.Sample(reader);
            if (!sample.Healthy)
            {
                throw new RoutedAbortException(RoutedAbort.ClockUncertain);
            }

            if (!CallVerifier.StillValid(expiresAt, StoreTime.FromMicroseconds(sample.BoundaryMicroseconds)))
            {
                throw new RoutedAbortException(RoutedAbort.Expired);
            }
            return;
        }

        if (!CallVerifier.StillValid(expiresAt, clock.GetUtcNow()))
        {
            throw new RoutedAbortException(RoutedAbort.Expired);
        }
    }
}

/// <summary>
/// The node's center-routed dispatcher (AF-CTR-05 CTR5-NODE-08..12; Plan decisions PB-2, D0-B1, N-5, N-8, N-9, PN-6, PN-8, PN-15; N2b
/// decisions B-1..B-4). It receives only calls N1's verifier passed and recorded pending, and answers each in this order (decisions B-2):
/// <list type="number">
/// <item>the link, read again (decisions B-3): a link switched off, signed out or ending drops the call unanswered;</item>
/// <item>the caller's shape (verifier N-4) and the payload as the method's TaskService request (the exact bytes are kept); a mutation's inner
/// <c>meta.command_id</c> must be the routed one;</item>
/// <item>the node's stop: <c>STATE/node_stopping</c>, the handler's own answer (DID_NOT_HAPPEN, AFTER_TIME);</item>
/// <item>for Submit and Cancel, the same caller class's duplicate (the account and user of an account session, the relaying node and local
/// origin of a relay; E2b review C2-N3): still in flight here or approved and executing answers the in-progress
/// <c>EXECUTION/operation_failed</c> (UNKNOWN, SAME_COMMAND); a recorded outcome over the same exact bytes is replayed byte for byte (Q-5);</item>
/// <item>the expiry, again (EXPIRED, decision 4);</item>
/// <item>the caller-level center-routed policy (<see cref="CenterRouting"/>), then the operation's routed cells for Submit and the reads;</item>
/// <item>the shared TaskService body with a center-routed <see cref="Caller"/> (origin REMOTE, the center caller, its cells), whose effect
/// re-reads the link, the stop and the expiry inside its writer transaction.</item>
/// </list>
/// Every EXECUTED handler error is either recorded and replayed exactly, or decided before any effect and DID_NOT_HAPPEN, or UNKNOWN
/// (decisions B-1). A refusal by the policy or the matrix, an approval raised included, is REFUSED_BY_POLICY with closed fields only.
/// </summary>
internal sealed class RoutedDispatcher(NodeRuntime node) : IRoutedDispatcher, IDisposable
{
    private const string Service = "arcforges.node.v1.TaskService";
    private readonly ConcurrentDictionary<string, CenterCaller> _inFlight = new(StringComparer.Ordinal);
    private TaskServiceHandler? _tasks;
    private WorkspaceServiceHandler? _workspaces;
    private FileServiceHandler? _files;

    /// <summary>Binds the actual handlers built by the host after the cloud link.</summary>
    public void Bind(TaskServiceHandler tasks, WorkspaceServiceHandler workspaces, FileServiceHandler files)
    {
        Volatile.Write(ref _files, files ?? throw new ArgumentNullException(nameof(files)));
        Volatile.Write(ref _workspaces, workspaces ?? throw new ArgumentNullException(nameof(workspaces)));
        Volatile.Write(ref _tasks, tasks ?? throw new ArgumentNullException(nameof(tasks)));
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _files, null)?.Dispose();
        Interlocked.Exchange(ref _workspaces, null)?.Dispose();
    }

    // Lets in-process tests coordinate an actual policy update between native preparation and the writer.
    internal WorkspaceServiceHandler? WorkspaceHandlerForTests => Volatile.Read(ref _workspaces);

    // Coordinates real policy changes around a file read in the in-process native fixture.
    internal FileServiceHandler? FileHandlerForTests => Volatile.Read(ref _files);

    /// <inheritdoc />
    public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(link);
        var header = call.Header;
        var method = header.Method;
        var risk = Risk(method);
        var operation = RoutedRefusals.Operation(method);
        RoutedAnswer ExecutedHere(RoutedMethod selected, RequestMeta? selectedMeta, ArcError error, byte[]? taskId, int selectedRisk,
            byte[]? workspaceId = null)
        {
            if (IsFileWorkspace(selected))
            {
                RoutedFileErrors.Complete(error, selectedMeta, header.CallId, node.Clock);
                if ((selected is RoutedMethod.ReadNodeFile or RoutedMethod.SearchNodeFiles or RoutedMethod.ListNodeDirectory or RoutedMethod.GetNodeFileOperation) && error.Category == ErrorCategory.Internal)
                {
                    ReadInternalFailure(error);
                }
            }

            return Executed(selected, selectedMeta, error, taskId, selectedRisk, workspaceId);
        }

        var actor = new ActorRef { Origin = Origin.Remote };
        if (header.Caller is { } statedCaller)
        {
            actor.CenterCaller = statedCaller.Clone();
        }

        if (header.CommandId is { Value.Length: 16 } statedCommand)
        {
            actor.RemoteCommandId = statedCommand.Clone();
        }

        if (Volatile.Read(ref _tasks) is not { } tasks)
        {
            return await AuditedRefusalAsync(actor, method, null, operation, RoutedRefusals.DispatchUnavailable, risk, null, callId: header.CallId).ConfigureAwait(false);
        }

        if (!link.Usable)
        {
            return null;
        }

        var workspaces = Volatile.Read(ref _workspaces);
        var files = Volatile.Read(ref _files);
        if (IsWorkspace(method) && workspaces is null || IsFile(method) && files is null)
        {
            try
            {
                await WriteRefusalAuditAsync(actor, method, operation, "enforcement_unavailable", PermissionDecision.Deny, null, null,
                    fleetEntry: true).ConfigureAwait(false);
                return ExecutedHere(method, null, NodeErrors.EnforcementUnavailable("workspace_service_unavailable"), null, risk);
            }
            catch (CommandQueueFullException)
            {
                return ExecutedHere(method, null, NodeErrors.Overloaded(node.Clock.GetUtcNow()), null, risk);
            }
        }

        var center = header.Caller;
        if (CenterRouting.Shape(center) is { } shape)
        {
            return await AuditedRefusalAsync(actor, method, null, operation, shape, risk, null, callId: header.CallId).ConfigureAwait(false);
        }

        IMessage request;
        RequestMeta? meta;
        try
        {
            (request, meta) = Parse(method, call.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            if (IsFileWorkspace(method))
            {
                await WriteRefusalAuditAsync(actor, method, operation, "invalid_argument", PermissionDecision.Deny, null, null).ConfigureAwait(false);
            }

            return ExecutedHere(method, null, NodeErrors.InvalidArgument("request: a node.v1 request of the routed method"), null, risk);
        }

        if (IsFileWorkspace(method) && call.Payload.Length > 245_760)
        {
            await WriteRefusalAuditAsync(actor, method, operation, "invalid_argument", PermissionDecision.Deny, null, null,
                workspaceId: WorkspaceIdOf(request), path: AuditPathOf(request)).ConfigureAwait(false);
            return ExecutedHere(method, meta, NodeErrors.InvalidArgument("request: serialized payload exceeds 245760 bytes"), null, risk,
                WorkspaceIdOf(request));
        }

        var mutation = method is RoutedMethod.SubmitNodeTask or RoutedMethod.CancelNodeTask or
            RoutedMethod.RegisterNodeWorkspace or RoutedMethod.UnregisterNodeWorkspace;
        if (mutation && (meta?.CommandId is not { } inner || header.CommandId is null || !inner.Value.Span.SequenceEqual(header.CommandId.Value.Span)))
        {
            if (IsFileWorkspace(method))
            {
                await WriteRefusalAuditAsync(actor, method, operation, "invalid_argument", PermissionDecision.Deny, null, null,
                    workspaceId: WorkspaceIdOf(request), path: AuditPathOf(request)).ConfigureAwait(false);
            }

            return ExecutedHere(method, meta, NodeErrors.InvalidArgument("meta.command_id: equals the routed call's command ID"),
                TaskIdOf(request), risk, WorkspaceIdOf(request));
        }

        if ((method is RoutedMethod.ReadNodeFile or RoutedMethod.SearchNodeFiles or RoutedMethod.ListNodeDirectory or RoutedMethod.GetNodeFileOperation or RoutedMethod.ListNodeWorkspaces or RoutedMethod.GetNodeWorkspace) && meta?.CommandId is not null)
        {
            await WriteRefusalAuditAsync(actor, method, operation, "invalid_argument", PermissionDecision.Deny, null, null,
                workspaceId: WorkspaceIdOf(request), path: AuditPathOf(request)).ConfigureAwait(false);
            return ExecutedHere(method, meta, NodeErrors.InvalidArgument("meta.command_id: absent for a read"), null, risk, WorkspaceIdOf(request));
        }

        // A stop or an ending link takes precedence over an in-progress or recorded replay (decisions B-2/B-3).
        if (!link.Usable)
        {
            return null;
        }

        if (link.Stopping || node.Lifecycle.IsStopping)
        {
            return ExecutedHere(method, meta, NodeErrors.NodeStopping(node.Clock.GetUtcNow()), TaskIdOf(request), risk);
        }

        var expires = ProtoTime.ToDateTimeOffset(header.ExpiresAt)!.Value;
        var lifetime = ProtoTime.ToDateTimeOffset(header.Deadline)!.Value - ProtoTime.ToDateTimeOffset(header.IssuedAt)!.Value;
        var context = new RoutedContext(link, node.Lifecycle, expires, lifetime, node.Clock,
            call.ReceivedAt ?? node.Clock.GetTimestamp(), header.CallId, IsFileWorkspace(method));

        async Task<RoutedAnswer?> FileTimeAbortAsync(RoutedAbortException abort)
        {
            if (abort.Kind is not (RoutedAbort.ClockUncertain or RoutedAbort.Expired) || !link.Usable)
            {
                return null;
            }

            Task<RoutedFileTimeSample>? pending = null;
            try
            {
                // Commit the observed boundary and the content-free refusal before any verified refusal is sent.
                pending = node.Processor.ExecuteAsync(command =>
                {
                    var sample = RoutedFileValidationTime.Advance(command.Transaction);
                    AuditLog.AppendFileWorkspace(command.Transaction, actor, operation + " routed.time", WorkspaceIdOf(request), null,
                        AuditPathOf(request), PermissionDecision.Deny, abort.Kind == RoutedAbort.Expired ? "refused: expired_before_effect" : "refused: clock_unavailable", null);
                    return sample;
                }, CommitDurability.Full);
                var remaining = context.RemainingFileOperation();
                if (remaining <= TimeSpan.Zero)
                {
                    _ = pending.ContinueWith(static task => _ = task.Exception, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                    return null;
                }

                var sample = await pending.WaitAsync(remaining, cancellationToken).ConfigureAwait(false);
                if (!sample.Healthy || abort.Kind != RoutedAbort.Expired ||
                    CallVerifier.StillValid(expires, StoreTime.FromMicroseconds(sample.BoundaryMicroseconds)) || !link.Usable)
                {
                    return null;
                }

                return new RoutedAnswer(RoutedOutcome.Expired, null, RoutedRefusals.ExpiredBeforeEffect(RoutedFileErrors.Correlation(meta, header.CallId)),
                    TaskIdOf(request), risk, WorkspaceId: WorkspaceIdOf(request));
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                // No verified reply is sent if the clock/audit transaction cannot be established in time.
                if (pending is not null)
                {
                    _ = pending.ContinueWith(static task => _ = task.Exception, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                }
                return null;
            }
        }

        if (IsFileWorkspace(method))
        {
            try
            {
                node.Store.Read(reader => { context.BeforeEffect(reader); return 0; });
            }
            catch (RoutedAbortException abort)
            {
                return await FileTimeAbortAsync(abort).ConfigureAwait(false);
            }
        }

        var raw = call.Payload.ToByteArray();
        var digest = PayloadDigest.Compute(raw);
        var key = mutation ? Convert.ToHexString(header.CommandId!.Value.Span) : null;

        // Decisions B-2: the same caller's duplicate is answered before anything that would assert DID_NOT_HAPPEN.
        if (key is not null)
        {
            if (_inFlight.TryGetValue(key, out var running) && CenterRouting.SameClass(running, center))
            {
                if (!link.Usable)
                {
                    return null;
                }

                return link.Stopping || node.Lifecycle.IsStopping
                    ? ExecutedHere(method, meta, NodeErrors.NodeStopping(node.Clock.GetUtcNow()), TaskIdOf(request), risk)
                    : ExecutedHere(method, meta, NodeErrors.CommandInProgress(), TaskIdOf(request), risk);
            }

            var recorded = node.Store.Read(reader => Recorded(reader, header.CommandId!.Value.Span, ServiceOf(method), MethodName(method), digest, center));
            if (recorded is not null)
            {
                if (!link.Usable)
                {
                    return null;
                }

                if (link.Stopping || node.Lifecycle.IsStopping)
                {
                    return ExecutedHere(method, meta, NodeErrors.NodeStopping(node.Clock.GetUtcNow()), TaskIdOf(request), risk);
                }
            }

            switch (recorded)
            {
                case { InProgress: true }:
                    return ExecutedHere(method, meta, NodeErrors.CommandInProgress(), TaskIdOf(request), risk);
                case { Outcome: { } outcome }:
                    return Replayed(method, outcome, request, risk);
            }
        }

        if (!CallVerifier.StillValid(expires, node.Clock.GetUtcNow()))
        {
            if (IsFileWorkspace(method))
            {
                return await FileTimeAbortAsync(new RoutedAbortException(RoutedAbort.Expired)).ConfigureAwait(false);
            }

            return new RoutedAnswer(RoutedOutcome.Expired, null, RoutedRefusals.ExpiredBeforeEffect(Correlation()), TaskIdOf(request), risk,
                WorkspaceId: WorkspaceIdOf(request));
        }
        var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: center.Clone())
        {
            CellsOrigin = CenterRouting.CellsOrigin(center, node.NodeId.Span),
            RemoteCommandId = mutation ? header.CommandId!.Clone() : null,
            RawRequest = raw,
            Routed = context,
        };
        var policy = node.Store.Read(PolicyRules.Current).Document;
        if (CenterRouting.Refusal(center, node.NodeId.Span, policy.CenterRouted) is { } reason)
        {
            return await AuditedRefusalAsync(caller.Actor, method, meta, operation, reason, risk, TaskIdOf(request), WorkspaceIdOf(request), header.CallId, AuditPathOf(request)).ConfigureAwait(false);
        }

        // The routed column narrowed by the caller's cells and the REMOTE overrides; a cancel is decided by its gate once its task is read.
        if (method != RoutedMethod.CancelNodeTask && tasks.Api.Decide(caller, operation) is { Decision: not PermissionDecision.Allow } verdict)
        {
            var denied = verdict.Source.StartsWith("policy permissions[", StringComparison.Ordinal) ? "permission_override" : "denied";
            return await AuditedRefusalAsync(caller.Actor, method, meta, operation, denied, risk, TaskIdOf(request), WorkspaceIdOf(request), header.CallId, AuditPathOf(request)).ConfigureAwait(false);
        }

        var slot = key is not null && _inFlight.TryAdd(key, center.Clone());
        try
        {
            var (response, error) = await RunAsync(tasks, workspaces, files, method, caller, request, cancellationToken).ConfigureAwait(false);
            if (response.CalculateSize() > ResultSigner.MaxPayloadBytes)
            {
                // A valid FULL view can exceed the wire limit. Report an existing bounded internal failure, never a truncated success.
                var oversized = NodeErrors.Internal(node.Clock.GetUtcNow());
                oversized.Effect = EffectCertainty.Unknown;
                oversized.Retry = new RetryAdvice { Mode = RetryMode.Never };
                return ExecutedHere(method, meta, oversized, TaskIdOf(request), risk);
            }

            if (error is not null && IsFileWorkspace(method))
            {
                RoutedFileErrors.Complete(error, meta, header.CallId, node.Clock);
            }

            var answer = Answer(response, error, context, request, meta, operation, risk);
            if (answer.Outcome == RoutedOutcome.RefusedByPolicy && !context.Audited)
            {
                var approved = error?.Code == "approval_required";
                await WriteRefusalAuditAsync(caller.Actor, method, context.Operation ?? operation, context.Reason ?? "denied",
                    approved ? PermissionDecision.Approval : PermissionDecision.Deny,
                    approved ? answer.Error?.Details?.State?.Resource?.Id?.Value.ToByteArray() : null, TaskIdOf(request),
                    workspaceId: WorkspaceIdOf(request), path: AuditPathOf(request)).ConfigureAwait(false);
            }

            return answer;
        }
        catch (CommandQueueFullException)
        {
            // A file read cannot claim a recorded refusal while the audit writer cannot admit it. The center observes no verified reply.
            if (IsFile(method))
            {
                return null;
            }

            // A policy refusal is never reported unless its audit committed.
            return ExecutedHere(method, meta, NodeErrors.Overloaded(node.Clock.GetUtcNow()), TaskIdOf(request), risk);
        }
        catch (RoutedAbortException abort)
        {
            if (IsFileWorkspace(method) && abort.Kind is RoutedAbort.ClockUncertain or RoutedAbort.Expired)
            {
                return await FileTimeAbortAsync(abort).ConfigureAwait(false);
            }

            return abort.Kind switch
            {
                RoutedAbort.Dropped => null,
                RoutedAbort.Stopping => ExecutedHere(method, meta, NodeErrors.NodeStopping(node.Clock.GetUtcNow()), TaskIdOf(request), risk),
                _ => new RoutedAnswer(RoutedOutcome.Expired, null, RoutedRefusals.ExpiredBeforeEffect(IsFileWorkspace(method) ? RoutedFileErrors.Correlation(meta, header.CallId) : Correlation()), TaskIdOf(request), risk),
            };
        }
        finally
        {
            if (slot)
            {
                _inFlight.TryRemove(key!, out _);
            }
        }
    }

    /// <summary>What the store holds for a routed command: a recorded outcome to replay, or an approved request still executing.</summary>
    private sealed record RecordedCommand(byte[]? Outcome, bool InProgress);

    /// <summary>
    /// For the same caller class only (decisions B-2, E2b review C2-N3): the outcome <c>command_dedup</c> recorded for this command, method and exact payload digest,
    /// or the outcome of its executed approval; or an approval of it that is APPROVED (executing). The caller is the recorded outcome's
    /// transactionally associated requester, or the approval's requester; another caller takes the normal policy path.
    /// </summary>
    private static RecordedCommand? Recorded(StoreReader reader, ReadOnlySpan<byte> commandId, string service, string method, byte[] digest, CenterCaller caller)
    {
        var id = commandId.ToArray();
        if (!RoutedCommandOwnership.MayUse(reader, id, caller))
        {
            return null;
        }

        if (Approvals.ByCommand(reader, id) is { } approval && CenterRouting.SameClass(approval.View.Requester?.CenterCaller, caller)
            && approval.RequestDigest.AsSpan().SequenceEqual(digest) && approval.View.Operation.EndsWith("." + method, StringComparison.Ordinal))
        {
            if (approval.State == ApprovalState.Approved)
            {
                return new RecordedCommand(null, true);
            }

            if (approval.State is ApprovalState.Executed or ApprovalState.Failed && approval.Outcome is { Length: > 0 } executed)
            {
                return new RecordedCommand(executed, false);
            }
        }

        byte[]? outcome = null;
        using (var command = reader.CreateCommand("SELECT method, payload_digest, outcome, expires_at FROM command_dedup WHERE command_id = $id;"))
        {
            command.Parameters.AddWithValue("$id", id);
            using var row = command.ExecuteReader();
            if (row.Read() && (row.GetInt64(3) > reader.NowMicroseconds || RoutedFileRetention.IsHeld(reader, id)) && !row.IsDBNull(2) && row.GetString(0) == service + "/" + method
                && ((byte[])row.GetValue(1)).AsSpan().SequenceEqual(digest))
            {
                outcome = (byte[])row.GetValue(2);
            }
        }

        return outcome is not null ? new RecordedCommand(outcome, false) : null;
    }

    private static (IMessage Request, RequestMeta? Meta) Parse(RoutedMethod method, ByteString payload) => method switch
    {
        RoutedMethod.GetNodeFileOperation => Pair(FileServiceGetFileOperationRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.ReadNodeFile => Pair(FileServiceReadFileRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.ListNodeDirectory => Pair(FileServiceListDirectoryRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.SearchNodeFiles => Pair(FileServiceSearchFilesRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.SubmitNodeTask => Pair(TaskServiceSubmitTaskRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.GetNodeTask => Pair(TaskServiceGetTaskRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.ListNodeTasks => Pair(TaskServiceListTasksRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.WaitNodeTask => Pair(TaskServiceWaitTaskRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.ReadNodeTaskOutput => Pair(TaskServiceReadTaskOutputRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.CancelNodeTask => Pair(TaskServiceCancelTaskRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.RegisterNodeWorkspace => Pair(WorkspaceServiceRegisterWorkspaceRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.UnregisterNodeWorkspace => Pair(WorkspaceServiceUnregisterWorkspaceRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.ListNodeWorkspaces => Pair(WorkspaceServiceListWorkspacesRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.GetNodeWorkspace => Pair(WorkspaceServiceGetWorkspaceRequest.Parser.ParseFrom(payload), request => request.Meta),
        _ => throw new ArgumentOutOfRangeException(nameof(method), "The verifier admits the routed task and workspace methods only."),
    };

    private static (IMessage, RequestMeta?) Pair<T>(T request, Func<T, RequestMeta?> meta)
        where T : IMessage => (request, meta(request));

    private static async Task<(IMessage Response, ArcError? Error)> RunAsync(TaskServiceHandler tasks, WorkspaceServiceHandler? workspaces, FileServiceHandler? files,
        RoutedMethod method, Caller caller, IMessage request,
        CancellationToken cancellationToken)
    {
        switch (method)
        {
            case RoutedMethod.GetNodeFileOperation:
                var operation = await files!.GetFileOperationAsync(caller, (FileServiceGetFileOperationRequest)request, cancellationToken).ConfigureAwait(false);
                return (operation, operation.Error);
            case RoutedMethod.ReadNodeFile:
                var file = await files!.ReadAsync(caller, (FileServiceReadFileRequest)request, cancellationToken).ConfigureAwait(false);
                return (file, file.Error);
            case RoutedMethod.ListNodeDirectory:
                var directory = await files!.ListDirectoryAsync(caller, (FileServiceListDirectoryRequest)request, cancellationToken).ConfigureAwait(false);
                return (directory, directory.Error);
            case RoutedMethod.SearchNodeFiles:
                var search = await files!.SearchAsync(caller, (FileServiceSearchFilesRequest)request, cancellationToken).ConfigureAwait(false);
                return (search, search.Error);
            case RoutedMethod.SubmitNodeTask:
                var submitted = await tasks.SubmitTask(caller, (TaskServiceSubmitTaskRequest)request, cancellationToken).ConfigureAwait(false);
                return (submitted, submitted.Error);
            case RoutedMethod.GetNodeTask:
                var got = await tasks.GetTask(caller, (TaskServiceGetTaskRequest)request, cancellationToken).ConfigureAwait(false);
                return (got, got.Error);
            case RoutedMethod.ListNodeTasks:
                var listed = await tasks.ListTasks(caller, (TaskServiceListTasksRequest)request, cancellationToken).ConfigureAwait(false);
                return (listed, listed.Error);
            case RoutedMethod.WaitNodeTask:
                var waited = await tasks.WaitTask(caller, (TaskServiceWaitTaskRequest)request, cancellationToken).ConfigureAwait(false);
                return (waited, waited.Error);
            case RoutedMethod.ReadNodeTaskOutput:
                var read = await tasks.ReadTaskOutput(caller, (TaskServiceReadTaskOutputRequest)request, cancellationToken).ConfigureAwait(false);
                return (read, read.Error);
            case RoutedMethod.CancelNodeTask:
                var cancelled = await tasks.CancelTask(caller, (TaskServiceCancelTaskRequest)request, cancellationToken).ConfigureAwait(false);
                return (cancelled, cancelled.Error);
            case RoutedMethod.RegisterNodeWorkspace:
                var registered = await workspaces!.RegisterAsync(caller, (WorkspaceServiceRegisterWorkspaceRequest)request, cancellationToken).ConfigureAwait(false);
                return (registered, registered.Error);
            case RoutedMethod.UnregisterNodeWorkspace:
                var unregistered = await workspaces!.UnregisterAsync(caller, (WorkspaceServiceUnregisterWorkspaceRequest)request, cancellationToken).ConfigureAwait(false);
                return (unregistered, unregistered.Error);
            case RoutedMethod.ListNodeWorkspaces:
                var listedWorkspaces = await workspaces!.ListAsync(caller, (WorkspaceServiceListWorkspacesRequest)request, cancellationToken).ConfigureAwait(false);
                return (listedWorkspaces, listedWorkspaces.Error);
            case RoutedMethod.GetNodeWorkspace:
                var gotWorkspace = await workspaces!.GetAsync(caller, (WorkspaceServiceGetWorkspaceRequest)request, cancellationToken).ConfigureAwait(false);
                return (gotWorkspace, gotWorkspace.Error);
            default:
                throw new ArgumentOutOfRangeException(nameof(method));
        }
    }

    /// <summary>
    /// The signed answer of a body's response (decisions B-1, Q4): an AUTHORIZATION refusal (the matrix, an approval raised, the command
    /// patterns) is REFUSED_BY_POLICY with closed fields only; anything else is EXECUTED with the response's exact bytes. An INTERNAL error
    /// that was not recorded is made UNKNOWN with NEVER (the catalogue's pair), never a final DID_NOT_HAPPEN it cannot prove.
    /// </summary>
    private RoutedAnswer Answer(IMessage response, ArcError? error, RoutedContext context, IMessage request, RequestMeta? meta, string operation, int risk)
    {
        var taskId = TaskIdOf(request) ?? (response is TaskServiceSubmitTaskResponse { Value.TaskId: { } created } ? created.Value.ToByteArray() : null);
        var workspaceId = WorkspaceIdOf(request) ?? (response is WorkspaceServiceRegisterWorkspaceResponse { Value.Workspace.WorkspaceId: { } added }
            ? added.Value.ToByteArray() : null) ??
            (response is FileServiceGetFileOperationResponse { Value.Operation.WorkspacePath.WorkspaceId: { } statusWorkspace }
                ? statusWorkspace.Value.ToByteArray() : null);
        if (error is { Category: ErrorCategory.Authorization })
        {
            var stated = context.Operation ?? operation;
            var correlation = IsFileWorkspaceMethod(request) ? context.Correlation(meta) : Correlation();
            var closed = error.Code switch
            {
                "approval_required" when error.Details?.State?.Resource?.Id is { } approval => RoutedRefusals.ApprovalRequired(stated, approval, correlation),
                "command_pattern_denied" => RoutedRefusals.Authorization("command_pattern_denied", stated, context.Reason ?? "agents.allowed_command_patterns", correlation),
                _ => RoutedRefusals.Policy(stated, context.Reason ?? "denied", correlation),
            };
            return new RoutedAnswer(RoutedOutcome.RefusedByPolicy, null, closed, taskId, risk, WorkspaceId: workspaceId);
        }

        if (error is { Category: ErrorCategory.Internal })
        {
            if (request is FileServiceReadFileRequest or FileServiceSearchFilesRequest or FileServiceListDirectoryRequest or FileServiceGetFileOperationRequest)
            {
                ReadInternalFailure(error);
            }
            else
            {
                error.Effect = EffectCertainty.Unknown;
                error.Retry = new RetryAdvice { Mode = RetryMode.Never };
            }
        }

        return new RoutedAnswer(RoutedOutcome.Executed, response.ToByteString(), null, taskId, risk, Code(error), workspaceId);
    }

    private void ReadInternalFailure(ArcError error)
    {
        // A read has no durable file effect; the file result was not returned. This is the read pair accepted by the catalogue.
        error.Effect = EffectCertainty.DidNotHappen;
        error.Retry = new RetryAdvice { Mode = RetryMode.AfterTime, RetryAt = ProtoTime.ToInstant(node.Clock.GetUtcNow().AddSeconds(1)) };
    }

    private static RoutedAnswer Executed(RoutedMethod method, RequestMeta? meta, ArcError error, byte[]? taskId, int risk, byte[]? workspaceId = null)
    {
        var responseMeta = ApiCommands.Meta(meta);
        if (IsFileWorkspace(method) && error.CorrelationId is not null)
        {
            responseMeta.CorrelationId = error.CorrelationId.Clone();
        }

        IMessage response = method switch
        {
            RoutedMethod.GetNodeFileOperation => new FileServiceGetFileOperationResponse { Meta = responseMeta, Error = error },
            RoutedMethod.ReadNodeFile => new FileServiceReadFileResponse { Meta = responseMeta, Error = error },
            RoutedMethod.ListNodeDirectory => new FileServiceListDirectoryResponse { Meta = responseMeta, Error = error },
            RoutedMethod.SearchNodeFiles => new FileServiceSearchFilesResponse { Meta = responseMeta, Error = error },
            RoutedMethod.SubmitNodeTask => new TaskServiceSubmitTaskResponse { Meta = responseMeta, Error = error },
            RoutedMethod.GetNodeTask => new TaskServiceGetTaskResponse { Meta = responseMeta, Error = error },
            RoutedMethod.ListNodeTasks => new TaskServiceListTasksResponse { Meta = responseMeta, Error = error },
            RoutedMethod.WaitNodeTask => new TaskServiceWaitTaskResponse { Meta = responseMeta, Error = error },
            RoutedMethod.ReadNodeTaskOutput => new TaskServiceReadTaskOutputResponse { Meta = responseMeta, Error = error },
            RoutedMethod.RegisterNodeWorkspace => new WorkspaceServiceRegisterWorkspaceResponse { Meta = responseMeta, Error = error },
            RoutedMethod.UnregisterNodeWorkspace => new WorkspaceServiceUnregisterWorkspaceResponse { Meta = responseMeta, Error = error },
            RoutedMethod.ListNodeWorkspaces => new WorkspaceServiceListWorkspacesResponse { Meta = responseMeta, Error = error },
            RoutedMethod.GetNodeWorkspace => new WorkspaceServiceGetWorkspaceResponse { Meta = responseMeta, Error = error },
            _ => new TaskServiceCancelTaskResponse { Meta = responseMeta, Error = error },
        };
        return new RoutedAnswer(RoutedOutcome.Executed, response.ToByteString(), null, taskId, risk, Code(error), workspaceId);
    }

    /// <summary>A recorded outcome, replayed byte for byte (Q-5): the stored bytes are the answer.</summary>
    private RoutedAnswer Replayed(RoutedMethod method, byte[] outcome, IMessage request, int risk)
    {
        if (outcome.Length > ResultSigner.MaxPayloadBytes)
        {
            var oversized = NodeErrors.Internal(node.Clock.GetUtcNow());
            oversized.Effect = EffectCertainty.Unknown;
            oversized.Retry = new RetryAdvice { Mode = RetryMode.Never };
            var meta = request switch
            {
                TaskServiceSubmitTaskRequest submit => submit.Meta,
                TaskServiceCancelTaskRequest cancel => cancel.Meta,
                WorkspaceServiceRegisterWorkspaceRequest register => register.Meta,
                WorkspaceServiceUnregisterWorkspaceRequest unregister => unregister.Meta,
                _ => null,
            };
            return Executed(method, meta, oversized, TaskIdOf(request), risk);
        }

        ArcError? error;
        byte[]? taskId = TaskIdOf(request);
        if (method == RoutedMethod.SubmitNodeTask)
        {
            var submitted = TaskServiceSubmitTaskResponse.Parser.ParseFrom(outcome);
            error = submitted.Error;
            taskId ??= submitted.Value?.TaskId?.Value.ToByteArray();
        }
        else if (method == RoutedMethod.CancelNodeTask)
        {
            error = TaskServiceCancelTaskResponse.Parser.ParseFrom(outcome).Error;
        }
        else
        {
            error = method == RoutedMethod.RegisterNodeWorkspace
                ? WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(outcome).Error
                : WorkspaceServiceUnregisterWorkspaceResponse.Parser.ParseFrom(outcome).Error;
        }

        var workspaceId = WorkspaceIdOf(request);
        if (method == RoutedMethod.RegisterNodeWorkspace)
        {
            workspaceId = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(outcome).Value?.Workspace?.WorkspaceId?.Value.ToByteArray();
        }

        return new RoutedAnswer(RoutedOutcome.Executed, ByteString.CopyFrom(outcome), null, taskId, risk, Code(error), workspaceId);
    }

    private static RoutedAnswer Refused(string operation, string reason, int risk, Id correlation, byte[]? taskId = null, byte[]? workspaceId = null) =>
        new(RoutedOutcome.RefusedByPolicy, null, RoutedRefusals.Policy(operation, reason, correlation), taskId, risk, WorkspaceId: workspaceId);

    private Id Correlation() => CommandIds.New(node.Clock);

    private async Task<RoutedAnswer> AuditedRefusalAsync(ActorRef actor, RoutedMethod method, RequestMeta? meta, string operation, string reason,
        int risk, byte[]? taskId, byte[]? workspaceId = null, Id? callId = null, string? path = null)
    {
        try
        {
            await WriteRefusalAuditAsync(actor, method, operation, reason, PermissionDecision.Deny, null, taskId, fleetEntry: true,
                workspaceId: workspaceId, path: path).ConfigureAwait(false);
            var correlation = IsFileWorkspace(method) && callId is not null ? RoutedFileErrors.Correlation(meta, callId) : Correlation();
            return Refused(operation, reason, risk, correlation, taskId, workspaceId);
        }
        catch (CommandQueueFullException)
        {
            var overloaded = NodeErrors.Overloaded(node.Clock.GetUtcNow());
            if (IsFileWorkspace(method) && callId is not null)
            {
                RoutedFileErrors.Complete(overloaded, meta, callId, node.Clock);
            }

            return Executed(method, meta, overloaded, taskId, risk);
        }
    }

    private Task<int> WriteRefusalAuditAsync(ActorRef actor, RoutedMethod method, string operation, string reason, PermissionDecision decision,
        byte[]? approvalId, byte[]? taskId, bool fleetEntry = false, byte[]? workspaceId = null, string? path = null) => node.Processor.ExecuteAsync(context =>
    {
        if (IsFileWorkspace(method))
        {
            AuditLog.AppendFileWorkspace(context.Transaction, actor,
                operation + (fleetEntry ? " FleetService." + method : IsFile(method) ? " FileService." + MethodName(method) : " WorkspaceService." + MethodName(method)),
                workspaceId, null, path, decision, "denied: " + reason, null);
        }
        else
        {
            AuditLog.Append(context.Transaction, actor, operation + (fleetEntry ? " FleetService." : " TaskService.") + MethodName(method), "task", taskId ?? [], decision,
                approvalId ?? [], "denied: " + reason);
        }
        return 0;
    }, CommitDurability.Full);

    private static string? AuditPathOf(IMessage request)
    {
        var path = request switch
        {
            FileServiceReadFileRequest { Path: { HasPath: true } selected } => selected,
            FileServiceListDirectoryRequest { Path: { HasPath: true } selected } => selected,
            FileServiceSearchFilesRequest { Path: { HasPath: true } selected } => selected,
            _ => null,
        };
        if (path is null)
        {
            return null;
        }

        try
        {
            return new System.Text.UTF8Encoding(false, true).GetByteCount(path.Path) <= 4096 ? path.Path : null;
        }
        catch (System.Text.EncoderFallbackException)
        {
            return null;
        }
    }

    private static string? Code(ArcError? error) => error is null ? null : error.Category.ToString().ToUpperInvariant() + "/" + error.Code;

    private static byte[]? TaskIdOf(IMessage request) => request switch
    {
        TaskServiceGetTaskRequest { TaskId: { } id } => id.Value.ToByteArray(),
        TaskServiceWaitTaskRequest { TaskId: { } id } => id.Value.ToByteArray(),
        TaskServiceCancelTaskRequest { TaskId: { } id } => id.Value.ToByteArray(),
        _ => null,
    } is { Length: 16 } task ? task : null;

    private static bool IsWorkspace(RoutedMethod method) =>
        method is RoutedMethod.RegisterNodeWorkspace or RoutedMethod.UnregisterNodeWorkspace or
            RoutedMethod.ListNodeWorkspaces or RoutedMethod.GetNodeWorkspace;

    private static bool IsFile(RoutedMethod method) => method is RoutedMethod.ReadNodeFile or RoutedMethod.SearchNodeFiles or RoutedMethod.ListNodeDirectory or RoutedMethod.GetNodeFileOperation;

    private static bool IsFileWorkspace(RoutedMethod method) => IsFile(method) || IsWorkspace(method);

    private static bool IsFileWorkspaceMethod(IMessage request) => request is FileServiceReadFileRequest or FileServiceSearchFilesRequest or FileServiceListDirectoryRequest or FileServiceGetFileOperationRequest or
        WorkspaceServiceRegisterWorkspaceRequest or WorkspaceServiceUnregisterWorkspaceRequest or
        WorkspaceServiceListWorkspacesRequest or WorkspaceServiceGetWorkspaceRequest;

    private static string ServiceOf(RoutedMethod method) => IsWorkspace(method) ? "arcforges.node.v1.WorkspaceService" :
        IsFile(method) ? "arcforges.node.v1.FileService" : Service;

    private static byte[]? WorkspaceIdOf(IMessage request) => request switch
    {
        FileServiceReadFileRequest { Path.WorkspaceId: { } id } => id.Value.ToByteArray(),
        FileServiceListDirectoryRequest { Path.WorkspaceId: { } id } => id.Value.ToByteArray(),
        FileServiceSearchFilesRequest { Path.WorkspaceId: { } id } => id.Value.ToByteArray(),
        WorkspaceServiceUnregisterWorkspaceRequest { WorkspaceId: { } id } => id.Value.ToByteArray(),
        WorkspaceServiceGetWorkspaceRequest { WorkspaceId: { } id } => id.Value.ToByteArray(),
        _ => null,
    } is { Length: 16 } workspace ? workspace : null;

    private static string MethodName(RoutedMethod method) => method switch
    {
        RoutedMethod.GetNodeFileOperation => "GetFileOperation",
        RoutedMethod.ReadNodeFile => "ReadFile",
        RoutedMethod.ListNodeDirectory => "ListDirectory",
        RoutedMethod.SearchNodeFiles => "SearchFiles",
        RoutedMethod.SubmitNodeTask => "SubmitTask",
        RoutedMethod.GetNodeTask => "GetTask",
        RoutedMethod.ListNodeTasks => "ListTasks",
        RoutedMethod.WaitNodeTask => "WaitTask",
        RoutedMethod.ReadNodeTaskOutput => "ReadTaskOutput",
        RoutedMethod.RegisterNodeWorkspace => "RegisterWorkspace",
        RoutedMethod.UnregisterNodeWorkspace => "UnregisterWorkspace",
        RoutedMethod.ListNodeWorkspaces => "ListWorkspaces",
        RoutedMethod.GetNodeWorkspace => "GetWorkspace",
        _ => "CancelTask",
    };

    /// <summary>The risk class for <c>routed_call_log.risk</c>: Submit high (3), Cancel medium (2), the reads low (1).</summary>
    private static int Risk(RoutedMethod method) => method switch
    {
        RoutedMethod.SubmitNodeTask or RoutedMethod.RegisterNodeWorkspace or RoutedMethod.UnregisterNodeWorkspace => 3,
        RoutedMethod.CancelNodeTask => 2,
        _ => 1,
    };
}
