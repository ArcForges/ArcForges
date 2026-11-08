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
internal sealed class RoutedContext(IRoutedLink link, DateTimeOffset expiresAt, TimeSpan lifetime, TimeProvider clock, long logId)
{
    /// <summary>The margin a routed answer keeps before the call's deadline.</summary>
    public static readonly TimeSpan Margin = TimeSpan.FromSeconds(1);

    private readonly long _received = clock.GetTimestamp();

    /// <summary>The link of the call.</summary>
    public IRoutedLink Link { get; } = link;

    /// <summary>The current verified call's row, excluded when comparing a prior caller for replay.</summary>
    public long LogId { get; } = logId;

    /// <summary>The matrix operation of the body's refusal, for its closed <c>state.state</c>.</summary>
    public string? Operation { get; private set; }

    /// <summary>The closed reason of the body's refusal.</summary>
    public string? Reason { get; private set; }

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
        var left = lifetime - clock.GetElapsedTime(_received) - Margin;
        return left > TimeSpan.Zero ? left : TimeSpan.Zero;
    }

    /// <summary>
    /// Immediately before the effect (decisions B-3 and PN-15), inside its writer transaction: the link must still be usable, the node not
    /// stopping and the call not past its expiry plus the skew; otherwise the transaction aborts and nothing is stored.
    /// </summary>
    public void BeforeEffect()
    {
        if (!Link.Usable)
        {
            throw new RoutedAbortException(RoutedAbort.Dropped);
        }

        if (Link.Stopping)
        {
            throw new RoutedAbortException(RoutedAbort.Stopping);
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
internal sealed class RoutedDispatcher(NodeRuntime node) : IRoutedDispatcher
{
    private const string Service = "arcforges.node.v1.TaskService";
    private readonly ConcurrentDictionary<string, CenterCaller> _inFlight = new(StringComparer.Ordinal);
    private TaskServiceHandler? _tasks;

    /// <summary>Binds the TaskService the calls run in (the host builds it after the cloud link); until then every call is refused.</summary>
    public void Bind(TaskServiceHandler tasks) => Volatile.Write(ref _tasks, tasks ?? throw new ArgumentNullException(nameof(tasks)));

    /// <inheritdoc />
    public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(link);
        var header = call.Header;
        var method = header.Method;
        var risk = Risk(method);
        var operation = RoutedRefusals.Operation(method);
        if (Volatile.Read(ref _tasks) is not { } tasks)
        {
            return Refused(operation, RoutedRefusals.DispatchUnavailable, risk);
        }

        if (!link.Usable)
        {
            return null;
        }

        var center = header.Caller;
        if (CenterRouting.Shape(center) is { } shape)
        {
            return Refused(operation, shape, risk);
        }

        IMessage request;
        RequestMeta? meta;
        try
        {
            (request, meta) = Parse(method, call.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return Executed(method, null, NodeErrors.InvalidArgument("request: a node.v1 TaskService request of the routed method"), null, risk);
        }

        var mutation = method is RoutedMethod.SubmitNodeTask or RoutedMethod.CancelNodeTask;
        if (mutation && (meta?.CommandId is not { } inner || header.CommandId is null || !inner.Value.Span.SequenceEqual(header.CommandId.Value.Span)))
        {
            return Executed(method, meta, NodeErrors.InvalidArgument("meta.command_id: equals the routed call's command ID"), TaskIdOf(request), risk);
        }

        // A stop or an ending link takes precedence over an in-progress or recorded replay (decisions B-2/B-3).
        if (!link.Usable)
        {
            return null;
        }

        if (link.Stopping || node.Lifecycle.IsStopping)
        {
            return Executed(method, meta, NodeErrors.NodeStopping(node.Clock.GetUtcNow()), TaskIdOf(request), risk);
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
                    ? Executed(method, meta, NodeErrors.NodeStopping(node.Clock.GetUtcNow()), TaskIdOf(request), risk)
                    : Executed(method, meta, NodeErrors.CommandInProgress(), TaskIdOf(request), risk);
            }

            var recorded = node.Store.Read(reader => Recorded(reader, header.CommandId!.Value.Span, MethodName(method), digest, center, call.LogId));
            if (recorded is not null)
            {
                if (!link.Usable)
                {
                    return null;
                }

                if (link.Stopping || node.Lifecycle.IsStopping)
                {
                    return Executed(method, meta, NodeErrors.NodeStopping(node.Clock.GetUtcNow()), TaskIdOf(request), risk);
                }
            }

            switch (recorded)
            {
                case { InProgress: true }:
                    return Executed(method, meta, NodeErrors.CommandInProgress(), TaskIdOf(request), risk);
                case { Outcome: { } outcome }:
                    return Replayed(method, outcome, request, risk);
            }
        }

        var expires = ProtoTime.ToDateTimeOffset(header.ExpiresAt)!.Value;
        if (!CallVerifier.StillValid(expires, node.Clock.GetUtcNow()))
        {
            return new RoutedAnswer(RoutedOutcome.Expired, null, RoutedRefusals.ExpiredBeforeEffect(Correlation()), TaskIdOf(request), risk);
        }

        var lifetime = ProtoTime.ToDateTimeOffset(header.Deadline)!.Value - ProtoTime.ToDateTimeOffset(header.IssuedAt)!.Value;
        var context = new RoutedContext(link, expires, lifetime, node.Clock, call.LogId);
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
            await AuditDeniedAsync(tasks, caller, operation, method, reason).ConfigureAwait(false);
            return Refused(operation, reason, risk, TaskIdOf(request));
        }

        // The routed column narrowed by the caller's cells and the REMOTE overrides; a cancel is decided by its gate once its task is read.
        if (method != RoutedMethod.CancelNodeTask && tasks.Api.Decide(caller, operation) is { Decision: not PermissionDecision.Allow } verdict)
        {
            var denied = verdict.Source.StartsWith("policy permissions[", StringComparison.Ordinal) ? "permission_override" : "denied";
            await AuditDeniedAsync(tasks, caller, operation, method, denied).ConfigureAwait(false);
            return Refused(operation, denied, risk, TaskIdOf(request));
        }

        var slot = key is not null && _inFlight.TryAdd(key, center.Clone());
        try
        {
            var (response, error) = await RunAsync(tasks, method, caller, request, cancellationToken).ConfigureAwait(false);
            return Answer(response, error, context, request, operation, risk);
        }
        catch (RoutedAbortException abort)
        {
            return abort.Kind switch
            {
                RoutedAbort.Dropped => null,
                RoutedAbort.Stopping => Executed(method, meta, NodeErrors.NodeStopping(node.Clock.GetUtcNow()), TaskIdOf(request), risk),
                _ => new RoutedAnswer(RoutedOutcome.Expired, null, RoutedRefusals.ExpiredBeforeEffect(Correlation()), TaskIdOf(request), risk),
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
    /// or the outcome of its executed approval; or an approval of it that is APPROVED (executing). The recorded caller is that of the first
    /// earlier routed call of the command ID (<c>routed_call_log</c>), or the approval's requester; another caller takes the normal path.
    /// </summary>
    private static RecordedCommand? Recorded(StoreReader reader, ReadOnlySpan<byte> commandId, string method, byte[] digest, CenterCaller caller, long logId)
    {
        var id = commandId.ToArray();
        if (Approvals.ByCommand(reader, id) is { } approval && CenterRouting.SameClass(approval.View.Requester?.CenterCaller, caller))
        {
            if (approval.State == ApprovalState.Approved)
            {
                return new RecordedCommand(null, true);
            }

            if (approval.State is ApprovalState.Executed or ApprovalState.Failed && approval.Outcome is { Length: > 0 } executed
                && approval.RequestDigest.AsSpan().SequenceEqual(digest) && approval.View.Operation.EndsWith("." + method, StringComparison.Ordinal))
            {
                return new RecordedCommand(executed, false);
            }
        }

        byte[]? outcome = null;
        using (var command = reader.CreateCommand("SELECT method, payload_digest, outcome, expires_at FROM command_dedup WHERE command_id = $id;"))
        {
            command.Parameters.AddWithValue("$id", id);
            using var row = command.ExecuteReader();
            if (row.Read() && row.GetInt64(3) > reader.NowMicroseconds && !row.IsDBNull(2) && row.GetString(0) == Service + "/" + method
                && ((byte[])row.GetValue(1)).AsSpan().SequenceEqual(digest))
            {
                outcome = (byte[])row.GetValue(2);
            }
        }

        if (outcome is null)
        {
            return null;
        }

        using var first = reader.CreateCommand("""
            SELECT caller FROM routed_call_log WHERE command_id = $id AND decision IN (1, 5) AND log_id <> $log ORDER BY log_id LIMIT 1;
            """);
        first.Parameters.AddWithValue("$id", id);
        first.Parameters.AddWithValue("$log", logId);
        return first.ExecuteScalar() is byte[] recorded && CenterRouting.SameClass(CenterCaller.Parser.ParseFrom(recorded), caller)
            ? new RecordedCommand(outcome, false)
            : null;
    }

    private static (IMessage Request, RequestMeta? Meta) Parse(RoutedMethod method, ByteString payload) => method switch
    {
        RoutedMethod.SubmitNodeTask => Pair(TaskServiceSubmitTaskRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.GetNodeTask => Pair(TaskServiceGetTaskRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.ListNodeTasks => Pair(TaskServiceListTasksRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.WaitNodeTask => Pair(TaskServiceWaitTaskRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.ReadNodeTaskOutput => Pair(TaskServiceReadTaskOutputRequest.Parser.ParseFrom(payload), request => request.Meta),
        RoutedMethod.CancelNodeTask => Pair(TaskServiceCancelTaskRequest.Parser.ParseFrom(payload), request => request.Meta),
        _ => throw new ArgumentOutOfRangeException(nameof(method), "The verifier admits the six routed methods only."),
    };

    private static (IMessage, RequestMeta?) Pair<T>(T request, Func<T, RequestMeta?> meta)
        where T : IMessage => (request, meta(request));

    private static async Task<(IMessage Response, ArcError? Error)> RunAsync(TaskServiceHandler tasks, RoutedMethod method, Caller caller, IMessage request,
        CancellationToken cancellationToken)
    {
        switch (method)
        {
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
            default:
                var cancelled = await tasks.CancelTask(caller, (TaskServiceCancelTaskRequest)request, cancellationToken).ConfigureAwait(false);
                return (cancelled, cancelled.Error);
        }
    }

    /// <summary>
    /// The signed answer of a body's response (decisions B-1, Q4): an AUTHORIZATION refusal (the matrix, an approval raised, the command
    /// patterns) is REFUSED_BY_POLICY with closed fields only; anything else is EXECUTED with the response's exact bytes. An INTERNAL error
    /// that was not recorded is made UNKNOWN with NEVER (the catalogue's pair), never a final DID_NOT_HAPPEN it cannot prove.
    /// </summary>
    private RoutedAnswer Answer(IMessage response, ArcError? error, RoutedContext context, IMessage request, string operation, int risk)
    {
        var taskId = TaskIdOf(request) ?? (response is TaskServiceSubmitTaskResponse { Value.TaskId: { } created } ? created.Value.ToByteArray() : null);
        if (error is { Category: ErrorCategory.Authorization })
        {
            var stated = context.Operation ?? operation;
            var correlation = Correlation();
            var closed = error.Code switch
            {
                "approval_required" when error.Details?.State?.Resource?.Id is { } approval => RoutedRefusals.ApprovalRequired(stated, approval, correlation),
                "command_pattern_denied" => RoutedRefusals.Authorization("command_pattern_denied", stated, context.Reason ?? "agents.allowed_command_patterns", correlation),
                _ => RoutedRefusals.Policy(stated, context.Reason ?? "denied", correlation),
            };
            return new RoutedAnswer(RoutedOutcome.RefusedByPolicy, null, closed, taskId, risk);
        }

        if (error is { Category: ErrorCategory.Internal })
        {
            error.Effect = EffectCertainty.Unknown;
            error.Retry = new RetryAdvice { Mode = RetryMode.Never };
        }

        return new RoutedAnswer(RoutedOutcome.Executed, response.ToByteString(), null, taskId, risk, Code(error));
    }

    private static RoutedAnswer Executed(RoutedMethod method, RequestMeta? meta, ArcError error, byte[]? taskId, int risk)
    {
        var responseMeta = ApiCommands.Meta(meta);
        IMessage response = method switch
        {
            RoutedMethod.SubmitNodeTask => new TaskServiceSubmitTaskResponse { Meta = responseMeta, Error = error },
            RoutedMethod.GetNodeTask => new TaskServiceGetTaskResponse { Meta = responseMeta, Error = error },
            RoutedMethod.ListNodeTasks => new TaskServiceListTasksResponse { Meta = responseMeta, Error = error },
            RoutedMethod.WaitNodeTask => new TaskServiceWaitTaskResponse { Meta = responseMeta, Error = error },
            RoutedMethod.ReadNodeTaskOutput => new TaskServiceReadTaskOutputResponse { Meta = responseMeta, Error = error },
            _ => new TaskServiceCancelTaskResponse { Meta = responseMeta, Error = error },
        };
        return new RoutedAnswer(RoutedOutcome.Executed, response.ToByteString(), null, taskId, risk, Code(error));
    }

    /// <summary>A recorded outcome, replayed byte for byte (Q-5): the stored bytes are the answer.</summary>
    private static RoutedAnswer Replayed(RoutedMethod method, byte[] outcome, IMessage request, int risk)
    {
        ArcError? error;
        byte[]? taskId = TaskIdOf(request);
        if (method == RoutedMethod.SubmitNodeTask)
        {
            var submitted = TaskServiceSubmitTaskResponse.Parser.ParseFrom(outcome);
            error = submitted.Error;
            taskId ??= submitted.Value?.TaskId?.Value.ToByteArray();
        }
        else
        {
            error = TaskServiceCancelTaskResponse.Parser.ParseFrom(outcome).Error;
        }

        return new RoutedAnswer(RoutedOutcome.Executed, ByteString.CopyFrom(outcome), null, taskId, risk, Code(error));
    }

    private RoutedAnswer Refused(string operation, string reason, int risk, byte[]? taskId = null) =>
        new(RoutedOutcome.RefusedByPolicy, null, RoutedRefusals.Policy(operation, reason, Correlation()), taskId, risk);

    private Id Correlation() => CommandIds.New(node.Clock);

    private static Task AuditDeniedAsync(TaskServiceHandler tasks, Caller caller, string operation, RoutedMethod method, string reason) =>
        tasks.Api.AuditAsync(caller, new GateRequest(operation, "FleetService." + MethodName(method), "center-routed " + MethodName(method)),
            PermissionDecision.Deny, "denied: " + reason);

    private static string? Code(ArcError? error) => error is null ? null : error.Category.ToString().ToUpperInvariant() + "/" + error.Code;

    private static byte[]? TaskIdOf(IMessage request) => request switch
    {
        TaskServiceGetTaskRequest { TaskId: { } id } => id.Value.ToByteArray(),
        TaskServiceWaitTaskRequest { TaskId: { } id } => id.Value.ToByteArray(),
        TaskServiceCancelTaskRequest { TaskId: { } id } => id.Value.ToByteArray(),
        _ => null,
    } is { Length: 16 } task ? task : null;

    private static string MethodName(RoutedMethod method) => method switch
    {
        RoutedMethod.SubmitNodeTask => "SubmitTask",
        RoutedMethod.GetNodeTask => "GetTask",
        RoutedMethod.ListNodeTasks => "ListTasks",
        RoutedMethod.WaitNodeTask => "WaitTask",
        RoutedMethod.ReadNodeTaskOutput => "ReadTaskOutput",
        _ => "CancelTask",
    };

    /// <summary>The risk class for <c>routed_call_log.risk</c>: Submit high (3), Cancel medium (2), the reads low (1).</summary>
    private static int Risk(RoutedMethod method) => method switch
    {
        RoutedMethod.SubmitNodeTask => 3,
        RoutedMethod.CancelNodeTask => 2,
        _ => 1,
    };
}
