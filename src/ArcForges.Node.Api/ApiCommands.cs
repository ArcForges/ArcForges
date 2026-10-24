// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// Who calls a method: the connection's session (its origin assigned at the hello), or, when an approved request executes, the requester
/// the approval captured. <see cref="ApprovalId"/> is set only for the latter, and then an APPROVAL cell of the matrix lets the call through.
/// </summary>
/// <param name="Origin">The origin.</param>
/// <param name="Kind">The client kind.</param>
/// <param name="Session">The connection's session, or <see langword="null"/> (no hello, or an approved request executing).</param>
/// <param name="ApprovalId">The approval under which the request executes, or <see langword="null"/>.</param>
public sealed record Caller(Origin Origin, ClientKind Kind, ClientSession? Session, byte[]? ApprovalId = null)
{
    /// <summary>The caller as an <see cref="ActorRef"/> (task owners, policy revisions, the audit log).</summary>
    public ActorRef Actor => new() { Origin = Origin, ClientKind = Kind };

    /// <summary>True while an approved request executes.</summary>
    public bool Approved => ApprovalId is not null;

    /// <summary>The caller of an approval's request.</summary>
    public static Caller OfApproval(ActorRef requester, byte[] approvalId)
    {
        ArgumentNullException.ThrowIfNull(requester);
        return new Caller(requester.Origin, requester.ClientKind, null, approvalId);
    }
}

/// <summary>What a gated call asks the approver, and what the audit log records.</summary>
/// <param name="Operation">The matrix operation (<see cref="PermissionMatrix"/>).</param>
/// <param name="Method">The method as <c>&lt;Service&gt;.&lt;Method&gt;</c>.</param>
/// <param name="Summary">A one-line summary.</param>
/// <param name="TargetKind">The kind of the object acted on, if any.</param>
/// <param name="TargetId">The object's ID, if any.</param>
public sealed record GateRequest(string Operation, string Method, string Summary, string? TargetKind = null, byte[]? TargetId = null)
{
    /// <summary>Details for the approver.</summary>
    public IReadOnlyList<KeyValue> Details { get; init; } = [];

    /// <summary>True when an AGENT caller's ALLOW is an APPROVAL for this target (the matrix's per-target rule, for example task.retry).</summary>
    public bool AgentApproval { get; init; }

    /// <summary>Why <see cref="AgentApproval"/> applies (shown as the decision's source).</summary>
    public string AgentApprovalReason { get; init; } = string.Empty;
}

/// <summary>
/// Thrown inside an idempotent command when what the gate relied on no longer holds (review round 2): the command stops before it acts, nothing
/// is stored under the command ID, and the request is checked again. <see cref="ReplayOnly"/>: the gate was skipped because the command had
/// already run, but its record expired before the command, so the call may only replay and answers <c>STATE/invalid_state</c> instead.
/// </summary>
internal sealed class GateStaleException : Exception
{
    public GateStaleException()
    {
    }

    public GateStaleException(string message)
        : base(message)
    {
    }

    public GateStaleException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>True for a call that skipped the gate as a replay.</summary>
    public bool ReplayOnly { get; init; }
}

/// <summary>
/// The shared plumbing of the node's services: response metas, the stopping check, the permission gate of 11 section 1 (the default matrix
/// with the policy's <c>permissions</c> overrides; an APPROVAL cell raises an approval and fails with <c>AUTHORIZATION/approval_required</c>
/// carrying its ID), the audit of privileged actions, and idempotent commands by <c>meta.command_id</c>, which also replay the outcome of a
/// request that executed after its approval.
/// </summary>
internal sealed class ApiCommands(NodeRuntime node, ClientSessions sessions, string service)
{
    /// <summary>Command IDs whose call skipped the gate as a replay of a recorded outcome: their idempotent command may only replay.</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _replayOnly = new(StringComparer.Ordinal);

    /// <summary>The response meta echoing the request's correlation ID.</summary>
    public static ResponseMeta Meta(RequestMeta? request)
    {
        var meta = new ResponseMeta();
        if (request?.CorrelationId is { } correlation)
        {
            meta.CorrelationId = correlation;
        }

        return meta;
    }

    /// <summary><c>STATE/node_stopping</c> while the node stops; counts the call.</summary>
    public ArcError? Stopping()
    {
        node.CountCall();
        return node.Lifecycle.IsStopping ? NodeErrors.NodeStopping(node.Clock.GetUtcNow()) : null;
    }

    /// <summary>The caller's origin.</summary>
    public Origin OriginOf(ServerCallContext context) => sessions.OriginOf(context);

    /// <summary>The caller of a connection's call.</summary>
    public Caller CallerOf(ServerCallContext context)
    {
        var session = sessions.SessionOf(context);
        return new Caller(session?.Origin ?? Origin.Script, session?.Kind ?? ClientKind.Unspecified, session);
    }

    /// <summary>The matrix decision for <paramref name="caller"/> on <paramref name="operation"/> under the current policy.</summary>
    public PermissionVerdict Decide(Caller caller, string operation) =>
        PermissionMatrix.Decide(caller.Origin, operation, node.Store.Read(PolicyRules.Current).Document.Permissions);

    /// <summary>True when the matrix allows <paramref name="operation"/> to <paramref name="caller"/> without an approval.</summary>
    public bool Allowed(Caller caller, string operation) => Decide(caller, operation).Decision == PermissionDecision.Allow;

    /// <summary>
    /// The permission gate (11 section 1) of a call that needs no approval capture (a refusal of an APPROVAL cell would raise one, so such
    /// operations go through <see cref="GateAsync"/>): <see langword="null"/> when allowed; a denial is audited.
    /// </summary>
    public async Task<ArcError?> DenyUnlessAllowedAsync(Caller caller, GateRequest gate, IMessage? request = null, RequestMeta? meta = null)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(gate);
        if (request is not null && meta is not null && Recorded(gate.Method, request, meta))
        {
            // Review round 1: a command that already ran answers with its recorded outcome, whatever the matrix says now (replay only).
            MarkReplayOnly(meta);
            return null;
        }

        var verdict = Decide(caller, gate.Operation);
        return verdict.Decision == PermissionDecision.Allow ? null : await DeniedAsync(caller, gate, verdict).ConfigureAwait(false);
    }

    /// <summary>
    /// The permission gate (11 section 1): <see langword="null"/> when the call may run. A DENY cell is <c>AUTHORIZATION/permission_denied</c>
    /// (audited). An APPROVAL cell raises an approval that captures <paramref name="request"/> under its <c>meta.command_id</c> and fails
    /// with <c>AUTHORIZATION/approval_required</c> carrying the approval ID; a retry with the same command ID finds the same approval: still
    /// pending, <c>approval_required</c> again; executed or failed, the call passes so that the idempotent command replays the executed outcome;
    /// denied or withdrawn, <c>permission_denied</c>; expired, <c>STATE/expired</c>. A request executing under its approval passes.
    /// </summary>
    public async Task<ArcError?> GateAsync(Caller caller, GateRequest gate, IMessage request, RequestMeta meta)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(meta);
        if (Recorded(gate.Method, request, meta))
        {
            // Review round 1: the gate runs after dedup. A command that already ran (within the 24-hour window, or after its approval) answers
            // with its recorded outcome and raises no new approval, whatever the matrix says now. Review round 2: replay only.
            MarkReplayOnly(meta);
            return null;
        }

        var verdict = Decide(caller, gate.Operation);
        if (verdict.Decision == PermissionDecision.Allow && gate.AgentApproval && caller.Origin == Origin.Agent && !caller.Approved)
        {
            // A row whose AGENT cell is ALLOW except for some targets (task.retry: a SIDE_EFFECTING or UNKNOWN task needs approval).
            verdict = verdict with { Decision = PermissionDecision.Approval, Source = verdict.Source + "; " + gate.AgentApprovalReason };
        }

        if (verdict.Decision == PermissionDecision.Allow || (verdict.Decision == PermissionDecision.Approval && caller.Approved))
        {
            return null;
        }

        if (verdict.Decision != PermissionDecision.Approval)
        {
            return await DeniedAsync(caller, gate, verdict).ConfigureAwait(false);
        }

        var capture = new ApprovalCapture
        {
            Operation = gate.Method,
            MatrixOperation = gate.Operation,
            Summary = gate.Summary,
            Details = gate.Details,
            Risk = PermissionMatrix.Find(gate.Operation)!.Risk,
            Requester = caller.Actor,
            CommandId = meta.CommandId.Value.ToByteArray(),
            Request = request.ToByteArray(),
            RequestDigest = PayloadDigest.Compute(request),
            TargetKind = gate.TargetKind,
            TargetId = gate.TargetId,
        };
        try
        {
            return await node.Processor.ExecuteAsync(context =>
            {
                Approvals.Expire(context);
                var policy = PolicyRules.Current(context.Transaction).Document.Approvals;
                var ttl = policy is { HasDefaultTtlMs: true, DefaultTtlMs: > 0 } ? TimeSpan.FromMilliseconds(policy.DefaultTtlMs) : Approvals.DefaultTtl;
                var (approval, created, error) = Approvals.Raise(context, capture, ttl);
                if (error is not null)
                {
                    return error;
                }

                if (created && policy?.NotifyDesktop != false)
                {
                    Notifications.Add(context, "approval_needed", Severity.Warning, "Approval needed",
                        $"{PermissionMatrix.Name(caller.Origin)} asks: {approval!.View.Summary}", "arcforges://approvals/" + IdText.Format(approval.View.ApprovalId));
                }

                var id = IdText.Format(approval!.View.ApprovalId);
                return approval.State switch
                {
                    ApprovalState.Pending or ApprovalState.Approved => Approvals.Required(approval.View),
                    ApprovalState.Executed or ApprovalState.Failed => null,
                    ApprovalState.Expired => StateExpired(id),
                    ApprovalState.Denied => NodeErrors.PermissionDenied($"{gate.Method}: approval {id} was denied"),
                    _ => NodeErrors.PermissionDenied($"{gate.Method}: approval {id} was withdrawn"),
                };
            }, CommitDurability.Full).ConfigureAwait(false);
        }
        catch (CommandQueueFullException)
        {
            return NodeErrors.Overloaded(node.Clock.GetUtcNow());
        }
    }

    /// <summary>
    /// Runs <paramref name="execute"/> once per command ID (24 h); a replay returns the recorded response. A request that already executed
    /// after its approval returns the approval's stored outcome instead of executing again (also after the 24-hour window). With
    /// <paramref name="audit"/>, the action is written to the audit log in its own transaction, with its outcome.
    /// </summary>
    public async Task<(TResponse Response, bool Replayed)> IdempotentAsync<TResponse>(IMessage request, RequestMeta meta, Caller caller, string method,
        MessageParser<TResponse> parser, Func<ArcError, TResponse> fail, Func<CommandContext, TResponse> execute, GateRequest? audit = null)
        where TResponse : class, IMessage<TResponse>
    {
        ArgumentNullException.ThrowIfNull(caller);
        var digest = PayloadDigest.Compute(request);
        var replayOnly = _replayOnly.TryRemove(Key(meta), out _);
        try
        {
            // Review round 1: an approval recorded under this command ID answers only the same method and request; another request reusing the
            // ID is CONFLICT/command_id_reused, as for any reused command ID.
            if (!caller.Approved && node.Store.Read(reader => Approvals.ByCommand(reader, meta.CommandId.Value.Span)) is { } earlier
                && !SameRequest(earlier, method, digest))
            {
                return (fail(StoreErrors.CommandIdReused()), false);
            }

            var outcome = await node.Processor.ExecuteIdempotentAsync(meta.CommandId.Value.Memory, service + "/" + method, digest, caller.Origin, command =>
            {
                if (!caller.Approved && Approvals.ByCommand(command.Transaction, meta.CommandId.Value.Span) is { State: ApprovalState.Executed or ApprovalState.Failed, Outcome: { Length: > 0 } stored } approved
                    && SameRequest(approved, method, digest))
                {
                    return stored;
                }

                if (replayOnly)
                {
                    // The gate let this call through as a replay, but the recorded outcome expired before the command: it never executes.
                    throw new GateStaleException("the recorded outcome expired before the command") { ReplayOnly = true };
                }

                var response = execute(command);
                if (audit is not null)
                {
                    var error = Approvals.OutcomeError(response.ToByteArray());
                    AuditLog.Append(command.Transaction, caller.Actor, audit.Operation + " " + audit.Method, audit.TargetKind, audit.TargetId ?? [],
                        PermissionDecision.Allow, caller.ApprovalId ?? [], error is null ? "done: " + audit.Summary : $"failed ({error.Category}/{error.Code}): {audit.Summary}");
                }

                return response.ToByteArray();
            }).ConfigureAwait(false);
            return outcome.Error is { } failure ? (fail(failure), false) : (parser.ParseFrom(outcome.Outcome), outcome.Replayed);
        }
        catch (CommandQueueFullException)
        {
            return (fail(NodeErrors.Overloaded(node.Clock.GetUtcNow())), false);
        }
        catch (GateStaleException stale) when (stale.ReplayOnly)
        {
            return (fail(NodeErrors.InvalidState("EXPIRED",
                "the recorded outcome of this command ID expired while the request was checked; nothing ran: send the request again")), false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException and not GateStaleException)
        {
            node.Log.Error("api.command.failed", exception);
            return (fail(NodeErrors.Internal(node.Clock.GetUtcNow())), false);
        }
    }

    /// <summary>
    /// True when the command <paramref name="meta"/> names already ran for this same method and request: its outcome is in
    /// <c>command_dedup</c> (24-hour window), or an approval executed it (any time). The gate lets such a retry through so that the
    /// idempotent command answers with the recorded outcome.
    /// </summary>
    public bool Recorded(string method, IMessage request, RequestMeta meta)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(meta);
        if (meta.CommandId is not { } id || id.Value.Length != 16)
        {
            return false;
        }

        var name = method[(method.LastIndexOf('.') + 1)..];
        var digest = PayloadDigest.Compute(request);
        var now = StoreTime.ToMicroseconds(node.Clock.GetUtcNow());
        return node.Store.Read(reader =>
        {
            using (var command = reader.CreateCommand("SELECT method, payload_digest, outcome, expires_at FROM command_dedup WHERE command_id = $id;"))
            {
                command.Parameters.AddWithValue("$id", id.Value.ToByteArray());
                using var row = command.ExecuteReader();
                if (row.Read() && row.GetInt64(3) > now && !row.IsDBNull(2) && row.GetString(0) == service + "/" + name
                    && ((byte[])row.GetValue(1)).AsSpan().SequenceEqual(digest))
                {
                    return true;
                }
            }

            return Approvals.ByCommand(reader, id.Value.Span) is { State: ApprovalState.Executed or ApprovalState.Failed, Outcome.Length: > 0 } approval
                && SameRequest(approval, name, digest);
        });
    }

    /// <summary>Marks the call of <paramref name="meta"/>'s command ID as replay-only (its gate was skipped as a replay).</summary>
    public void MarkReplayOnly(RequestMeta meta)
    {
        ArgumentNullException.ThrowIfNull(meta);
        _replayOnly[Key(meta)] = 0;
    }

    private static string Key(RequestMeta meta) => meta.CommandId is { } id ? Convert.ToHexString(id.Value.Span) : string.Empty;

    /// <summary>True when an approval captured this method (<c>&lt;Service&gt;.&lt;Method&gt;</c>) and this request digest.</summary>
    private static bool SameRequest(StoredApproval approval, string method, ReadOnlySpan<byte> digest) =>
        approval.View.Operation.EndsWith("." + method, StringComparison.Ordinal) && approval.RequestDigest.AsSpan().SequenceEqual(digest);

    /// <summary>Writes an audit entry for an action outside an idempotent command (for example a refused one).</summary>
    public async Task AuditAsync(Caller caller, GateRequest gate, PermissionDecision decision, string outcome)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(gate);
        try
        {
            await node.Processor.ExecuteAsync(context =>
            {
                AuditLog.Append(context.Transaction, caller.Actor, gate.Operation + " " + gate.Method, gate.TargetKind, gate.TargetId ?? [], decision,
                    caller.ApprovalId ?? [], outcome);
                return 0;
            }).ConfigureAwait(false);
        }
        catch (CommandQueueFullException)
        {
            node.Log.Warning("api.audit.dropped", new LogField("operation", gate.Operation));
        }
    }

    /// <summary><c>STATE/expired</c> (errors.md: a flow, offer, pairing or approval expired).</summary>
    public static ArcError StateExpired(string approvalId) => new()
    {
        Code = "expired",
        Category = ErrorCategory.State,
        MessageKey = "error.state.expired",
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
        Details = new ErrorDetails { State = new StateFailure { State = "EXPIRED", Reason = "approval " + approvalId + " expired" } },
    };

    private async Task<ArcError> DeniedAsync(Caller caller, GateRequest gate, PermissionVerdict verdict)
    {
        await AuditAsync(caller, gate, verdict.Decision, "denied: " + gate.Summary).ConfigureAwait(false);
        return NodeErrors.PermissionDenied($"{gate.Method}: {gate.Operation} is denied for {PermissionMatrix.Name(caller.Origin)} callers ({verdict.Source})");
    }
}
