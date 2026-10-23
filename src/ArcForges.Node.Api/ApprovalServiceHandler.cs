// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// The requests an approval can carry, by method (<c>&lt;Service&gt;.&lt;Method&gt;</c>): each gated service registers how its captured request
/// runs again under the requester, with the original <c>command_id</c>, once a HUMAN approved it (11 section 1; contracts README section 6).
/// </summary>
internal sealed class ApprovalExecutors
{
    private readonly Dictionary<string, (string Operation, Func<byte[], Caller, Task<byte[]>> Run)> _executors = new(StringComparer.Ordinal);

    /// <summary>Registers the executor of <paramref name="method"/>, gated as the matrix operation <paramref name="operation"/>.</summary>
    public void Register<TRequest, TResponse>(string method, string operation, MessageParser<TRequest> parser, Func<TRequest, Caller, Task<TResponse>> run)
        where TRequest : IMessage<TRequest>
        where TResponse : IMessage<TResponse> =>
        _executors[method] = (operation, async (bytes, caller) => (await run(parser.ParseFrom(bytes), caller).ConfigureAwait(false)).ToByteArray());

    /// <summary>The executor of <paramref name="method"/>, or <see langword="null"/>.</summary>
    public (string Operation, Func<byte[], Caller, Task<byte[]>> Run)? Find(string method) => _executors.TryGetValue(method, out var found) ? found : null;
}

/// <summary>
/// <c>arcforges.node.v1.ApprovalService</c> (approvals.proto; SM-APPROVAL): lists and reads approvals (pending first; an AGENT caller sees its
/// own requests), decides them (HUMAN only, 11 section 1: the approver must be HUMAN), and withdraws them (the requester or a HUMAN). An
/// approval executes the captured request under its original <c>command_id</c> as the requester, right after the decision, so the
/// requester's retry with that command ID receives the executed outcome; the decision call returns the approval with its outcome. An
/// approval left APPROVED by a node stop executes when the node starts again (<see cref="ResumeAsync"/>).
/// </summary>
public sealed class ApprovalServiceHandler : ApprovalService.ApprovalServiceBase
{
    private const string ServiceName = "arcforges.node.v1.ApprovalService";
    private readonly NodeRuntime _node;
    private readonly ApiCommands _api;
    private readonly ApprovalExecutors _executors;

    internal ApprovalServiceHandler(NodeRuntime node, ClientSessions sessions, ApprovalExecutors executors)
    {
        _node = node ?? throw new ArgumentNullException(nameof(node));
        _api = new ApiCommands(node, sessions ?? throw new ArgumentNullException(nameof(sessions)), ServiceName);
        _executors = executors ?? throw new ArgumentNullException(nameof(executors));
    }

    /// <inheritdoc />
    public override async Task<ApprovalServiceListApprovalsResponse> ListApprovals(ApprovalServiceListApprovalsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ApprovalServiceListApprovalsResponse { Meta = ApiCommands.Meta(request.Meta) };
        var limit = 50;
        var offset = 0;
        var refused = _api.Stopping();
        if (refused is null && request.States.Distinct().Count() != request.States.Count)
        {
            refused = NodeErrors.InvalidArgument("states: unique values");
        }

        if (refused is null && request.Page is { } page)
        {
            if (page.HasLimit && page.Limit is < 1 or > 500)
            {
                refused = NodeErrors.InvalidArgument("page.limit: 1..500");
            }
            else if (page.HasLimit)
            {
                limit = (int)page.Limit;
            }

            if (refused is null && page.HasCursor && page.Cursor.Length > 0
                && (!int.TryParse(page.Cursor, NumberStyles.None, CultureInfo.InvariantCulture, out offset) || offset < 0))
            {
                refused = NodeErrors.InvalidCursor();
            }
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        await ExpireAsync().ConfigureAwait(false);
        var caller = _api.CallerOf(context);
        var (items, next) = _node.Store.Read(reader => Approvals.List(reader, [.. request.States], approval => Visible(caller, approval), offset, limit));
        var value = new ApprovalServiceListApprovalsValue { Page = new PageState { HasMore = next is not null } };
        value.Approvals.Add(items);
        if (next is not null)
        {
            value.Page.NextCursor = next;
        }

        response.Value = value;
        return response;
    }

    /// <inheritdoc />
    public override async Task<ApprovalServiceGetApprovalResponse> GetApproval(ApprovalServiceGetApprovalRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ApprovalServiceGetApprovalResponse { Meta = ApiCommands.Meta(request.Meta) };
        if ((_api.Stopping() ?? Validation.RequiredId(request.ApprovalId, "approval_id")) is { } refused)
        {
            response.Error = refused;
            return response;
        }

        await ExpireAsync().ConfigureAwait(false);
        var caller = _api.CallerOf(context);
        var approval = _node.Store.Read(reader => Approvals.Get(reader, request.ApprovalId.Value.Span));
        if (approval is null || !Visible(caller, approval.View))
        {
            response.Error = NodeErrors.NotFound("approval", request.ApprovalId.Value.Span);
        }
        else
        {
            response.Value = new ApprovalServiceGetApprovalValue { Approval = approval.View };
        }

        return response;
    }

    /// <inheritdoc />
    public override async Task<ApprovalServiceDecideApprovalResponse> DecideApproval(ApprovalServiceDecideApprovalRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ApprovalServiceDecideApprovalResponse { Meta = ApiCommands.Meta(request.Meta) };
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.ApprovalId, "approval_id")
            ?? (request.Decision is ApprovalDecisionKind.Approve or ApprovalDecisionKind.Deny ? null : NodeErrors.InvalidArgument("decision: APPROVE or DENY"))
            ?? (request.HasComment && request.Comment.Length > 500 ? NodeErrors.InvalidArgument("comment: <= 500 chars") : null);
        var caller = _api.CallerOf(context);
        var id = Bytes(request.ApprovalId);
        refused ??= await _api.DenyUnlessAllowedAsync(caller, new GateRequest(PermissionMatrix.ApprovalDecide, "ApprovalService.DecideApproval",
            "decide approval " + IdText.Format(id), "approval", id)).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var approve = request.Decision == ApprovalDecisionKind.Approve;
        StoredApproval? decided = null;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "DecideApproval", ApprovalServiceDecideApprovalResponse.Parser,
            failure => new ApprovalServiceDecideApprovalResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                Approvals.Expire(command);
                var current = Approvals.Get(command.Transaction, id);
                ArcError? error = current?.State switch
                {
                    null => NodeErrors.NotFound("approval", id),
                    ApprovalState.Expired => ApiCommands.StateExpired(IdText.Format(id)),
                    ApprovalState.Cancelled => NodeErrors.InvalidState("CANCELLED", "the approval was withdrawn"),
                    _ => null,
                };
                if (error is not null)
                {
                    return new ApprovalServiceDecideApprovalResponse { Meta = ApiCommands.Meta(request.Meta), Error = error };
                }

                // approvals.proto: a second decision returns the first.
                if (current!.State == ApprovalState.Pending)
                {
                    current = Approvals.Decide(command, id, approve, caller.Actor, request.HasComment ? request.Comment : null);
                    decided = current;
                }

                return new ApprovalServiceDecideApprovalResponse
                {
                    Meta = ApiCommands.Meta(request.Meta),
                    Value = new ApprovalServiceDecideApprovalValue { Approval = current.View },
                };
            }).ConfigureAwait(false);
        if (result.OutcomeCase != ApprovalServiceDecideApprovalResponse.OutcomeOneofCase.Value)
        {
            return result;
        }

        if (!replayed && decided is { State: ApprovalState.Approved } approved)
        {
            await ExecuteAsync(approved).ConfigureAwait(false);
        }

        // The approval as it is now: after this decision's execution, or (a replayed decision) whatever happened since.
        if (_node.Store.Read(reader => Approvals.Get(reader, id)) is { } now)
        {
            result.Value.Approval = now.View;
        }

        _node.Log.Info("api.approval.decided", new LogField("approval", IdText.Format(id)), new LogField("decision", approve ? "approve" : "deny"),
            new LogField("state", result.Value.Approval.State), new LogField("replayed", replayed));
        return result;
    }

    /// <inheritdoc />
    public override async Task<ApprovalServiceCancelApprovalResponse> CancelApproval(ApprovalServiceCancelApprovalRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ApprovalServiceCancelApprovalResponse { Meta = ApiCommands.Meta(request.Meta) };
        if ((_api.Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.ApprovalId, "approval_id")) is { } refused)
        {
            response.Error = refused;
            return response;
        }

        var caller = _api.CallerOf(context);
        var id = request.ApprovalId.Value.ToByteArray();
        var (result, _) = await _api.IdempotentAsync(request, request.Meta, caller, "CancelApproval", ApprovalServiceCancelApprovalResponse.Parser,
            failure => new ApprovalServiceCancelApprovalResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                Approvals.Expire(command);
                var current = Approvals.Get(command.Transaction, id);
                ArcError? error = null;
                if (current is null || !Visible(caller, current.View))
                {
                    error = NodeErrors.NotFound("approval", id);
                }
                else if (caller.Origin != Origin.Human && !Requester(caller, current.View))
                {
                    // approvals.proto: the requester or a HUMAN withdraws.
                    error = NodeErrors.PermissionDenied("ApprovalService.CancelApproval: only the requester or a HUMAN caller withdraws an approval");
                }
                else if (current.State != ApprovalState.Pending)
                {
                    error = NodeErrors.InvalidState(current.State.ToString().ToUpperInvariant(), "only a PENDING approval can be withdrawn");
                }

                return error is not null
                    ? new ApprovalServiceCancelApprovalResponse { Meta = ApiCommands.Meta(request.Meta), Error = error }
                    : new ApprovalServiceCancelApprovalResponse
                    {
                        Meta = ApiCommands.Meta(request.Meta),
                        Value = new ApprovalServiceCancelApprovalValue { Approval = Approvals.Cancel(command, id, caller.Actor).View },
                    };
            }).ConfigureAwait(false);
        return result;
    }

    /// <summary>Executes the approvals a node stop left APPROVED (called once the execution supervisor runs).</summary>
    public async Task ResumeAsync()
    {
        foreach (var approval in _node.Store.Read(Approvals.Unexecuted))
        {
            await ExecuteAsync(approval).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Runs an APPROVED approval's captured request under its original command ID as the requester, and records the outcome: EXECUTED, or
    /// FAILED when the response carries an error (an executor that throws, or a method without one, is FAILED with an internal error).
    /// </summary>
    private async Task ExecuteAsync(StoredApproval approval)
    {
        byte[] outcome;
        var operation = "approval.execute";
        if (_executors.Find(approval.View.Operation) is { } executor)
        {
            operation = executor.Operation;
            try
            {
                outcome = await executor.Run(approval.Request, Caller.OfApproval(approval.View.Requester, approval.Id)).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                _node.Log.Error("api.approval.execute_failed", exception);
                outcome = ErrorResponse(NodeErrors.Internal(_node.Clock.GetUtcNow()));
            }
        }
        else
        {
            outcome = ErrorResponse(NodeErrors.InvalidState("UNSUPPORTED", approval.View.Operation + " cannot run from an approval on this node"));
        }

        try
        {
            await _node.Processor.ExecuteAsync(command => Approvals.Executed(command, approval.Id, outcome, Approvals.OutcomeError(outcome), operation), CommitDurability.Full)
                .ConfigureAwait(false);
        }
        catch (CommandQueueFullException)
        {
            _node.Log.Warning("api.approval.record_deferred", new LogField("approval", IdText.Format(approval.Id)));
        }
    }

    private static byte[] Bytes(Id? id) => id?.Value.ToByteArray() ?? [];

    /// <summary>A serialized response carrying only <paramref name="error"/> (field 3 of every node response, contracts README section 4).</summary>
    private static byte[] ErrorResponse(ArcError error)
    {
        using var buffer = new MemoryStream();
        var output = new CodedOutputStream(buffer);
        output.WriteTag(3, WireFormat.WireType.LengthDelimited);
        output.WriteMessage(error);
        output.Flush();
        return buffer.ToArray();
    }

    private async Task ExpireAsync()
    {
        try
        {
            await _node.Processor.ExecuteAsync(Approvals.Expire).ConfigureAwait(false);
        }
        catch (CommandQueueFullException)
        {
        }
    }

    /// <summary>approvals.proto: HUMAN and SCRIPT callers see every approval, an AGENT caller its own requests.</summary>
    private static bool Visible(Caller caller, Approval approval) => caller.Origin != Origin.Agent || Requester(caller, approval);

    /// <summary>
    /// True when <paramref name="caller"/> is the approval's requester: the same origin and client kind (sessions, which would tell two agent
    /// sessions apart, arrive with AF-AI-01).
    /// </summary>
    private static bool Requester(Caller caller, Approval approval) =>
        approval.Requester is { } requester && requester.Origin == caller.Origin && requester.ClientKind == caller.Kind;
}
