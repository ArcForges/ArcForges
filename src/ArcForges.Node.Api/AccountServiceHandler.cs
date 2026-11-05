// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Security;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>AccountService</c> on the local endpoint (AF-CTR-04 CTR4-NODE-10/11 as amended; parts N1 and N2): <c>GetAccountStatus</c>, the sign-in
/// methods <c>BeginSignIn</c>, <c>GetSignInFlow</c> and <c>CancelSignIn</c>, and <c>SignOut</c>; phone pairing
/// (AF-CLD-02), the cloud link switch (AF-CTR-05) and the entitlement refresh (AF-CLD-03) are later tasks: they answer <c>UNIMPLEMENTED</c>.
/// <para><c>SignOut</c> follows the I/O rule of node-3: the permission gate and the replay check, then the cloud link's gate and the replay
/// check again, then the center and secret-store I/O outside the single writer, then one short idempotent command that only records the
/// outcome. The state change is journaled on topic ACCOUNT by the link afterwards.</para>
/// <para><c>SignOut</c> fits its 15 s deadline (N1 decision R-5): one budget from the handler's entry; the wait for a center call in flight,
/// the remote part and the local ending all come out of it, and the local ending keeps <see cref="CloudLinkService.SignOutLocalReserve"/>.</para>
/// </summary>
internal sealed class AccountServiceHandler : AccountService.AccountServiceBase
{
    /// <summary>The service's full name.</summary>
    public const string ServiceName = "arcforges.node.v1.AccountService";

    /// <summary>The warning of a sign-out whose remote revocation was not confirmed (<c>ResponseMeta.warnings</c>).</summary>
    public const string RemoteUnconfirmed = "remote_sign_out_unconfirmed";

    /// <summary>The warning of a local sign-out that abandoned a link of another secret-store backend or node ID (N2 decision R-3).</summary>
    public const string Abandoned = "stranded_credential_abandoned";

    /// <summary>The warning of a sign-out refused because the link's store cannot be read now (nothing changed; retried).</summary>
    public const string StoreUnavailable = "credential_store_unavailable";

    private readonly NodeRuntime _node;
    private readonly CloudLinkService _cloud;
    private readonly ApiCommands _api;

    /// <summary>Creates the service.</summary>
    public AccountServiceHandler(NodeRuntime node, ClientSessions sessions, CloudLinkService cloud)
    {
        _node = node ?? throw new ArgumentNullException(nameof(node));
        _cloud = cloud ?? throw new ArgumentNullException(nameof(cloud));
        _api = new ApiCommands(node, sessions ?? throw new ArgumentNullException(nameof(sessions)), "AccountService");
    }

    /// <inheritdoc />
    public override Task<AccountServiceGetAccountStatusResponse> GetAccountStatus(AccountServiceGetAccountStatusRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);

        // account.proto: auth: HUMAN=A SCRIPT=A AGENT=A; idempotency: read.
        var response = new AccountServiceGetAccountStatusResponse { Meta = ApiCommands.Meta(request.Meta) };
        if (_api.Stopping() is { } stopping)
        {
            response.Error = stopping;
        }
        else
        {
            response.Value = new AccountServiceGetAccountStatusValue { Status = _cloud.Status() };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    /// <remarks>
    /// account.proto: "auth: HUMAN=A (interactive) SCRIPT=D AGENT=D", "idempotency: command_id; one active flow at a time (returns it)". Not
    /// recorded under its command ID (decision node-3): the one-active-flow rule returns the live flow. The center calls and the opener run
    /// outside the single writer and outside the link's gate, within one budget from this handler's entry (N2 decisions F-4, N-5).
    /// </remarks>
    public override async Task<AccountServiceBeginSignInResponse> BeginSignIn(AccountServiceBeginSignInRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var entered = _cloud.Options.Clock.GetTimestamp();
        var response = new AccountServiceBeginSignInResponse { Meta = ApiCommands.Meta(request.Meta) };
        var caller = _api.CallerOf(context);
        var gate = new GateRequest(PermissionMatrix.Integrations, "AccountService.BeginSignIn", "sign the node in to its center", "node");
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta) ?? await _api.DenyUnlessAllowedAsync(caller, gate).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var method = request.HasMethod && request.Method == SignInMethod.DeviceCode ? SignInMethod.DeviceCode : SignInMethod.Browser;
        var reply = await _cloud.SignIn.BeginAsync(method, entered, _node.Stopping).ConfigureAwait(false);
        if (reply.Error is { } error)
        {
            response.Error = error;
            return response;
        }

        response.Meta.Warnings.AddRange(reply.Warnings);
        response.Value = new AccountServiceBeginSignInValue { Flow = reply.Flow };
        return response;
    }

    /// <inheritdoc />
    /// <remarks>account.proto: "auth: HUMAN=A SCRIPT=A AGENT=D", "idempotency: read", "errors: STATE/not_found" (row <c>account.sign_in.read</c>).</remarks>
    public override async Task<AccountServiceGetSignInFlowResponse> GetSignInFlow(AccountServiceGetSignInFlowRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new AccountServiceGetSignInFlowResponse { Meta = ApiCommands.Meta(request.Meta) };
        var gate = new GateRequest(PermissionMatrix.SignInRead, "AccountService.GetSignInFlow", "read a sign-in flow", "sign_in_flow");
        var refused = _api.Stopping() ?? FlowId(request.FlowId) ?? await _api.DenyUnlessAllowedAsync(_api.CallerOf(context), gate).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
        }
        else if (_cloud.SignIn.Get(request.FlowId) is { } flow)
        {
            response.Value = new AccountServiceGetSignInFlowValue { Flow = flow };
        }
        else
        {
            response.Error = NodeErrors.NotFound("sign_in_flow", request.FlowId.Value.Span);
        }

        return response;
    }

    /// <inheritdoc />
    /// <remarks>
    /// account.proto: "auth: HUMAN=A SCRIPT=D AGENT=D", "idempotency: command_id", "errors: STATE/not_found, STATE/invalid_state". The cancel
    /// runs outside the single writer; one short idempotent command then records its outcome, so a replay answers it without cancelling again.
    /// </remarks>
    public override async Task<AccountServiceCancelSignInResponse> CancelSignIn(AccountServiceCancelSignInRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new AccountServiceCancelSignInResponse { Meta = ApiCommands.Meta(request.Meta) };
        var caller = _api.CallerOf(context);
        var gate = new GateRequest(PermissionMatrix.Integrations, "AccountService.CancelSignIn", "cancel a sign-in", "sign_in_flow");
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta) ?? FlowId(request.FlowId);
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        (SignInFlow? Flow, ArcError? Error)? result = null;
        if (_api.Recorded(gate.Method, request, request.Meta))
        {
            _api.MarkReplayOnly(request.Meta);
        }
        else
        {
            result = _cloud.SignIn.Cancel(request.FlowId);
        }

        return (await _api.IdempotentAsync(request, request.Meta, caller, "CancelSignIn", AccountServiceCancelSignInResponse.Parser,
            failure => new AccountServiceCancelSignInResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure },
            _ =>
            {
                var outcome = result ?? throw new InvalidOperationException("A replayed cancel never executes.");
                var answer = new AccountServiceCancelSignInResponse { Meta = ApiCommands.Meta(request.Meta) };
                if (outcome.Error is { } error)
                {
                    answer.Error = error;
                }
                else
                {
                    answer.Value = new AccountServiceCancelSignInValue { Flow = Recordable(outcome.Flow!) };
                }

                return answer;
            }, gate).ConfigureAwait(false)).Response;
    }

    /// <inheritdoc />
    public override async Task<AccountServiceSignOutResponse> SignOut(AccountServiceSignOutRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var entered = Stopwatch.GetTimestamp();
        var left = context.Deadline == DateTime.MaxValue ? CloudLinkService.SignOutDeadline : context.Deadline - DateTime.UtcNow;
        var budget = left < CloudLinkService.SignOutDeadline ? left : CloudLinkService.SignOutDeadline;
        TimeSpan Remote() => budget - Stopwatch.GetElapsedTime(entered) - CloudLinkService.SignOutLocalReserve;
        var response = new AccountServiceSignOutResponse { Meta = ApiCommands.Meta(request.Meta) };
        var caller = _api.CallerOf(context);
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta);

        // account.proto: auth: HUMAN=A (interactive) SCRIPT=D AGENT=D (integration.change, fixed).
        var gate = new GateRequest(PermissionMatrix.Integrations, "AccountService.SignOut", "sign the node out of its center", "node");
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        // N2 decision N-2: an active sign-in ends first, so the sign-out never deletes the key under a flow.
        _cloud.SignIn.CancelActive();
        AccountServiceSignOutResponse outcome;
        using (await _cloud.EnterForSignOutAsync(Remote(), _node.Stopping).ConfigureAwait(false))
        {
            // A second request with the same command ID that waited on the gate is a replay: no center call (node-3 addition 1).
            SignOutResult? result = null;
            if (_api.Recorded(gate.Method, request, request.Meta))
            {
                _api.MarkReplayOnly(request.Meta);
            }
            else
            {
                result = await _cloud.SignOutHeldAsync(!request.HasRevokeRemote || request.RevokeRemote, Remote()).ConfigureAwait(false);
            }

            outcome = (await _api.IdempotentAsync(request, request.Meta, caller, "SignOut", AccountServiceSignOutResponse.Parser,
                failure => new AccountServiceSignOutResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure },
                _ => Outcome(request, result ?? throw new InvalidOperationException("A replayed sign-out never executes.")), gate).ConfigureAwait(false)).Response;
        }

        await _cloud.PublishCurrentAsync().ConfigureAwait(false);
        return outcome;
    }

    /// <summary>
    /// The cancelled flow as CancelSignIn answers and records it (the outcome is kept in the node's database for replays): without the
    /// derived URLs, which carry the center's flow ID, and without the user code (N2-15; R-4: they are shown only while the flow runs).
    /// </summary>
    private static SignInFlow Recordable(SignInFlow flow)
    {
        var copy = flow.Clone();
        copy.ClearAuthorizeUrl();
        copy.ClearUserCode();
        copy.ClearVerificationUri();
        copy.ClearVerificationUriComplete();
        copy.ClearQrPayload();
        return copy;
    }

    private static ArcError? FlowId(Id? id) => id is { Value.Length: 16 } ? null : NodeErrors.InvalidArgument("flow_id: required");

    private static AccountServiceSignOutResponse Outcome(AccountServiceSignOutRequest request, SignOutResult result)
    {
        var response = new AccountServiceSignOutResponse { Meta = ApiCommands.Meta(request.Meta) };
        if (result == SignOutResult.StoreUnavailable)
        {
            // N2 decision R-3 and review FX-3: the store cannot be read now; refused, nothing was changed, the node retries reading it.
            response.Error = NodeErrors.InvalidState("signed_out", StoreUnavailable);
            return response;
        }

        if (result == SignOutResult.NotSignedIn)
        {
            response.Error = NodeErrors.NotSignedIn();
            return response;
        }

        if (result == SignOutResult.Abandoned)
        {
            response.Meta.Warnings.Add(Abandoned);
            response.Meta.Warnings.Add(RemoteUnconfirmed);
        }

        if (result == SignOutResult.RemoteUnconfirmed)
        {
            response.Meta.Warnings.Add(RemoteUnconfirmed);
        }

        response.Value = new AccountServiceSignOutValue
        {
            Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
        };
        return response;
    }
}
