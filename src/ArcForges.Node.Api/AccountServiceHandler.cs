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
/// <c>AccountService</c> on the local endpoint (AF-CTR-04 CTR4-NODE-10/11 as amended; part N1): <c>GetAccountStatus</c> and
/// <c>SignOut</c>. The sign-in methods (<c>BeginSignIn</c>, <c>GetSignInFlow</c>, <c>CancelSignIn</c>) arrive with part N2; phone pairing
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

    private static AccountServiceSignOutResponse Outcome(AccountServiceSignOutRequest request, SignOutResult result)
    {
        var response = new AccountServiceSignOutResponse { Meta = ApiCommands.Meta(request.Meta) };
        if (result == SignOutResult.NotSignedIn)
        {
            response.Error = NodeErrors.NotSignedIn();
            return response;
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
