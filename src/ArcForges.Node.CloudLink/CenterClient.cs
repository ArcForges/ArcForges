// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Http;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.CloudLink;

/// <summary>How a center call ended, as the node classifies it (AF-CTR-04 N1 (b); Design errors.md, the ingress table).</summary>
internal enum CenterOutcome
{
    /// <summary>The method's value.</summary>
    Value,

    /// <summary>A domain refusal: gRPC status 0 with an <c>ArcError</c> (also the Worker's own replies without <c>ResponseMeta</c>).</summary>
    Refused,

    /// <summary>An ingress refusal of the credential: trailers-only <c>grpc-status</c> 16 with <c>auth.*</c>, no ArcError.</summary>
    Transport,

    /// <summary>The center does not speak this protocol here (<c>unimplemented</c>, a refused request shape, an HTTP 404/415): a path or version defect.</summary>
    ProtocolMismatch,

    /// <summary>No center answer: a network failure, a timeout, an HTTP error from something in between (never a reason to delete anything).</summary>
    Unreachable,
}

/// <summary>A center call's result.</summary>
/// <typeparam name="T">The method's value type.</typeparam>
/// <param name="Outcome">The classification.</param>
/// <param name="Value">The value, for <see cref="CenterOutcome.Value"/>.</param>
/// <param name="Error">The ArcError, for <see cref="CenterOutcome.Refused"/>.</param>
/// <param name="TransportCode">The ingress code (for example <c>auth.credential_revoked</c>), for <see cref="CenterOutcome.Transport"/> and the ingress codes of the other outcomes.</param>
/// <param name="MaybeApplied">For <see cref="CenterOutcome.Unreachable"/>: the request may have reached the center (the effect is unknown).</param>
/// <param name="Detail">A one-line description for the log (never a token or body).</param>
internal sealed record CenterReply<T>(CenterOutcome Outcome, T? Value, ArcError? Error, string? TransportCode, bool MaybeApplied, string Detail)
    where T : class
{
    /// <summary>The <c>CATEGORY/code</c> of a domain refusal.</summary>
    public string? Code => Error is null ? null : Error.Category.ToString().ToUpperInvariant() + "/" + Error.Code;
}

/// <summary>
/// The node's typed calls to its center over <see cref="CenterHttpClient"/>. The access token is attached only to the credentialed methods
/// (<c>ReportNodeInfo</c>, <c>SignOutNode</c>); the anonymous methods carry none, and the refresh token appears only in the
/// <c>RefreshNodeSession</c> body. Deadlines are the contract's.
/// </summary>
internal sealed class CenterClient(CenterHttpClient http, TimeProvider clock)
{
    /// <summary>The ingress codes the center answers before any handler (Cloud <c>ingress/errors.go</c>; Design errors.md).</summary>
    internal static readonly HashSet<string> AuthCodes = new HashSet<string>(StringComparer.Ordinal)
    {
        "auth.unauthenticated", "auth.token_expired", "auth.credential_revoked",
    };

    private static readonly HashSet<string> MismatchCodes = new HashSet<string>(StringComparer.Ordinal)
    {
        "unimplemented", "validation.invalid_request", "perm.resource_denied",
    };

    /// <summary>The center.</summary>
    public CenterEndpoint Center => http.Center;

    /// <summary>RefreshNodeSession (anonymous; the refresh token in the body; deadline 10 s).</summary>
    public Task<CenterReply<NodeEnrollmentServiceRefreshNodeSessionValue>> RefreshAsync(string refreshToken, CancellationToken cancellationToken) =>
        CallAsync(async options =>
        {
            var response = await http.Fleet.RefreshNodeSessionAsync(new NodeEnrollmentServiceRefreshNodeSessionRequest
            {
                Meta = Meta(command: false),
                RefreshToken = refreshToken,
            }, options).ConfigureAwait(false);
            return (response.Value, response.Error, response.OutcomeCase == NodeEnrollmentServiceRefreshNodeSessionResponse.OutcomeOneofCase.None);
        }, TimeSpan.FromSeconds(10), bearer: null, cancellationToken);

    /// <summary>ReportNodeInfo (node credential; <c>meta.command_id</c> required by the center; deadline 10 s).</summary>
    public Task<CenterReply<NodeEnrollmentServiceReportNodeInfoValue>> ReportNodeInfoAsync(string accessToken, EnrollingNodeInfo node, Id commandId,
        CancellationToken cancellationToken) =>
        CallAsync(async options =>
        {
            var response = await http.Fleet.ReportNodeInfoAsync(new NodeEnrollmentServiceReportNodeInfoRequest
            {
                Meta = new RequestMeta { CommandId = commandId, CorrelationId = CommandIds.New(clock) },
                Node = node,
            }, options).ConfigureAwait(false);
            return (response.Value, response.Error, response.OutcomeCase == NodeEnrollmentServiceReportNodeInfoResponse.OutcomeOneofCase.None);
        }, TimeSpan.FromSeconds(10), accessToken, cancellationToken);

    /// <summary>SignOutNode (node credential; <c>meta.command_id</c>; deadline 10 s).</summary>
    public Task<CenterReply<NodeEnrollmentServiceSignOutNodeValue>> SignOutNodeAsync(string accessToken, Id commandId, CancellationToken cancellationToken) =>
        CallAsync(async options =>
        {
            var response = await http.Fleet.SignOutNodeAsync(new NodeEnrollmentServiceSignOutNodeRequest
            {
                Meta = new RequestMeta { CommandId = commandId, CorrelationId = CommandIds.New(clock) },
            }, options).ConfigureAwait(false);
            return (response.Value, response.Error, response.OutcomeCase == NodeEnrollmentServiceSignOutNodeResponse.OutcomeOneofCase.None);
        }, TimeSpan.FromSeconds(10), accessToken, cancellationToken);

    /// <summary>BeginNodeSignIn (anonymous; deadline 10 s). For the sign-in flows of part N2; the protocol probe against a real center uses it now.</summary>
    public Task<CenterReply<NodeEnrollmentServiceBeginNodeSignInValue>> BeginNodeSignInAsync(NodeEnrollmentServiceBeginNodeSignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Meta ??= Meta(command: true);
        return CallAsync(async options =>
        {
            var response = await http.Fleet.BeginNodeSignInAsync(request, options).ConfigureAwait(false);
            return (response.Value, response.Error, response.OutcomeCase == NodeEnrollmentServiceBeginNodeSignInResponse.OutcomeOneofCase.None);
        }, TimeSpan.FromSeconds(10), bearer: null, cancellationToken);
    }

    /// <summary>CompleteNodeSignIn (anonymous, flow-bound proof; deadline 15 s). For the browser sign-in of part N2.</summary>
    public Task<CenterReply<NodeEnrollmentServiceCompleteNodeSignInValue>> CompleteNodeSignInAsync(NodeEnrollmentServiceCompleteNodeSignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Meta ??= Meta(command: false);
        return CallAsync(async options =>
        {
            var response = await http.Fleet.CompleteNodeSignInAsync(request, options).ConfigureAwait(false);
            return (response.Value, response.Error, response.OutcomeCase == NodeEnrollmentServiceCompleteNodeSignInResponse.OutcomeOneofCase.None);
        }, TimeSpan.FromSeconds(15), bearer: null, cancellationToken);
    }

    /// <summary>StartDeviceAuthorization (anonymous; deadline 10 s).</summary>
    public Task<CenterReply<NodeEnrollmentServiceStartDeviceAuthorizationValue>> StartDeviceAuthorizationAsync(
        NodeEnrollmentServiceStartDeviceAuthorizationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Meta ??= Meta(command: true);
        return CallAsync(async options =>
        {
            var response = await http.Fleet.StartDeviceAuthorizationAsync(request, options).ConfigureAwait(false);
            return (response.Value, response.Error, response.OutcomeCase == NodeEnrollmentServiceStartDeviceAuthorizationResponse.OutcomeOneofCase.None);
        }, TimeSpan.FromSeconds(10), bearer: null, cancellationToken);
    }

    /// <summary>PollDeviceAuthorization (anonymous, device code and key proof; deadline 10 s).</summary>
    public Task<CenterReply<NodeEnrollmentServicePollDeviceAuthorizationValue>> PollDeviceAuthorizationAsync(
        NodeEnrollmentServicePollDeviceAuthorizationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Meta ??= Meta(command: false);
        return CallAsync(async options =>
        {
            var response = await http.Fleet.PollDeviceAuthorizationAsync(request, options).ConfigureAwait(false);
            return (response.Value, response.Error, response.OutcomeCase == NodeEnrollmentServicePollDeviceAuthorizationResponse.OutcomeOneofCase.None);
        }, TimeSpan.FromSeconds(10), bearer: null, cancellationToken);
    }

    /// <summary>Forwards one already-signed fleet request without parsing or re-encoding its inner node request.</summary>
    internal Task<CenterReply<T>> RelayAsync<T>(Func<FleetService.FleetServiceClient, CallOptions, Task<T>> call, TimeSpan deadline, string bearer,
        CancellationToken cancellationToken)
        where T : class =>
        CallAsync(async options => (await call(http.RoutedFleet, options).ConfigureAwait(false), (ArcError?)null, false), deadline, bearer, cancellationToken);

    /// <summary>Classifies a gRPC failure (AF-CTR-04 N1 (b), N1 decision R-6): the parsed <c>grpc-message</c> decides, never the status alone.</summary>
    internal static (CenterOutcome Outcome, string? Code, bool MaybeApplied, string Detail) Classify(RpcException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var code = exception.Status.Detail;
        var status = exception.StatusCode;
        if (status == StatusCode.Unauthenticated && AuthCodes.Contains(code))
        {
            return (CenterOutcome.Transport, code, false, "ingress refusal " + code);
        }

        if (MismatchCodes.Contains(code) || status == StatusCode.Unimplemented)
        {
            return (CenterOutcome.ProtocolMismatch, MismatchCodes.Contains(code) ? code : null, false, "the center refused the call's shape (" + status + ")");
        }

        if (code == "state.stale_generation")
        {
            return (CenterOutcome.Unreachable, code, false, "the center is not ready (" + code + ")");
        }

        if (code == "dependency.unavailable")
        {
            // The Go ingress sends it before any handler runs, but the hosted Worker also sends it when the container's reply ends without a
            // status or the upstream aborts, after the request reached the center: the effect is unknown.
            return (CenterOutcome.Unreachable, code, true, "the center is not ready (" + code + ")");
        }

        // An HTTP status from something in between (a proxy's 401/403, a 404 of the wrong path, 5xx) maps to a gRPC status whose detail is
        // the client library's text, not an ingress code: never a credential verdict.
        if (exception.Status.DebugException is HttpRequestException { HttpRequestError: var error }
            && error is HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError or HttpRequestError.SecureConnectionError
                or HttpRequestError.ProxyTunnelError)
        {
            return (CenterOutcome.Unreachable, null, false, "not sent (" + error + ")");
        }

        if (code.Contains("HTTP status code: 404", StringComparison.Ordinal) || code.Contains("HTTP status code: 415", StringComparison.Ordinal)
            || code.Contains("HTTP status code: 405", StringComparison.Ordinal))
        {
            return (CenterOutcome.ProtocolMismatch, null, false, "the center path answered HTTP " + code[(code.LastIndexOf(' ') + 1)..]);
        }

        return (CenterOutcome.Unreachable, null, true, "no center answer (" + status + ")");
    }

    private static async Task<CenterReply<T>> CallAsync<T>(Func<CallOptions, Task<(T? Value, ArcError? Error, bool Empty)>> call, TimeSpan deadline, string? bearer,
        CancellationToken cancellationToken)
        where T : class
    {
        Metadata? headers = null;
        if (bearer is not null)
        {
            headers = new Metadata { { "authorization", "Bearer " + bearer } };
        }

        // Grpc.Net.Client turns the deadline into a grpc-timeout duration against the system clock at once, so it is taken from that clock (the
        // node's own clock only names IDs here).
        var options = new CallOptions(headers, DateTime.UtcNow + deadline, cancellationToken);
        try
        {
            var (value, error, empty) = await call(options).ConfigureAwait(false);
            if (error is not null)
            {
                return new CenterReply<T>(CenterOutcome.Refused, null, error, null, false, "refused " + error.Category + "/" + error.Code);
            }

            return value is null || empty
                ? new CenterReply<T>(CenterOutcome.ProtocolMismatch, null, null, null, false, "a reply without value or error")
                : new CenterReply<T>(CenterOutcome.Value, value, null, null, false, "ok");
        }
        catch (RpcException exception)
        {
            var (outcome, code, applied, detail) = Classify(exception);
            return new CenterReply<T>(outcome, null, null, code, applied, detail);
        }
        catch (InvalidProtocolBufferException)
        {
            return new CenterReply<T>(CenterOutcome.ProtocolMismatch, null, null, null, true, "an unparsable reply");
        }
    }

    private RequestMeta Meta(bool command)
    {
        var meta = new RequestMeta { CorrelationId = CommandIds.New(clock) };
        if (command)
        {
            meta.CommandId = CommandIds.New(clock);
        }

        return meta;
    }
}
