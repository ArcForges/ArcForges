// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>A call FakeCenter received (recorded for assertions; the body as sent).</summary>
internal sealed record FakeCall(string Method, string Path, string? Authorization, string? ContentType, string? GrpcTimeout, byte[] Body);

/// <summary>A scripted behaviour for the next call of a method (faults are not center replies: they stay outside the conformance claim).</summary>
internal abstract record FakeFault
{
    /// <summary>Waits before handling the call.</summary>
    public sealed record Delay(TimeSpan Time) : FakeFault;

    /// <summary>Handles the call (its effect applies), then aborts the connection: the reply is lost.</summary>
    public sealed record DropReply : FakeFault;

    /// <summary>Answers an HTTP status without gRPC (a proxy, an edge or a wrong path).</summary>
    public sealed record HttpStatus(int Status) : FakeFault;

    /// <summary>The call is executed (a refresh commits), but its reply is replaced by an ingress or Worker trailer (a lost reply).</summary>
    public sealed record ReplacedReply(int Status, string Code) : FakeFault;

    /// <summary>An HTTP redirect (a 3xx with <c>Location</c>) instead of a gRPC-Web reply.</summary>
    public sealed record Redirect(int Status, string Location) : FakeFault;

    /// <summary>Answers a trailers-only ingress refusal (<c>grpc-status</c> and the code, percent-encoded as the ingress sends it).</summary>
    public sealed record Transport(int Status, string Code) : FakeFault;

    /// <summary>Answers a domain refusal as the Worker does: an ArcError without <c>ResponseMeta</c>.</summary>
    public sealed record WorkerRefusal(ArcError Error) : FakeFault;

    /// <summary>Answers a domain refusal with the center's response meta (a refusal no capture pins yet; contract-modelled).</summary>
    public sealed record Refusal(ArcError Error) : FakeFault;

    /// <summary>Answers these exact reply bytes (the conformance test serves a captured reply to the real client).</summary>
    public sealed record Raw(byte[] Body) : FakeFault;

    /// <summary>Holds the call until the source completes (a test can act while it is in flight).</summary>
    public sealed record Hold(TaskCompletionSource Release) : FakeFault;
}

/// <summary>
/// An in-process stand-in for the center's node-facing fleet methods (the Plan's AF-CTR-04 <c>fakes_allowed</c>: "FakeCenter (the center, in
/// node tests only; conformance-tested against exchanges captured from a real center)"; CTR4-TST-03). It serves binary gRPC-Web over a real
/// loopback HTTP/1.1 listener under a path base, with the center's ingress refusals and the node credential's strict rotation:
/// RefreshNodeSession (a spent token revokes the family), ReportNodeInfo and SignOutNode (receipts by command ID). Its replies for these
/// methods are compared byte for byte with the REAL captures (<c>FakeCenterConformanceTests</c>). Part N2 adds the sign-in methods
/// (BeginNodeSignIn, CompleteNodeSignIn, StartDeviceAuthorization, PollDeviceAuthorization) with the account's side as test controls (approve,
/// deny, expire), its own S256 check and its own node key proof verifier (node-13 item 4: independent of the node's builder), and the
/// center's rules of docs/center-fleet.md (held keys, the one-use code, reuse revocation, SLOW_DOWN). It never stands in for an end-to-end
/// result.
/// </summary>
internal sealed class FakeCenter : IAsyncDisposable
{
    /// <summary>The service path.</summary>
    public const string Service = "/arcforges.fleet.v1.NodeEnrollmentService/";

    private readonly WebApplication _app;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, Session> _byRefresh = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Session> _byAccess = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (byte[] Digest, byte[] Reply)> _receipts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ConcurrentQueue<FakeFault>> _faults = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<FakeCall> _calls = new();
    private readonly string _pathBase;
    private int _counter;

    private FakeCenter(WebApplication app, string pathBase, CenterEndpoint endpoint)
    {
        _app = app;
        _pathBase = pathBase;
        Endpoint = endpoint;
        Channel = new FakeChannelPeer(this);
    }

    /// <summary>The node channel peer (AF-CTR-05 N1), served at <c>&lt;path base&gt;/fleet/v1/node</c>.</summary>
    public FakeChannelPeer Channel { get; }

    /// <summary>The node, installation and account of a live access token (the channel's bearer), or <see langword="null"/>.</summary>
    internal (byte[] NodeId, byte[] Installation, byte[] Account)? ChannelIdentity(string accessToken)
    {
        lock (_gate)
        {
            return _byAccess.TryGetValue(accessToken, out var session) && session is { Revoked: false } && session.Access == accessToken
                && session.AccessExpires > Clock.GetUtcNow()
                ? (session.NodeId, session.Installation, session.Account)
                : null;
        }
    }

    /// <summary>The center's URL (<c>http://127.0.0.1:&lt;port&gt;&lt;path base&gt;</c>).</summary>
    public CenterEndpoint Endpoint { get; }

    /// <summary>The center's clock (the instants of its replies).</summary>
    public TimeProvider Clock { get; set; } = TimeProvider.System;

    /// <summary>The access lifetime it issues (default 60 minutes, the policy default).</summary>
    public TimeSpan AccessLifetime { get; set; } = TimeSpan.FromMinutes(60);

    /// <summary>The family lifetime it issues (default 365 days).</summary>
    public TimeSpan FamilyLifetime { get; set; } = TimeSpan.FromDays(365);

    /// <summary>The command keys it delivers with every credential and refresh.</summary>
    public List<PublicKey> CommandKeys { get; } = [];

    /// <summary>
    /// Placeholder mode (conformance): the tokens and correlation IDs it issues next, in order, instead of random ones (the capture's
    /// normalized values).
    /// </summary>
    public Queue<string> NextTokens { get; } = new();

    /// <summary>As <see cref="NextTokens"/>, the next correlation IDs.</summary>
    public Queue<byte[]> NextCorrelations { get; } = new();

    /// <summary>
    /// The refreshes one session may make in a 10-minute window (the center's <c>node_refresh_session</c> bucket; its policy default is 60), or
    /// <see langword="null"/> for no limit.
    /// </summary>
    public int? RefreshSessionLimit { get; set; }

    /// <summary>Marks the session of <paramref name="refreshOrAccess"/> as a Restricted account's (ReportNodeInfo is refused).</summary>
    public void Restrict(string refreshOrAccess)
    {
        lock (_gate)
        {
            if ((_byRefresh.GetValueOrDefault(refreshOrAccess) ?? _byAccess.GetValueOrDefault(refreshOrAccess)) is { } session)
            {
                session.Restricted = true;
            }
        }
    }

    /// <summary>Refresh tokens of account sessions (not node credentials): RefreshNodeSession refuses them.</summary>
    public HashSet<string> AccountTokens { get; } = new(StringComparer.Ordinal);

    /// <summary>The calls received, in order.</summary>
    public IReadOnlyList<FakeCall> Calls => [.. _calls];

    /// <summary>Starts a center under <paramref name="pathBase"/> (empty, or <c>/segment</c>).</summary>
    public static async Task<FakeCenter> StartAsync(string pathBase = "/api")
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1));
        var app = builder.Build();
        FakeCenter? center = null;
        app.UseWebSockets();
        app.Run(context => center!.HandleAsync(context));
        await app.StartAsync();
        var address = new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First());
        center = new FakeCenter(app, pathBase, CenterEndpoint.Parse("http://127.0.0.1:" + address.Port + pathBase));
        return center;
    }

    /// <summary>Scripts the next call of <paramref name="method"/>.</summary>
    public void Script(string method, FakeFault fault) => _faults.GetOrAdd(method, _ => new ConcurrentQueue<FakeFault>()).Enqueue(fault);

    /// <summary>
    /// Issues a node credential as a completed sign-in would (the sign-in flows are part N2's): a live session of the node and installation.
    /// </summary>
    public NodeCredentials Issue(ReadOnlySpan<byte> nodeId, string displayName = "Test Account")
    {
        var id = nodeId.ToArray();
        lock (_gate)
        {
            return IssueLocked(id, displayName);
        }
    }

    private NodeCredentials IssueLocked(byte[] nodeId, string displayName)
    {
        var installation = NextInstallationIds.Count > 0 ? NextInstallationIds.Dequeue() : RandomNumberGenerator.GetBytes(16);
        var session = new Session(nodeId, installation, NewToken("afa1."), NewToken("afr1."), Clock.GetUtcNow() + AccessLifetime,
            Clock.GetUtcNow() + FamilyLifetime);
        _byRefresh[session.Refresh] = session;
        _byAccess[session.Access] = session;
        session.Account = NextAccountIds.Count > 0 ? NextAccountIds.Dequeue() : RandomNumberGenerator.GetBytes(16);

        var credentials = new NodeCredentials
        {
            RefreshToken = session.Refresh,
            AccessToken = session.Access,
            AccessExpiresAt = ProtoTime.ToInstant(session.AccessExpires),
            Account = new AccountSummary
            {
                AccountId = new Id { Value = ByteString.CopyFrom(session.Account) },
                DisplayName = displayName,
                EmailMasked = displayName == Account.Name ? Account.Email : "t***@example.test",
            },
            InstallationId = new Id { Value = ByteString.CopyFrom(installation) },
            SessionExpiresAt = ProtoTime.ToInstant(session.SessionExpires),
            AccessLifetimeMs = (ulong)AccessLifetime.TotalMilliseconds,
        };
        credentials.CommandKeys.AddRange(CommandKeys);
        return credentials;
    }

    /// <summary>
    /// The outcomes FakeCenter itself emits (scripted faults aside), as the captures name them: each is pinned by a vendored capture or listed
    /// in the conformance test's reviewed table of contract-modelled outcomes.
    /// </summary>
    public static readonly IReadOnlyList<(string Method, string Outcome)> Outcomes =
    [
        ("RefreshNodeSession", "ok"), ("RefreshNodeSession", "AUTHENTICATION/credential_revoked"), ("RefreshNodeSession", "AUTHENTICATION/unauthenticated"),
        ("RefreshNodeSession", "AUTHORIZATION/permission_denied"), ("RefreshNodeSession", "AUTHENTICATION/token_expired"),
        ("RefreshNodeSession", "VALIDATION/invalid_argument"), ("RefreshNodeSession", "RESOURCE/rate_limited"),
        ("ReportNodeInfo", "ok"), ("ReportNodeInfo", "CONFLICT/command_id_reused"), ("ReportNodeInfo", "VALIDATION/invalid_argument"),
        ("ReportNodeInfo", "AUTHORIZATION/permission_denied"), ("ReportNodeInfo", "AUTHENTICATION/unauthenticated"),
        ("ReportNodeInfo", "transport:auth.unauthenticated"), ("ReportNodeInfo", "transport:auth.credential_revoked"), ("ReportNodeInfo", "transport:auth.token_expired"),
        ("SignOutNode", "ok"), ("SignOutNode", "transport:auth.credential_revoked"), ("SignOutNode", "transport:auth.unauthenticated"),
        ("SignOutNode", "transport:auth.token_expired"), ("SignOutNode", "CONFLICT/command_id_reused"), ("SignOutNode", "AUTHENTICATION/unauthenticated"),
        ("BeginNodeSignIn", "ok"), ("BeginNodeSignIn", "VALIDATION/invalid_argument"), ("BeginNodeSignIn", "CONFLICT/already_exists:node_key"),
        ("CompleteNodeSignIn", "ok"), ("CompleteNodeSignIn", "VALIDATION/invalid_argument"), ("CompleteNodeSignIn", "STATE/not_found"),
        ("CompleteNodeSignIn", "STATE/expired"), ("CompleteNodeSignIn", "AUTHENTICATION/unauthenticated"), ("CompleteNodeSignIn", "CONFLICT/code_reused"),
        ("CompleteNodeSignIn", "CONFLICT/already_exists:node"), ("CompleteNodeSignIn", "CONFLICT/already_exists:node_key"),
        ("CompleteNodeSignIn", "AUTHENTICATION/credential_revoked"), ("CompleteNodeSignIn", "RESOURCE/quota_exceeded"),
        ("StartDeviceAuthorization", "ok"), ("StartDeviceAuthorization", "VALIDATION/invalid_argument"), ("StartDeviceAuthorization", "CONFLICT/already_exists:node_key"),
        ("PollDeviceAuthorization", "ok"), ("PollDeviceAuthorization", "VALIDATION/invalid_argument"), ("PollDeviceAuthorization", "STATE/not_found"),
        ("PollDeviceAuthorization", "AUTHENTICATION/unauthenticated"), ("PollDeviceAuthorization", "CONFLICT/already_exists:node"),
        ("PollDeviceAuthorization", "CONFLICT/already_exists:node_key"), ("PollDeviceAuthorization", "AUTHENTICATION/credential_revoked"),
        ("PollDeviceAuthorization", "RESOURCE/quota_exceeded"),
    ];

    /// <summary>Seeds a live session with given tokens (the conformance test puts FakeCenter in a capture's state).</summary>
    public void Seed(ReadOnlySpan<byte> nodeId, string access, string refresh, bool revoked = false, bool restricted = false, bool nodeLive = true,
        bool accessExpired = false, bool familyExpired = false, int refreshesUsed = 0)
    {
        var now = Clock.GetUtcNow();
        var session = new Session(nodeId.ToArray(), new byte[16], access, refresh, accessExpired ? now : now + AccessLifetime,
            familyExpired ? now - TimeSpan.FromSeconds(1) : now + FamilyLifetime)
        {
            Revoked = revoked,
            Restricted = restricted,
            NodeLive = nodeLive,
            Refreshes = refreshesUsed,
            WindowStart = now,
        };
        lock (_gate)
        {
            _byRefresh[refresh] = session;
            _byAccess[access] = session;
        }
    }

    /// <summary>Marks <paramref name="refresh"/> as spent by an earlier rotation (its session stays live).</summary>
    public void MarkSpent(string refresh)
    {
        lock (_gate)
        {
            if (_byRefresh.GetValueOrDefault(refresh) is { } session)
            {
                session.Spent.Add(refresh);
            }
        }
    }

    /// <summary>Revokes the session that holds <paramref name="refreshOrAccess"/> (a device revocation on the web).</summary>
    public void Revoke(string refreshOrAccess)
    {
        lock (_gate)
        {
            if ((_byRefresh.GetValueOrDefault(refreshOrAccess) ?? _byAccess.GetValueOrDefault(refreshOrAccess)) is { } session)
            {
                session.Revoked = true;
            }
        }
    }

    /// <summary>Forgets every session (a center whose store no longer knows the node's tokens: unauthenticated).</summary>
    public void Forget()
    {
        lock (_gate)
        {
            _byRefresh.Clear();
            _byAccess.Clear();
        }
    }

    /// <summary>Ends the family of the session that holds <paramref name="refresh"/> now (its absolute lifetime passed).</summary>
    public void Expire(string refresh)
    {
        lock (_gate)
        {
            if (_byRefresh.GetValueOrDefault(refresh) is { } session)
            {
                session.SessionExpires = Clock.GetUtcNow() - TimeSpan.FromSeconds(1);
            }
        }
    }

    /// <summary>True when the session that holds <paramref name="token"/> is live (not revoked, not superseded by a reuse).</summary>
    public bool IsLive(string token)
    {
        lock (_gate)
        {
            return (_byRefresh.GetValueOrDefault(token) ?? _byAccess.GetValueOrDefault(token)) is { Revoked: false };
        }
    }

    /// <summary>The calls of one method.</summary>
    public List<FakeCall> CallsOf(string method) => [.. _calls.Where(call => call.Method == method)];

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    /// <summary>The reply FakeCenter gives to one request body, without HTTP (the conformance test compares it with the captures).</summary>
    public (byte[] Body, int Status) Reply(string method, string? authorization, byte[] requestBody)
    {
        var (reply, transport) = Dispatch(method, authorization, Payload(requestBody));
        return transport is { } code ? (TrailerFrame(16, code), 200) : (Concat(DataFrame(reply!), TrailerFrame(0, null)), 200);
    }

    private async Task HandleAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        if (path == _pathBase + FakeChannelPeer.Path)
        {
            await Channel.HandleAsync(context);
            return;
        }

        if (context.Request.Method != "POST" || !path.StartsWith(_pathBase + Service, StringComparison.Ordinal))
        {
            context.Response.StatusCode = 404;
            return;
        }

        // The media types the center's ingress admits for gRPC-Web (Cloud center/internal/ingress/pipeline.go); text mode is refused.
        if (context.Request.ContentType is not ("application/grpc-web" or "application/grpc-web+proto"))
        {
            context.Response.StatusCode = 415;
            return;
        }

        var method = path[(_pathBase + Service).Length..];
        using var buffer = new MemoryStream();
        await context.Request.Body.CopyToAsync(buffer);
        var body = buffer.ToArray();
        var authorization = context.Request.Headers.Authorization.ToString();
        _calls.Enqueue(new FakeCall(method, path, authorization.Length == 0 ? null : authorization, context.Request.ContentType,
            context.Request.Headers["grpc-timeout"].ToString() is { Length: > 0 } timeout ? timeout : null, body));
        var drop = false;
        while (_faults.TryGetValue(method, out var queue) && queue.TryDequeue(out var fault))
        {
            switch (fault)
            {
                case FakeFault.Delay delay:
                    await Task.Delay(delay.Time);
                    continue;
                case FakeFault.Hold hold:
                    await hold.Release.Task;
                    continue;
                case FakeFault.DropReply:
                    drop = true;
                    continue;
                case FakeFault.Raw raw:
                    await WriteAsync(context, raw.Body);
                    return;
                case FakeFault.HttpStatus status:
                    context.Response.StatusCode = status.Status;
                    return;
                case FakeFault.ReplacedReply replaced:
                    _ = Reply(method, authorization.Length == 0 ? null : authorization, body);
                    await WriteAsync(context, TrailerFrame(replaced.Status, replaced.Code));
                    return;
                case FakeFault.Redirect redirect:
                    context.Response.StatusCode = redirect.Status;
                    context.Response.Headers.Location = redirect.Location;
                    return;
                case FakeFault.Transport transport:
                    await WriteAsync(context, TrailerFrame(transport.Status, transport.Code));
                    return;
                case FakeFault.WorkerRefusal worker:
                    await WriteAsync(context, Concat(DataFrame(ReplyWithError(method, worker.Error, meta: false)), TrailerFrame(0, null)));
                    return;
                case FakeFault.Refusal refusal:
                    await WriteAsync(context, Concat(DataFrame(ReplyWithError(method, refusal.Error, meta: true)), TrailerFrame(0, null)));
                    return;
                default:
                    break;
            }
        }

        var (bodyBytes, _) = Reply(method, authorization.Length == 0 ? null : authorization, body);
        if (drop)
        {
            context.Abort();
            return;
        }

        await WriteAsync(context, bodyBytes);
    }

    private static async Task WriteAsync(HttpContext context, byte[] body)
    {
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/grpc-web+proto";
        context.Response.ContentLength = body.Length;
        await context.Response.Body.WriteAsync(body);
    }

    private (IMessage? Reply, string? Transport) Dispatch(string method, string? authorization, byte[] payload)
    {
        lock (_gate)
        {
            return method switch
            {
                "RefreshNodeSession" => (Refresh(NodeEnrollmentServiceRefreshNodeSessionRequest.Parser.ParseFrom(payload)), null),
                "ReportNodeInfo" => Credentialed(authorization, session => Report(session, NodeEnrollmentServiceReportNodeInfoRequest.Parser.ParseFrom(payload), payload)),
                "SignOutNode" => Credentialed(authorization, session => SignOut(session, NodeEnrollmentServiceSignOutNodeRequest.Parser.ParseFrom(payload), payload)),
                "BeginNodeSignIn" => (Begin(NodeEnrollmentServiceBeginNodeSignInRequest.Parser.ParseFrom(payload)), null),
                "CompleteNodeSignIn" => (Complete(NodeEnrollmentServiceCompleteNodeSignInRequest.Parser.ParseFrom(payload)), null),
                "StartDeviceAuthorization" => (Start(NodeEnrollmentServiceStartDeviceAuthorizationRequest.Parser.ParseFrom(payload)), null),
                "PollDeviceAuthorization" => (Poll(NodeEnrollmentServicePollDeviceAuthorizationRequest.Parser.ParseFrom(payload)), null),
                _ => (null, "unimplemented"),
            };
        }
    }

    private (IMessage? Reply, string? Transport) Credentialed(string? authorization, Func<Session, IMessage> handler)
    {
        // The ingress (Design errors.md, the ingress table): a known native bearer whose access token expired is auth.token_expired, a revoked
        // one auth.credential_revoked, anything else auth.unauthenticated; no receipt is read before.
        if (authorization is null || !authorization.StartsWith("Bearer ", StringComparison.Ordinal)
            || _byAccess.GetValueOrDefault(authorization["Bearer ".Length..]) is not { } session)
        {
            return (null, "auth.unauthenticated");
        }

        if (session.Revoked)
        {
            return (null, "auth.credential_revoked");
        }

        if (session.AccessExpires <= Clock.GetUtcNow() || session.SessionExpires <= Clock.GetUtcNow())
        {
            return (null, "auth.token_expired");
        }

        return (handler(session), null);
    }

    private NodeEnrollmentServiceRefreshNodeSessionResponse Refresh(NodeEnrollmentServiceRefreshNodeSessionRequest request)
    {
        var response = new NodeEnrollmentServiceRefreshNodeSessionResponse { Meta = Meta() };
        var token = request.RefreshToken;
        if (token.Length is 0 or > 8192)
        {
            response.Error = Error(ErrorCategory.Validation, "invalid_argument", response.Meta, new StateFailure { State = "refresh_token", Reason = "length" });
            return response;
        }

        if (AccountTokens.Contains(token))
        {
            response.Error = Error(ErrorCategory.Authorization, "permission_denied", response.Meta,
                new StateFailure { State = "operation", Reason = "fleet.refreshNodeSession" });
            return response;
        }

        if (_byRefresh.GetValueOrDefault(token) is not { } session)
        {
            response.Error = Error(ErrorCategory.Authentication, "unauthenticated", response.Meta, null);
            return response;
        }

        if (session.Revoked || session.Spent.Contains(token) || !session.NodeLive)
        {
            // Strict rotation: a spent token (also a retry whose reply was lost) revokes the family; a revoked device or a node row that is
            // not live is credential_revoked too.
            session.Revoked = true;
            response.Error = Error(ErrorCategory.Authentication, "credential_revoked", response.Meta, null);
            return response;
        }

        if (session.SessionExpires <= Clock.GetUtcNow())
        {
            response.Error = Error(ErrorCategory.Authentication, "token_expired", response.Meta, null);
            response.Error.Retry.Mode = RetryMode.SameCommand;
            return response;
        }

        if (Clock.GetUtcNow() - session.WindowStart >= TimeSpan.FromMinutes(10))
        {
            session.WindowStart = Clock.GetUtcNow();
            session.Refreshes = 0;
        }

        if (RefreshSessionLimit is { } limit && session.Refreshes >= limit)
        {
            var recovery = ProtoTime.ToInstant(session.WindowStart + TimeSpan.FromMinutes(10));
            response.Error = Error(ErrorCategory.Resource, "rate_limited", response.Meta, null);
            response.Error.Retry = new RetryAdvice { Mode = RetryMode.AfterTime, RetryAt = recovery };
            response.Error.Details = new ErrorDetails
            {
                Limit = new LimitFailure { LimitName = "node_refresh_session", Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = limit.ToString(System.Globalization.CultureInfo.InvariantCulture) }, RecoveryAt = recovery },
            };
            return response;
        }

        session.Refreshes++;

        session.Spent.Add(token);
        _byAccess.Remove(session.Access);
        session.Access = NewToken("afa1.");
        session.Refresh = NewToken("afr1.");
        session.AccessExpires = Clock.GetUtcNow() + AccessLifetime;
        _byRefresh[session.Refresh] = session;
        _byAccess[session.Access] = session;
        var value = new NodeEnrollmentServiceRefreshNodeSessionValue
        {
            RefreshToken = session.Refresh,
            AccessToken = session.Access,
            AccessExpiresAt = ProtoTime.ToInstant(session.AccessExpires),
            SessionExpiresAt = ProtoTime.ToInstant(session.SessionExpires),
            AccessLifetimeMs = (ulong)AccessLifetime.TotalMilliseconds,
        };
        value.CommandKeys.AddRange(CommandKeys);
        response.Value = value;
        return response;
    }

    private NodeEnrollmentServiceReportNodeInfoResponse Report(Session session, NodeEnrollmentServiceReportNodeInfoRequest request, byte[] payload)
    {
        var response = new NodeEnrollmentServiceReportNodeInfoResponse { Meta = Meta() };
        if (Replay(request.Meta, payload, NodeEnrollmentServiceReportNodeInfoResponse.Parser, out var replayed, out _))
        {
            return replayed ?? With(response, Error(ErrorCategory.Conflict, "command_id_reused", response.Meta, null));
        }

        if (!session.NodeLive)
        {
            response.Error = Error(ErrorCategory.Authentication, "unauthenticated", response.Meta, null);
            return response;
        }

        if (session.Restricted)
        {
            response.Error = Error(ErrorCategory.Authorization, "permission_denied", response.Meta,
                new StateFailure { State = "operation", Reason = "fleet.reportNodeInfo" });
            return response;
        }

        if (!request.Node.NodeId.Value.Span.SequenceEqual(session.NodeId))
        {
            response.Error = Error(ErrorCategory.Validation, "invalid_argument", response.Meta, new StateFailure { State = "node.node_id", Reason = "node.node_id: mismatch" });
        }
        else
        {
            session.ReportedName = request.Node.Name;
            response.Value = new NodeEnrollmentServiceReportNodeInfoValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened } };
        }

        Store(request.Meta, payload, response);
        return response;
    }

    private NodeEnrollmentServiceSignOutNodeResponse SignOut(Session session, NodeEnrollmentServiceSignOutNodeRequest request, byte[] payload)
    {
        var response = new NodeEnrollmentServiceSignOutNodeResponse { Meta = Meta() };
        if (Replay(request.Meta, payload, NodeEnrollmentServiceSignOutNodeResponse.Parser, out var replayed, out _))
        {
            return replayed ?? With(response, Error(ErrorCategory.Conflict, "command_id_reused", response.Meta, null));
        }

        if (!session.NodeLive)
        {
            response.Error = Error(ErrorCategory.Authentication, "unauthenticated", response.Meta, null);
            return response;
        }

        session.Revoked = true;
        response.Value = new NodeEnrollmentServiceSignOutNodeValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened } };
        Store(request.Meta, payload, response);
        return response;
    }

    private bool Replay<T>(RequestMeta meta, byte[] payload, MessageParser<T> parser, out T? replayed, out bool reused)
        where T : class, IMessage<T>
    {
        replayed = null;
        reused = false;
        var key = Convert.ToHexString(meta.CommandId.Value.Span);
        if (!_receipts.TryGetValue(key, out var stored))
        {
            return false;
        }

        var digest = SHA256.HashData(payload);
        if (digest.AsSpan().SequenceEqual(stored.Digest))
        {
            replayed = parser.ParseFrom(stored.Reply);
            return true;
        }

        reused = true;
        return true;
    }

    private void Store(RequestMeta meta, byte[] payload, IMessage response) =>
        _receipts[Convert.ToHexString(meta.CommandId.Value.Span)] = (SHA256.HashData(payload), response.ToByteArray());

    private static T With<T>(T response, ArcError error)
        where T : IMessage
    {
        response.Descriptor.FindFieldByName("error").Accessor.SetValue(response, error);
        return response;
    }

    private IMessage ReplyWithError(string method, ArcError error, bool meta)
    {
        IMessage response = method switch
        {
            "RefreshNodeSession" => new NodeEnrollmentServiceRefreshNodeSessionResponse(),
            "ReportNodeInfo" => new NodeEnrollmentServiceReportNodeInfoResponse(),
            "SignOutNode" => new NodeEnrollmentServiceSignOutNodeResponse(),
            "BeginNodeSignIn" => new NodeEnrollmentServiceBeginNodeSignInResponse(),
            "StartDeviceAuthorization" => new NodeEnrollmentServiceStartDeviceAuthorizationResponse(),
            "PollDeviceAuthorization" => new NodeEnrollmentServicePollDeviceAuthorizationResponse(),
            _ => new NodeEnrollmentServiceCompleteNodeSignInResponse(),
        };
        if (meta)
        {
            response.Descriptor.FindFieldByName("meta").Accessor.SetValue(response, Meta());
        }

        response.Descriptor.FindFieldByName("error").Accessor.SetValue(response, error);
        return response;
    }

    private ResponseMeta Meta() => new()
    {
        CorrelationId = new Id { Value = ByteString.CopyFrom(NextCorrelations.Count > 0 ? NextCorrelations.Dequeue() : RandomNumberGenerator.GetBytes(16)) },
    };

    private static ArcError Error(ErrorCategory category, string code, ResponseMeta meta, StateFailure? state)
    {
        var error = new ArcError
        {
            Code = code,
            Category = category,
            MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
            CorrelationId = meta.CorrelationId,
        };
        if (state is not null)
        {
            error.Details = new ErrorDetails { State = state };
        }

        return error;
    }

    private string NewToken(string prefix)
    {
        if (NextTokens.Count > 0)
        {
            return NextTokens.Dequeue();
        }

        Interlocked.Increment(ref _counter);
        return prefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// FakeCenter's own node key proof verifier (node-13 item 4: independent of the node's builder; the sign-in methods of part N2 use it),
    /// pinned to the Go center's verdicts by the vendored proof vectors: a 91-byte P-256 PKIX key, a 64-byte P1363 signature with r in
    /// [1, n-1] and s in [1, n/2], ES256 over SHA-256 of the message.
    /// </summary>
    public static bool VerifyNodeKeyProof(byte[] publicKey, byte[] message, byte[] proof)
    {
        if (proof.Length != 64 || publicKey.Length != 91)
        {
            return false;
        }

        using var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            {
                return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }

        var order = System.Numerics.BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
        var r = new System.Numerics.BigInteger(proof.AsSpan(0, 32), isUnsigned: true, isBigEndian: true);
        var low = new System.Numerics.BigInteger(proof.AsSpan(32), isUnsigned: true, isBigEndian: true);
        return r.Sign > 0 && r < order && low.Sign > 0 && low <= order >> 1
            && key.VerifyData(message, proof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }


    // ---- Part N2: the sign-in methods (docs/center-fleet.md "Browser sign-in" and "Device-code sign-in") ----

    private readonly List<SignInFlowRow> _flows = [];
    private readonly List<DeviceRow> _devices = [];
    private readonly Dictionary<string, bool> _heldKeys = new(StringComparer.Ordinal);

    /// <summary>Node IDs live under another account (Enroll: <c>CONFLICT/already_exists</c>, <c>state.state</c> <c>node</c>).</summary>
    public HashSet<string> ForeignNodes { get; } = new(StringComparer.Ordinal);

    /// <summary>The account's node cap is reached (Enroll: <c>RESOURCE/quota_exceeded</c>).</summary>
    public bool QuotaReached { get; set; }

    /// <summary>A hostile center: the <c>authorize_url</c> it answers instead of the derived one.</summary>
    public string? AuthorizeUrlOverride { get; set; }

    /// <summary>A hostile center: the <c>verification_uri</c> it answers instead of the derived one.</summary>
    public string? VerificationUriOverride { get; set; }

    /// <summary>A hostile center: the user code it answers.</summary>
    public string? UserCodeOverride { get; set; }

    /// <summary>The browser sign-ins begun.</summary>
    public int FlowCount
    {
        get
        {
            lock (_gate)
            {
                return _flows.Count;
            }
        }
    }

    /// <summary>The device authorizations started.</summary>
    public int DeviceCount
    {
        get
        {
            lock (_gate)
            {
                return _devices.Count;
            }
        }
    }

    /// <summary>The state of the latest browser sign-in (PENDING, APPROVED, COMPLETED, DENIED, EXPIRED, REVOKED), or null.</summary>
    public string? LatestFlowState
    {
        get
        {
            lock (_gate)
            {
                return _flows.Count == 0 ? null : _flows[^1].State.ToString().ToUpperInvariant();
            }
        }
    }

    /// <summary>The state of the latest device authorization, or null.</summary>
    public string? LatestDeviceState
    {
        get
        {
            lock (_gate)
            {
                return _devices.Count == 0 ? null : _devices[^1].State.ToString().ToUpperInvariant();
            }
        }
    }

    /// <summary>The refresh token delivered by the latest sign-in (either flow), or null.</summary>
    public string? LatestDelivered
    {
        get
        {
            lock (_gate)
            {
                return _deliveredRefresh;
            }
        }
    }

    private string? _deliveredRefresh;

    /// <summary>
    /// The center's public base URL (the derived URLs and the proof audience): its own endpoint, unless a test names another (the
    /// conformance test uses the captures' <c>https://center.example.test/api</c>).
    /// </summary>
    public CenterEndpoint PublicBase
    {
        get => _publicBase ?? Endpoint;
        set => _publicBase = value;
    }

    private CenterEndpoint? _publicBase;

    /// <summary>Placeholder mode (conformance): the flow IDs it draws next.</summary>
    public Queue<byte[]> NextFlowIds { get; } = new();

    /// <summary>Placeholder mode: the device codes it draws next.</summary>
    public Queue<string> NextDeviceCodes { get; } = new();

    /// <summary>Placeholder mode: the user codes it draws next.</summary>
    public Queue<string> NextUserCodes { get; } = new();

    /// <summary>Placeholder mode: the installation IDs it draws next.</summary>
    public Queue<byte[]> NextInstallationIds { get; } = new();

    /// <summary>Placeholder mode: the account IDs it names next.</summary>
    public Queue<byte[]> NextAccountIds { get; } = new();

    /// <summary>The account's display name and masked e-mail address in delivered credentials.</summary>
    public (string Name, string Email) Account { get; set; } = ("Test Account", "t***@example.test");

    /// <summary>
    /// The conformance seam (FakeCenterConformanceTests only): the captured requests carry placeholder proofs (64 bytes of one value
    /// 0xe0+n, because ES256 draws a nonce), which this accepts; every behaviour test leaves it off and the real verifier decides.
    /// </summary>
    public bool AcceptPlaceholderProofs { get; set; }

    private bool Placeholder(ByteString proof) => AcceptPlaceholderProofs && proof.Length == 64 && proof.All(b => b == proof[0]) && proof[0] >= 0xe0;

    /// <summary>Seeds a browser flow (the conformance test puts FakeCenter in a capture's state).</summary>
    public void SeedFlow(byte[] flowId, byte[] nodeId, byte[] key, string challenge, string? code, string state, TimeSpan life, TimeSpan codeLife)
    {
        lock (_gate)
        {
            _flows.Add(new SignInFlowRow(flowId, challenge, "http://127.0.0.1:53682/callback", "node-state-0123456789abcdefghij", nodeId, key, Clock.GetUtcNow() + life)
            {
                State = Enum.Parse<FlowRowState>(state, ignoreCase: true),
                Code = code,
                CodeExpires = Clock.GetUtcNow() + codeLife,
            });
        }
    }

    /// <summary>Seeds a device authorization.</summary>
    public void SeedDevice(string deviceCode, byte[] nodeId, byte[] key, string state, TimeSpan life, DateTimeOffset? lastPoll = null)
    {
        lock (_gate)
        {
            _devices.Add(new DeviceRow(deviceCode, "BBBBBBBC", nodeId, key, Clock.GetUtcNow() + life)
            {
                State = Enum.Parse<DeviceRowState>(state, ignoreCase: true),
                LastPoll = lastPoll,
            });
        }
    }

    /// <summary>Marks <paramref name="publicKey"/> as held by an installation: live (refused at Begin/Start and Enroll) or retired.</summary>
    public void HoldKey(byte[] publicKey, bool retired = false)
    {
        lock (_gate)
        {
            _heldKeys[Convert.ToHexString(publicKey)] = retired;
        }
    }

    /// <summary>True when <paramref name="publicKey"/> is held by an installation.</summary>
    public bool Holds(byte[] publicKey)
    {
        lock (_gate)
        {
            return _heldKeys.ContainsKey(Convert.ToHexString(publicKey));
        }
    }

    /// <summary>The account approves the latest pending browser sign-in: the one-use code and the loopback redirect (center-fleet.md "Decision").</summary>
    public string ApproveFlow()
    {
        lock (_gate)
        {
            var flow = _flows.LastOrDefault(row => row.State is FlowRowState.Pending or FlowRowState.Approved) ?? throw new InvalidOperationException("No flow to approve.");
            flow.State = FlowRowState.Approved;
            flow.Code = Base64Url(RandomNumberGenerator.GetBytes(32));
            flow.CodeExpires = Clock.GetUtcNow() + TimeSpan.FromMinutes(2);
            return flow.RedirectUri + "?code=" + flow.Code + "&state=" + flow.State0;
        }
    }

    /// <summary>The account denies the latest pending browser sign-in: the denial redirect.</summary>
    public string DenyFlow()
    {
        lock (_gate)
        {
            var flow = _flows.LastOrDefault(row => row.State is FlowRowState.Pending or FlowRowState.Approved) ?? throw new InvalidOperationException("No flow to deny.");
            flow.State = FlowRowState.Denied;
            return flow.RedirectUri + "?error=access_denied&state=" + flow.State0;
        }
    }

    /// <summary>The account approves the latest pending device authorization.</summary>
    public void ApproveDevice()
    {
        lock (_gate)
        {
            (_devices.LastOrDefault(row => row.State == DeviceRowState.Pending) ?? throw new InvalidOperationException("No authorization to approve.")).State = DeviceRowState.Approved;
        }
    }

    /// <summary>The account denies the latest pending device authorization.</summary>
    public void DenyDevice()
    {
        lock (_gate)
        {
            (_devices.LastOrDefault(row => row.State is DeviceRowState.Pending or DeviceRowState.Approved) ?? throw new InvalidOperationException("No authorization to deny.")).State = DeviceRowState.Denied;
        }
    }

    /// <summary>The latest user code shown (8 letters), or null.</summary>
    /// <summary>Every device code and user code the center issued (test verification: N2-15 looks for each one).</summary>
    public IReadOnlyList<(string DeviceCode, string UserCode)> IssuedDeviceCodes
    {
        get
        {
            lock (_gate)
            {
                return [.. _devices.Select(row => (row.DeviceCode, row.UserCode))];
            }
        }
    }

    public string? LatestUserCode
    {
        get
        {
            lock (_gate)
            {
                return _devices.Count == 0 ? null : _devices[^1].UserCode;
            }
        }
    }

    private NodeEnrollmentServiceBeginNodeSignInResponse Begin(NodeEnrollmentServiceBeginNodeSignInRequest request)
    {
        var response = new NodeEnrollmentServiceBeginNodeSignInResponse { Meta = Meta() };
        if (!IsBase64Url43(request.CodeChallenge))
        {
            response.Error = Invalid(response.Meta, "code_challenge", "code_challenge: pattern");
            return response;
        }

        if (!AdmittedRedirect(request.RedirectUri))
        {
            response.Error = Invalid(response.Meta, "redirect_uri", "redirect_uri: not_admitted");
            return response;
        }

        if (NodeShape(request.Node, request.NodePublicKey) is { } invalid)
        {
            response.Error = Invalid(response.Meta, invalid.Field, invalid.Reason);
            return response;
        }

        if (request.State is not { Length: >= 16 and <= 128 } state || !state.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '~' or '-'))
        {
            response.Error = Invalid(response.Meta, "state", "state: pattern");
            return response;
        }

        if (_heldKeys.ContainsKey(Convert.ToHexString(request.NodePublicKey.Span)))
        {
            response.Error = Error(ErrorCategory.Conflict, "already_exists", response.Meta, new StateFailure { State = "node_key", Reason = "already_registered" });
            return response;
        }

        var key = request.NodePublicKey.ToByteArray();
        var nodeId = request.Node.NodeId.Value.ToByteArray();
        foreach (var older in _flows.Where(row => row.State == FlowRowState.Pending && row.NodeId.AsSpan().SequenceEqual(nodeId) && row.Key.AsSpan().SequenceEqual(key)))
        {
            // "A newer Begin of the same node ID and the same key expires the node's PENDING flows."
            older.State = FlowRowState.Expired;
        }

        var flow = new SignInFlowRow(NextFlowIds.Count > 0 ? NextFlowIds.Dequeue() : RandomNumberGenerator.GetBytes(16), request.CodeChallenge, request.RedirectUri, request.State, nodeId, key, Clock.GetUtcNow() + TimeSpan.FromMinutes(10));
        _flows.Add(flow);
        response.Value = new NodeEnrollmentServiceBeginNodeSignInValue
        {
            FlowId = new Id { Value = ByteString.CopyFrom(flow.Id) },
            AuthorizeUrl = AuthorizeUrlOverride ?? PublicBase.ConnectUrl(flow.Id),
            ExpiresAt = ProtoTime.ToInstant(flow.Expires),
        };
        return response;
    }

    private NodeEnrollmentServiceCompleteNodeSignInResponse Complete(NodeEnrollmentServiceCompleteNodeSignInRequest request)
    {
        var response = new NodeEnrollmentServiceCompleteNodeSignInResponse { Meta = Meta() };
        if (request.FlowId is not { Value.Length: 16 })
        {
            response.Error = Invalid(response.Meta, "flow_id", "flow_id: required");
            return response;
        }

        if (request.CodeVerifier is not { Length: >= 43 and <= 128 } verifier || !verifier.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~'))
        {
            response.Error = Invalid(response.Meta, "code_verifier", "code_verifier: pattern");
            return response;
        }

        if (request.NodeKeyProof.Length != 64)
        {
            response.Error = Invalid(response.Meta, "node_key_proof", "node_key_proof: length");
            return response;
        }

        var flow = _flows.FirstOrDefault(row => row.Id.AsSpan().SequenceEqual(request.FlowId.Value.Span));
        if (flow is null)
        {
            response.Error = Error(ErrorCategory.State, "not_found", response.Meta, new StateFailure
            {
                State = "node_sign_in",
                Reason = "not_found",
                Resource = new AggregateRef { Kind = "node_sign_in", Id = request.FlowId.Clone() },
            });
            return response;
        }

        var now = Clock.GetUtcNow();
        if ((flow.State is FlowRowState.Pending or FlowRowState.Approved && now >= flow.Expires) || (flow.State == FlowRowState.Approved && now >= flow.CodeExpires))
        {
            response.Error = Error(ErrorCategory.State, "expired", response.Meta, null);
            return response;
        }

        // The code first, in constant time; any mismatch, in every state, is unauthenticated with nothing written (protocol-1).
        var matches = flow.Code is { } code && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(code), Encoding.ASCII.GetBytes(request.Code ?? string.Empty));
        if (!matches || flow.State == FlowRowState.Denied)
        {
            response.Error = Error(ErrorCategory.Authentication, "unauthenticated", response.Meta, null);
            return response;
        }

        switch (flow.State)
        {
            case FlowRowState.Expired:
                response.Error = Error(ErrorCategory.State, "expired", response.Meta, null);
                return response;
            case FlowRowState.Revoked:
                response.Error = Error(ErrorCategory.Conflict, "code_reused", response.Meta, null);
                return response;
            case FlowRowState.Completed:
                // A reuse: the flow and the family it delivered are revoked.
                flow.State = FlowRowState.Revoked;
                if (flow.Delivered is { } delivered)
                {
                    delivered.Revoked = true;
                }

                response.Error = Error(ErrorCategory.Conflict, "code_reused", response.Meta, null);
                return response;
        }

        var verifierOk = S256(request.CodeVerifier) == flow.Challenge;
        var proofOk = Placeholder(request.NodeKeyProof) || VerifyNodeKeyProof(flow.Key, ProofMessage(0x01, flow.NodeId, [.. flow.Id, .. Encoding.ASCII.GetBytes(request.Code!)]), request.NodeKeyProof.ToByteArray());
        if (!verifierOk || !proofOk)
        {
            flow.State = FlowRowState.Revoked;
            response.Error = Error(ErrorCategory.Authentication, "unauthenticated", response.Meta, null);
            return response;
        }

        if (Enroll(flow.NodeId, flow.Key, response.Meta, out var credentials, out var session) is { } refused)
        {
            response.Error = refused;
            return response;
        }

        flow.State = FlowRowState.Completed;
        flow.Delivered = session;
        response.Value = new NodeEnrollmentServiceCompleteNodeSignInValue { Credentials = credentials };
        return response;
    }

    private NodeEnrollmentServiceStartDeviceAuthorizationResponse Start(NodeEnrollmentServiceStartDeviceAuthorizationRequest request)
    {
        var response = new NodeEnrollmentServiceStartDeviceAuthorizationResponse { Meta = Meta() };
        if (NodeShape(request.Node, request.NodePublicKey) is { } invalid)
        {
            response.Error = Invalid(response.Meta, invalid.Field, invalid.Reason);
            return response;
        }

        if (_heldKeys.ContainsKey(Convert.ToHexString(request.NodePublicKey.Span)))
        {
            response.Error = Error(ErrorCategory.Conflict, "already_exists", response.Meta, new StateFailure { State = "node_key", Reason = "already_registered" });
            return response;
        }

        var key = request.NodePublicKey.ToByteArray();
        var nodeId = request.Node.NodeId.Value.ToByteArray();
        foreach (var older in _devices.Where(row => row.State == DeviceRowState.Pending && row.NodeId.AsSpan().SequenceEqual(nodeId) && row.Key.AsSpan().SequenceEqual(key)))
        {
            older.State = DeviceRowState.Expired;
        }

        var userCode = UserCodeOverride ?? (NextUserCodes.Count > 0 ? NextUserCodes.Dequeue() : new string([.. RandomNumberGenerator.GetBytes(8).Select(b => "BCDFGHJKLMNPQRSTVWXZ"[b % 20])]));
        var device = new DeviceRow(NextDeviceCodes.Count > 0 ? NextDeviceCodes.Dequeue() : Base64Url(RandomNumberGenerator.GetBytes(32)), userCode, nodeId, key,
            Clock.GetUtcNow() + TimeSpan.FromSeconds(600));
        _devices.Add(device);
        var display = userCode.Length == 8 ? userCode[..4] + "-" + userCode[4..] : userCode;
        response.Value = new NodeEnrollmentServiceStartDeviceAuthorizationValue
        {
            Authorization = new DeviceAuthorization
            {
                DeviceCode = device.DeviceCode,
                UserCode = userCode,
                VerificationUri = VerificationUriOverride ?? PublicBase.ActivateUrl,
                VerificationUriComplete = (VerificationUriOverride ?? PublicBase.ActivateUrl) + "#code=" + display,
                IntervalMs = device.IntervalMs,
                ExpiresAt = ProtoTime.ToInstant(device.Expires),
            },
        };
        return response;
    }

    private NodeEnrollmentServicePollDeviceAuthorizationResponse Poll(NodeEnrollmentServicePollDeviceAuthorizationRequest request)
    {
        var response = new NodeEnrollmentServicePollDeviceAuthorizationResponse { Meta = Meta() };
        if (string.IsNullOrEmpty(request.DeviceCode))
        {
            response.Error = Invalid(response.Meta, "device_code", "device_code: required");
            return response;
        }

        if (request.NodeKeyProof.Length != 64)
        {
            response.Error = Invalid(response.Meta, "node_key_proof", "node_key_proof: length");
            return response;
        }

        var device = _devices.FirstOrDefault(row => row.DeviceCode == request.DeviceCode);
        if (device is null)
        {
            response.Error = Error(ErrorCategory.State, "not_found", response.Meta, new StateFailure { State = "device_authorization", Reason = "not_found" });
            return response;
        }

        if (!Placeholder(request.NodeKeyProof) && !VerifyNodeKeyProof(device.Key, ProofMessage(0x02, device.NodeId, Encoding.ASCII.GetBytes(device.DeviceCode)), request.NodeKeyProof.ToByteArray()))
        {
            // "A bad node key proof on an APPROVED authorization is AUTHENTICATION/unauthenticated and leaves it APPROVED."
            response.Error = Error(ErrorCategory.Authentication, "unauthenticated", response.Meta, null);
            return response;
        }

        var now = Clock.GetUtcNow();
        var value = new NodeEnrollmentServicePollDeviceAuthorizationValue { IntervalMs = device.IntervalMs };
        response.Value = value;
        if (device.State is DeviceRowState.Pending or DeviceRowState.Approved && now >= device.Expires)
        {
            device.State = DeviceRowState.Expired;
        }

        switch (device.State)
        {
            case DeviceRowState.Denied:
                value.State = DeviceAuthorizationState.Denied;
                return response;
            case DeviceRowState.Expired:
                value.State = DeviceAuthorizationState.Expired;
                return response;
            case DeviceRowState.Completed:
                if (!device.Reused)
                {
                    device.Reused = true;
                    if (device.Delivered is { } delivered)
                    {
                        delivered.Revoked = true;
                    }
                }

                value.State = DeviceAuthorizationState.Completed;
                return response;
        }

        if (device.LastPoll is { } last && now - last < TimeSpan.FromMilliseconds(device.IntervalMs - 500))
        {
            device.IntervalMs = Math.Min(device.IntervalMs + 5000, 60000);
            value.IntervalMs = device.IntervalMs;
            value.State = DeviceAuthorizationState.SlowDown;
            return response;
        }

        device.LastPoll = now;
        if (device.State == DeviceRowState.Pending)
        {
            value.State = DeviceAuthorizationState.Pending;
            return response;
        }

        if (Enroll(device.NodeId, device.Key, response.Meta, out var credentials, out var session) is { } refused)
        {
            response.Value = null;
            response.Error = refused;
            return response;
        }

        device.State = DeviceRowState.Completed;
        device.Delivered = session;
        value.State = DeviceAuthorizationState.Approved;
        value.Credentials = credentials;
        return response;
    }

    /// <summary>fleet.Enroll's refusals (center-fleet.md "Enrollment" rules 2 and 4), then a new node session; the key becomes held.</summary>
    private ArcError? Enroll(byte[] nodeId, byte[] key, ResponseMeta meta, out NodeCredentials? credentials, out Session? session)
    {
        credentials = null;
        session = null;
        if (ForeignNodes.Contains(Convert.ToHexString(nodeId)))
        {
            return Error(ErrorCategory.Conflict, "already_exists", meta, new StateFailure { State = "node", Reason = "already_exists" });
        }

        if (_heldKeys.TryGetValue(Convert.ToHexString(key), out var retired))
        {
            return retired
                ? Error(ErrorCategory.Authentication, "credential_revoked", meta, null)
                : Error(ErrorCategory.Conflict, "already_exists", meta, new StateFailure { State = "node_key", Reason = "already_registered" });
        }

        if (QuotaReached)
        {
            var error = Error(ErrorCategory.Resource, "quota_exceeded", meta, null);
            error.Details = new ErrorDetails { Limit = new LimitFailure { LimitName = "max_nodes_per_account", Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = "2" } } };
            return error;
        }

        credentials = IssueLocked(nodeId, Account.Name);
        session = _byRefresh[credentials.RefreshToken];
        _deliveredRefresh = credentials.RefreshToken;
        _heldKeys[Convert.ToHexString(key)] = false;
        Channel.RegisterInstallationKey(session.Installation, key);
        return null;
    }

    private static ArcError Invalid(ResponseMeta meta, string field, string reason) =>
        Error(ErrorCategory.Validation, "invalid_argument", meta, new StateFailure { State = field, Reason = reason });

    private static (string Field, string Reason)? NodeShape(EnrollingNodeInfo? node, ByteString key)
    {
        if (node is null || node.NodeId is not { Value.Length: 16 })
        {
            return ("node.node_id", "node.node_id: required");
        }

        if (key.Length != 91)
        {
            return ("node_public_key", "node_public_key: required");
        }

        return node.Name is { Length: >= 1 and <= 64 } ? null : ("node.name", "node.name: length");
    }

    /// <summary>The center's loopback admission (the vendored redirect vectors).</summary>
    public static bool AdmittedRedirect(string? uri) =>
        uri is not null && System.Text.RegularExpressions.Regex.IsMatch(uri, @"^http://(127\.0\.0\.1|\[::1\]):([1-9][0-9]{3,4})/callback$")
        && int.Parse(uri[(uri.LastIndexOf(':') + 1)..uri.LastIndexOf('/')], System.Globalization.CultureInfo.InvariantCulture) is >= 1024 and <= 65535;

    /// <summary>The proof message, built by FakeCenter's own code (fleet.proto "Node key proof").</summary>
    private byte[] ProofMessage(byte purpose, byte[] nodeId, byte[] binding) =>
        [.. Encoding.ASCII.GetBytes("ArcForges node-key-proof v1\n"), purpose, .. SHA256.HashData(Encoding.UTF8.GetBytes(PublicBase.Url)), .. nodeId, .. binding];

    /// <summary>FakeCenter's own S256 (RFC 7636 section 4.2), independent of the node's <c>Pkce</c>.</summary>
    public static string S256(string verifier) => Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    private static bool IsBase64Url43(string? value) => value is { Length: 43 } && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private enum FlowRowState
    {
        Pending,
        Approved,
        Completed,
        Denied,
        Expired,
        Revoked,
    }

    private enum DeviceRowState
    {
        Pending,
        Approved,
        Completed,
        Denied,
        Expired,
    }

    private sealed class SignInFlowRow(byte[] id, string challenge, string redirectUri, string state, byte[] nodeId, byte[] key, DateTimeOffset expires)
    {
        public byte[] Id { get; } = id;

        public string Challenge { get; } = challenge;

        public string RedirectUri { get; } = redirectUri;

        public string State0 { get; } = state;

        public byte[] NodeId { get; } = nodeId;

        public byte[] Key { get; } = key;

        public DateTimeOffset Expires { get; } = expires;

        public FlowRowState State { get; set; }

        public string? Code { get; set; }

        public DateTimeOffset CodeExpires { get; set; }

        public Session? Delivered { get; set; }
    }

    private sealed class DeviceRow(string deviceCode, string userCode, byte[] nodeId, byte[] key, DateTimeOffset expires)
    {
        public string DeviceCode { get; } = deviceCode;

        public string UserCode { get; } = userCode;

        public byte[] NodeId { get; } = nodeId;

        public byte[] Key { get; } = key;

        public DateTimeOffset Expires { get; } = expires;

        public DeviceRowState State { get; set; }

        public DateTimeOffset? LastPoll { get; set; }

        public ulong IntervalMs { get; set; } = 5000;

        public bool Reused { get; set; }

        public Session? Delivered { get; set; }
    }

    /// <summary>The message of a gRPC-Web request body (one uncompressed data frame).</summary>
    public static byte[] Payload(byte[] body)
    {
        if (body.Length < 5 || body[0] != 0 || BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(1)) != body.Length - 5)
        {
            throw new InvalidDataException("Not one uncompressed gRPC-Web data frame.");
        }

        return body[5..];
    }

    /// <summary>A gRPC-Web data frame.</summary>
    public static byte[] DataFrame(IMessage message)
    {
        var payload = message.ToByteArray();
        var frame = new byte[5 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), (uint)payload.Length);
        payload.CopyTo(frame, 5);
        return frame;
    }

    /// <summary>The trailer frame (flag 0x80): <c>grpc-status</c> and, for a refusal, <c>grpc-message</c> percent-encoded.</summary>
    public static byte[] TrailerFrame(int status, string? message)
    {
        var text = "grpc-status: " + status + "\r\n" + (message is null ? string.Empty : "grpc-message: " + Uri.EscapeDataString(message).Replace("%2E", ".", StringComparison.Ordinal).Replace("%5F", "_", StringComparison.Ordinal) + "\r\n");
        var bytes = Encoding.ASCII.GetBytes(text);
        var frame = new byte[5 + bytes.Length];
        frame[0] = 0x80;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), (uint)bytes.Length);
        bytes.CopyTo(frame, 5);
        return frame;
    }

    /// <summary>A trailer frame (flag 0x80) with <paramref name="trailers"/> exactly as given (each line ends with CR LF).</summary>
    public static byte[] RawTrailerFrame(string trailers)
    {
        var bytes = Encoding.ASCII.GetBytes(trailers);
        var frame = new byte[5 + bytes.Length];
        frame[0] = 0x80;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), (uint)bytes.Length);
        bytes.CopyTo(frame, 5);
        return frame;
    }

    private static byte[] Concat(byte[] first, byte[] second) => [.. first, .. second];

    private sealed class Session(byte[] nodeId, byte[] installation, string access, string refresh, DateTimeOffset accessExpires, DateTimeOffset sessionExpires)
    {
        public byte[] NodeId { get; } = nodeId;

        public byte[] Installation { get; } = installation;

        public byte[] Account { get; set; } = new byte[16];

        public string Access { get; set; } = access;

        public string Refresh { get; set; } = refresh;

        public DateTimeOffset AccessExpires { get; set; } = accessExpires;

        public DateTimeOffset SessionExpires { get; set; } = sessionExpires;

        public HashSet<string> Spent { get; } = new(StringComparer.Ordinal);

        public bool Revoked { get; set; }

        public bool Restricted { get; set; }

        public bool NodeLive { get; set; } = true;

        public int Refreshes { get; set; }

        public DateTimeOffset WindowStart { get; set; } = DateTimeOffset.MinValue;

        public string? ReportedName { get; set; }
    }
}
