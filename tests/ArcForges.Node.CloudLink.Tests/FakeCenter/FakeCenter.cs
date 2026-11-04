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
/// methods are compared byte for byte with the REAL captures (<c>FakeCenterConformanceTests</c>). The sign-in methods are part N2's. It never
/// stands in for an end-to-end result.
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
        var installation = RandomNumberGenerator.GetBytes(16);
        var session = new Session(nodeId.ToArray(), installation, NewToken("afa1."), NewToken("afr1."), Clock.GetUtcNow() + AccessLifetime,
            Clock.GetUtcNow() + FamilyLifetime);
        lock (_gate)
        {
            _byRefresh[session.Refresh] = session;
            _byAccess[session.Access] = session;
        }

        var credentials = new NodeCredentials
        {
            RefreshToken = session.Refresh,
            AccessToken = session.Access,
            AccessExpiresAt = ProtoTime.ToInstant(session.AccessExpires),
            Account = new AccountSummary { AccountId = new Id { Value = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(16)) }, DisplayName = displayName, EmailMasked = "t***@example.test" },
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

    private static byte[] Concat(byte[] first, byte[] second) => [.. first, .. second];

    private sealed class Session(byte[] nodeId, byte[] installation, string access, string refresh, DateTimeOffset accessExpires, DateTimeOffset sessionExpires)
    {
        public byte[] NodeId { get; } = nodeId;

        public byte[] Installation { get; } = installation;

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
