// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Node.Core;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// The node's one HTTP seam (AF-CTR-04 CTR4-NODE-03 as amended by node-8; the only type in <c>src/</c> that creates an <c>HttpClient</c>,
/// an outbound handler or a <c>GrpcChannel</c>; <c>ArcForges.Repository.Tests</c> checks this). Built as DesktopPlatform's PRF.05 probe
/// channel: <c>GrpcChannel.ForAddress(origin)</c> over <c>HttpClient(GrpcWebHandler(GrpcWeb, PathBaseHandler(AuthorityGuardHandler(
/// SocketsHttpHandler))))</c>. Binary gRPC-Web over HTTP/1.1 only; the path base of the center URL is applied by a handler, because
/// Grpc.Net.Client sends <c>/&lt;service&gt;/&lt;method&gt;</c> and discards any path of the channel address (the hosted center is
/// served under <c>/api</c>); every request whose scheme, host or port differ from the center is refused; no redirect is followed; the
/// HTTP client has no timeout of its own: each call carries its contract deadline (sent as <c>grpc-timeout</c>). Certificates are
/// validated by the platform's defaults; nothing here relaxes them.
/// </summary>
internal sealed class CenterHttpClient : IDisposable
{
    private readonly GrpcChannel _channel;

    /// <summary>Creates the client for <paramref name="center"/>; <paramref name="connectLog"/> (test mode only) records each attempted authority.</summary>
    public CenterHttpClient(CenterEndpoint center, string? connectLog = null)
    {
        Center = center ?? throw new ArgumentNullException(nameof(center));
        var transport = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(50),
            AutomaticDecompression = DecompressionMethods.None,
        };
        var guard = new AuthorityGuardHandler(center, connectLog) { InnerHandler = transport };
        var pathBase = new PathBaseHandler(center.PathBase) { InnerHandler = guard };
        var grpcWeb = new GrpcWebHandler(GrpcWebMode.GrpcWeb, pathBase);
        var http = new HttpClient(grpcWeb) { Timeout = Timeout.InfiniteTimeSpan };
        _channel = GrpcChannel.ForAddress(new Uri(center.Origin), new GrpcChannelOptions
        {
            HttpClient = http,
            DisposeHttpClient = true,
            MaxReceiveMessageSize = 1024 * 1024,
            MaxSendMessageSize = 64 * 1024,
            HttpVersion = HttpVersion.Version11,
            HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        });
        Fleet = new NodeEnrollmentService.NodeEnrollmentServiceClient(_channel);
    }

    /// <summary>The center this client may reach.</summary>
    public CenterEndpoint Center { get; }

    /// <summary>The generated fleet client over this channel.</summary>
    public NodeEnrollmentService.NodeEnrollmentServiceClient Fleet { get; }

    /// <inheritdoc />
    public void Dispose() => _channel.Dispose();

    /// <summary>Prefixes the center's path base to every request path, once.</summary>
    internal sealed class PathBaseHandler(string pathBase) : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            if (pathBase.Length > 0 && request.RequestUri is { } uri)
            {
                request.RequestUri = new UriBuilder(uri) { Path = pathBase + uri.AbsolutePath }.Uri;
            }

            return base.SendAsync(request, cancellationToken);
        }
    }

    /// <summary>
    /// Refuses every request whose scheme, host or port differ from the center (CTR4-SEC-19; the channel's ws/wss is http/https of the same origin), and with the test-mode hook
    /// <c>ARCFORGES_TEST_CONNECT_LOG</c> appends <c>host:port sent</c> or <c>host:port refused</c> and the UTC instant for each attempt (nothing else: no path,
    /// header or body). The log is the node's own corroboration, not independent evidence.
    /// </summary>
    internal sealed class AuthorityGuardHandler(CenterEndpoint center, string? connectLog) : DelegatingHandler
    {
        private static readonly Lock LogGate = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            var uri = request.RequestUri;

            // The node channel's upgrade (CenterChannelClient) reaches the guard with its ws or wss URI: the scheme of the same origin.
            var scheme = uri?.Scheme switch { "ws" => "http", "wss" => "https", var other => other };
            var allowed = uri is not null && uri.IsAbsoluteUri && string.Equals(scheme, center.Scheme, StringComparison.Ordinal)
                && string.Equals(uri.Host, center.Host, StringComparison.Ordinal)
                && uri.Port == center.EffectivePort;
            Record(uri is null ? "unknown" : uri.Host + ":" + uri.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), allowed ? "sent" : "refused");
            if (!allowed)
            {
                throw new HttpRequestException(HttpRequestError.ConnectionError,
                    "The node sends requests only to its configured center " + center.Origin + ".");
            }

            return base.SendAsync(request, cancellationToken);
        }

        private void Record(string authority, string outcome)
        {
            if (connectLog is null)
            {
                return;
            }

            lock (LogGate)
            {
                File.AppendAllText(connectLog, authority + " " + outcome + " " + DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture) + "\n");
            }
        }
    }
}
