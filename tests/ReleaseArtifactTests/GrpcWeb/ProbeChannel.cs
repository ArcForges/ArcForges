// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;

namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

/// <summary>What one transport attempt looked like below the gRPC-Web handler.</summary>
internal sealed record TapEntry(
    string Method,
    Uri Uri,
    string? RequestMediaType,
    string? GrpcTimeout,
    int? Status,
    string? ResponseMediaType,
    IReadOnlyDictionary<string, string> ResponseHeaders);

/// <summary>
/// Records every request that reaches the transport (so a hidden retry is visible), and can run an action at
/// the moment a request is handed to the transport (so a cancellation can be made to happen while it is in flight).
/// Only an allowlist of response headers is retained; no request header or body is ever recorded.
/// </summary>
internal sealed class RequestTap(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    private static readonly string[] RetainedResponseHeaders =
    [
        "x-arcforges-worker-revision",
        "x-content-type-options",
        "cache-control",
    ];

    private readonly Lock _gate = new();
    private readonly List<TapEntry> _entries = [];

    public Action? BeforeSend { get; set; }

    public IReadOnlyList<TapEntry> Entries
    {
        get
        {
            lock (_gate)
            {
                return [.. _entries];
            }
        }
    }

    /// <summary>The most recent transport attempt, or null when none has happened.</summary>
    public TapEntry? Last
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count == 0 ? null : _entries[^1];
            }
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        string? requestMediaType = request.Content?.Headers.ContentType?.MediaType;
        string? timeout = request.Headers.TryGetValues("grpc-timeout", out var values) ? values.FirstOrDefault() : null;
        BeforeSend?.Invoke();
        HttpResponseMessage? response = null;
        try
        {
            response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            return response;
        }
        finally
        {
            var retained = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (response is not null)
            {
                foreach (string name in RetainedResponseHeaders)
                {
                    if (response.Headers.TryGetValues(name, out var found))
                    {
                        retained[name] = found.First();
                    }
                }
            }

            var entry = new TapEntry(request.Method.Method, request.RequestUri ?? new Uri("about:blank"), requestMediaType, timeout,
                response is null ? null : (int)response.StatusCode, response?.Content.Headers.ContentType?.MediaType, retained);
            lock (_gate)
            {
                _entries.Add(entry);
            }
        }
    }
}

/// <summary>One generated-client channel over the binary gRPC-Web handler and a caller-supplied transport.</summary>
internal sealed class ProbeChannel : IDisposable
{
    private const int MaximumMessageBytes = 64 * 1024;

    [SuppressMessage("Reliability", "CA2000", Justification = "The handler chain is owned by the HttpClient (disposeHandler), which the channel disposes (DisposeHttpClient).")]
    public ProbeChannel(Uri address, HttpMessageHandler transport, Action<HttpRequestMessage>? mutateRequest = null)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(transport);
        Tap = new RequestTap(transport);
        // Grpc.Net.Client sends "/<service>/<method>" and drops any path of the channel address, so the ingress path
        // base (for example /api) is applied by a handler between the gRPC-Web handler and the tap.
        var mutator = new MutateRequestHandler(mutateRequest, Tap);
        var pathBase = new PathBaseHandler(address.AbsolutePath.TrimEnd('/'), mutator);
        var http = new HttpClient(new GrpcWebHandler(GrpcWebMode.GrpcWeb, pathBase), disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        Channel = GrpcChannel.ForAddress(new Uri(address.GetLeftPart(UriPartial.Authority)), new GrpcChannelOptions
        {
            HttpClient = http,
            DisposeHttpClient = true,
            MaxReceiveMessageSize = MaximumMessageBytes,
            MaxSendMessageSize = MaximumMessageBytes,
        });
    }

    public RequestTap Tap { get; }

    public GrpcChannel Channel { get; }

    public void Dispose() => Channel.Dispose();

    /// <summary>A channel over the real socket transport (used for a target nobody listens on).</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The channel takes ownership of the transport it is given.")]
    public static ProbeChannel CreateReal(Uri address, bool useSystemProxy) => new(address, CreateRealTransport(useSystemProxy));

    /// <summary>The real transport: no redirect, cookies, decompression or credentials of any kind.</summary>
    public static SocketsHttpHandler CreateRealTransport(bool useSystemProxy) => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = useSystemProxy,
        AutomaticDecompression = System.Net.DecompressionMethods.None,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        PooledConnectionLifetime = TimeSpan.FromMinutes(1),
    };
}

/// <summary>Prefixes every request path with the ingress path base; an empty base leaves requests untouched.</summary>
internal sealed class PathBaseHandler(string pathBase, HttpMessageHandler inner) : DelegatingHandler(inner)
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (pathBase.Length != 0 && request.RequestUri is { } uri)
        {
            request.RequestUri = new UriBuilder(uri) { Path = pathBase + uri.AbsolutePath }.Uri;
        }

        return base.SendAsync(request, cancellationToken);
    }
}

/// <summary>
/// Test seam: lets the self-test damage the request just before the tap sees it, to show that the verifier notices a
/// wrong path, method, media type or timeout. It does nothing when no mutation is given.
/// </summary>
internal sealed class MutateRequestHandler(Action<HttpRequestMessage>? mutate, HttpMessageHandler inner) : DelegatingHandler(inner)
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        mutate?.Invoke(request);
        return base.SendAsync(request, cancellationToken);
    }
}
