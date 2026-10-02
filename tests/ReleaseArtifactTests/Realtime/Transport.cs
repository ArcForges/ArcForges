// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.CompilerServices;
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.PublicApi.V1;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;

namespace RealtimeAotProbe;

/// <summary>The four generated calls the realtime logic uses, as one seam.</summary>
internal interface IRealtimeTransport
{
    IAsyncEnumerable<StreamFrame> WatchAsync(string subscriptionKey, string? cursor, CancellationToken cancellationToken);

    Task<EventServicePollResponse> PollAsync(string subscriptionKey, string? cursor, CancellationToken cancellationToken);

    IAsyncEnumerable<StreamFrame> WatchOutputAsync(ExecutionOwner owner, string? cursor, CancellationToken cancellationToken);

    Task<ExecutionServiceReadOutputResponse> ReadOutputAsync(ExecutionOwner owner, string? cursor, CancellationToken cancellationToken);
}

/// <summary>The generated <c>EventService</c>/<c>ExecutionService</c> clients over any gRPC channel.</summary>
internal sealed class GeneratedRealtimeTransport(ChannelBase channel, RealtimePolicy policy) : IRealtimeTransport
{
    private readonly EventService.EventServiceClient _events = new(channel);
    private readonly ExecutionService.ExecutionServiceClient _executions = new(channel);
    private readonly RealtimePolicy _policy = policy ?? throw new ArgumentNullException(nameof(policy));

    public async IAsyncEnumerable<StreamFrame> WatchAsync(string subscriptionKey, string? cursor, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var request = new EventServiceWatchRequest { Meta = NewMeta(), SubscriptionKey = subscriptionKey };
        if (cursor is not null)
        {
            request.Cursor = cursor;
        }

        using AsyncServerStreamingCall<StreamFrame> call = _events.Watch(request, cancellationToken: cancellationToken);
        await foreach (StreamFrame frame in call.ResponseStream.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return frame;
        }
    }

    public async Task<EventServicePollResponse> PollAsync(string subscriptionKey, string? cursor, CancellationToken cancellationToken)
    {
        var request = new EventServicePollRequest { Meta = NewMeta(), SubscriptionKey = subscriptionKey };
        if (cursor is not null)
        {
            request.Cursor = cursor;
        }

        return await _events.PollAsync(request, cancellationToken: cancellationToken).ResponseAsync.ConfigureAwait(false);
    }

    public async IAsyncEnumerable<StreamFrame> WatchOutputAsync(ExecutionOwner owner, string? cursor, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var request = new ExecutionServiceWatchOutputRequest { Meta = NewMeta(), Owner = owner };
        if (cursor is not null)
        {
            request.Cursor = cursor;
        }

        using AsyncServerStreamingCall<StreamFrame> call = _executions.WatchOutput(request, cancellationToken: cancellationToken);
        await foreach (StreamFrame frame in call.ResponseStream.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return frame;
        }
    }

    public async Task<ExecutionServiceReadOutputResponse> ReadOutputAsync(ExecutionOwner owner, string? cursor, CancellationToken cancellationToken)
    {
        var request = new ExecutionServiceReadOutputRequest { Meta = NewMeta(), Owner = owner, Limit = (uint)_policy.MaximumPageChunks };
        if (cursor is not null)
        {
            request.Cursor = cursor;
        }

        return await _executions.ReadOutputAsync(request, cancellationToken: cancellationToken).ResponseAsync.ConfigureAwait(false);
    }

    private static RequestMeta NewMeta()
    {
        Span<byte> bytes = stackalloc byte[16];
        Guid.NewGuid().TryWriteBytes(bytes, bigEndian: true, out _);
        return new RequestMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(bytes) } };
    }
}

/// <summary>Builds the one binary gRPC-Web channel the probe uses against a deployed ingress.</summary>
internal static class RealtimeChannel
{
    /// <summary>The bound on one received message: the 256 KiB ReadOutput response bound plus envelope headroom.</summary>
    internal const int MaximumReceiveBytes = 512 * 1024;

    /// <summary>The public business route prefix (annex 10 section 1: <c>/api/package.Service/Method</c>).</summary>
    internal const string ApiPrefix = "api/";

    /// <summary>Validate and normalize a base address: HTTPS (or plain HTTP to loopback), no user information, no query.</summary>
    public static Uri NormalizeAddress(Uri address, string? authorization)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!address.IsAbsoluteUri)
        {
            throw new ArgumentException("The base address must be absolute.", nameof(address));
        }

        bool https = address.Scheme == Uri.UriSchemeHttps;
        bool loopbackHttp = address.Scheme == Uri.UriSchemeHttp && address.IsLoopback;
        if (!https && !loopbackHttp)
        {
            throw new ArgumentException("The base address must use HTTPS, or HTTP to a loopback host.", nameof(address));
        }

        if (address.UserInfo.Length > 0 || address.Query.Length > 0 || address.Fragment.Length > 0)
        {
            throw new ArgumentException("The base address must not carry user information, a query or a fragment.", nameof(address));
        }

        if (authorization is not null && !https && !loopbackHttp)
        {
            throw new ArgumentException("An authorization value is never sent over cleartext HTTP.", nameof(address));
        }

        string path = address.AbsolutePath.EndsWith('/') ? address.AbsolutePath : address.AbsolutePath + "/";
        return new UriBuilder(address) { Path = path + ApiPrefix }.Uri;
    }

    /// <summary>Create the channel. <paramref name="inner"/> is the transport handler; the default never follows a redirect.</summary>
    public static GrpcChannel Create(Uri address, string? authorization, HttpMessageHandler? inner = null)
    {
        Uri normalized = NormalizeAddress(address, authorization);
        HttpMessageHandler transport = inner ?? new SocketsHttpHandler { AllowAutoRedirect = false };
        if (authorization is not null)
        {
            transport = new AuthorizationHandler(authorization, transport);
        }

        return GrpcChannel.ForAddress(normalized, new GrpcChannelOptions
        {
            HttpHandler = new GrpcWebHandler(GrpcWebMode.GrpcWeb, transport),
            MaxReceiveMessageSize = MaximumReceiveBytes,
            MaxSendMessageSize = MaximumReceiveBytes,
            ThrowOperationCanceledOnCancellation = true,
            DisposeHttpClient = true,
        });
    }

    private sealed class AuthorizationHandler(string authorization, HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
