// SPDX-License-Identifier: AGPL-3.0-only
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace ArcForges.LocalRpc;

/// <summary>
/// Tracks whether the current logical call is running inside a Local RPC handler, so the first call a handler makes
/// is marked as a callback and a second hop is refused. The marker is cooperative: it protects first-party endpoints
/// from a wait cycle between two saturated lanes; a hostile peer that omits it is still held to the data bounds,
/// the deadlines and the connection limits.
/// </summary>
internal static class LocalRpcCallbackGuard
{
    private static readonly AsyncLocal<int?> Depth = new();

    /// <summary>The handler depth of the current flow: null outside a handler, 0 in a handler, 1 in a callback handler.</summary>
    internal static int? CurrentDepth => Depth.Value;

    /// <summary>Marks the current flow as running a handler at <paramref name="depth"/> until the returned scope is disposed.</summary>
    internal static Scope Enter(int depth)
    {
        var previous = Depth.Value;
        Depth.Value = depth;
        return new Scope(previous);
    }

    internal readonly struct Scope(int? previous) : IDisposable
    {
        public void Dispose() => Depth.Value = previous;
    }
}

/// <summary>
/// Wraps the channel's invoker. A call made from inside a handler carries the callback marker, so the receiving
/// server never queues it; a call made from inside a callback handler is refused here, before anything is sent.
/// </summary>
internal sealed class LocalRpcCallbackInterceptor : Interceptor
{
    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        if (!TryMark(ref context, out var refusal))
        {
            return new AsyncUnaryCall<TResponse>(
                Task.FromException<TResponse>(refusal!),
                Task.FromResult(new Metadata()),
                () => refusal!.Status,
                () => refusal!.Trailers,
                () => { });
        }

        return continuation(request, context);
    }

    public override TResponse BlockingUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        BlockingUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        return TryMark(ref context, out var refusal) ? continuation(request, context) : throw refusal!;
    }

    public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncClientStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        return TryMark(ref context, out var refusal) ? continuation(context) : throw refusal!;
    }

    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncServerStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        return TryMark(ref context, out var refusal) ? continuation(request, context) : throw refusal!;
    }

    public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncDuplexStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        return TryMark(ref context, out var refusal) ? continuation(context) : throw refusal!;
    }

    private static bool TryMark<TRequest, TResponse>(ref ClientInterceptorContext<TRequest, TResponse> context, out RpcException? refusal)
        where TRequest : class
        where TResponse : class
    {
        refusal = null;
        var depth = LocalRpcCallbackGuard.CurrentDepth;
        if (depth is null)
        {
            return true;
        }

        if (depth >= 1)
        {
            refusal = new RpcException(
                new Status(StatusCode.FailedPrecondition, "A callback handler does not make further calls."),
                new Metadata
                {
                    { LocalRpcRefusal.ReasonTrailer, LocalRpcRefusal.NameOf(LocalRpcRefusalReason.RecursiveCallback) },
                    { LocalRpcRefusal.DispatchedTrailer, "0" },
                });
            return false;
        }

        var headers = new Metadata();
        if (context.Options.Headers is { } existing)
        {
            foreach (var entry in existing)
            {
                headers.Add(entry);
            }
        }

        headers.Add(LocalRpcRefusal.NestedHeader, "1");
        context = new ClientInterceptorContext<TRequest, TResponse>(context.Method, context.Host, context.Options.WithHeaders(headers));
        return true;
    }
}
