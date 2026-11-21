// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Sandboxes;
using Google.Protobuf;
using Grpc.Core;
using V2 = ArcForges.Contracts.Sandbox.V2;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>The local owner's V2 resource observations and policy controls.</summary>
internal sealed class SandboxResourceServiceHandler(NodeRuntime node) : V2.ResourceService.ResourceServiceBase
{
    // A subscriber may have one snapshot pending. Preserve the second slot for its typed refusal.
    internal const int WatchBuffer = 2;
    private const uint DefaultWatchIntervalMs = 5_000;

    public override Task<V2.ResourceServiceGetBudgetResponse> GetBudget(V2.ResourceServiceGetBudgetRequest request,
        ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta,
            static value => V2Shapes.IsValid(value) && HasKnownFields(value, V2.ResourceServiceGetBudgetRequest.Parser),
            static (manager, value, cancellation) => manager.GetResourceBudget(value, cancellation),
            static (meta, error) => new V2.ResourceServiceGetBudgetResponse { Meta = meta, Error = error });

    public override Task<V2.ResourceServiceSetPolicyResponse> SetPolicy(V2.ResourceServiceSetPolicyRequest request,
        ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta,
            static value => V2Shapes.IsValid(value) && HasKnownFields(value, V2.ResourceServiceSetPolicyRequest.Parser),
            static (manager, value, cancellation) => manager.SetResourcePolicy(value, cancellation),
            static (meta, error) => new V2.ResourceServiceSetPolicyResponse { Meta = meta, Error = error });

    public override async Task WatchUsage(V2.ResourceServiceWatchUsageRequest request,
        IServerStreamWriter<V2.ResourceServiceWatchUsageFrame> responseStream, ServerCallContext context)
    {
        var writer = context.OpenLocalRpcStream(responseStream);
        await using (writer.ConfigureAwait(false))
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(writer.Ended, context.CancellationToken, node.Stopping);
            var watch = await SandboxLocalCalls.Execute<V2.ResourceServiceWatchUsageRequest,
                (SandboxManager? Manager, V2.ResourceServiceGetBudgetRequest? Query, V2.ResourceServiceGetBudgetResponse Initial)>(
                node, context, request, request.Meta,
                static value => V2Shapes.IsValid(value) && HasKnownFields(value, V2.ResourceServiceWatchUsageRequest.Parser),
                static (manager, value, cancellation) =>
                {
                    var query = new V2.ResourceServiceGetBudgetRequest
                    {
                        Meta = value.Meta,
                        ScopeKind = value.ScopeKind,
                        ScopeId = value.ScopeId,
                    };
                    return (manager, query, manager.GetResourceBudget(query, cancellation));
                }, static (meta, error) => (null, null, new() { Meta = meta, Error = error })).ConfigureAwait(false);

            var initial = UsageFrame(watch.Initial);
            if (writer.TryWrite(initial) && initial.Snapshot is { } sample)
            {
                var interval = TimeSpan.FromMilliseconds(request.HasIntervalMs ? request.IntervalMs : DefaultWatchIntervalMs);
                await FollowUsageAsync(watch.Manager!, watch.Query!, writer, initial.Meta, sample, interval, stop.Token).ConfigureAwait(false);
            }

            await writer.CompleteAsync().ConfigureAwait(false);
        }
    }

    private async Task FollowUsageAsync(SandboxManager manager, V2.ResourceServiceGetBudgetRequest query,
        LocalRpcStreamWriter<V2.ResourceServiceWatchUsageFrame> writer, ResponseMeta meta, V2.ResourceSnapshot previous,
        TimeSpan interval, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval, node.Clock);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                if (writer.Buffered != 0)
                {
                    _ = writer.TryWrite(ErrorFrame(meta, NodeErrors.Overloaded(node.Clock.GetUtcNow())));
                    return;
                }

                var frame = UsageFrame(manager.GetResourceBudget(query, cancellationToken));
                if (frame.Snapshot is not { } sample)
                {
                    _ = writer.TryWrite(frame);
                    return;
                }

                if (sample.SampleEpoch == previous.SampleEpoch && sample.SampleSequence == previous.SampleSequence
                    && sample.Stale == previous.Stale)
                {
                    continue;
                }

                if (!writer.TryWrite(frame))
                {
                    return;
                }

                previous = sample;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private V2.ResourceServiceWatchUsageFrame UsageFrame(V2.ResourceServiceGetBudgetResponse response)
    {
        if (response.Error is { } error)
        {
            return ErrorFrame(response.Meta, error);
        }

        var snapshot = response.Value?.Snapshot;
        return V2Shapes.IsValid(snapshot)
            ? new() { Meta = response.Meta, Snapshot = snapshot }
            : ErrorFrame(response.Meta, NodeErrors.Internal(node.Clock.GetUtcNow()));
    }

    private static V2.ResourceServiceWatchUsageFrame ErrorFrame(ResponseMeta meta, ArcError error)
    {
        var failure = error.Clone();
        failure.CorrelationId = meta.CorrelationId.Clone();
        return new() { Meta = meta, Error = failure };
    }

    private static bool HasKnownFields<T>(T request, MessageParser<T> parser) where T : class, IMessage<T> =>
        request.Equals(parser.WithDiscardUnknownFields(true).ParseFrom(request.ToByteArray()));
}
