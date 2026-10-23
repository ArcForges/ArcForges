// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Resources;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>arcforges.node.v1.ResourceService</c> (resources.proto; architecture 03): <c>GetResourceSnapshot</c>, <c>WatchResources</c> (a
/// snapshot at once, then one per interval, with 15 s heartbeats when none was due), <c>ListProcesses</c> and <c>GetSamples</c>. The
/// answers are built by <see cref="ResourceViews"/>. <c>AdoptProcess</c> and <c>TerminateProcess</c> belong to later tasks, and the
/// guest-link methods are retired (AD-0018 section 3); the generated base answers them <c>UNIMPLEMENTED</c>.
/// </summary>
public sealed class ResourceServiceHandler : ResourceService.ResourceServiceBase
{
    private readonly NodeRuntime _node;

    /// <summary>Creates the service over the running node.</summary>
    public ResourceServiceHandler(NodeRuntime node) => _node = node ?? throw new ArgumentNullException(nameof(node));

    /// <inheritdoc />
    public override Task<ResourceServiceGetResourceSnapshotResponse> GetResourceSnapshot(ResourceServiceGetResourceSnapshotRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ResourceServiceGetResourceSnapshotResponse { Meta = Meta(request.Meta) };
        if (Stopping() is { } stopping)
        {
            response.Error = stopping;
        }
        else
        {
            response.Value = new ResourceServiceGetResourceSnapshotValue { Snapshot = Snapshot() };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task WatchResources(ResourceServiceWatchResourcesRequest request, IServerStreamWriter<ResourceServiceWatchResourcesFrame> responseStream,
        ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var writer = context.OpenLocalRpcStream(responseStream);
        await using (writer.ConfigureAwait(false))
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(writer.Ended, context.CancellationToken, _node.Stopping);
            var invalid = ResourceViews.Validate(request, out var interval);
            var refused = Stopping() ?? invalid;
            if (refused is not null)
            {
                writer.TryWrite(new ResourceServiceWatchResourcesFrame { Meta = Meta(request.Meta), Error = refused });
                await writer.CompleteAsync().ConfigureAwait(false);
                return;
            }

            ulong sequence = 0;
            var lastWrite = _node.Clock.GetTimestamp();
            var nextSnapshot = lastWrite;
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var now = _node.Clock.GetTimestamp();
                    if (now >= nextSnapshot)
                    {
                        writer.TryWrite(new ResourceServiceWatchResourcesFrame
                        {
                            Meta = new ResponseMeta(),
                            Position = new StreamPosition { Sequence = ++sequence },
                            Snapshot = Snapshot(),
                        });
                        lastWrite = now;
                        nextSnapshot = now + (long)(interval.TotalSeconds * _node.Clock.TimestampFrequency);
                    }
                    else if (_node.Clock.GetElapsedTime(lastWrite) >= NodeEventServiceHandler.HeartbeatInterval)
                    {
                        writer.TryWrite(new ResourceServiceWatchResourcesFrame
                        {
                            Meta = new ResponseMeta(),
                            Heartbeat = new Heartbeat { At = ProtoTime.ToInstant(_node.Clock.GetUtcNow()) },
                        });
                        lastWrite = now;
                    }

                    var due = _node.Clock.GetElapsedTime(_node.Clock.GetTimestamp(), nextSnapshot);
                    var heartbeat = NodeEventServiceHandler.HeartbeatInterval - _node.Clock.GetElapsedTime(lastWrite);
                    var wait = due < heartbeat ? due : heartbeat;
                    await Task.Delay(wait > TimeSpan.Zero ? wait : TimeSpan.Zero, stop.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
            }

            await writer.CompleteAsync().ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public override Task<ResourceServiceListProcessesResponse> ListProcesses(ResourceServiceListProcessesRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ResourceServiceListProcessesResponse { Meta = Meta(request.Meta) };
        if (Stopping() is { } stopping)
        {
            response.Error = stopping;
            return Task.FromResult(response);
        }

        var (processes, error) = ResourceViews.Processes(_node, request.Filter);
        if (error is not null)
        {
            response.Error = error;
        }
        else
        {
            var value = new ResourceServiceListProcessesValue();
            value.Processes.Add(processes);
            response.Value = value;
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<ResourceServiceGetSamplesResponse> GetSamples(ResourceServiceGetSamplesRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ResourceServiceGetSamplesResponse { Meta = Meta(request.Meta) };
        if (Stopping() is { } stopping)
        {
            response.Error = stopping;
            return Task.FromResult(response);
        }

        var (value, error) = ResourceViews.Samples(_node, request);
        if (error is not null)
        {
            response.Error = error;
        }
        else
        {
            response.Value = value;
        }

        return Task.FromResult(response);
    }

    /// <summary>The snapshot, or (before the monitor's first evaluation, or on a node that observes nothing) the capacity part alone.</summary>
    private ResourceSnapshot Snapshot() => ResourceViews.Snapshot(_node) ?? new ResourceSnapshot
    {
        At = ProtoTime.ToInstant(_node.Clock.GetUtcNow()),
        Capabilities = _node.Capabilities,
        PressureDetail = new PressureDetail { Available = false },
    };

    private static ResponseMeta Meta(RequestMeta? request)
    {
        var meta = new ResponseMeta();
        if (request?.CorrelationId is { } correlation)
        {
            meta.CorrelationId = correlation;
        }

        return meta;
    }

    private ArcError? Stopping()
    {
        _node.CountCall();
        return _node.Lifecycle.IsStopping ? NodeErrors.NodeStopping(_node.Clock.GetUtcNow()) : null;
    }
}
