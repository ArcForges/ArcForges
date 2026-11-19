// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.RunSupervisor.Protocol;
using Grpc.Core;
using Microsoft.AspNetCore.Connections.Features;
using V2 = ArcForges.Contracts.Sandbox.V2;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>The owner's local V2 Run lifecycle methods.</summary>
internal sealed class RunServiceHandler(NodeRuntime node, ClientSessions sessions) : V2.RunService.RunServiceBase
{
    internal const int OutputBuffer = 8;

    public override Task<V2.RunServiceStartResponse> Start(
        V2.RunServiceStartRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.Start(value, cancellation),
            static (meta, error) => new V2.RunServiceStartResponse { Meta = meta, Error = error });

    public override Task<V2.RunServiceListResponse> List(
        V2.RunServiceListRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.ListRuns(value, cancellation),
            static (meta, error) => new V2.RunServiceListResponse { Meta = meta, Error = error });

    public override Task<V2.RunServiceInspectResponse> Inspect(
        V2.RunServiceInspectRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.InspectRun(value, cancellation),
            static (meta, error) => new V2.RunServiceInspectResponse { Meta = meta, Error = error });

    public override Task<V2.RunServiceStopResponse> Stop(
        V2.RunServiceStopRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.Stop(value, cancellation),
            static (meta, error) => new V2.RunServiceStopResponse { Meta = meta, Error = error });

    public override Task<V2.RunServiceAcquireTerminalResponse> AcquireTerminal(
        V2.RunServiceAcquireTerminalRequest request, ServerCallContext context) =>
        TerminalCall(request, request.Meta, context, V2Shapes.IsValid,
            static (manager, value, caller, closed, wait) => manager.AcquireTerminalAsync(value, caller, closed, wait),
            static (meta, error) => new V2.RunServiceAcquireTerminalResponse { Meta = meta, Error = error });

    public override Task<V2.RunServiceWriteTerminalResponse> WriteTerminal(
        V2.RunServiceWriteTerminalRequest request, ServerCallContext context) =>
        TerminalCall(request, request.Meta, context, V2Shapes.IsValid,
            static (manager, value, caller, closed, wait) => manager.WriteTerminalAsync(value, caller, closed, wait),
            static (meta, error) => new V2.RunServiceWriteTerminalResponse { Meta = meta, Error = error });

    public override Task<V2.RunServiceResizeTerminalResponse> ResizeTerminal(
        V2.RunServiceResizeTerminalRequest request, ServerCallContext context) =>
        TerminalCall(request, request.Meta, context, V2Shapes.IsValid,
            static (manager, value, caller, closed, wait) => manager.ResizeTerminalAsync(value, caller, closed, wait),
            static (meta, error) => new V2.RunServiceResizeTerminalResponse { Meta = meta, Error = error });

    public override Task<V2.RunServiceDetachTerminalResponse> DetachTerminal(
        V2.RunServiceDetachTerminalRequest request, ServerCallContext context) =>
        TerminalCall(request, request.Meta, context, static value => value.Lease is not null && V2Shapes.IsValid(value),
            static (manager, value, caller, closed, wait) => manager.DetachTerminalAsync(value, caller, closed, wait),
            static (meta, error) => new V2.RunServiceDetachTerminalResponse { Meta = meta, Error = error });

    public override async Task WatchOutput(V2.RunServiceWatchOutputRequest request,
        IServerStreamWriter<V2.RunServiceWatchOutputFrame> responseStream, ServerCallContext context)
    {
        var writer = context.OpenLocalRpcStream(responseStream);
        await using (writer.ConfigureAwait(false))
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(writer.Ended, context.CancellationToken, node.Stopping);
            var watch = await SandboxLocalCalls.Execute<V2.RunServiceWatchOutputRequest,
                (IAsyncEnumerable<V2.RunServiceWatchOutputFrame>? Frames, V2.RunServiceWatchOutputFrame? Refusal)>(
                node, context, request, request.Meta, V2Shapes.IsValid,
                (manager, value, _) => (manager.WatchRunOutputAsync(value, AuditOutputWatch, stop.Token), null),
                static (meta, error) => (null, new() { Meta = meta, Error = error }))
                .ConfigureAwait(false);
            if (watch.Refusal is { } refusal)
            {
                _ = writer.TryWrite(refusal);
                await writer.CompleteAsync().ConfigureAwait(false);
                return;
            }

            var output = watch.Frames!.GetAsyncEnumerator(stop.Token);
            await using var disposeOutput = output.ConfigureAwait(false);
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    // Read only after the previous frame reached the transport. Native output drains
                    // independently, so a lagging watcher resumes from the spool or receives a gap.
                    var transportWaited = false;
                    while (writer.Buffered != 0)
                    {
                        transportWaited = true;
                        await Task.Delay(10, stop.Token).ConfigureAwait(false);
                    }

                    if (!await output.MoveNextAsync().ConfigureAwait(false))
                    {
                        break;
                    }

                    var frame = output.Current;
                    if (transportWaited && frame.Gap is { Reason: "retention" } gap && gap.EarliestOffset > gap.RequestedOffset)
                    {
                        // The transport delayed this cursor and the spool proved it fell outside retention.
                        gap.Reason = "slow_consumer";
                    }

                    if (!writer.TryWrite(frame))
                    {
                        break;
                    }
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
            }

            await writer.CompleteAsync().ConfigureAwait(false);
        }
    }

    private void AuditOutputWatch(string runId, V2.StreamKind stream) =>
        node.Log.Info("api.run.output.accessed", new LogField("run", runId), new LogField("stream", stream));

    private Task<TResponse> TerminalCall<TRequest, TResponse>(TRequest request, RequestMeta? meta, ServerCallContext context,
        Func<TRequest, bool> validate,
        Func<SandboxManager, TRequest, RunTerminalCaller, CancellationToken, CancellationToken, Task<TResponse>> execute,
        Func<ResponseMeta, ArcError, TResponse> fail) =>
        SandboxLocalCalls.Execute<TRequest, Task<TResponse>>(node, context, request, meta, validate,
            (manager, value, wait) =>
            {
                var peer = context.GetLocalRpcPeer()!;
                var lifetime = context.GetHttpContext().Features.Get<IConnectionLifetimeFeature>();
                var connectionId = Convert.ToHexStringLower(sessions.RelaySessionIdOf(context).Value.Span);
                var caller = new RunTerminalCaller(peer.ProcessId, peer.Process.StartTimeUtcTicks, connectionId);
                return execute(manager, value, caller, lifetime?.ConnectionClosed ?? CancellationToken.None, wait);
            }, (response, error) => Task.FromResult(fail(response, error))).Unwrap();
}
