// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core;
using Grpc.Core;
using V2 = ArcForges.Contracts.Sandbox.V2;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>The owner's local V2 Run lifecycle methods.</summary>
internal sealed class RunServiceHandler(NodeRuntime node) : V2.RunService.RunServiceBase
{
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
}
