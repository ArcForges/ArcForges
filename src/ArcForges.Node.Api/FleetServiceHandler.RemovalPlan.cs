// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Api;

internal sealed partial class FleetServiceHandler
{
    public override async Task<FleetServicePlanNodeRemovalResponse> PlanNodeRemoval(FleetServicePlanNodeRemovalRequest request,
        ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        var correlation = Validation.RequiredId(request.Meta?.CorrelationId, "correlation_id") is null
            ? request.Meta!.CorrelationId.Clone() : CommandIds.New(node.Clock);
        var meta = ApiCommands.Meta(request.Meta);
        meta.CorrelationId = correlation.Clone();
        FleetServicePlanNodeRemovalResponse Fail(ArcError error)
        {
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            return new FleetServicePlanNodeRemovalResponse { Meta = meta, Error = error };
        }

        var invalid = Validation.RequiredId(forwarded.NodeId, "node_id") ?? Payload(forwarded.HasRequest, forwarded.Request, 245760);
        FileServicePlanRemovalRequest? inner = null;
        if (invalid is null && request.Meta?.CorrelationId is { } suppliedCorrelation)
            invalid = Validation.RequiredId(suppliedCorrelation, "meta.correlation_id");
        Id? command = null;
        if (invalid is null)
        {
            try
            {
                inner = FileServicePlanRemovalRequest.Parser.ParseFrom(forwarded.Request);
                command = inner.Meta?.CommandId;
                invalid = Validation.CommandId(forwarded.Meta) ?? Validation.RequiredId(command, "request.meta.command_id");
                if (invalid is null && !command!.Equals(forwarded.Meta.CommandId))
                    invalid = NodeErrors.InvalidArgument("meta.command_id must equal the inner request command_id");
            }
            catch (InvalidProtocolBufferException)
            {
                invalid = NodeErrors.InvalidArgument("request: invalid node request bytes");
            }
        }

        if (invalid is not null) return Fail(invalid);
        var response = await ForwardAsync(context, correlation, RoutedMethod.PlanNodeRemoval, forwarded.NodeId, command,
            _ => SHA256.HashData(forwarded.Request.Span),
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.PlanNodeRemovalAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null, Fail).ConfigureAwait(false);
        return RoutedFileResponseValidation.PlanRemoval(response, forwarded.NodeId, inner!)
            ? response : Fail(NodeErrors.Internal(node.Clock.GetUtcNow()));
    }
}
