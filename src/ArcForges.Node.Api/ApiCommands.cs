// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// The shared plumbing of the queue and policy services: response metas, the stopping check, the interim permission gate of the default
/// matrix (<see cref="InterimPermissions"/>: <c>P</c> is refused for every origin until approvals arrive with AF-SEC-01) and idempotent
/// commands by <c>meta.command_id</c>.
/// </summary>
internal sealed class ApiCommands(NodeRuntime node, ClientSessions sessions, string service)
{
    /// <summary>The response meta echoing the request's correlation ID.</summary>
    public static ResponseMeta Meta(RequestMeta? request)
    {
        var meta = new ResponseMeta();
        if (request?.CorrelationId is { } correlation)
        {
            meta.CorrelationId = correlation;
        }

        return meta;
    }

    /// <summary><c>STATE/node_stopping</c> while the node stops; counts the call.</summary>
    public ArcError? Stopping()
    {
        node.CountCall();
        return node.Lifecycle.IsStopping ? NodeErrors.NodeStopping(node.Clock.GetUtcNow()) : null;
    }

    /// <summary>The caller's origin.</summary>
    public Origin OriginOf(ServerCallContext context) => sessions.OriginOf(context);

    /// <summary>The interim permission gate (<see cref="InterimPermissions"/>) for the caller's origin.</summary>
    public ArcError? Permit(ServerCallContext context, GatedOperation operation, string method) =>
        InterimPermissions.Check(sessions.OriginOf(context), operation, method);

    /// <summary>The caller as a policy revision's actor.</summary>
    public ActorRef Actor(ServerCallContext context) => new()
    {
        Origin = sessions.OriginOf(context),
        ClientKind = sessions.SessionOf(context)?.Kind ?? ClientKind.Unspecified,
    };

    /// <summary>Runs <paramref name="execute"/> once per command ID (24 h); a replay returns the recorded response.</summary>
    public async Task<(TResponse Response, bool Replayed)> IdempotentAsync<TResponse>(IMessage request, RequestMeta meta, ServerCallContext context, string method,
        MessageParser<TResponse> parser, Func<ArcError, TResponse> fail, Func<CommandContext, TResponse> execute)
        where TResponse : class, IMessage<TResponse>
    {
        var digest = PayloadDigest.Compute(request);
        var origin = sessions.OriginOf(context);
        try
        {
            var outcome = await node.Processor.ExecuteIdempotentAsync(meta.CommandId.Value.Memory, service + "/" + method, digest, origin,
                command => execute(command).ToByteArray()).ConfigureAwait(false);
            return outcome.Error is { } failure ? (fail(failure), false) : (parser.ParseFrom(outcome.Outcome), outcome.Replayed);
        }
        catch (CommandQueueFullException)
        {
            return (fail(NodeErrors.Overloaded(node.Clock.GetUtcNow())), false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            node.Log.Error("api.command.failed", exception);
            return (fail(NodeErrors.Internal(node.Clock.GetUtcNow())), false);
        }
    }
}
