// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// The restricted local FleetService proxy. It derives the caller and local session from the actual LocalRpc connection, signs a fresh
/// channel nonce over the original request bytes, and forwards only the eight AF-CTR-05 methods through the node's bound center transport.
/// All other FleetService methods retain the generated UNIMPLEMENTED implementation.
/// </summary>
internal sealed class FleetServiceHandler(NodeRuntime node, ClientSessions sessions, CloudLinkService cloud) : FleetService.FleetServiceBase
{
    private readonly ApiCommands _api = new(node, sessions, "FleetService");

    public override Task<FleetServiceListNodesResponse> ListNodes(FleetServiceListNodesRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        return ForwardAsync(context, request.Meta?.CorrelationId, RoutedMethod.ListNodes, null, null,
            caller =>
            {
                forwarded.Caller = caller;
                forwarded.ClearRelayAssertion();
                return SHA256.HashData(forwarded.ToByteArray());
            },
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.ListNodesAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null,
            error => new FleetServiceListNodesResponse { Meta = ApiCommands.Meta(request.Meta), Error = error });
    }

    public override Task<FleetServiceGetNodeResponse> GetNode(FleetServiceGetNodeRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        if (Validation.RequiredId(forwarded.NodeId, "node_id") is { } invalid)
        {
            return Task.FromResult(new FleetServiceGetNodeResponse { Meta = ApiCommands.Meta(request.Meta), Error = invalid });
        }

        return ForwardAsync(context, request.Meta?.CorrelationId, RoutedMethod.GetNode, forwarded.NodeId, null,
            caller =>
            {
                forwarded.Caller = caller;
                forwarded.ClearRelayAssertion();
                return SHA256.HashData(forwarded.ToByteArray());
            },
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.GetNodeAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null,
            error => new FleetServiceGetNodeResponse { Meta = ApiCommands.Meta(request.Meta), Error = error });
    }

    public override Task<FleetServiceSubmitNodeTaskResponse> SubmitNodeTask(FleetServiceSubmitNodeTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        var invalid = Validation.RequiredId(forwarded.NodeId, "node_id")
            ?? Payload(forwarded.HasRequest, forwarded.Request, 253952);
        Id? command = null;
        if (invalid is null)
        {
            try
            {
                command = TaskServiceSubmitTaskRequest.Parser.ParseFrom(forwarded.Request).Meta?.CommandId;
                invalid = Validation.CommandId(forwarded.Meta) ?? Validation.RequiredId(command, "request.meta.command_id");
                if (invalid is null && !command!.Equals(forwarded.Meta.CommandId))
                {
                    invalid = NodeErrors.InvalidArgument("meta.command_id must equal the inner request command_id");
                }
            }
            catch (InvalidProtocolBufferException)
            {
                invalid = NodeErrors.InvalidArgument("request: invalid node request bytes");
            }
        }
        if (invalid is null)
        {
            // A direct Fleet caller can bypass the CLI. Classify the original bytes before requesting a nonce or opening relay transport.
            invalid = RoutedEnvironmentGuard.Check(forwarded.Request, forwarded.NodeId.Value.Span.SequenceEqual(node.NodeId.Span),
                request.Meta?.CorrelationId, node.Clock, () =>
                {
                    var current = node.Store.Read(PolicyRules.Current);
                    if (!CryptographicOperations.FixedTimeEquals(current.Digest, PolicyDocuments.Digest(current.Document)))
                    {
                        throw new InvalidDataException("current policy digest mismatch");
                    }

                    return current.Document.Privacy?.SecretNamePatterns.ToArray() ?? [];
                });
        }
        if (invalid is not null)
        {
            return Task.FromResult(new FleetServiceSubmitNodeTaskResponse { Meta = ApiCommands.Meta(request.Meta), Error = invalid });
        }

        return ForwardAsync(context, request.Meta?.CorrelationId, RoutedMethod.SubmitNodeTask, forwarded.NodeId, command,
            _ => SHA256.HashData(forwarded.Request.Span),
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.SubmitNodeTaskAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null,
            error => new FleetServiceSubmitNodeTaskResponse { Meta = ApiCommands.Meta(request.Meta), Error = error });
    }

    public override Task<FleetServiceGetNodeTaskResponse> GetNodeTask(FleetServiceGetNodeTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        var invalid = Validation.RequiredId(forwarded.NodeId, "node_id")
            ?? Payload(forwarded.HasRequest, forwarded.Request, 3072);
        Id? command = null;
        if (invalid is not null)
        {
            return Task.FromResult(new FleetServiceGetNodeTaskResponse { Meta = ApiCommands.Meta(request.Meta), Error = invalid });
        }

        return ForwardAsync(context, request.Meta?.CorrelationId, RoutedMethod.GetNodeTask, forwarded.NodeId, command,
            _ => SHA256.HashData(forwarded.Request.Span),
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.GetNodeTaskAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null,
            error => new FleetServiceGetNodeTaskResponse { Meta = ApiCommands.Meta(request.Meta), Error = error });
    }

    public override Task<FleetServiceListNodeTasksResponse> ListNodeTasks(FleetServiceListNodeTasksRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        var invalid = Validation.RequiredId(forwarded.NodeId, "node_id")
            ?? Payload(forwarded.HasRequest, forwarded.Request, 3072);
        Id? command = null;
        if (invalid is not null)
        {
            return Task.FromResult(new FleetServiceListNodeTasksResponse { Meta = ApiCommands.Meta(request.Meta), Error = invalid });
        }

        return ForwardAsync(context, request.Meta?.CorrelationId, RoutedMethod.ListNodeTasks, forwarded.NodeId, command,
            _ => SHA256.HashData(forwarded.Request.Span),
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.ListNodeTasksAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null,
            error => new FleetServiceListNodeTasksResponse { Meta = ApiCommands.Meta(request.Meta), Error = error });
    }

    public override Task<FleetServiceWaitNodeTaskResponse> WaitNodeTask(FleetServiceWaitNodeTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        var invalid = Validation.RequiredId(forwarded.NodeId, "node_id")
            ?? Payload(forwarded.HasRequest, forwarded.Request, 3072);
        Id? command = null;
        if (invalid is not null)
        {
            return Task.FromResult(new FleetServiceWaitNodeTaskResponse { Meta = ApiCommands.Meta(request.Meta), Error = invalid });
        }

        return ForwardAsync(context, request.Meta?.CorrelationId, RoutedMethod.WaitNodeTask, forwarded.NodeId, command,
            _ => SHA256.HashData(forwarded.Request.Span),
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.WaitNodeTaskAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null,
            error => new FleetServiceWaitNodeTaskResponse { Meta = ApiCommands.Meta(request.Meta), Error = error });
    }

    public override Task<FleetServiceReadNodeTaskOutputResponse> ReadNodeTaskOutput(FleetServiceReadNodeTaskOutputRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        var invalid = Validation.RequiredId(forwarded.NodeId, "node_id")
            ?? Payload(forwarded.HasRequest, forwarded.Request, 3072);
        Id? command = null;
        if (invalid is not null)
        {
            return Task.FromResult(new FleetServiceReadNodeTaskOutputResponse { Meta = ApiCommands.Meta(request.Meta), Error = invalid });
        }

        return ForwardAsync(context, request.Meta?.CorrelationId, RoutedMethod.ReadNodeTaskOutput, forwarded.NodeId, command,
            _ => SHA256.HashData(forwarded.Request.Span),
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.ReadNodeTaskOutputAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null,
            error => new FleetServiceReadNodeTaskOutputResponse { Meta = ApiCommands.Meta(request.Meta), Error = error });
    }

    public override Task<FleetServiceCancelNodeTaskResponse> CancelNodeTask(FleetServiceCancelNodeTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var forwarded = request.Clone();
        var invalid = Validation.RequiredId(forwarded.NodeId, "node_id")
            ?? Payload(forwarded.HasRequest, forwarded.Request, 3072);
        Id? command = null;
        if (invalid is null)
        {
            try
            {
                command = TaskServiceCancelTaskRequest.Parser.ParseFrom(forwarded.Request).Meta?.CommandId;
                invalid = Validation.CommandId(forwarded.Meta) ?? Validation.RequiredId(command, "request.meta.command_id");
                if (invalid is null && !command!.Equals(forwarded.Meta.CommandId))
                {
                    invalid = NodeErrors.InvalidArgument("meta.command_id must equal the inner request command_id");
                }
            }
            catch (InvalidProtocolBufferException)
            {
                invalid = NodeErrors.InvalidArgument("request: invalid node request bytes");
            }
        }
        if (invalid is not null)
        {
            return Task.FromResult(new FleetServiceCancelNodeTaskResponse { Meta = ApiCommands.Meta(request.Meta), Error = invalid });
        }

        return ForwardAsync(context, request.Meta?.CorrelationId, RoutedMethod.CancelNodeTask, forwarded.NodeId, command,
            _ => SHA256.HashData(forwarded.Request.Span),
            (caller, assertion, client, options) =>
            {
                forwarded.Caller = caller;
                forwarded.RelayAssertion = assertion;
                return client.CancelNodeTaskAsync(forwarded, options).ResponseAsync;
            }, answer => answer.Error, answer => answer.Value is not null,
            error => new FleetServiceCancelNodeTaskResponse { Meta = ApiCommands.Meta(request.Meta), Error = error });
    }

    private static ArcError? Payload(bool present, ByteString bytes, int maximum) =>
        !present || bytes.Length == 0 || bytes.Length > maximum ? NodeErrors.InvalidArgument("request: required within the routed size limit") : null;

    private async Task<T> ForwardAsync<T>(ServerCallContext context, Id? correlation, RoutedMethod method, Id? target, Id? command,
        Func<RoutedCaller, byte[]> digest, Func<RoutedCaller, ByteString, FleetService.FleetServiceClient, CallOptions, Task<T>> send,
        Func<T, ArcError?> errorOf, Func<T, bool> hasValue, Func<ArcError, T> fail)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(context);
        if (_api.Stopping() is { } stopping)
        {
            return fail(stopping);
        }

        var origin = sessions.OriginOf(context);
        if (origin == Origin.Agent && target is not null && !target.Value.Span.SequenceEqual(node.NodeId.Span))
        {
            return fail(NodeErrors.PermissionDenied("relayed_agent_own_node_only"));
        }

        if (!cloud.AccountLinked)
        {
            return fail(NodeErrors.NotSignedIn());
        }

        var caller = new RoutedCaller
        {
            Kind = CallerKind.NodeRelay,
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(node.NodeId.Span) },
            LocalOrigin = origin,
        };
        var localSession = sessions.RelaySessionIdOf(context);
        var requestDigest = digest(caller);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var signed = await cloud.SignBoundRelayAssertionAsync(origin, localSession, method, requestDigest, target, command, context.CancellationToken)
                .ConfigureAwait(false);
            if (signed is null)
            {
                return fail(Unavailable(cloud.AccountLinked ? "channel_not_connected" : "signed_out", correlation));
            }

            var left = context.Deadline - DateTime.UtcNow;
            if (left <= TimeSpan.Zero)
            {
                throw new RpcException(new Status(StatusCode.DeadlineExceeded, "local deadline exceeded"));
            }

            var maximum = method == RoutedMethod.WaitNodeTask ? TimeSpan.FromSeconds(55) :
                method == RoutedMethod.ReadNodeTaskOutput ? TimeSpan.FromSeconds(30) : TimeSpan.FromSeconds(10);
            var answer = await cloud.ForwardRelayAsync(signed,
                (client, options) => send(caller, signed.Assertion.ToByteString(), client, options), left < maximum ? left : maximum, context.CancellationToken)
                .ConfigureAwait(false);
            if (answer.Outcome == CenterOutcome.Value && answer.Value is { } response)
            {
                var error = errorOf(response);
                if (attempt == 0 && error is { Category: ErrorCategory.Authentication, Code: "unauthenticated" }
                    && error.Details?.State?.State == "relay_assertion" && error.Details.State.Reason is "expired" or "nonce_reused")
                {
                    // The center rejected this assertion before routing. The next iteration signs the same request with a fresh nonce.
                    continue;
                }

                if (error is null && !hasValue(response))
                {
                    var malformed = NodeErrors.Internal(node.Clock.GetUtcNow());
                    malformed.Retry.Mode = RetryMode.Never;
                    return fail(malformed);
                }

                return response;
            }

            context.CancellationToken.ThrowIfCancellationRequested();
            if (answer.Outcome == CenterOutcome.Unreachable && answer.MaybeApplied && command is not null)
            {
                // A center transport failure after send has no reliable effect verdict. Preserve it as a transport failure: the CLI can
                // retry the identical command and bytes and must not claim that nothing was submitted.
                throw new RpcException(new Status(StatusCode.Unavailable, "center reply lost; command outcome unknown"));
            }

            if (answer.Outcome == CenterOutcome.Transport)
            {
                return fail(new ArcError
                {
                    Category = ErrorCategory.Authentication,
                    Code = "unauthenticated",
                    MessageKey = "error.authentication.unauthenticated",
                    Retry = new RetryAdvice { Mode = RetryMode.Never },
                    Effect = EffectCertainty.DidNotHappen,
                    Details = new ErrorDetails { State = new StateFailure { State = "node_credential", Reason = "center_refused" } },
                });
            }

            if (answer.Outcome == CenterOutcome.ProtocolMismatch)
            {
                var internalError = NodeErrors.Internal(node.Clock.GetUtcNow());
                internalError.Retry.Mode = RetryMode.Never;
                return fail(internalError);
            }

            return fail(Unavailable("center_unreachable", correlation));
        }

        return fail(Unavailable("channel_not_connected", correlation));
    }

    private ArcError Unavailable(string reason, Id? correlation)
    {
        // This path has not sent a mutation (or has a definite pre-handler refusal). Keep the catalogue's complete retry/effect pair,
        // state details and correlation; a potentially applied mutation is returned above as an uncertain transport failure instead.
        var error = NodeErrors.CloudUnreachable(reason);
        error.CorrelationId = Validation.RequiredId(correlation, "correlation_id") is null ? correlation!.Clone() : CommandIds.New(node.Clock);
        error.Details.State.State = "cloud_link";
        error.Retry.Mode = RetryMode.AfterTime;
        error.Retry.RetryAt = ProtoTime.ToInstant(node.Clock.GetUtcNow().AddSeconds(2));
        return error;
    }
}
