// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>arcforges.node.v1.NodeService</c> (node.proto): the client hello and compatibility, node information, health and
/// capabilities, rename, settings, stop, jobs and the notification centre. Mutations carry <c>meta.command_id</c> and are
/// deduplicated for 24 hours by the payload digest of their wire bytes (contracts README section 6). <c>WipeNode</c> is not served
/// by this build (its scope is a later task); the generated base answers <c>UNIMPLEMENTED</c>.
/// </summary>
public sealed class NodeServiceHandler : NodeService.NodeServiceBase
{
    private const string ServiceName = "arcforges.node.v1.NodeService";
    private readonly NodeRuntime _node;
    private readonly ClientSessions _sessions;

    /// <summary>Creates the service over the running node.</summary>
    public NodeServiceHandler(NodeRuntime node, ClientSessions sessions)
    {
        _node = node ?? throw new ArgumentNullException(nameof(node));
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    }

    /// <inheritdoc />
    public override Task<NodeServiceHelloResponse> Hello(NodeServiceHelloRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new NodeServiceHelloResponse { Meta = Meta(request.Meta) };
        if (Stopping() is { } stopping)
        {
            response.Error = stopping;
            return Task.FromResult(response);
        }

        var peer = context.GetLocalRpcPeer();
        if (Validation.Hello(request.Hello, peer) is { } invalid)
        {
            response.Error = invalid;
            _node.Log.Warning("api.hello.refused", new LogField("code", invalid.Code), new LogField("pid", peer?.ProcessId ?? 0));
            return Task.FromResult(response);
        }

        var hello = request.Hello;
        var origin = ClientSessions.AssignOrigin(hello);
        _sessions.Register(context, new ClientSession(peer!, hello.ClientKind, origin));
        var value = new NodeServiceHelloValue
        {
            Node = _node.Store.Read(_node.Info),
            AssignedOrigin = origin,
        };
        if (hello.ContractMinor > NodeContract.Minor)
        {
            value.Warnings.Add($"The client speaks node contract 1.{hello.ContractMinor}; this node speaks 1.{NodeContract.Minor}. Newer features are unavailable.");
        }

        response.Value = value;
        _node.Log.Debug("api.hello", new LogField("clientKind", hello.ClientKind), new LogField("origin", origin), new LogField("pid", peer!.ProcessId),
            new LogField("clientVersion", hello.ClientVersion));
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<NodeServiceGetNodeInfoResponse> GetNodeInfo(NodeServiceGetNodeInfoRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new NodeServiceGetNodeInfoResponse { Meta = Meta(request.Meta) };
        if (Stopping() is { } stopping)
        {
            response.Error = stopping;
        }
        else
        {
            response.Value = new NodeServiceGetNodeInfoValue { Node = _node.Store.Read(_node.Info) };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<NodeServiceGetHealthResponse> GetHealth(NodeServiceGetHealthRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        _node.CountCall();
        var value = new NodeServiceGetHealthValue { State = _node.Lifecycle.State };
        var recovery = _node.Recovery;
        value.Checks.Add(new DoctorCheck
        {
            CheckId = "node.store",
            Area = "node",
            Status = recovery.IntegrityCheck is null or "ok" ? CheckStatus.Pass : CheckStatus.Fail,
            Summary = recovery.IntegrityCheck is null
                ? "The store opened after a clean shutdown."
                : "The store passed its integrity check after an unclean shutdown.",
        });
        value.Checks.Add(new DoctorCheck
        {
            CheckId = "node.endpoint",
            Area = "node",
            Status = CheckStatus.Pass,
            Summary = "The node listens on its same-user endpoint.",
        });
        value.Checks.Add(new DoctorCheck
        {
            CheckId = "node.enforcement",
            Area = "enforcement",
            Status = NodeCapabilities.FullyEnforced(_node.Capabilities) ? CheckStatus.Pass : CheckStatus.Warn,
            Summary = NodeCapabilities.FullyEnforced(_node.Capabilities) ? "Resource limits are enforced." : "Resource limits are observed only: " + NodeCapabilities.NotInBuild + ".",
        });
        value.Metrics.Add(Gauge("node.uptime_seconds", (_node.Clock.GetUtcNow() - _node.StartedAt).TotalSeconds));
        value.Metrics.Add(Counter("node.rpc_calls", _node.RpcCalls));
        value.Metrics.Add(Counter("node.commands_executed", _node.Processor.Executed));
        value.Metrics.Add(Gauge("node.commands_queued", _node.Processor.Queued));
        value.Metrics.Add(Gauge("node.event_sequence", _node.Journal.Latest));
        value.Metrics.Add(Gauge("node.event_generation", _node.Journal.Generation));
        value.Metrics.Add(Gauge("node.stream_subscribers", _node.Hub.Count));
        value.Metrics.Add(Gauge("node.store_bytes", _node.StoreBytes()));
        value.Metrics.Add(Gauge("node.client_sessions", _sessions.Count));
        if (_node.ServerMetrics is { } server)
        {
            value.Metrics.Add(server());
        }

        return Task.FromResult(new NodeServiceGetHealthResponse { Meta = Meta(request.Meta), Value = value });
    }

    /// <inheritdoc />
    public override Task<NodeServiceGetCapabilitiesResponse> GetCapabilities(NodeServiceGetCapabilitiesRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new NodeServiceGetCapabilitiesResponse { Meta = Meta(request.Meta) };
        if (Stopping() is { } stopping)
        {
            response.Error = stopping;
        }
        else
        {
            var report = request.Reevaluate ? _node.Reevaluate() : _node.Capabilities;
            response.Value = new NodeServiceGetCapabilitiesValue { Capabilities = report };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<NodeServiceRenameNodeResponse> RenameNode(NodeServiceRenameNodeRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new NodeServiceRenameNodeResponse { Meta = Meta(request.Meta) };
        if ((Stopping() ?? Validation.CommandId(request.Meta) ?? (NodeName.IsValid(request.Name) ? null : NodeErrors.InvalidArgument("name: 1..64 chars; printable"))) is { } refused)
        {
            response.Error = refused;
            return response;
        }

        return await Idempotent(request, request.Meta, context, "RenameNode", NodeServiceRenameNodeResponse.Parser,
            failure => new NodeServiceRenameNodeResponse { Meta = Meta(request.Meta), Error = failure }, command =>
        {
            NodeName.Set(command.Transaction, request.Name);
            command.Emit(EventTopic.Node, new NodeEvent { Node = _node.Status("renamed") });
            return new NodeServiceRenameNodeResponse
            {
                Meta = Meta(request.Meta),
                Value = new NodeServiceRenameNodeValue { Node = _node.Info(command.Transaction) },
            };
        }).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override Task<NodeServiceGetNodeSettingsResponse> GetNodeSettings(NodeServiceGetNodeSettingsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new NodeServiceGetNodeSettingsResponse { Meta = Meta(request.Meta) };
        if (Stopping() is { } stopping)
        {
            response.Error = stopping;
        }
        else
        {
            var settings = _node.Settings.Current();
            response.Value = new NodeServiceGetNodeSettingsValue { Settings = settings };
            response.Meta.ResultRev = settings.Revision;
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<NodeServiceUpdateNodeSettingsResponse> UpdateNodeSettings(NodeServiceUpdateNodeSettingsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new NodeServiceUpdateNodeSettingsResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.CommandId(request.Meta);
        if (refused is null && request.HasLogLevel && !Enum.IsDefined(request.LogLevel))
        {
            refused = NodeErrors.InvalidArgument("log_level: a LogLevel value");
        }

        if (refused is null && request.HasTelemetryOptIn && _sessions.OriginOf(context) != Origin.Human)
        {
            // node.proto: telemetry_opt_in "validate: HUMAN only".
            refused = NodeErrors.PermissionDenied("UpdateNodeSettings.telemetry_opt_in (HUMAN only)");
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        long? expected = request.Meta.ExpectedRev is { HasValue: true } revision ? revision.Value : null;
        return await Idempotent(request, request.Meta, context, "UpdateNodeSettings", NodeServiceUpdateNodeSettingsResponse.Parser,
            failure => new NodeServiceUpdateNodeSettingsResponse { Meta = Meta(request.Meta), Error = failure }, _ =>
        {
            var (settings, restart, error) = _node.Settings.Update(expected, request.HasLogLevel ? request.LogLevel : LogLevel.Unspecified,
                request.HasTelemetryOptIn ? request.TelemetryOptIn : null);
            var result = new NodeServiceUpdateNodeSettingsResponse { Meta = Meta(request.Meta) };
            if (error is not null)
            {
                result.Error = error;
            }
            else
            {
                result.Value = new NodeServiceUpdateNodeSettingsValue { Settings = settings, RestartRequired = restart };
                result.Meta.ResultRev = settings!.Revision;
            }

            return result;
        }).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task<NodeServiceStopNodeResponse> StopNode(NodeServiceStopNodeRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new NodeServiceStopNodeResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.CommandId(request.Meta);
        if (refused is null && request.HasReason && request.Reason.Length > 200)
        {
            refused = NodeErrors.InvalidArgument("reason: <= 200 chars");
        }

        if (refused is null && request.HasTimeoutMs && request.TimeoutMs > 600_000)
        {
            refused = NodeErrors.InvalidArgument("timeout_ms: 0..600 s");
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var reason = request.HasReason && request.Reason.Length > 0 ? request.Reason : "stop requested";
        var result = await Idempotent(request, request.Meta, context, "StopNode", NodeServiceStopNodeResponse.Parser,
            failure => new NodeServiceStopNodeResponse { Meta = Meta(request.Meta), Error = failure }, command =>
        {
            if (!_node.Lifecycle.IsStopping)
            {
                _node.Lifecycle.MoveTo(NodeLifecycleState.Stopping, "stop_node");
                command.Emit(EventTopic.Node, new NodeEvent { Node = _node.Status("stop_node") });
            }

            return new NodeServiceStopNodeResponse
            {
                Meta = Meta(request.Meta),
                Value = new NodeServiceStopNodeValue
                {
                    Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
                },
            };
        }).ConfigureAwait(false);
        if (result.OutcomeCase == NodeServiceStopNodeResponse.OutcomeOneofCase.Value)
        {
            // The caller's free-text reason is not logged (it may carry anything); the log records that one was given and its length.
            _node.Log.Info("node.stop.requested", new LogField("origin", _sessions.OriginOf(context)), new LogField("reasonGiven", request.HasReason && request.Reason.Length > 0),
                new LogField("reasonLength", request.Reason.Length), new LogField("cancelRunning", request.CancelRunning));
            _node.RequestStop("stop_node");
        }

        return result;
    }

    /// <inheritdoc />
    public override Task<NodeServiceGetJobResponse> GetJob(NodeServiceGetJobRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new NodeServiceGetJobResponse { Meta = Meta(request.Meta) };
        if ((Stopping() ?? Validation.RequiredId(request.JobId, "job_id")) is { } refused)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var id = request.JobId.Value.ToByteArray();
        var job = _node.Store.Read(reader => Jobs.Get(reader, id));
        if (job is null)
        {
            response.Error = NodeErrors.NotFound("job", id);
        }
        else
        {
            response.Value = new NodeServiceGetJobValue { Job = job };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<NodeServiceListJobsResponse> ListJobs(NodeServiceListJobsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new NodeServiceListJobsResponse { Meta = Meta(request.Meta) };
        var invalidPage = Validation.Page(request.Page, 500, 100, out var limit, out var cursor);
        var refused = Stopping() ?? invalidPage;
        if (refused is null && (request.States.Distinct().Count() != request.States.Count || request.States.Any(state => state == JobState.Unspecified || !Enum.IsDefined(state))))
        {
            refused = NodeErrors.InvalidArgument("states: unique known values");
        }

        if (refused is not null)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var page = _node.Store.Read(reader => Jobs.List(reader, [.. request.States], cursor, limit));
        var value = new NodeServiceListJobsValue { Page = new PageState { HasMore = page.NextCursor is not null } };
        value.Jobs.Add(page.Items);
        if (page.NextCursor is { } next)
        {
            value.Page.NextCursor = next;
        }

        response.Value = value;
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<NodeServiceCancelJobResponse> CancelJob(NodeServiceCancelJobRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new NodeServiceCancelJobResponse { Meta = Meta(request.Meta) };
        if ((Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.JobId, "job_id")) is { } refused)
        {
            response.Error = refused;
            return response;
        }

        var id = request.JobId.Value.ToByteArray();
        return await Idempotent(request, request.Meta, context, "CancelJob", NodeServiceCancelJobResponse.Parser,
            failure => new NodeServiceCancelJobResponse { Meta = Meta(request.Meta), Error = failure }, command =>
        {
            var (job, error) = Jobs.Cancel(command, id);
            var result = new NodeServiceCancelJobResponse { Meta = Meta(request.Meta) };
            if (error is not null)
            {
                result.Error = error;
            }
            else
            {
                result.Value = new NodeServiceCancelJobValue { Job = job };
            }

            return result;
        }).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override Task<NodeServiceListNotificationsResponse> ListNotifications(NodeServiceListNotificationsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new NodeServiceListNotificationsResponse { Meta = Meta(request.Meta) };
        var invalidPage = Validation.Page(request.Page, 200, 50, out var limit, out var cursor);
        if ((Stopping() ?? invalidPage) is { } refused)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var page = _node.Store.Read(reader => Notifications.List(reader, request.UnreadOnly, cursor, limit));
        var value = new NodeServiceListNotificationsValue
        {
            Page = new PageState { HasMore = page.NextCursor is not null },
            UnreadCount = page.UnreadCount,
        };
        value.Notifications.Add(page.Items);
        if (page.NextCursor is { } next)
        {
            value.Page.NextCursor = next;
        }

        response.Value = value;
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<NodeServiceMarkNotificationsReadResponse> MarkNotificationsRead(NodeServiceMarkNotificationsReadRequest request,
        ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new NodeServiceMarkNotificationsReadResponse { Meta = Meta(request.Meta) };
        var refused = Stopping();
        if (refused is null && request.NotificationIds.Count > 500)
        {
            refused = NodeErrors.InvalidArgument("notification_ids: <= 500");
        }

        if (refused is null && request.NotificationIds.Any(id => id.Value.Length != 16))
        {
            refused = NodeErrors.InvalidArgument("notification_ids: 16-byte IDs");
        }

        long? upTo = null;
        if (refused is null && request.NotificationIds.Count == 0)
        {
            if (ProtoTime.ToDateTimeOffset(request.UpTo) is { } time)
            {
                upTo = StoreTime.ToMicroseconds(time);
            }
            else
            {
                refused = NodeErrors.InvalidArgument("up_to: required when notification_ids is empty");
            }
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        // Natural idempotency: marking read twice succeeds (node.proto), so no command record is needed.
        var ids = request.NotificationIds.Select(id => id.Value.ToByteArray()).ToList();
        var unread = await Run(() => _node.Processor.ExecuteAsync(command => Notifications.MarkRead(command, ids, upTo))).ConfigureAwait(false);
        if (unread.Error is { } failure)
        {
            response.Error = failure;
        }
        else
        {
            response.Value = new NodeServiceMarkNotificationsReadValue { UnreadCount = unread.Value };
        }

        return response;
    }

    private static ResponseMeta Meta(RequestMeta? request)
    {
        var meta = new ResponseMeta();
        if (request?.CorrelationId is { } correlation)
        {
            meta.CorrelationId = correlation;
        }

        return meta;
    }

    private static HealthMetric Gauge(string name, double value) => new() { Name = name, Kind = MetricKind.Gauge, Value = value };

    private static HealthMetric Counter(string name, double value) => new() { Name = name, Kind = MetricKind.Counter, Value = value };

    private ArcError? Stopping()
    {
        _node.CountCall();
        return _node.Lifecycle.IsStopping ? NodeErrors.NodeStopping(_node.Clock.GetUtcNow()) : null;
    }

    /// <summary>Runs a command and maps a full queue or an unexpected failure to an <c>ArcError</c>.</summary>
    private async Task<(T Value, ArcError? Error)> Run<T>(Func<Task<T>> command)
    {
        try
        {
            return (await command().ConfigureAwait(false), null);
        }
        catch (CommandQueueFullException)
        {
            return (default!, NodeErrors.Overloaded(_node.Clock.GetUtcNow()));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _node.Log.Error("api.command.failed", exception);
            return (default!, NodeErrors.Internal(_node.Clock.GetUtcNow()));
        }
    }

    /// <summary>
    /// Executes a mutation at most once per <c>meta.command_id</c>: the payload digest covers the request's top-level fields except
    /// <c>meta</c>, in wire order, so a retry must resend the same bytes. The response (value or error) is stored with the effects.
    /// </summary>
    private async Task<TResponse> Idempotent<TResponse>(Google.Protobuf.IMessage request, RequestMeta meta, ServerCallContext context, string method,
        Google.Protobuf.MessageParser<TResponse> parser, Func<ArcError, TResponse> fail, Func<CommandContext, TResponse> execute)
        where TResponse : class, Google.Protobuf.IMessage<TResponse>
    {
        var digest = PayloadDigest.Compute(request);
        var origin = _sessions.OriginOf(context);
        var (outcome, error) = await Run(() => _node.Processor.ExecuteIdempotentAsync(meta.CommandId.Value.Memory, ServiceName + "/" + method, digest, origin,
            command => Google.Protobuf.MessageExtensions.ToByteArray(execute(command)))).ConfigureAwait(false);
        if ((error ?? outcome.Error) is { } failure)
        {
            return fail(failure);
        }

        var response = parser.ParseFrom(outcome.Outcome);
        if (outcome.Replayed)
        {
            _node.Log.Debug("api.command.replayed", new LogField("method", method));
        }

        return response;
    }
}
