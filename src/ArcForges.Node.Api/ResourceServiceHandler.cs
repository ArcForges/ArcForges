// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using V2 = ArcForges.Contracts.Sandbox.V2;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>arcforges.node.v1.ResourceService</c> (resources.proto; architecture 03): <c>GetResourceSnapshot</c>, <c>WatchResources</c> (a
/// snapshot at once, then one per interval, with 15 s heartbeats when none was due), <c>ListProcesses</c> and <c>GetSamples</c>, built by
/// <see cref="ResourceViews"/>; <c>AdoptProcess</c> reconciles original adoption receipts. <c>TerminateProcess</c> (HUMAN A, SCRIPT and AGENT P)
/// ends only a same-user process the node manages, adopted, or classified (an attempt's member, an ESCAPED process, a leftover): never
/// an unrelated one, and always by process ID and start time, so a reused ID is never terminated. Termination is audited. The guest-link methods are
/// retired (AD-0018 section 3); the generated base answers them <c>UNIMPLEMENTED</c>.
/// </summary>
public sealed class ResourceServiceHandler : ResourceService.ResourceServiceBase
{
    private const string ServiceName = "arcforges.node.v1.ResourceService";

    /// <summary>How far a process's start time may differ from the one recorded or named (Linux reads it in clock ticks of 10 ms).</summary>
    private static readonly TimeSpan StartTolerance = TimeSpan.FromMilliseconds(20);

    private readonly NodeRuntime _node;
    private readonly ApiCommands _api;

    /// <summary>Creates the service over the running node.</summary>
    public ResourceServiceHandler(NodeRuntime node, ClientSessions sessions)
        : this(node, sessions, new ApprovalExecutors())
    {
    }

    /// <summary>Creates the service and registers how its approval-gated requests execute once approved.</summary>
    internal ResourceServiceHandler(NodeRuntime node, ClientSessions sessions, ApprovalExecutors executors)
    {
        ArgumentNullException.ThrowIfNull(executors);
        _node = node ?? throw new ArgumentNullException(nameof(node));
        _api = new ApiCommands(node, sessions ?? throw new ArgumentNullException(nameof(sessions)), ServiceName);
        executors.Register<ResourceServiceTerminateProcessRequest, ResourceServiceTerminateProcessResponse>("ResourceService.TerminateProcess",
            PermissionMatrix.ProcessTerminate, ResourceServiceTerminateProcessRequest.Parser, TerminateProcess);
        executors.RegisterRetained("ResourceService.AdoptProcess", PermissionMatrix.ProcessAdopt, ResourceServiceAdoptProcessRequest.Parser,
            ReconcileAdoption, response => response.Error);
    }

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

    /// <inheritdoc />
    public override Task<ResourceServiceAdoptProcessResponse> AdoptProcess(ResourceServiceAdoptProcessRequest request, ServerCallContext context) =>
        AdoptProcess(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary>Reconciles only the original adoption request for the caller or an approval's requester.</summary>
    internal Task<ResourceServiceAdoptProcessResponse> AdoptProcess(ResourceServiceAdoptProcessRequest request, Caller caller) =>
        Task.FromResult(ReconcileAdoption(request, caller).Response);

    private (ResourceServiceAdoptProcessResponse Response, bool Retained) ReconcileAdoption(ResourceServiceAdoptProcessRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        ResourceServiceAdoptProcessResponse Failed(ArcError error) => new() { Meta = ApiCommands.Meta(request.Meta), Error = error };
        if ((Stopping() ?? Validation.CommandId(request.Meta) ?? Identity(request.Process, out _, out _)) is { } refused)
        {
            return (Failed(refused), false);
        }

        var retained = _api.ReadRetained(request, request.Meta, caller, "AdoptProcess", ResourceServiceAdoptProcessResponse.Parser,
            Failed, NodeErrors.LegacyAdoptionUnknown());
        return retained.Retained && !ValidAdoptionOutcome(retained.Response, request.Meta.CommandId)
            ? (Failed(NodeErrors.LegacyAdoptionUnknown()), false)
            : retained;
    }

    private static bool ValidAdoptionOutcome(ResourceServiceAdoptProcessResponse response, Id commandId) =>
        NodeShapes.IsValid(response) && (response.Value is { TaskId.Value.Length: 16, Receipt: { HasEffect: true, Effect: EffectCertainty.Happened } receipt }
            && commandId.Equals(receipt.CommandId) || response.Error is
            { Code.Length: > 0, HasEffect: true, Effect: EffectCertainty.Happened or EffectCertainty.DidNotHappen or EffectCertainty.Unknown });

    /// <inheritdoc />
    public override Task<ResourceServiceTerminateProcessResponse> TerminateProcess(ResourceServiceTerminateProcessRequest request, ServerCallContext context) =>
        TerminateProcess(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>TerminateProcess</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<ResourceServiceTerminateProcessResponse> TerminateProcess(ResourceServiceTerminateProcessRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new ResourceServiceTerminateProcessResponse { Meta = ApiCommands.Meta(request.Meta) };
        var platform = _node.Execution?.Platform;
        var invalid = Identity(request.Process, out var pid, out var start);
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? invalid
            ?? (request.HasReason && request.Reason.Length > 500 ? NodeErrors.InvalidArgument("reason: <= 500 chars") : null)
            ?? (request.FindingId is { } finding && finding.Value.Length is not (0 or 16) ? NodeErrors.InvalidArgument("finding_id: a 16-byte ID") : null)
            ?? (platform is null ? NodeErrors.EnforcementUnavailable("no execution platform could be started on this node (see the node log)") : null);
        var target = refused is null ? Classify(pid, start) : null;
        if (refused is null && target is null)
        {
            // resources.proto: never unrelated processes.
            refused = NodeErrors.ProcessNotFound(string.Create(CultureInfo.InvariantCulture,
                $"process {pid}: not a process this node manages, adopted or classified (MANAGED, ADOPTED, ESCAPED or a leftover)"));
        }

        var gate = new GateRequest(PermissionMatrix.ProcessTerminate, "ResourceService.TerminateProcess",
            string.Create(CultureInfo.InvariantCulture, $"terminate {target?.Image ?? "process"} ({pid}, {target?.Label ?? "?"})")
                + (request.HasReason && request.Reason.Length > 0 ? ": " + request.Reason : string.Empty),
            "attempt", target?.AttemptId);
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var outcome = ProcessTermination.Failed;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "TerminateProcess", ResourceServiceTerminateProcessResponse.Parser,
            failure => new ResourceServiceTerminateProcessResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                outcome = platform!.TerminateProcess(pid, start);
                return outcome switch
                {
                    ProcessTermination.Terminated or ProcessTermination.Gone => new ResourceServiceTerminateProcessResponse
                    {
                        // resources.proto: a process already gone returns HAPPENED (the audit entry and the log say it was gone).
                        Meta = ApiCommands.Meta(request.Meta),
                        Value = new ResourceServiceTerminateProcessValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened } },
                    },
                    ProcessTermination.OtherUser => new ResourceServiceTerminateProcessResponse
                    {
                        Meta = ApiCommands.Meta(request.Meta),
                        Error = NodeErrors.PermissionDenied("ResourceService.TerminateProcess: the process runs as another user and is never terminated"),
                    },
                    _ => new ResourceServiceTerminateProcessResponse
                    {
                        Meta = ApiCommands.Meta(request.Meta),
                        Error = NodeErrors.PermissionDenied("ResourceService.TerminateProcess: the operating system refused to terminate the process"),
                    },
                };
            }, gate).ConfigureAwait(false);
        if (!replayed && result.OutcomeCase == ResourceServiceTerminateProcessResponse.OutcomeOneofCase.Value)
        {
            _node.Execution?.Adoptions.Wake();
            _node.Log.Info("api.process.terminated", new LogField("pid", pid), new LogField("label", target!.Label), new LogField("outcome", outcome),
                new LogField("origin", caller.Origin));
        }

        return result;
    }

    /// <summary>A process the node may terminate: its label, the attempt it belongs to or escaped from, and its image.</summary>
    private sealed record ProcessTarget(string Label, byte[]? AttemptId, string Image);

    /// <summary>
    /// What the node knows about the process (<paramref name="pid"/>, <paramref name="start"/>): a member of a running attempt's container
    /// (MANAGED), of an adoption container (ADOPTED), or a process the node recorded for an attempt (an ESCAPED process found by the ancestry
    /// scan, or another recorded process of an attempt, such as a leftover); or <see langword="null"/>.
    /// </summary>
    private ProcessTarget? Classify(int pid, DateTimeOffset start)
    {
        if (_node.Execution is not { } execution)
        {
            return null;
        }

        foreach (var attempt in execution.RunningAttempts)
        {
            try
            {
                if (attempt.Handle?.Processes().FirstOrDefault(process => process.Pid == pid) is { } member)
                {
                    return new ProcessTarget("MANAGED", attempt.AttemptId, member.Image);
                }
            }
            catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or IOException or InvalidOperationException or ObjectDisposedException)
            {
                _node.Log.Debug("api.process.classify_failed", new LogField("errorType", exception.GetType().Name));
            }
        }

        foreach (var adopted in execution.Adoptions.Tracked)
        {
            if (adopted.Container.Processes().Contains(pid))
            {
                return new ProcessTarget("ADOPTED", adopted.AttemptId, "adopted process");
            }
        }

        var micros = StoreTime.ToMicroseconds(start);
        var tolerance = (long)StartTolerance.TotalMicroseconds;
        return _node.Store.Read(reader =>
        {
            using var command = reader.CreateCommand(
                "SELECT attempt_id, executable, label FROM process_record WHERE pid = $pid AND start_at BETWEEN $from AND $to ORDER BY last_seen DESC LIMIT 1;");
            command.Parameters.AddWithValue("$pid", pid);
            command.Parameters.AddWithValue("$from", micros - tolerance);
            command.Parameters.AddWithValue("$to", micros + tolerance);
            using var rows = command.ExecuteReader();
            return rows.Read()
                ? new ProcessTarget((ProcessLabel)rows.GetInt32(2) == ProcessLabel.Escaped ? "ESCAPED" : "leftover", (byte[])rows.GetValue(0), rows.GetString(1))
                : null;
        });
    }

    /// <summary>common.proto <c>ProcessIdentity</c>: <c>pid</c> &gt; 0 and <c>start_time</c> required.</summary>
    private static ArcError? Identity(ProcessIdentity? process, out int pid, out DateTimeOffset start)
    {
        pid = 0;
        start = default;
        if (process is not { HasPid: true, Pid: > 0 and <= int.MaxValue } || ProtoTime.ToDateTimeOffset(process.StartTime) is not { } time)
        {
            return NodeErrors.InvalidArgument("process: required (pid > 0 and start_time)");
        }

        pid = (int)process.Pid;
        start = time;
        return null;
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
