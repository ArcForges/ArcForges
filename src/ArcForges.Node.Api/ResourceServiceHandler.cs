// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>arcforges.node.v1.ResourceService</c> (resources.proto; architecture 03): <c>GetResourceSnapshot</c>, <c>WatchResources</c> (a
/// snapshot at once, then one per interval, with 15 s heartbeats when none was due), <c>ListProcesses</c> and <c>GetSamples</c>, built by
/// <see cref="ResourceViews"/>; <c>AdoptProcess</c> (04 section 10; HUMAN only) and <c>TerminateProcess</c> (HUMAN A, SCRIPT and AGENT P),
/// which ends only a same-user process the node manages, adopted, or classified (an attempt's member, an ESCAPED process, a leftover): never
/// an unrelated one, and always by process ID and start time, so a reused ID is never terminated. Both are audited. The guest-link methods are
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
        executors.Register<ResourceServiceAdoptProcessRequest, ResourceServiceAdoptProcessResponse>("ResourceService.AdoptProcess",
            PermissionMatrix.ProcessAdopt, ResourceServiceAdoptProcessRequest.Parser, AdoptProcess);
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

    /// <summary><c>AdoptProcess</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<ResourceServiceAdoptProcessResponse> AdoptProcess(ResourceServiceAdoptProcessRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new ResourceServiceAdoptProcessResponse { Meta = ApiCommands.Meta(request.Meta) };
        var execution = _node.Execution;
        var pool = request.HasPool && request.Pool.Length > 0 ? request.Pool : "default";
        var invalid = Identity(request.Process, out var pid, out var start);
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? invalid
            ?? (request.HasTitle && request.Title.Length > 200 ? NodeErrors.InvalidArgument("title: <= 200 chars") : null)
            ?? (execution is null ? NodeErrors.EnforcementUnavailable("no execution platform could be started on this node (see the node log)") : null)
            ?? (execution is not null && !execution.Settings.Pools.Contains(pool, StringComparer.Ordinal) ? NodeErrors.InvalidArgument("pool: an existing pool") : null);
        var gate = new GateRequest(PermissionMatrix.ProcessAdopt, "ResourceService.AdoptProcess",
            "adopt process " + pid.ToString(CultureInfo.InvariantCulture) + (request.HasTitle ? " (" + request.Title + ")" : string.Empty), "process");
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        // Review round 1: the platform's adoption (D-Bus and a job wait, or job assignment) runs outside the store writer, then the result is
        // recorded in the command. A command that already ran replays its outcome without adopting again.
        PreparedAdoption? prepared = null;
        if (_api.Recorded(gate.Method, request, request.Meta))
        {
            _api.MarkReplayOnly(request.Meta);
        }
        else
        {
            try
            {
                prepared = await Task.Run(() => execution!.Adoptions.Prepare(pid, start, request.HasTitle ? request.Title : null, pool)).ConfigureAwait(false);
            }
            catch (AdoptionRefusedException refusal)
            {
                var error = refusal.NotFound ? NodeErrors.ProcessNotFound(refusal.Message)
                    : refusal.AlreadyManaged ? NodeErrors.AlreadyExists("process", pid.ToString(CultureInfo.InvariantCulture))
                    : NodeErrors.AdoptNotPermitted(refusal.Message);
                await _api.AuditAsync(caller, gate, PermissionDecision.Allow, $"failed ({error.Category}/{error.Code}): {gate.Summary}: {refusal.Message}").ConfigureAwait(false);
                response.Error = error;
                return response;
            }
        }

        var recorded = false;
        var (result, _) = await _api.IdempotentAsync(request, request.Meta, caller, "AdoptProcess", ResourceServiceAdoptProcessResponse.Parser,
            failure => new ResourceServiceAdoptProcessResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                if (prepared is null)
                {
                    // The recorded outcome expired between the check and the command: nothing was adopted for this request now.
                    return new ResourceServiceAdoptProcessResponse { Meta = ApiCommands.Meta(request.Meta), Error = NodeErrors.Internal(_node.Clock.GetUtcNow()) };
                }

                var outcome = execution!.Adoptions.Record(command, prepared, caller.Actor);
                recorded = true;
                return new ResourceServiceAdoptProcessResponse
                {
                    Meta = ApiCommands.Meta(request.Meta),
                    Value = new ResourceServiceAdoptProcessValue
                    {
                        Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
                        TaskId = new Id { Value = ByteString.CopyFrom(outcome.TaskId) },
                        AdoptedChildren = (uint)outcome.AdoptedChildren,
                        FailedChildren = (uint)outcome.FailedChildren,
                    },
                };
            }, gate).ConfigureAwait(false);
        if (prepared is not null && !recorded)
        {
            // Review round 2: the platform placed the process, but the node could not record it. Nothing is terminated; the outcome is
            // reported and audited as it is.
            var released = Adoptions.Release(prepared);
            _node.Log.Warning("api.adoption.not_recorded", new LogField("pid", pid), new LogField("container", prepared.Result.Container.ContainerName),
                new LogField("outcome", released));
            await _api.AuditAsync(caller, gate, PermissionDecision.Allow, "failed: not recorded: " + gate.Summary + ": " + released).ConfigureAwait(false);
            if (result.OutcomeCase == ResourceServiceAdoptProcessResponse.OutcomeOneofCase.Error && result.Error.Details?.State is { } state)
            {
                state.Reason = string.IsNullOrEmpty(state.Reason) ? released : state.Reason + "; " + released;
            }
            else if (result.OutcomeCase == ResourceServiceAdoptProcessResponse.OutcomeOneofCase.Error)
            {
                result.Error.Details = new ErrorDetails { State = new StateFailure { Reason = released } };
            }
        }

        return result;
    }

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
