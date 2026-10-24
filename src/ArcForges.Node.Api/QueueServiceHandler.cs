// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>arcforges.node.v1.QueueService</c> (queue.proto; architecture 03 section 4): the queue in admission order with the budget summary,
/// <c>ExplainTask</c> (blocking reason, feasibility, the numbers, keys and their holders, dependencies), pools and their mutations as
/// policy revisions, pausing pools, and <c>SetParallelism</c> (R-EXE-013). The admission order and the reasons come from the scheduler's
/// last pass (<see cref="ExecutionSupervisor.Queue"/>); pool, policy and parallelism changes wake admission at once.
/// </summary>
public sealed class QueueServiceHandler : QueueService.QueueServiceBase
{
    private const string ServiceName = "arcforges.node.v1.QueueService";
    private readonly NodeRuntime _node;
    private readonly ApiCommands _api;

    /// <summary>Creates the service over the running node.</summary>
    public QueueServiceHandler(NodeRuntime node, ClientSessions sessions)
        : this(node, sessions, new ApprovalExecutors())
    {
    }

    /// <summary>Creates the service and registers how its approval-gated requests execute once approved.</summary>
    internal QueueServiceHandler(NodeRuntime node, ClientSessions sessions, ApprovalExecutors executors)
    {
        ArgumentNullException.ThrowIfNull(executors);
        _node = node ?? throw new ArgumentNullException(nameof(node));
        _api = new ApiCommands(node, sessions ?? throw new ArgumentNullException(nameof(sessions)), ServiceName);
        executors.Register<QueueServiceCreatePoolRequest, QueueServiceCreatePoolResponse>("QueueService.CreatePool", PermissionMatrix.PolicyChange,
            QueueServiceCreatePoolRequest.Parser, CreatePool);
        executors.Register<QueueServiceUpdatePoolRequest, QueueServiceUpdatePoolResponse>("QueueService.UpdatePool", PermissionMatrix.PolicyChange,
            QueueServiceUpdatePoolRequest.Parser, UpdatePool);
        executors.Register<QueueServiceDeletePoolRequest, QueueServiceDeletePoolResponse>("QueueService.DeletePool", PermissionMatrix.PolicyChange,
            QueueServiceDeletePoolRequest.Parser, DeletePool);
        executors.Register<QueueServicePausePoolRequest, QueueServicePausePoolResponse>("QueueService.PausePool", PermissionMatrix.PoolPause,
            QueueServicePausePoolRequest.Parser, PausePool);
        executors.Register<QueueServiceResumePoolRequest, QueueServiceResumePoolResponse>("QueueService.ResumePool", PermissionMatrix.PoolPause,
            QueueServiceResumePoolRequest.Parser, ResumePool);
        executors.Register<QueueServiceSetParallelismRequest, QueueServiceSetParallelismResponse>("QueueService.SetParallelism", PermissionMatrix.ParallelismChange,
            QueueServiceSetParallelismRequest.Parser, SetParallelism);
    }

    private ExecutionSupervisor Execution => _node.Execution ?? throw new InvalidOperationException("The node has no execution supervisor.");

    /// <inheritdoc />
    public override Task<QueueServiceGetQueueResponse> GetQueue(QueueServiceGetQueueRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new QueueServiceGetQueueResponse { Meta = ApiCommands.Meta(request.Meta) };
        var settings = Execution.Settings;
        var refused = _api.Stopping();
        if (refused is null && request.HasPool && !settings.PoolPolicies.Any(pool => pool.Name == request.Pool))
        {
            refused = NodeErrors.NotFound("pool", request.Pool);
        }

        if (refused is not null)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var snapshot = Snapshot();
        var value = new QueueServiceGetQueueValue { Budget = Budget(snapshot, settings) };
        value.Pools.Add(Pools(snapshot, settings));
        foreach (var name in snapshot.Result.Order)
        {
            if (!snapshot.Tasks.TryGetValue(name, out var view) || (request.HasPool && view.Pool != request.Pool) || !IsQueued(view.TaskId))
            {
                continue;
            }

            var verdict = snapshot.Result.Waiting.GetValueOrDefault(name);
            var entry = new QueueEntry
            {
                TaskId = new Id { Value = ByteString.CopyFrom(view.TaskId) },
                Title = view.Title,
                Pool = view.Pool,
                EffectivePriority = view.Effective,
                Owner = view.Owner,
                Queue = new QueueInfo
                {
                    Position = (uint)(verdict?.Position ?? 0),
                    BlockingReason = verdict?.Reason ?? "admitted",
                    WaitedMs = (ulong)Math.Max(0, (StoreTime.ToMicroseconds(_node.Clock.GetUtcNow()) - view.QueuedAt) / 1000),
                },
                Request = view.Request,
                ReservedForLarge = snapshot.Result.Reservation?.Task == name,
                Aged = view.Aged,
            };
            value.Entries.Add(entry);
        }

        response.Value = value;
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<QueueServiceExplainTaskResponse> ExplainTask(QueueServiceExplainTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new QueueServiceExplainTaskResponse { Meta = ApiCommands.Meta(request.Meta) };
        if ((_api.Stopping() ?? Validation.RequiredId(request.TaskId, "task_id")) is { } refused)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var id = request.TaskId.Value.ToByteArray();
        var explanation = _node.Store.Read(reader => Explain(reader, id));
        if (explanation is null)
        {
            response.Error = NodeErrors.NotFound("task", id);
        }
        else
        {
            response.Value = new QueueServiceExplainTaskValue { Explanation = explanation };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<QueueServiceListPoolsResponse> ListPools(QueueServiceListPoolsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new QueueServiceListPoolsResponse { Meta = ApiCommands.Meta(request.Meta) };
        if (_api.Stopping() is { } refused)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var value = new QueueServiceListPoolsValue();
        value.Pools.Add(Pools(Snapshot(), Execution.Settings));
        response.Value = value;
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<QueueServiceCreatePoolResponse> CreatePool(QueueServiceCreatePoolRequest request, ServerCallContext context) =>
        CreatePool(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>CreatePool</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<QueueServiceCreatePoolResponse> CreatePool(QueueServiceCreatePoolRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new QueueServiceCreatePoolResponse { Meta = ApiCommands.Meta(request.Meta) };
        var gate = new GateRequest(PermissionMatrix.PolicyChange, "QueueService.CreatePool", $"create pool '{request.Name}'", "pool");
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta)
            ?? PoolFields(request.HasName, request.Name, request.HasWeight, request.Weight, request.HasMaxParallelMode, request.MaxParallelMode, request.HasMaxParallelFixed,
                request.MaxParallelFixed, request.HasDefaultPriority, request.DefaultPriority, nameRequired: true);
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var actor = caller.Actor;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "CreatePool", QueueServiceCreatePoolResponse.Parser,
            failure => new QueueServiceCreatePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                var current = PolicyRules.Current(command.Transaction);
                var document = WithPools(current.Document);
                if (document.Pools.Any(pool => pool.Name == request.Name))
                {
                    return new QueueServiceCreatePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = NodeErrors.AlreadyExists("pool", request.Name) };
                }

                var pool = new PoolPolicy
                {
                    Name = request.Name,
                    Weight = request.HasWeight ? request.Weight : 1,
                    MaxParallelMode = request.HasMaxParallelMode ? request.MaxParallelMode : ParallelismMode.Auto,
                    BuiltIn = false,
                };
                if (pool.MaxParallelMode == ParallelismMode.Fixed)
                {
                    pool.MaxParallelFixed = request.MaxParallelFixed;
                }

                if (request.HasDefaultPriority)
                {
                    pool.DefaultPriority = request.DefaultPriority;
                }

                document.Pools.Add(pool);
                var (row, error) = Write(command, document, actor, $"create pool '{request.Name}'");
                return error is not null
                    ? new QueueServiceCreatePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = error }
                    : new QueueServiceCreatePoolResponse
                    {
                        Meta = ApiCommands.Meta(request.Meta),
                        Value = new QueueServiceCreatePoolValue { Pool = PoolView(pool, null, Execution.Settings), PolicyRevision = new Revision { Value = row!.Revision } },
                    };
            }, gate).ConfigureAwait(false);
        Changed(result.OutcomeCase == QueueServiceCreatePoolResponse.OutcomeOneofCase.Value && !replayed);
        return result;
    }

    /// <inheritdoc />
    public override Task<QueueServiceUpdatePoolResponse> UpdatePool(QueueServiceUpdatePoolRequest request, ServerCallContext context) =>
        UpdatePool(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>UpdatePool</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<QueueServiceUpdatePoolResponse> UpdatePool(QueueServiceUpdatePoolRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new QueueServiceUpdatePoolResponse { Meta = ApiCommands.Meta(request.Meta) };
        var gate = new GateRequest(PermissionMatrix.PolicyChange, "QueueService.UpdatePool", $"update pool '{request.Name}'", "pool");
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta)
            ?? PoolFields(request.HasName, request.Name, request.HasWeight, request.Weight, request.HasMaxParallelMode, request.MaxParallelMode, request.HasMaxParallelFixed,
                request.MaxParallelFixed, request.HasDefaultPriority, request.DefaultPriority, nameRequired: true);
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var actor = caller.Actor;
        long? expected = request.Meta.ExpectedRev is { HasValue: true } revision ? revision.Value : null;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "UpdatePool", QueueServiceUpdatePoolResponse.Parser,
            failure => new QueueServiceUpdatePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                var current = PolicyRules.Current(command.Transaction);
                if (expected is { } rev && rev != current.Revision)
                {
                    return new QueueServiceUpdatePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = NodeErrors.RevisionConflict(rev, current.Revision) };
                }

                var document = WithPools(current.Document);
                if (document.Pools.FirstOrDefault(candidate => candidate.Name == request.Name) is not { } pool)
                {
                    return new QueueServiceUpdatePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = NodeErrors.NotFound("pool", request.Name) };
                }

                if (request.HasWeight)
                {
                    pool.Weight = request.Weight;
                }

                if (request.HasMaxParallelMode)
                {
                    pool.MaxParallelMode = request.MaxParallelMode;
                    pool.ClearMaxParallelFixed();
                }

                if (request.HasMaxParallelFixed)
                {
                    pool.MaxParallelFixed = request.MaxParallelFixed;
                }

                if (request.HasDefaultPriority)
                {
                    pool.DefaultPriority = request.DefaultPriority;
                }

                var (row, error) = Write(command, document, actor, $"update pool '{request.Name}'");
                return error is not null
                    ? new QueueServiceUpdatePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = error }
                    : new QueueServiceUpdatePoolResponse
                    {
                        Meta = ApiCommands.Meta(request.Meta),
                        Value = new QueueServiceUpdatePoolValue { Pool = PoolView(pool, null, Execution.Settings), PolicyRevision = new Revision { Value = row!.Revision } },
                    };
            }, gate).ConfigureAwait(false);
        Changed(result.OutcomeCase == QueueServiceUpdatePoolResponse.OutcomeOneofCase.Value && !replayed);
        return result;
    }

    /// <inheritdoc />
    public override Task<QueueServiceDeletePoolResponse> DeletePool(QueueServiceDeletePoolRequest request, ServerCallContext context) =>
        DeletePool(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>DeletePool</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<QueueServiceDeletePoolResponse> DeletePool(QueueServiceDeletePoolRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new QueueServiceDeletePoolResponse { Meta = ApiCommands.Meta(request.Meta) };
        var gate = new GateRequest(PermissionMatrix.PolicyChange, "QueueService.DeletePool", $"delete pool '{request.Name}'", "pool");
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta)
            ?? (request.HasName && request.Name.Length > 0 ? null : NodeErrors.InvalidArgument("name: required"));
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var actor = caller.Actor;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "DeletePool", QueueServiceDeletePoolResponse.Parser,
            failure => new QueueServiceDeletePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                var current = PolicyRules.Current(command.Transaction);
                var document = WithPools(current.Document);
                ArcError? error = null;
                if (document.Pools.FirstOrDefault(candidate => candidate.Name == request.Name) is not { } pool)
                {
                    error = NodeErrors.NotFound("pool", request.Name);
                }
                else if (pool.BuiltIn || DefaultPolicy.BuiltInPools.Contains(pool.Name))
                {
                    error = NodeErrors.InvalidState("BUILT_IN", $"the built-in pool '{pool.Name}' cannot be deleted");
                }
                else if (Convert.ToInt64(command.Transaction.Scalar("SELECT count(*) FROM task WHERE pool = $pool AND state BETWEEN 1 AND 6;", ("$pool", pool.Name)),
                    CultureInfo.InvariantCulture) is var live and > 0)
                {
                    error = NodeErrors.InUse(string.Create(CultureInfo.InvariantCulture, $"{live} queued or running task(s) in pool '{pool.Name}'"));
                }
                else
                {
                    document.Pools.Remove(pool);
                    var rules = document.Parallelism.Where(rule => rule.Scope == ParallelismScope.Pool && rule.Target == pool.Name).ToList();
                    foreach (var rule in rules)
                    {
                        document.Parallelism.Remove(rule);
                    }
                }

                if (error is not null)
                {
                    return new QueueServiceDeletePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = error };
                }

                var (row, writeError) = Write(command, document, actor, $"delete pool '{request.Name}'");
                return writeError is not null
                    ? new QueueServiceDeletePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = writeError }
                    : new QueueServiceDeletePoolResponse
                    {
                        Meta = ApiCommands.Meta(request.Meta),
                        Value = new QueueServiceDeletePoolValue { PolicyRevision = new Revision { Value = row!.Revision } },
                    };
            }, gate).ConfigureAwait(false);
        Changed(result.OutcomeCase == QueueServiceDeletePoolResponse.OutcomeOneofCase.Value && !replayed);
        return result;
    }

    /// <inheritdoc />
    public override Task<QueueServicePausePoolResponse> PausePool(QueueServicePausePoolRequest request, ServerCallContext context) =>
        PausePool(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>PausePool</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<QueueServicePausePoolResponse> PausePool(QueueServicePausePoolRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new QueueServicePausePoolResponse { Meta = ApiCommands.Meta(request.Meta) };
        var gate = new GateRequest(PermissionMatrix.PoolPause, "QueueService.PausePool", request.All ? "pause every pool" : $"pause pool '{request.Pool}'", "pool");
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta) ?? PoolTarget(request.HasPool ? request.Pool : null, request.All);
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "PausePool", QueueServicePausePoolResponse.Parser,
            failure => new QueueServicePausePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                Execution.SetPoolPaused(command, request.All ? null : request.Pool, paused: true);
                return new QueueServicePausePoolResponse
                {
                    Meta = ApiCommands.Meta(request.Meta),
                    Value = new QueueServicePausePoolValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened } },
                };
            }, gate).ConfigureAwait(false);
        if (!replayed && result.OutcomeCase == QueueServicePausePoolResponse.OutcomeOneofCase.Value)
        {
            Execution.PoolsChanged();
            _node.Log.Info("api.queue.paused", new LogField("pool", request.All ? "*" : request.Pool), new LogField("origin", caller.Origin));
        }

        return result;
    }

    /// <inheritdoc />
    public override Task<QueueServiceResumePoolResponse> ResumePool(QueueServiceResumePoolRequest request, ServerCallContext context) =>
        ResumePool(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>ResumePool</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<QueueServiceResumePoolResponse> ResumePool(QueueServiceResumePoolRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new QueueServiceResumePoolResponse { Meta = ApiCommands.Meta(request.Meta) };
        var gate = new GateRequest(PermissionMatrix.PoolPause, "QueueService.ResumePool", request.All ? "resume every pool" : $"resume pool '{request.Pool}'", "pool");
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta) ?? PoolTarget(request.HasPool ? request.Pool : null, request.All);
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "ResumePool", QueueServiceResumePoolResponse.Parser,
            failure => new QueueServiceResumePoolResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                Execution.SetPoolPaused(command, request.All ? null : request.Pool, paused: false);
                return new QueueServiceResumePoolResponse
                {
                    Meta = ApiCommands.Meta(request.Meta),
                    Value = new QueueServiceResumePoolValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened } },
                };
            }, gate).ConfigureAwait(false);
        if (!replayed && result.OutcomeCase == QueueServiceResumePoolResponse.OutcomeOneofCase.Value)
        {
            Execution.PoolsChanged();
        }

        return result;
    }

    /// <inheritdoc />
    public override Task<QueueServiceSetParallelismResponse> SetParallelism(QueueServiceSetParallelismRequest request, ServerCallContext context) =>
        SetParallelism(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>SetParallelism</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<QueueServiceSetParallelismResponse> SetParallelism(QueueServiceSetParallelismRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new QueueServiceSetParallelismResponse { Meta = ApiCommands.Meta(request.Meta) };
        var gate = new GateRequest(PermissionMatrix.ParallelismChange, "QueueService.SetParallelism",
            $"set parallelism {request.Scope.ToString().ToLowerInvariant()}{(request.HasTarget && request.Target.Length > 0 ? ":" + request.Target : string.Empty)} "
            + request.Mode.ToString().ToLowerInvariant() + (request.Mode == ParallelismMode.Fixed ? " " + request.Fixed.ToString(CultureInfo.InvariantCulture) : string.Empty));
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta) ?? ParallelismFields(request);
        refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var actor = caller.Actor;
        var target = request.HasTarget ? request.Target : string.Empty;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "SetParallelism", QueueServiceSetParallelismResponse.Parser,
            failure => new QueueServiceSetParallelismResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                var transaction = command.Transaction;
                var document = WithPools(PolicyRules.Current(transaction).Document);
                ArcError? error = null;
                switch (request.Scope)
                {
                    case ParallelismScope.Pool:
                        if (document.Pools.FirstOrDefault(pool => pool.Name == target) is not { } pool)
                        {
                            error = NodeErrors.NotFound("pool", target);
                            break;
                        }

                        // A pool's limit is the pool's own parallelism mode (one source of truth).
                        pool.MaxParallelMode = request.Mode;
                        pool.ClearMaxParallelFixed();
                        if (request.Mode == ParallelismMode.Fixed)
                        {
                            pool.MaxParallelFixed = request.Fixed;
                        }

                        break;
                    case ParallelismScope.Workspace:
                        error = Exists(transaction, "workspace", "SELECT count(*) FROM workspace WHERE workspace_id = $id AND removed_at IS NULL;", target);
                        break;
                    case ParallelismScope.Session:
                        error = Exists(transaction, "session", "SELECT count(*) FROM session WHERE session_id = $id;", target);
                        break;
                }

                if (error is not null)
                {
                    return new QueueServiceSetParallelismResponse { Meta = ApiCommands.Meta(request.Meta), Error = error };
                }

                foreach (var rule in document.Parallelism.Where(rule => rule.Scope == request.Scope && string.Equals(rule.Target, target, StringComparison.OrdinalIgnoreCase)).ToList())
                {
                    document.Parallelism.Remove(rule);
                }

                if (request.Scope != ParallelismScope.Pool && request.Mode != ParallelismMode.Auto)
                {
                    var rule = new ParallelismRule { Scope = request.Scope, Mode = request.Mode };
                    if (target.Length > 0)
                    {
                        rule.Target = target;
                    }

                    if (request.Mode == ParallelismMode.Fixed)
                    {
                        rule.Fixed = request.Fixed;
                    }

                    document.Parallelism.Add(rule);
                }

                var (row, writeError) = Write(command, document, actor,
                    $"parallelism {request.Scope.ToString().ToLowerInvariant()}{(target.Length > 0 ? ":" + target : string.Empty)} {request.Mode.ToString().ToLowerInvariant()}"
                    + (request.Mode == ParallelismMode.Fixed ? " " + request.Fixed.ToString(CultureInfo.InvariantCulture) : string.Empty));
                return writeError is not null
                    ? new QueueServiceSetParallelismResponse { Meta = ApiCommands.Meta(request.Meta), Error = writeError }
                    : new QueueServiceSetParallelismResponse
                    {
                        Meta = ApiCommands.Meta(request.Meta),
                        Value = new QueueServiceSetParallelismValue { PolicyRevision = new Revision { Value = row!.Revision } },
                    };
            }, gate).ConfigureAwait(false);
        Changed(result.OutcomeCase == QueueServiceSetParallelismResponse.OutcomeOneofCase.Value && !replayed);
        return result;
    }

    // ------------------------------------------------------------------------------------------------------------------- views

    /// <summary>The explanation of one task (queue.proto <c>AdmissionExplanation</c>), or <see langword="null"/> when it does not exist.</summary>
    private AdmissionExplanation? Explain(StoreReader reader, byte[] id)
    {
        var task = TaskRecords.GetTask(reader, id, full: false);
        if (task is null)
        {
            return null;
        }

        var row = TaskRecords.GetRow(reader, id)!;
        var settings = Execution.Settings;
        var snapshot = Snapshot();
        var name = IdText.Format(id);
        var explanation = new AdmissionExplanation { TaskId = task.TaskId, State = task.State };
        var (cpu, expected, ceiling, source) = settings.Request(row.Spec.Resources?.Hint, light: false);
        explanation.Request = snapshot.Tasks.TryGetValue(name, out var view) ? view.Request
            : new ResourceDemand { CpuMillicores = (uint)Math.Min(cpu, uint.MaxValue), MemExpectedBytes = (ulong)expected, MemCeilingBytes = (ulong)ceiling, Source = source };
        explanation.BlockingKeys.Add(task.ExclusiveKeys);
        var running = Execution.RunningAttempts.ToList();
        var availableMemory = snapshot.BudgetMemory - running.Sum(attempt => attempt.AccountedMemory);
        var cpuLimit = (long)(settings.OvercommitCpu * snapshot.BudgetCpu);
        explanation.AvailableMemBytes = (ulong)Math.Max(0, availableMemory);
        explanation.AvailableCpuMillicores = (uint)Math.Clamp(cpuLimit - running.Sum(attempt => attempt.CpuGrant), 0, uint.MaxValue);
        explanation.PoolRunning = (uint)running.Count(attempt => attempt.Pool == row.Pool && !attempt.Light);
        explanation.PoolMaxParallel = (uint)(snapshot.Pools.FirstOrDefault(pool => pool.Name == row.Pool)?.MaxParallel
            ?? ExecutionSettings.MaxParallel(ParallelismMode.Auto, 0, snapshot.BudgetCpu));
        explanation.LargeReservationActive = snapshot.Result.Reservation is not null;
        var feasibility = AdmissionEngine.Classify((long)explanation.Request.MemExpectedBytes, settings.MaxShareMemory,
            settings.CapacityMemory - settings.ReserveMemory - (Execution.Resources?.Current?.UnmanagedMemory ?? 0), settings.MaxTaskMemory);
        explanation.Feasibility = ExecutionSupervisor.Word(feasibility);
        switch (task.State)
        {
            case TaskState.Queued:
                {
                    var verdict = snapshot.Result.Waiting.GetValueOrDefault(name);
                    explanation.BlockingReason = verdict?.Reason ?? task.Queue?.BlockingReason ?? BlockingReasons.GlobalLimit;
                    explanation.Position = (uint)(verdict?.Position ?? (int)(task.Queue?.Position ?? 0));
                    explanation.Feasibility = ExecutionSupervisor.Word(verdict?.Feasibility ?? feasibility);
                    explanation.Text = verdict?.Text ?? "waiting for the next admission pass";
                    explanation.BlockingKeys.Clear();
                    explanation.BlockingKeys.Add(verdict?.BlockingKeys ?? []);
                    foreach (var holder in verdict?.Holders ?? [])
                    {
                        if (IdText.TryParse(holder, out var holderId))
                        {
                            explanation.WaitingOnTasks.Add(new Id { Value = ByteString.CopyFrom(holderId) });
                        }
                    }

                    // The aging clock starts at the later of the queueing and the last SetTaskPriority (task.aged_at).
                    var queuedAt = reader.Scalar("SELECT max(coalesce(queued_at, created_at), coalesce(aged_at, 0)) FROM task WHERE task_id = $id;", ("$id", id)) is long at ? at : 0;
                    if (AdmissionEngine.AgesAt(task.EffectivePriority, queuedAt, reader.NowMicroseconds, (long)settings.StarvationBound.TotalMicroseconds) is { } ages)
                    {
                        explanation.AgesAt = Notifications.Time(ages);
                    }

                    if (snapshot.Result.Reservation?.Task == name)
                    {
                        explanation.Text += "; it holds the large-task reservation";
                    }

                    break;
                }

            case TaskState.WaitingDependency:
                {
                    explanation.BlockingReason = BlockingReasons.Dependency;
                    var waiting = new List<string>();
                    using var command = reader.CreateCommand(
                        "SELECT d.depends_on_task_id, d.condition, t.state, t.ready FROM task_dependency d JOIN task t ON t.task_id = d.depends_on_task_id WHERE d.task_id = $id;");
                    command.Parameters.AddWithValue("$id", id);
                    using var rows = command.ExecuteReader();
                    while (rows.Read())
                    {
                        var condition = (DependencyCondition)rows.GetInt32(1);
                        if (!ExecutionSupervisor.DependencySatisfied(condition, (TaskState)rows.GetInt32(2), rows.GetInt32(3) == 1))
                        {
                            var dependency = (byte[])rows.GetValue(0);
                            explanation.WaitingOnTasks.Add(new Id { Value = ByteString.CopyFrom(dependency) });
                            waiting.Add($"{IdText.Format(dependency)} ({condition.ToString().ToUpperInvariant()})");
                        }
                    }

                    explanation.Text = "waits for its dependencies: " + string.Join(", ", waiting);
                    break;
                }

            case TaskState.RetryWait:
                explanation.Text = (task.HasStateReason ? task.StateReason : "an automatic retry") + " (RETRY_WAIT)";
                break;
            default:
                explanation.Text = TaskRecords.IsTerminal(task.State) ? $"the task is {task.State.ToString().ToUpperInvariant()}" : $"the task was admitted and is {task.State.ToString().ToUpperInvariant()}";
                break;
        }

        return explanation;
    }

    private QueueSnapshot Snapshot()
    {
        var settings = Execution.Settings;
        return Execution.Queue ?? QueueSnapshot.Empty(_node.Clock.GetUtcNow(), Execution.Resources?.Current?.BudgetCpu ?? settings.BudgetCpu,
            Execution.Resources?.Current?.BudgetMemory ?? settings.MaxShareMemory, settings.GlobalMaxRunning, Execution.Resources?.Current?.Pressure ?? PressureLevel.Normal);
    }

    private BudgetSummary Budget(QueueSnapshot snapshot, ExecutionSettings settings)
    {
        var running = Execution.RunningAttempts.ToList();
        return new BudgetSummary
        {
            BudgetCpuMillicores = (uint)Math.Clamp(snapshot.BudgetCpu, 0, uint.MaxValue),
            BudgetMemBytes = (ulong)Math.Max(0, snapshot.BudgetMemory),
            CpuLoadMillicores = (uint)Math.Clamp(running.Sum(attempt => attempt.CpuGrant), 0, uint.MaxValue),
            CpuLimitMillicores = (uint)Math.Clamp((long)(settings.OvercommitCpu * snapshot.BudgetCpu), 0, uint.MaxValue),
            AccountedMemBytes = (ulong)Math.Max(0, running.Sum(attempt => attempt.AccountedMemory)),
            GlobalRunning = (uint)running.Count,
            GlobalMaxRunning = (uint)settings.GlobalMaxRunning,
            Pressure = Execution.Resources?.Current?.Pressure ?? snapshot.Pressure,
        };
    }

    private List<Pool> Pools(QueueSnapshot snapshot, ExecutionSettings settings)
    {
        var counts = _node.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT pool, count(*) FROM task WHERE state IN (1, 2, 6) GROUP BY pool;");
            using var rows = command.ExecuteReader();
            var result = new Dictionary<string, uint>(StringComparer.Ordinal);
            while (rows.Read())
            {
                result[rows.GetString(0)] = (uint)rows.GetInt64(1);
            }

            return result;
        });
        var running = Execution.RunningAttempts.Where(attempt => !attempt.Light).GroupBy(attempt => attempt.Pool).ToDictionary(group => group.Key, group => (uint)group.Count(),
            StringComparer.Ordinal);
        return [.. settings.PoolPolicies.Select(pool =>
        {
            var view = PoolView(pool, snapshot, settings);
            view.Running = running.GetValueOrDefault(pool.Name);
            view.Queued = counts.GetValueOrDefault(pool.Name);
            return view;
        })];
    }

    private Pool PoolView(PoolPolicy pool, QueueSnapshot? snapshot, ExecutionSettings settings)
    {
        var budgetCpu = snapshot?.BudgetCpu ?? Execution.Resources?.Current?.BudgetCpu ?? settings.BudgetCpu;
        var paused = Execution.PausedPoolNames;
        var view = new Pool
        {
            Name = pool.Name,
            BuiltIn = pool.BuiltIn || DefaultPolicy.BuiltInPools.Contains(pool.Name),
            Weight = pool.HasWeight ? pool.Weight : 1,
            MaxParallelMode = pool.HasMaxParallelMode ? pool.MaxParallelMode : ParallelismMode.Auto,
            EffectiveMaxParallel = (uint)(snapshot?.Pools.FirstOrDefault(limits => limits.Name == pool.Name)?.MaxParallel
                ?? ExecutionSettings.MaxParallel(pool.HasMaxParallelMode ? pool.MaxParallelMode : ParallelismMode.Auto, pool.MaxParallelFixed, budgetCpu)),
            DefaultPriority = pool.HasDefaultPriority ? pool.DefaultPriority : Priority.Normal,
            Paused = paused.Contains("*") || paused.Contains(pool.Name),
        };
        if (pool.HasMaxParallelFixed)
        {
            view.MaxParallelFixed = pool.MaxParallelFixed;
        }

        return view;
    }

    private bool IsQueued(byte[] taskId) => _node.Store.Read(reader => reader.Scalar("SELECT state FROM task WHERE task_id = $id;", ("$id", taskId))) is 1L;

    // ------------------------------------------------------------------------------------------------------------------- mutations

    /// <summary>The document with its pools listed (an empty list means the built-in pools).</summary>
    private static PolicyDocument WithPools(PolicyDocument current)
    {
        var document = current.Clone();
        if (document.Pools.Count == 0)
        {
            foreach (var pool in DefaultPolicy.BuiltInPools)
            {
                document.Pools.Add(new PoolPolicy { Name = pool, Weight = 1, MaxParallelMode = ParallelismMode.Auto, BuiltIn = true });
            }
        }

        return document;
    }

    /// <summary>Validates the changed document and writes it as the new current revision.</summary>
    private (PolicyRow? Row, ArcError? Error) Write(CommandContext command, PolicyDocument document, ActorRef actor, string comment)
    {
        var settings = Execution.Settings;
        var errors = PolicyRules.Validate(document, settings.CapacityMemory, (int)(settings.CapacityCpu / 1000)).Where(issue => issue.Severity == Severity.Error)
            .Select(issue => issue.Path + ": " + issue.Message).ToList();
        if (errors.Count > 0)
        {
            return (null, NodeErrors.InvalidPolicy(errors));
        }

        return (PolicyRules.Write(command.Transaction, document, actor, comment), null);
    }

    private void Changed(bool changed)
    {
        if (changed)
        {
            Execution.PolicyChanged();
        }
    }

    private static ArcError? Exists(StoreReader reader, string kind, string sql, string target)
    {
        if (!IdText.TryParse(target, out var id))
        {
            return NodeErrors.InvalidArgument($"target: a {kind} ID (base32)");
        }

        return Convert.ToInt64(reader.Scalar(sql, ("$id", id)), CultureInfo.InvariantCulture) > 0 ? null : NodeErrors.NotFound(kind, id);
    }

    private ArcError? PoolTarget(string? pool, bool all)
    {
        if (all)
        {
            return pool is { Length: > 0 } ? NodeErrors.InvalidArgument("pool: empty with all = true") : null;
        }

        if (pool is not { Length: > 0 })
        {
            return NodeErrors.InvalidArgument("pool: an existing pool, or all = true");
        }

        return Execution.Settings.PoolPolicies.Any(candidate => candidate.Name == pool) ? null : NodeErrors.NotFound("pool", pool);
    }

    private static ArcError? PoolFields(bool hasName, string name, bool hasWeight, uint weight, bool hasMode, ParallelismMode mode, bool hasFixed, uint fixedLimit,
        bool hasPriority, Priority priority, bool nameRequired)
    {
        if (nameRequired && (!hasName || !PolicyRules.PoolName.IsMatch(name)))
        {
            return NodeErrors.InvalidArgument("name: ^[a-z][a-z0-9-]{0,31}$");
        }

        if (hasWeight && weight is < 1 or > 100)
        {
            return NodeErrors.InvalidArgument("weight: 1..100");
        }

        if (hasMode && (mode == ParallelismMode.Unspecified || !Enum.IsDefined(mode)))
        {
            return NodeErrors.InvalidArgument("max_parallel_mode: AUTO, FIXED or DISABLED");
        }

        if (hasFixed && (mode != ParallelismMode.Fixed || fixedLimit is < 1 or > 256))
        {
            return NodeErrors.InvalidArgument("max_parallel_fixed: FIXED only; 1..256");
        }

        if (hasMode && mode == ParallelismMode.Fixed && !hasFixed)
        {
            return NodeErrors.InvalidArgument("max_parallel_fixed: required with FIXED; 1..256");
        }

        if (hasPriority && (priority is Priority.Interactive or Priority.Unspecified || !Enum.IsDefined(priority)))
        {
            return NodeErrors.InvalidArgument("default_priority: HIGH, NORMAL, LOW or BACKGROUND (not INTERACTIVE)");
        }

        return null;
    }

    private static ArcError? ParallelismFields(QueueServiceSetParallelismRequest request)
    {
        if (!request.HasScope || request.Scope == ParallelismScope.Unspecified || !Enum.IsDefined(request.Scope))
        {
            return NodeErrors.InvalidArgument("scope: required (GLOBAL, POOL, WORKSPACE or SESSION)");
        }

        var target = request.HasTarget ? request.Target : string.Empty;
        if (request.Scope == ParallelismScope.Global ? target.Length > 0 : target.Length == 0)
        {
            return NodeErrors.InvalidArgument(request.Scope == ParallelismScope.Global ? "target: empty for GLOBAL" : "target: required");
        }

        if (!request.HasMode || request.Mode == ParallelismMode.Unspecified || !Enum.IsDefined(request.Mode))
        {
            return NodeErrors.InvalidArgument("mode: required (AUTO, FIXED or DISABLED)");
        }

        if (request.Mode == ParallelismMode.Fixed ? !request.HasFixed || request.Fixed is < 1 or > 256 : request.HasFixed)
        {
            return NodeErrors.InvalidArgument("fixed: FIXED only; 1..256");
        }

        return null;
    }
}
