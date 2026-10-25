// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>arcforges.node.v1.TaskService</c> (tasks.proto; architecture 04; AD-0006): Submit (with dependencies, keys and the side-effect class
/// from the caller or a <c>retry_safety</c> rule), Get, List, Wait, Attach (with STREAM stdin through Write/CloseTaskInput),
/// ReleaseCallerBinding, Cancel, Retry (manual, with an optional larger memory grant), SetTaskPriority (the class or pool of a waiting task,
/// the class and CPU weight of a running one), Pause and Resume (Linux; Windows reports pause unsupported), Pin, PurgeTaskRecord,
/// ReadTaskOutput, WatchTaskOutput, GetAttempt and ListAttempts. Mutations are idempotent by <c>meta.command_id</c> (24 h; the payload
/// digest of the request's wire bytes). <c>GetTimeline</c> belongs to a later task; the generated base answers it <c>UNIMPLEMENTED</c>.
/// </summary>
public sealed class TaskServiceHandler : TaskService.TaskServiceBase
{
    /// <summary>The bytes one output follow step reads (8 chunks); with the stream's room check it bounds an attach's memory.</summary>
    private const int FollowBudget = 8 * OutputReader.ChunkBytes;

    private const string ServiceName = "arcforges.node.v1.TaskService";
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(15);
    private readonly NodeRuntime _node;
    private readonly ClientSessions _sessions;
    private readonly ApiCommands _api;

    /// <summary>Creates the service over the running node.</summary>
    public TaskServiceHandler(NodeRuntime node, ClientSessions sessions)
        : this(node, sessions, new ApprovalExecutors())
    {
    }

    /// <summary>Creates the service and registers how its approval-gated requests execute once approved.</summary>
    internal TaskServiceHandler(NodeRuntime node, ClientSessions sessions, ApprovalExecutors executors)
    {
        ArgumentNullException.ThrowIfNull(executors);
        _node = node ?? throw new ArgumentNullException(nameof(node));
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _api = new ApiCommands(node, sessions, ServiceName);
        executors.Register<TaskServiceCancelTaskRequest, TaskServiceCancelTaskResponse>("TaskService.CancelTask", PermissionMatrix.TaskCancelOthers,
            TaskServiceCancelTaskRequest.Parser, CancelTask);
        executors.Register<TaskServiceSetTaskPriorityRequest, TaskServiceSetTaskPriorityResponse>("TaskService.SetTaskPriority", PermissionMatrix.TaskSetPriority,
            TaskServiceSetTaskPriorityRequest.Parser, SetTaskPriority);
        executors.Register<TaskServicePauseTaskRequest, TaskServicePauseTaskResponse>("TaskService.PauseTask", PermissionMatrix.TaskPause,
            TaskServicePauseTaskRequest.Parser, (request, caller) => PauseTask(request, caller, CancellationToken.None));
        executors.Register<TaskServiceResumeTaskRequest, TaskServiceResumeTaskResponse>("TaskService.ResumeTask", PermissionMatrix.TaskCancelOthers,
            TaskServiceResumeTaskRequest.Parser, (request, caller) => ResumeTask(request, caller, CancellationToken.None));
        executors.Register<TaskServiceRetryTaskRequest, TaskServiceRetryTaskResponse>("TaskService.RetryTask", PermissionMatrix.TaskRetry,
            TaskServiceRetryTaskRequest.Parser, RetryTask);
    }

    private ExecutionSupervisor Execution => _node.Execution ?? throw new InvalidOperationException("The node has no execution supervisor.");

    /// <inheritdoc />
    public override async Task<TaskServiceSubmitTaskResponse> SubmitTask(TaskServiceSubmitTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new TaskServiceSubmitTaskResponse { Meta = Meta(request.Meta) };
        var origin = _sessions.OriginOf(context);
        var execution = Execution;
        var settings = execution.Settings;
        var refused = Stopping() ?? Validation.CommandId(request.Meta)
            ?? TaskValidation.Submit(request, origin, settings, _node.NodeId.Span, _node.Capabilities);
        if (refused is null && execution.Platform is null)
        {
            refused = NodeErrors.EnforcementUnavailable("no execution platform could be started on this node (see the node log)");
        }

        // 03 section 8 (R-RES-008): an observe-only or partial node runs tasks unenforced unless the policy forbids it.
        if (refused is null && execution.Unenforced && settings.AllowUnenforced == false)
        {
            refused = NodeErrors.EnforcementUnavailable("resources.allow_unenforced is false and this node does not enforce cpu and memory limits");
        }

        var spec = request.Spec;
        if (refused is null)
        {
            try
            {
                execution.Platform!.Prepare(new CommandRequest
                {
                    Argv = spec.Command.FormCase == CommandSpec.FormOneofCase.Argv ? [.. spec.Command.Argv.Argv] : null,
                    Shell = spec.Command.FormCase == CommandSpec.FormOneofCase.Shell ? spec.Command.Shell.Kind : ShellKind.Unspecified,
                    Script = spec.Command.FormCase == CommandSpec.FormOneofCase.Shell ? spec.Command.Shell.Script : null,
                    ShellPath = spec.Command.FormCase == CommandSpec.FormOneofCase.Shell && spec.Command.Shell.HasShellPath ? spec.Command.Shell.ShellPath : null,
                    WorkingDirectory = spec.WorkingDirectory,
                    Environment = ExecutionSupervisor.ValidationEnvironment(spec, execution.Platform.EnvironmentNames),
                });
            }
            catch (CommandRefusedException exception)
            {
                refused = NodeErrors.Validation(exception.Code, exception.Reason);
            }
        }

        // R-EXE-012: a dependency must name a task of this node (a new task can never close a cycle: nothing depends on it yet).
        if (refused is null && spec.DependsOn.Count > 0)
        {
            refused = _node.Store.Read(reader =>
            {
                for (var index = 0; index < spec.DependsOn.Count; index++)
                {
                    var dependency = spec.DependsOn[index].TaskId.Value.ToByteArray();
                    if (TaskRecords.GetRow(reader, dependency) is not { Purged: false })
                    {
                        return NodeErrors.InvalidDependency(dependency, $"depends_on[{index}]: task {IdText.Format(dependency)} does not exist on this node");
                    }
                }

                return (ArcError?)null;
            });
        }

        if (refused is null && origin == Origin.Agent && !settings.AgentCommandAllowed(CommandLine(spec.Command)))
        {
            // 11 section 1, "Submit task (own)": AGENT A subject to agents.allowed_command_patterns (default all); a guardrail over the argv.
            refused = NodeErrors.CommandPatternDenied("agents.allowed_command_patterns");
            await _api.AuditAsync(_api.CallerOf(context), new GateRequest(PermissionMatrix.TaskSubmit, "TaskService.SubmitTask",
                "submit " + CommandText.Summary(spec.Command, settings.SecretNames), "task"), PermissionDecision.Deny,
                "denied: the command matches no agents.allowed_command_patterns").ConfigureAwait(false);
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var parts = SubmittedEnvironment.Split(spec, settings.SecretNames);
        if (parts.Secrets is not null)
        {
            // The node data key loads at startup; sealing never waits on the OS secret store under the writer lock.
            await execution.KeysReady.ConfigureAwait(false);
        }

        var session = _sessions.SessionOf(context);
        var warnings = new List<string>();
        var sideEffect = spec.HasSideEffect ? spec.SideEffect : SideEffectClass.Unknown;
        var source = spec.HasSideEffect && sideEffect != SideEffectClass.Unknown ? SideEffectSource.Caller : SideEffectSource.Default;
        if (origin == Origin.Agent && !settings.AcceptAgentAssertions && sideEffect is SideEffectClass.Pure or SideEffectClass.Idempotent)
        {
            warnings.Add($"The agent's side-effect class {sideEffect.ToString().ToUpperInvariant()} is not accepted (retry_safety.accept_agent_assertions is false); the task is UNKNOWN.");
            sideEffect = SideEffectClass.Unknown;
            source = SideEffectSource.Default;
        }

        // 03 section 4 and 04 section 1: the workspace is the registered root that contains the working directory (longest prefix).
        var workspace = _node.Store.Read(reader => ExecutionSupervisor.WorkspaceOf(reader, spec.WorkingDirectory));

        // AD-0006 section 4: a HUMAN-edited retry_safety rule may assert PURE or IDEMPOTENT for a command no caller classified.
        if (source == SideEffectSource.Default && settings.RetrySafetyRules.Count > 0
            && PolicyRules.RetrySafety(settings.RetrySafetyRules, CommandLine(spec.Command), workspace ?? []) is { } ruled)
        {
            sideEffect = ruled;
            source = SideEffectSource.Policy;
        }

        var (keys, _) = KeyHolders.FromSpec(spec.Concurrency?.ExclusiveKeys ?? [], spec.Concurrency?.SharedKeys ?? []);
        var pool = spec.HasPool ? spec.Pool : "default";
        var poolPolicy = settings.PoolPolicies.FirstOrDefault(candidate => candidate.Name == pool);

        if (execution.Unenforced)
        {
            warnings.Add("This node does not enforce every resource limit (" + (NodeCapabilities.MissingReason(_node.Capabilities) ?? "observe only")
                + "); the task runs unenforced (03 section 8).");
        }

        if (request.JoinExisting)
        {
            warnings.Add("join_existing joins only tasks of the same session; sessions arrive with AF-AI-01, so the task was queued as a new task.");
        }

        var summary = CommandText.Summary(spec.Command, settings.SecretNames);
        var plan = new SubmitPlan
        {
            Parts = parts,
            Owner = new ActorRef { Origin = origin, ClientKind = session?.Kind ?? ClientKind.Unspecified },
            Title = spec.HasTitle && spec.Title.Length > 0 ? spec.Title : summary,
            Summary = summary,
            Fingerprint = CommandText.Fingerprint(spec.Command),
            CommandDigest = CommandText.Digest(spec, EnvironmentDigest(spec.Environment)),
            Kind = spec.HasKind ? spec.Kind : TaskKind.Command,
            Pool = pool,
            Priority = spec.HasPriority ? spec.Priority : poolPolicy is { HasDefaultPriority: true, DefaultPriority: not Priority.Unspecified } ? poolPolicy.DefaultPriority : Priority.Normal,
            SideEffect = sideEffect,
            SideEffectSource = source,
            Warnings = warnings,
            CommandId = request.Meta.CommandId,
            Dependencies = [.. spec.DependsOn.Select(dependency => (dependency.TaskId.Value.ToByteArray(),
                dependency.HasCondition ? dependency.Condition : DependencyCondition.Succeeded))],
            Keys = keys,
            WorkspaceId = workspace,
        };
        CallerKey? caller = request.CancelWhenCallerGone && session is not null
            ? new CallerKey(session.Peer.ProcessId, session.Peer.ProcessStartTime.UtcTicks)
            : null;
        var (result, replayed) = await Idempotent(request, request.Meta, context, "SubmitTask", TaskServiceSubmitTaskResponse.Parser,
            failure => new TaskServiceSubmitTaskResponse { Meta = Meta(request.Meta), Error = failure },
            command => new TaskServiceSubmitTaskResponse { Meta = Meta(request.Meta), Value = execution.Submit(command, plan) }).ConfigureAwait(false);
        if (result.OutcomeCase == TaskServiceSubmitTaskResponse.OutcomeOneofCase.Value && !replayed)
        {
            execution.Submitted(result.Value.TaskId.Value.Span, caller);
            _node.Log.Debug("api.task.submitted", new LogField("task", IdText.Format(result.Value.TaskId)), new LogField("origin", origin),
                new LogField("callerBound", caller is not null));
        }

        return result;
    }

    /// <inheritdoc />
    public override Task<TaskServiceGetTaskResponse> GetTask(TaskServiceGetTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new TaskServiceGetTaskResponse { Meta = Meta(request.Meta) };
        if ((Stopping() ?? Validation.RequiredId(request.TaskId, "task_id")) is { } refused)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var id = request.TaskId.Value.ToByteArray();
        var task = _node.Store.Read(reader => TaskRecords.GetTask(reader, id, request.Detail == TaskDetail.Full));
        if (task is null)
        {
            response.Error = NodeErrors.NotFound("task", id);
        }
        else
        {
            response.Value = new TaskServiceGetTaskValue { Task = task };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<TaskServiceListTasksResponse> ListTasks(TaskServiceListTasksRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new TaskServiceListTasksResponse { Meta = Meta(request.Meta) };
        var invalidPage = Validation.Page(request.Page, 500, 100, out var limit, out var cursor);
        var refused = Stopping() ?? invalidPage;
        if (refused is null && request.Filter is { } filter)
        {
            if (filter.States.Any(state => state == TaskState.Unspecified || !Enum.IsDefined(state)))
            {
                refused = NodeErrors.InvalidArgument("filter.states: known values");
            }
            else if (filter.HasText && filter.Text.Length > 200)
            {
                refused = NodeErrors.InvalidArgument("filter.text: <= 200 chars");
            }
        }

        if (refused is not null)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var (tasks, next) = _node.Store.Read(reader => TaskRecords.ListTasks(reader, request.Filter, cursor, limit));
        var value = new TaskServiceListTasksValue { Page = new PageState { HasMore = next is not null } };
        value.Tasks.Add(tasks);
        if (next is not null)
        {
            value.Page.NextCursor = next;
        }

        response.Value = value;
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<TaskServiceWaitTaskResponse> WaitTask(TaskServiceWaitTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new TaskServiceWaitTaskResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.RequiredId(request.TaskId, "task_id");
        if (refused is null && request.HasWaitMs && request.WaitMs > 55_000)
        {
            refused = NodeErrors.InvalidArgument("wait_ms: 0..55,000");
        }

        if (refused is null && request.HasTailBytes && request.TailBytes > 65_536)
        {
            refused = NodeErrors.InvalidArgument("tail_bytes: 0..65,536");
        }

        if (refused is null && request.HasTarget && (request.Target == WaitTarget.Unspecified || !Enum.IsDefined(request.Target)))
        {
            refused = NodeErrors.InvalidArgument("target: TERMINAL, STARTED or READY");
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var id = request.TaskId.Value.ToByteArray();
        var target = request.HasTarget ? request.Target : WaitTarget.Terminal;
        var pulse = Execution.TaskPulse(id);
        var started = _node.Clock.GetTimestamp();
        var budget = TimeSpan.FromMilliseconds(request.HasWaitMs ? request.WaitMs : 0);
        ManagedTask? task;
        bool reached;
        while (true)
        {
            var next = pulse.Next;
            task = _node.Store.Read(reader => TaskRecords.GetTask(reader, id, full: false));
            if (task is null)
            {
                response.Error = NodeErrors.NotFound("task", id);
                return response;
            }

            reached = target switch
            {
                WaitTarget.Started => task.State != TaskState.Queued && task.State != TaskState.WaitingDependency && task.State != TaskState.Placing,
                WaitTarget.Ready => task.Ready || TaskRecords.IsTerminal(task.State),
                _ => TaskRecords.IsTerminal(task.State) && (AttemptName(task) is not { } name || Execution.Running(name) is null),
            };
            var remaining = budget - _node.Clock.GetElapsedTime(started);
            if (reached || remaining <= TimeSpan.Zero)
            {
                break;
            }

            await Task.WhenAny(next, Task.Delay(remaining < TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1), context.CancellationToken)).ConfigureAwait(false);
            context.CancellationToken.ThrowIfCancellationRequested();
        }

        var value = new TaskServiceWaitTaskValue { Task = task, Reached = reached };
        if (request.TailBytes > 0 && task.CurrentAttempt is { } attempt)
        {
            var (tail, truncated) = OutputReader.Tail(new AttemptFiles(_node.DataRoot, IdText.Format(attempt.AttemptId)), (int)request.TailBytes);
            value.Tail = ByteString.CopyFrom(tail);
            value.TailTruncated = truncated;
        }

        response.Value = value;
        return response;
    }

    /// <inheritdoc />
    public override async Task AttachTask(TaskServiceAttachTaskRequest request, IServerStreamWriter<TaskServiceAttachTaskFrame> responseStream, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        _node.CountCall();
        var writer = context.OpenLocalRpcStream(responseStream);
        await using (writer.ConfigureAwait(false))
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(writer.Ended, context.CancellationToken, _node.Stopping);
            var refused = (_node.Lifecycle.IsStopping ? NodeErrors.NodeStopping(_node.Clock.GetUtcNow()) : null) ?? Validation.RequiredId(request.TaskId, "task_id");
            var id = refused is null ? request.TaskId.Value.ToByteArray() : [];
            var spec = refused is null ? _node.Store.Read(reader => TaskRecords.GetRow(reader, id)) : null;
            if (refused is null && spec is null)
            {
                refused = NodeErrors.NotFound("task", id);
            }

            if (refused is null && request.WantStdin && spec!.Spec.Stdin?.Mode != StdinMode.Stream)
            {
                refused = NodeErrors.InvalidState("STDIN_" + (spec.Spec.Stdin?.Mode ?? StdinMode.None).ToString().ToUpperInvariant(), "want_stdin needs stdin mode STREAM");
            }

            if (refused is not null)
            {
                writer.TryWrite(new TaskServiceAttachTaskFrame { Meta = new ResponseMeta(), Error = refused });
                await writer.CompleteAsync().ConfigureAwait(false);
                return;
            }

            var execution = Execution;
            var attachId = CommandIds.New();
            var attachText = IdText.Format(attachId);
            var stdinGranted = false;
            try
            {
                var pulse = execution.TaskPulse(id);
                var next = pulse.Next;
                if (request.WantStdin)
                {
                    stdinGranted = await ClaimStdinAsync(execution, id, attachText, stop.Token).ConfigureAwait(false);
                }

                writer.TryWrite(new TaskServiceAttachTaskFrame
                {
                    Meta = new ResponseMeta(),
                    Started = new TaskAttachStarted { AttachId = attachId, StdinGranted = stdinGranted },
                });
                long revision = -1;
                string? attemptName = null;
                var cursor = new OutputCursor(0, (long)request.StdoutFromOffset, (long)request.StderrFromOffset);
                var lastWrite = _node.Clock.GetTimestamp();
                while (!stop.IsCancellationRequested)
                {
                    var task = _node.Store.Read(reader => TaskRecords.GetTask(reader, id, full: false));
                    if (task is null)
                    {
                        break;
                    }

                    if (task.Revision.Value != revision)
                    {
                        revision = task.Revision.Value;
                        writer.TryWrite(new TaskServiceAttachTaskFrame { Meta = new ResponseMeta(), Task = task });
                        lastWrite = _node.Clock.GetTimestamp();
                    }

                    var current = AttemptName(task);
                    if (current is not null && current != attemptName)
                    {
                        // A new attempt (a retry) starts its output at zero; the first one at the requested offsets.
                        cursor = attemptName is null ? cursor with { Record = 0 } : new OutputCursor(0, 0, 0);
                        attemptName = current;
                    }

                    if (attemptName is not null)
                    {
                        var files = new AttemptFiles(_node.DataRoot, attemptName);
                        while (true)
                        {
                            var (slices, following, atEnd) = OutputReader.Follow(files, cursor, FollowBudget);
                            cursor = following;
                            foreach (var slice in slices)
                            {
                                await WaitForRoomAsync(writer, stop.Token).ConfigureAwait(false);
                                writer.TryWrite(new TaskServiceAttachTaskFrame
                                {
                                    Meta = new ResponseMeta(),
                                    Output = Chunk(task.CurrentAttempt!.AttemptId, slice),
                                });
                                lastWrite = _node.Clock.GetTimestamp();
                            }

                            if (atEnd)
                            {
                                break;
                            }
                        }
                    }

                    if (TaskRecords.IsTerminal(task.State) && (attemptName is null || execution.Running(attemptName) is null))
                    {
                        // The record and the output are final: the result frame ends the stream (tasks.proto).
                        var final = _node.Store.Read(reader => TaskRecords.GetTask(reader, id, full: false));
                        if (final is not null && final.Revision.Value != revision)
                        {
                            writer.TryWrite(new TaskServiceAttachTaskFrame { Meta = new ResponseMeta(), Task = final });
                        }

                        if (attemptName is not null)
                        {
                            var files = new AttemptFiles(_node.DataRoot, attemptName);
                            while (true)
                            {
                                var (slices, following, atEnd) = OutputReader.Follow(files, cursor, FollowBudget);
                                cursor = following;
                                foreach (var slice in slices)
                                {
                                    await WaitForRoomAsync(writer, stop.Token).ConfigureAwait(false);
                                    writer.TryWrite(new TaskServiceAttachTaskFrame { Meta = new ResponseMeta(), Output = Chunk(final!.CurrentAttempt!.AttemptId, slice) });
                                }

                                if (atEnd)
                                {
                                    break;
                                }
                            }
                        }

                        writer.TryWrite(new TaskServiceAttachTaskFrame
                        {
                            Meta = new ResponseMeta(),
                            Result = (final ?? task).CurrentAttempt?.Result ?? new AttemptResult
                            {
                                TerminationReason = TerminationReason.Cancelled,
                                Effect = EffectCertainty.DidNotHappen,
                                Detail = "the task ended before an attempt started",
                            },
                        });
                        break;
                    }

                    if (request.WantStdin && !stdinGranted && task.State == TaskState.Running)
                    {
                        stdinGranted = execution.ClaimStdin(id, attachText);
                        if (stdinGranted)
                        {
                            writer.TryWrite(new TaskServiceAttachTaskFrame
                            {
                                Meta = new ResponseMeta(),
                                Started = new TaskAttachStarted { AttachId = attachId, StdinGranted = true },
                            });
                        }
                    }

                    var wait = HeartbeatInterval - _node.Clock.GetElapsedTime(lastWrite);
                    if (wait <= TimeSpan.Zero)
                    {
                        writer.TryWrite(new TaskServiceAttachTaskFrame
                        {
                            Meta = new ResponseMeta(),
                            Heartbeat = new Heartbeat { At = ProtoTime.ToInstant(_node.Clock.GetUtcNow()) },
                        });
                        lastWrite = _node.Clock.GetTimestamp();
                        continue;
                    }

                    await Task.WhenAny(next, Task.Delay(wait < TimeSpan.FromSeconds(1) ? wait : TimeSpan.FromSeconds(1), stop.Token)).ConfigureAwait(false);
                    next = pulse.Next;
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
            }
            finally
            {
                execution.ReleaseStdin(attachText);
            }

            await writer.CompleteAsync().ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public override Task<TaskServiceWriteTaskInputResponse> WriteTaskInput(TaskServiceWriteTaskInputRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new TaskServiceWriteTaskInputResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.RequiredId(request.TaskId, "task_id") ?? Validation.RequiredId(request.AttachId, "attach_id");
        if (refused is null && (request.Data.Length is < 1 or > 64 * 1024))
        {
            refused = NodeErrors.InvalidArgument("data: 1 byte..64 KiB");
        }

        if (refused is not null)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var (accepted, error) = Execution.WriteInput(request.TaskId.Value.Span, IdText.Format(request.AttachId), request.Offset, request.Data.Span);
        if (error is not null)
        {
            response.Error = error;
        }
        else
        {
            response.Value = new TaskServiceWriteTaskInputValue { AcceptedThrough = accepted };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<TaskServiceCloseTaskInputResponse> CloseTaskInput(TaskServiceCloseTaskInputRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new TaskServiceCloseTaskInputResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.TaskId, "task_id")
            ?? Validation.RequiredId(request.AttachId, "attach_id");
        if (refused is null)
        {
            refused = Execution.CloseInput(request.TaskId.Value.Span, IdText.Format(request.AttachId));
        }

        if (refused is not null)
        {
            response.Error = refused;
        }
        else
        {
            response.Value = new TaskServiceCloseTaskInputValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened } };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<TaskServiceReleaseCallerBindingResponse> ReleaseCallerBinding(TaskServiceReleaseCallerBindingRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new TaskServiceReleaseCallerBindingResponse { Meta = Meta(request.Meta) };
        if ((Stopping() ?? Validation.RequiredId(request.TaskId, "task_id")) is { } refused)
        {
            response.Error = refused;
            return response;
        }

        // Natural idempotency (tasks.proto): releasing twice succeeds.
        var id = request.TaskId.Value.ToByteArray();
        var (value, error) = await Run(() => _node.Processor.ExecuteAsync(command => Execution.ReleaseCaller(command, id))).ConfigureAwait(false);
        if ((error ?? value.Error) is { } failure)
        {
            response.Error = failure;
        }
        else
        {
            response.Value = new TaskServiceReleaseCallerBindingValue
            {
                Receipt = new Receipt { CommandId = request.Meta?.CommandId ?? CommandIds.New(), Effect = EffectCertainty.Happened },
                State = value.State,
            };
            _node.Log.Info("api.task.caller_released", new LogField("task", IdText.Format(id)));
        }

        return response;
    }

    /// <inheritdoc />
    public override Task<TaskServiceCancelTaskResponse> CancelTask(TaskServiceCancelTaskRequest request, ServerCallContext context) =>
        CancelTask(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>CancelTask</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<TaskServiceCancelTaskResponse> CancelTask(TaskServiceCancelTaskRequest request, Caller caller)
    {
        try
        {
            return await CancelTaskOnce(request, caller, allowSettled: true).ConfigureAwait(false);
        }
        catch (GateStaleException)
        {
            // Review round 2: the task changed between the check and the command; the request is checked again, with the gate.
            return await CancelTaskOnce(request, caller, allowSettled: false).ConfigureAwait(false);
        }
    }

    private async Task<TaskServiceCancelTaskResponse> CancelTaskOnce(TaskServiceCancelTaskRequest request, Caller caller, bool allowSettled)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new TaskServiceCancelTaskResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.TaskId, "task_id");
        if (refused is null && request.HasReason && request.Reason.Length > 500)
        {
            refused = NodeErrors.InvalidArgument("reason: <= 500 chars");
        }

        if (refused is null && request.HasGraceMs && request.GraceMs > 300_000)
        {
            refused = NodeErrors.InvalidArgument("grace_ms: 0..300 s");
        }

        // Review round 1: cancelling a task that already ended (or does not exist) changes nothing and is answered without an approval.
        var settled = allowSettled && refused is null && Settled(request.TaskId);
        var gate = refused is null && !settled ? TaskGate(request.TaskId, "TaskService.CancelTask", "cancel task") : null;
        if (refused is null && gate is not null)
        {
            refused = await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var id = request.TaskId.Value.ToByteArray();
        var reason = request.HasReason && request.Reason.Length > 0 ? request.Reason : "cancelled";
        string? stopAttempt = null;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "CancelTask", TaskServiceCancelTaskResponse.Parser,
            failure => new TaskServiceCancelTaskResponse { Meta = Meta(request.Meta), Error = failure }, command =>
        {
            EnsureStillSettled(command, id, settled);
            var (state, error, attempt) = Execution.Cancel(command, id, reason);
            stopAttempt = attempt;
            return error is not null
                ? new TaskServiceCancelTaskResponse { Meta = Meta(request.Meta), Error = error }
                : new TaskServiceCancelTaskResponse
                {
                    Meta = Meta(request.Meta),
                    Value = new TaskServiceCancelTaskValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened }, State = state },
                };
        }, gate).ConfigureAwait(false);
        if (!replayed && stopAttempt is not null)
        {
            await Execution.StopAsync(stopAttempt, TerminationReason.Cancelled, request.HasGraceMs ? TimeSpan.FromMilliseconds(request.GraceMs) : null).ConfigureAwait(false);
        }

        if (!replayed && result.OutcomeCase == TaskServiceCancelTaskResponse.OutcomeOneofCase.Value)
        {
            Execution.Kick();
            _node.Log.Info("api.task.cancel", new LogField("task", IdText.Format(id)), new LogField("origin", caller.Origin),
                new LogField("running", stopAttempt is not null));
        }

        return result;
    }

    /// <inheritdoc />
    public override Task<TaskServiceRetryTaskResponse> RetryTask(TaskServiceRetryTaskRequest request, ServerCallContext context) =>
        RetryTask(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary>
    /// <c>RetryTask</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester): <c>task.retry</c>, ALLOW for every
    /// origin except an AGENT's retry of a SIDE_EFFECTING or UNKNOWN task, which needs an approval (tasks.proto).
    /// </summary>
    internal async Task<TaskServiceRetryTaskResponse> RetryTask(TaskServiceRetryTaskRequest request, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new TaskServiceRetryTaskResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.TaskId, "task_id");
        if (refused is null && request.HasReason && request.Reason.Length > 500)
        {
            refused = NodeErrors.InvalidArgument("reason: <= 500 chars");
        }

        if (refused is null && request.OverrideDemand is { } demand)
        {
            var maxTask = Execution.Settings.MaxTaskMemory;
            if ((demand.HasMemExpectedBytes && (demand.MemExpectedBytes < 1024 * 1024 || (long)demand.MemExpectedBytes > maxTask))
                || (demand.HasMemCeilingBytes && ((long)demand.MemCeilingBytes > maxTask || (demand.HasMemExpectedBytes && demand.MemCeilingBytes < demand.MemExpectedBytes)))
                || (demand.HasCpuMillicores && demand.CpuMillicores is < 1 or > 1_024_000))
            {
                refused = NodeErrors.InvalidArgument("override_demand: mem_expected_bytes 1 MiB..max_task_memory, mem_ceiling_bytes >= mem_expected_bytes and <= max_task_memory, cpu 1..1,024,000");
            }
        }

        GateRequest? gate = null;
        if (refused is null)
        {
            var row = _node.Store.Read(reader => TaskRecords.GetRow(reader, request.TaskId.Value.Span));
            gate = new GateRequest(PermissionMatrix.TaskRetry, "TaskService.RetryTask",
                "retry task " + IdText.Format(request.TaskId) + (row is null ? string.Empty : " (" + row.SideEffect.ToString().ToUpperInvariant() + ")"), "task", Bytes(request.TaskId))
            {
                AgentApproval = row is { SideEffect: SideEffectClass.SideEffecting or SideEffectClass.Unknown },
                AgentApprovalReason = "an AGENT's retry of a SIDE_EFFECTING or UNKNOWN task needs approval (tasks.proto RetryTask)",
            };
            refused = await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var id = request.TaskId.Value.ToByteArray();
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "RetryTask", TaskServiceRetryTaskResponse.Parser,
            failure => new TaskServiceRetryTaskResponse { Meta = Meta(request.Meta), Error = failure }, command =>
        {
            var (value, error) = Execution.Retry(command, id, request.Meta.CommandId, request.OverrideDemand);
            return error is not null
                ? new TaskServiceRetryTaskResponse { Meta = Meta(request.Meta), Error = error }
                : new TaskServiceRetryTaskResponse { Meta = Meta(request.Meta), Value = value };
        }, gate).ConfigureAwait(false);
        if (!replayed && result.OutcomeCase == TaskServiceRetryTaskResponse.OutcomeOneofCase.Value)
        {
            Execution.Kick();
        }

        return result;
    }

    /// <inheritdoc />
    public override Task<TaskServiceSetTaskPriorityResponse> SetTaskPriority(TaskServiceSetTaskPriorityRequest request, ServerCallContext context) =>
        SetTaskPriority(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))));

    /// <summary><c>SetTaskPriority</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<TaskServiceSetTaskPriorityResponse> SetTaskPriority(TaskServiceSetTaskPriorityRequest request, Caller caller)
    {
        try
        {
            return await SetTaskPriorityOnce(request, caller, allowSettled: true).ConfigureAwait(false);
        }
        catch (GateStaleException)
        {
            return await SetTaskPriorityOnce(request, caller, allowSettled: false).ConfigureAwait(false);
        }
    }

    private async Task<TaskServiceSetTaskPriorityResponse> SetTaskPriorityOnce(TaskServiceSetTaskPriorityRequest request, Caller caller, bool allowSettled)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new TaskServiceSetTaskPriorityResponse { Meta = Meta(request.Meta) };
        var origin = caller.Origin;
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.TaskId, "task_id");
        if (refused is null && !request.HasPriority && !request.HasPool)
        {
            refused = NodeErrors.InvalidArgument("priority or pool: at least one");
        }

        if (refused is null && request.HasPriority && (request.Priority == Priority.Unspecified || !Enum.IsDefined(request.Priority)))
        {
            refused = NodeErrors.InvalidArgument("priority: INTERACTIVE, HIGH, NORMAL, LOW or BACKGROUND");
        }

        if (refused is null && request.Priority == Priority.Interactive && origin != Origin.Human)
        {
            refused = NodeErrors.PermissionDenied("SetTaskPriority.priority INTERACTIVE (HUMAN origin or a session grant)");
        }

        if (refused is null && request.HasPool && !Execution.Settings.Pools.Contains(request.Pool, StringComparer.Ordinal))
        {
            refused = NodeErrors.InvalidArgument("pool: an existing pool");
        }

        var summary = "change the priority of task" + (request.HasPriority ? " to " + request.Priority.ToString().ToUpperInvariant() : string.Empty)
            + (request.HasPool ? " (pool " + request.Pool + ")" : string.Empty);
        var gate = new GateRequest(PermissionMatrix.TaskSetPriority, "TaskService.SetTaskPriority", summary + " " + IdText.Format(request.TaskId), "task",
            Bytes(request.TaskId));
        var settled = allowSettled && refused is null && Settled(request.TaskId);
        if (!settled)
        {
            refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
            if (refused is null && TaskGate(request.TaskId!, "TaskService.SetTaskPriority", summary) is { } others)
            {
                refused = await _api.GateAsync(caller, others, request, request.Meta).ConfigureAwait(false);
            }
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var id = request.TaskId.Value.ToByteArray();
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "SetTaskPriority", TaskServiceSetTaskPriorityResponse.Parser,
            failure => new TaskServiceSetTaskPriorityResponse { Meta = Meta(request.Meta), Error = failure }, command =>
            {
                EnsureStillSettled(command, id, settled);
                var (queue, error) = Execution.SetPriority(command, id, request.HasPriority ? request.Priority : null, request.HasPool ? request.Pool : null);
                return error is not null
                    ? new TaskServiceSetTaskPriorityResponse { Meta = Meta(request.Meta), Error = error }
                    : new TaskServiceSetTaskPriorityResponse
                    {
                        Meta = Meta(request.Meta),
                        Value = new TaskServiceSetTaskPriorityValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened }, Queue = queue },
                    };
            }, settled ? null : gate).ConfigureAwait(false);
        if (!replayed && result.OutcomeCase == TaskServiceSetTaskPriorityResponse.OutcomeOneofCase.Value)
        {
            Execution.Kick();
        }

        return result;
    }

    /// <summary>
    /// The matrix operation of acting on a task that is not simply the caller's own (11 section 1), or <see langword="null"/>: a task an agent
    /// session owns belongs to that session, and until connections carry sessions (AF-AI-01) no SCRIPT or AGENT caller is that session, so it is
    /// another owner's task (<c>task.cancel_others</c>: HUMAN A, SCRIPT and AGENT P); an ADOPTED task is a process the user placed under
    /// management, so ending it is terminating a process (<c>process.terminate</c>: HUMAN A, SCRIPT and AGENT P).
    /// </summary>
    /// <summary>
    /// True when the task does not exist or already ended: an action on it changes nothing (the execution answers with the state or the
    /// error), so no approval is raised for it (review round 1).
    /// </summary>
    private bool Settled(Id taskId) =>
        _node.Store.Read(reader => TaskRecords.GetRow(reader, taskId.Value.Span)) is not { Purged: false } row || row.Terminal;

    /// <summary>
    /// Review round 2: when the gate was skipped because the task had ended (or did not exist), that is checked again inside the command; a
    /// task re-queued in between makes the command stop before it acts (nothing is stored), and the handler checks the request again with the
    /// gate.
    /// </summary>
    private static void EnsureStillSettled(CommandContext command, byte[] taskId, bool settled)
    {
        if (settled && TaskRecords.GetRow(command.Transaction, taskId) is { Purged: false } row && !row.Terminal)
        {
            throw new GateStaleException("the task changed after the gate's check");
        }
    }

    private GateRequest? TaskGate(Id taskId, string method, string summary)
    {
        var id = taskId.Value.ToByteArray();
        var (owned, kind) = _node.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT owner_session_id, kind FROM task WHERE task_id = $id;");
            command.Parameters.AddWithValue("$id", id);
            using var rows = command.ExecuteReader();
            return rows.Read() ? (!rows.IsDBNull(0), (TaskKind)rows.GetInt32(1)) : (false, TaskKind.Unspecified);
        });
        var text = summary + " " + IdText.Format(id);
        return kind == TaskKind.Adopted && method == "TaskService.CancelTask"
            ? new GateRequest(PermissionMatrix.ProcessTerminate, method, text + " (an adopted process: ending it terminates the process)", "task", id)
            : owned ? new GateRequest(PermissionMatrix.TaskCancelOthers, method, text + " (owned by an agent session)", "task", id) : null;
    }

    /// <inheritdoc />
    public override Task<TaskServicePauseTaskResponse> PauseTask(TaskServicePauseTaskRequest request, ServerCallContext context) =>
        PauseTask(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))), context.CancellationToken);

    /// <summary><c>PauseTask</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<TaskServicePauseTaskResponse> PauseTask(TaskServicePauseTaskRequest request, Caller caller, CancellationToken cancellationToken)
    {
        try
        {
            return await PauseTaskOnce(request, caller, allowSettled: true, cancellationToken).ConfigureAwait(false);
        }
        catch (GateStaleException)
        {
            return await PauseTaskOnce(request, caller, allowSettled: false, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<TaskServicePauseTaskResponse> PauseTaskOnce(TaskServicePauseTaskRequest request, Caller caller, bool allowSettled, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new TaskServicePauseTaskResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.TaskId, "task_id");
        var gate = new GateRequest(PermissionMatrix.TaskPause, "TaskService.PauseTask", "pause task " + IdText.Format(request.TaskId), "task", Bytes(request.TaskId));
        var settled = allowSettled && refused is null && Settled(request.TaskId);
        if (!settled)
        {
            refused ??= await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
            if (refused is null && TaskGate(request.TaskId!, "TaskService.PauseTask", "pause task") is { } others)
            {
                refused = await _api.GateAsync(caller, others, request, request.Meta).ConfigureAwait(false);
            }
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var id = request.TaskId.Value.ToByteArray();
        var done = Task.CompletedTask;
        var (result, _) = await _api.IdempotentAsync(request, request.Meta, caller, "PauseTask", TaskServicePauseTaskResponse.Parser,
            failure => new TaskServicePauseTaskResponse { Meta = Meta(request.Meta), Error = failure }, command =>
            {
                EnsureStillSettled(command, id, settled);
                return Execution.PauseTask(command.Transaction, id, out done) is { } error
                    ? new TaskServicePauseTaskResponse { Meta = Meta(request.Meta), Error = error }
                    : new TaskServicePauseTaskResponse
                    {
                        Meta = Meta(request.Meta),
                        Value = new TaskServicePauseTaskValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened }, State = TaskState.Paused },
                    };
            }, settled ? null : gate).ConfigureAwait(false);
        await Task.WhenAny(done, Task.Delay(TimeSpan.FromSeconds(8), cancellationToken)).ConfigureAwait(false);
        return result;
    }

    /// <inheritdoc />
    public override Task<TaskServiceResumeTaskResponse> ResumeTask(TaskServiceResumeTaskRequest request, ServerCallContext context) =>
        ResumeTask(request, _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context))), context.CancellationToken);

    /// <summary><c>ResumeTask</c> for <paramref name="caller"/> (a connection's caller, or an approval's requester).</summary>
    internal async Task<TaskServiceResumeTaskResponse> ResumeTask(TaskServiceResumeTaskRequest request, Caller caller, CancellationToken cancellationToken)
    {
        try
        {
            return await ResumeTaskOnce(request, caller, allowSettled: true, cancellationToken).ConfigureAwait(false);
        }
        catch (GateStaleException)
        {
            return await ResumeTaskOnce(request, caller, allowSettled: false, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<TaskServiceResumeTaskResponse> ResumeTaskOnce(TaskServiceResumeTaskRequest request, Caller caller, bool allowSettled, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);
        var response = new TaskServiceResumeTaskResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.TaskId, "task_id");
        var settled = allowSettled && refused is null && Settled(request.TaskId);
        var gate = refused is null && !settled ? TaskGate(request.TaskId, "TaskService.ResumeTask", "resume task") : null;
        if (gate is not null)
        {
            refused = await _api.GateAsync(caller, gate, request, request.Meta).ConfigureAwait(false);
        }

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var id = request.TaskId.Value.ToByteArray();
        var done = Task.CompletedTask;
        var (result, _) = await _api.IdempotentAsync(request, request.Meta, caller, "ResumeTask", TaskServiceResumeTaskResponse.Parser,
            failure => new TaskServiceResumeTaskResponse { Meta = Meta(request.Meta), Error = failure }, command =>
            {
                EnsureStillSettled(command, id, settled);
                return Execution.ResumeTask(command.Transaction, id, out done) is { } error
                    ? new TaskServiceResumeTaskResponse { Meta = Meta(request.Meta), Error = error }
                    : new TaskServiceResumeTaskResponse
                    {
                        Meta = Meta(request.Meta),
                        Value = new TaskServiceResumeTaskValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened }, State = TaskState.Running },
                    };
            }, gate).ConfigureAwait(false);
        await Task.WhenAny(done, Task.Delay(TimeSpan.FromSeconds(8), cancellationToken)).ConfigureAwait(false);
        return result;
    }

    /// <inheritdoc />
    public override async Task<TaskServicePinTaskResponse> PinTask(TaskServicePinTaskRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new TaskServicePinTaskResponse { Meta = Meta(request.Meta) };
        if ((Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.TaskId, "task_id")) is { } refused)
        {
            response.Error = refused;
            return response;
        }

        var id = request.TaskId.Value.ToByteArray();
        var pinned = !request.HasPinned || request.Pinned;
        var (result, _) = await Idempotent(request, request.Meta, context, "PinTask", TaskServicePinTaskResponse.Parser,
            failure => new TaskServicePinTaskResponse { Meta = Meta(request.Meta), Error = failure }, command =>
                Execution.Pin(command, id, pinned) is { } error
                    ? new TaskServicePinTaskResponse { Meta = Meta(request.Meta), Error = error }
                    : new TaskServicePinTaskResponse
                    {
                        Meta = Meta(request.Meta),
                        Value = new TaskServicePinTaskValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened } },
                    }).ConfigureAwait(false);
        return result;
    }

    /// <inheritdoc />
    public override async Task<TaskServicePurgeTaskRecordResponse> PurgeTaskRecord(TaskServicePurgeTaskRecordRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new TaskServicePurgeTaskRecordResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.CommandId(request.Meta) ?? Validation.RequiredId(request.TaskId, "task_id");
        var caller = _api.CallerOf(context);
        var gate = new GateRequest(PermissionMatrix.TaskPurge, "TaskService.PurgeTaskRecord", "purge the record of task " + IdText.Format(request.TaskId), "task",
            Bytes(request.TaskId));

        // tasks.proto: HUMAN=A SCRIPT=D AGENT=D.
        refused ??= await _api.DenyUnlessAllowedAsync(caller, gate, request, request.Meta).ConfigureAwait(false);

        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var id = request.TaskId.Value.ToByteArray();
        List<string> directories = [];
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, caller, "PurgeTaskRecord", TaskServicePurgeTaskRecordResponse.Parser,
            failure => new TaskServicePurgeTaskRecordResponse { Meta = Meta(request.Meta), Error = failure }, command =>
        {
            var (paths, error) = Execution.Purge(command, id);
            directories = paths;
            return error is not null
                ? new TaskServicePurgeTaskRecordResponse { Meta = Meta(request.Meta), Error = error }
                : new TaskServicePurgeTaskRecordResponse
                {
                    Meta = Meta(request.Meta),
                    Value = new TaskServicePurgeTaskRecordValue { Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened } },
                };
        }, gate).ConfigureAwait(false);
        if (!replayed)
        {
            foreach (var directory in directories)
            {
                try
                {
                    if (Directory.Exists(directory))
                    {
                        Directory.Delete(directory, recursive: true);
                    }
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    _node.Log.Warning("api.task.purge_files_failed", new LogField("errorType", exception.GetType().Name));
                }
            }
        }

        return result;
    }

    /// <inheritdoc />
    public override Task<TaskServiceReadTaskOutputResponse> ReadTaskOutput(TaskServiceReadTaskOutputRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new TaskServiceReadTaskOutputResponse { Meta = Meta(request.Meta) };
        var refused = Stopping() ?? Validation.RequiredId(request.AttemptId, "attempt_id");
        if (refused is null && request.HasMaxBytes && request.MaxBytes is < 1 or > 4 * 1024 * 1024)
        {
            refused = NodeErrors.InvalidArgument("max_bytes: 1..4 MiB");
        }

        if (refused is null && request.HasStream && (request.Stream == OutputStream.Unspecified || !Enum.IsDefined(request.Stream)))
        {
            refused = NodeErrors.InvalidArgument("stream: STDOUT, STDERR or MERGED");
        }

        if (refused is not null)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var id = request.AttemptId.Value.ToByteArray();
        var attempt = _node.Store.Read(reader => TaskRecords.GetAttempt(reader, id));
        if (attempt is null)
        {
            response.Error = NodeErrors.NotFound("attempt", id);
            return Task.FromResult(response);
        }

        var name = IdText.Format(id);
        var finished = attempt.State == AttemptState.Finished && Execution.Running(name) is null;
        // A response must fit the 4 MiB message bound with its index records, so a read returns at most 4 MiB - 256 KiB of data.
        var maxBytes = Math.Min(request.HasMaxBytes ? (int)request.MaxBytes : 256 * 1024, (4 * 1024 * 1024) - (256 * 1024));
        var value = OutputReader.Read(new AttemptFiles(_node.DataRoot, name), request.HasStream ? request.Stream : OutputStream.Merged, request.FromOffset,
            maxBytes, finished);
        value.TruncatedByRetention = _node.Store.Read(reader => reader.Scalar("SELECT output_purged FROM attempt WHERE attempt_id = $id;", ("$id", id)) is 1L);
        response.Value = value;
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task WatchTaskOutput(TaskServiceWatchTaskOutputRequest request, IServerStreamWriter<TaskServiceWatchTaskOutputFrame> responseStream,
        ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        _node.CountCall();
        var writer = context.OpenLocalRpcStream(responseStream);
        await using (writer.ConfigureAwait(false))
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(writer.Ended, context.CancellationToken, _node.Stopping);
            var refused = (_node.Lifecycle.IsStopping ? NodeErrors.NodeStopping(_node.Clock.GetUtcNow()) : null) ?? Validation.RequiredId(request.AttemptId, "attempt_id");
            var id = refused is null ? request.AttemptId.Value.ToByteArray() : [];
            var attempt = refused is null ? _node.Store.Read(reader => TaskRecords.GetAttempt(reader, id)) : null;
            if (refused is null && attempt is null)
            {
                refused = NodeErrors.NotFound("attempt", id);
            }

            if (refused is not null)
            {
                writer.TryWrite(new TaskServiceWatchTaskOutputFrame { Meta = new ResponseMeta(), Error = refused });
                await writer.CompleteAsync().ConfigureAwait(false);
                return;
            }

            var stream = request.HasStream ? request.Stream : OutputStream.Merged;
            var name = IdText.Format(id);
            var files = new AttemptFiles(_node.DataRoot, name);
            var pulse = Execution.TaskPulse(attempt!.TaskId.Value.Span);
            var from = (long)request.FromOffset;
            var cursor = new OutputCursor(0, stream == OutputStream.Stdout ? from : stream == OutputStream.Stderr ? long.MaxValue : 0,
                stream == OutputStream.Stderr ? from : stream == OutputStream.Stdout ? long.MaxValue : 0);
            long merged = 0;
            var lastWrite = _node.Clock.GetTimestamp();
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var next = pulse.Next;
                    var running = Execution.Running(name) is not null;
                    var (slices, following, atEnd) = OutputReader.Follow(files, cursor, FollowBudget);
                    cursor = following;
                    foreach (var slice in slices)
                    {
                        if (stream == OutputStream.Merged && merged + slice.Data.Length <= from)
                        {
                            merged += slice.Data.Length;
                            continue;
                        }

                        var data = slice;
                        if (stream == OutputStream.Merged && merged < from)
                        {
                            var skip = (int)(from - merged);
                            data = slice with { Offset = slice.Offset + skip, Data = slice.Data[skip..] };
                        }

                        merged += slice.Data.Length;
                        await WaitForRoomAsync(writer, stop.Token).ConfigureAwait(false);
                        writer.TryWrite(new TaskServiceWatchTaskOutputFrame { Meta = new ResponseMeta(), Output = Chunk(attempt.AttemptId, data) });
                        lastWrite = _node.Clock.GetTimestamp();
                    }

                    if (!atEnd)
                    {
                        // More index to read (possibly records this follower skips): only the end of the index means caught up.
                        continue;
                    }

                    var current = _node.Store.Read(reader => TaskRecords.GetAttempt(reader, id));
                    if (current is { State: AttemptState.Finished } && !running)
                    {
                        writer.TryWrite(new TaskServiceWatchTaskOutputFrame { Meta = new ResponseMeta(), Result = current.Result ?? new AttemptResult() });
                        break;
                    }

                    if (_node.Clock.GetElapsedTime(lastWrite) >= HeartbeatInterval)
                    {
                        writer.TryWrite(new TaskServiceWatchTaskOutputFrame
                        {
                            Meta = new ResponseMeta(),
                            Heartbeat = new Heartbeat { At = ProtoTime.ToInstant(_node.Clock.GetUtcNow()) },
                        });
                        lastWrite = _node.Clock.GetTimestamp();
                    }

                    await Task.WhenAny(next, Task.Delay(TimeSpan.FromSeconds(1), stop.Token)).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
            }

            await writer.CompleteAsync().ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public override Task<TaskServiceGetAttemptResponse> GetAttempt(TaskServiceGetAttemptRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new TaskServiceGetAttemptResponse { Meta = Meta(request.Meta) };
        if ((Stopping() ?? Validation.RequiredId(request.AttemptId, "attempt_id")) is { } refused)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var id = request.AttemptId.Value.ToByteArray();
        var attempt = _node.Store.Read(reader => TaskRecords.GetAttempt(reader, id));
        if (attempt is null)
        {
            response.Error = NodeErrors.NotFound("attempt", id);
        }
        else
        {
            response.Value = new TaskServiceGetAttemptValue { Attempt = attempt };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<TaskServiceListAttemptsResponse> ListAttempts(TaskServiceListAttemptsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new TaskServiceListAttemptsResponse { Meta = Meta(request.Meta) };
        if ((Stopping() ?? Validation.RequiredId(request.TaskId, "task_id")) is { } refused)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var id = request.TaskId.Value.ToByteArray();
        var (exists, attempts) = _node.Store.Read(reader => (TaskRecords.GetRow(reader, id) is not null, TaskRecords.ListAttempts(reader, id)));
        if (!exists)
        {
            response.Error = NodeErrors.NotFound("task", id);
        }
        else
        {
            response.Value = new TaskServiceListAttemptsValue();
            response.Value.Attempts.Add(attempts);
        }

        return Task.FromResult(response);
    }

    /// <summary>The command line a <c>retry_safety</c> pattern is matched against: the argument vector joined by spaces, or the shell script.</summary>
    internal static string CommandLine(CommandSpec command) =>
        command.FormCase == CommandSpec.FormOneofCase.Argv ? string.Join(' ', command.Argv.Argv) : command.Shell?.Script ?? string.Empty;

    /// <summary>The digest of an environment spec (inherit mode, caller environment, set and unset, in canonical order).</summary>
    internal static byte[] EnvironmentDigest(EnvironmentSpec? environment)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Add(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            hash.AppendData(BitConverter.GetBytes(bytes.Length));
            hash.AppendData(bytes);
        }

        Add("arcforges.environment-digest.v1");
        Add(((int)(environment?.Inherit ?? EnvironmentInherit.Unspecified)).ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var (name, map) in (ReadOnlySpan<(string, Google.Protobuf.Collections.MapField<string, string>?)>)[("caller", environment?.CallerEnvironment), ("set", environment?.Set)])
        {
            Add(name);
            foreach (var pair in (map ?? []).OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                Add(pair.Key);
                Add(pair.Value);
            }
        }

        Add("unset");
        foreach (var name in (environment?.Unset ?? []).Order(StringComparer.Ordinal))
        {
            Add(name);
        }

        return hash.GetHashAndReset();
    }

    private static OutputChunk Chunk(Id attemptId, OutputSlice slice) => new()
    {
        AttemptId = attemptId,
        Stream = slice.Stream == OutputStreamKind.Stdout ? OutputStream.Stdout : OutputStream.Stderr,
        Offset = (ulong)slice.Offset,
        Data = ByteString.CopyFrom(slice.Data),
        UnixNanos = slice.UnixNanos,
    };

    private static string? AttemptName(ManagedTask task) => task.CurrentAttempt?.AttemptId is { } id ? IdText.Format(id) : null;

    private static async Task<bool> ClaimStdinAsync(ExecutionSupervisor execution, byte[] taskId, string attachId, CancellationToken cancellationToken)
    {
        // The attempt may still be launching: the claim succeeds once its stdin pipe exists.
        for (var tries = 0; tries < 20; tries++)
        {
            if (execution.ClaimStdin(taskId, attachId))
            {
                return true;
            }

            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    private static async Task WaitForRoomAsync<T>(LocalRpcStreamWriter<T> writer, CancellationToken cancellationToken)
        where T : class
    {
        while (writer.Buffered >= 256)
        {
            await Task.Delay(2, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>The bytes of an optional ID (audit targets, before validation decided).</summary>
    private static byte[]? Bytes(Id? id) => id?.Value.ToByteArray();

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

    private async Task<(TResponse Response, bool Replayed)> Idempotent<TResponse>(IMessage request, RequestMeta meta, ServerCallContext context, string method,
        MessageParser<TResponse> parser, Func<ArcError, TResponse> fail, Func<CommandContext, TResponse> execute)
        where TResponse : class, IMessage<TResponse>
    {
        var digest = PayloadDigest.Compute(request);
        var origin = _sessions.OriginOf(context);
        var (outcome, error) = await Run(() => _node.Processor.ExecuteIdempotentAsync(meta.CommandId.Value.Memory, ServiceName + "/" + method, digest, origin,
            command => execute(command).ToByteArray())).ConfigureAwait(false);
        if ((error ?? outcome.Error) is { } failure)
        {
            return (fail(failure), false);
        }

        return (parser.ParseFrom(outcome.Outcome), outcome.Replayed);
    }
}
