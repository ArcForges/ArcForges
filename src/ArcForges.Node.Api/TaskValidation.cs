// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Execution;

namespace ArcForges.Node.Api;

/// <summary>
/// The <c>validate:</c> rules of <c>TaskSpec</c> (architecture 04 section 1; tasks.proto), run in the API layer before a command is
/// accepted: a violation is <c>ERROR_CATEGORY_VALIDATION</c> with <c>code</c> naming the field and <c>effect=DID_NOT_HAPPEN</c>. Fields
/// whose behaviour belongs to later tasks are refused rather than ignored: remote placement (LAN tasks), workspace IDs (AF-WS-01) and
/// sessions (AF-AI-01). Dependencies that name an unknown task are refused by the handler, which reads the store (<c>invalid_dependency</c>).
/// </summary>
internal static class TaskValidation
{
    private const int MiB = 1024 * 1024;
    private const ulong MaxTimeoutMs = 30UL * 24 * 60 * 60 * 1000;

    /// <summary>Validates a submission; returns the first violation, or <see langword="null"/>.</summary>
    public static ArcError? Submit(TaskServiceSubmitTaskRequest request, Origin origin, ExecutionSettings settings, ReadOnlySpan<byte> nodeId,
        CapabilityReport capabilities)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(settings);
        if (request.Spec is not { } spec)
        {
            return NodeErrors.InvalidArgument("spec: required");
        }

        if (request.SessionId is { Value.Length: > 0 })
        {
            return NodeErrors.InvalidArgument("session_id: no active session with this ID (sessions arrive with AF-AI-01)");
        }

        if (request.HasAgentId)
        {
            return NodeErrors.InvalidArgument("agent_id: requires session_id");
        }

        return Command(spec.Command) ?? WorkingDirectory(spec) ?? Environment(spec.Environment) ?? Stdin(spec.Stdin) ?? Limits(spec, origin, settings)
            ?? Shape(spec, nodeId) ?? Resources(spec.Resources, settings, capabilities) ?? Output(spec);
    }

    private static ArcError? Command(CommandSpec? command)
    {
        switch (command?.FormCase)
        {
            case CommandSpec.FormOneofCase.Argv:
                var argv = command.Argv.Argv;
                if (argv.Count is < 1 or > 4096 || argv[0].Length == 0)
                {
                    return NodeErrors.InvalidArgument("command.argv: 1..4096 elements; argv[0] non-empty");
                }

                if (argv.Sum(argument => (long)Encoding.UTF8.GetByteCount(argument)) > MiB)
                {
                    return NodeErrors.InvalidArgument("command.argv: total <= 1 MiB");
                }

                return null;
            case CommandSpec.FormOneofCase.Shell:
                var shell = command.Shell;
                if (!shell.HasKind || shell.Kind == ShellKind.Unspecified || !Enum.IsDefined(shell.Kind))
                {
                    return NodeErrors.InvalidArgument("command.shell.kind: required");
                }

                if (!shell.HasScript || shell.Script.Length == 0 || Encoding.UTF8.GetByteCount(shell.Script) > MiB)
                {
                    return NodeErrors.InvalidArgument("command.shell.script: 1 byte..1 MiB");
                }

                if (shell.HasShellPath && !Path.IsPathFullyQualified(shell.ShellPath))
                {
                    return NodeErrors.InvalidArgument("command.shell.shell_path: absolute path");
                }

                return null;
            default:
                return NodeErrors.InvalidArgument("command: required; exactly one form");
        }
    }

    private static ArcError? WorkingDirectory(TaskSpec spec)
    {
        if (!spec.HasWorkingDirectory || spec.WorkingDirectory.Length == 0 || !Path.IsPathFullyQualified(spec.WorkingDirectory))
        {
            return NodeErrors.InvalidArgument("working_directory: absolute path required");
        }

        return Directory.Exists(spec.WorkingDirectory) ? null : NodeErrors.Validation("path_not_found", "working_directory");
    }

    private static ArcError? Environment(EnvironmentSpec? environment)
    {
        if (environment is null)
        {
            return null;
        }

        if (environment.HasInherit && (environment.Inherit == EnvironmentInherit.Unspecified || !Enum.IsDefined(environment.Inherit)))
        {
            return NodeErrors.InvalidArgument("environment.inherit: NONE, CALLER or NODE");
        }

        if (environment.Set.Count > 4096 || environment.Unset.Count > 4096 || environment.CallerEnvironment.Count > 4096)
        {
            return NodeErrors.InvalidArgument("environment: <= 4096 entries in set, unset and caller_environment");
        }

        foreach (var name in environment.Set.Keys.Concat(environment.Unset).Concat(environment.CallerEnvironment.Keys))
        {
            if (name.Length == 0 || name.Contains('=', StringComparison.Ordinal) || name.Contains('\0', StringComparison.Ordinal))
            {
                return NodeErrors.InvalidArgument("environment: variable names are non-empty and contain no '='");
            }
        }

        if (Size(environment.Set) > MiB || Size(environment.CallerEnvironment) > MiB)
        {
            return NodeErrors.InvalidArgument("environment: set and caller_environment total <= 1 MiB each");
        }

        if (environment.Set.Values.Concat(environment.CallerEnvironment.Values).Any(value => value.Contains('\0', StringComparison.Ordinal)))
        {
            return NodeErrors.InvalidArgument("environment: values contain no NUL");
        }

        if (environment.Inherit == EnvironmentInherit.Caller && environment.CallerEnvironment.Count == 0)
        {
            return NodeErrors.InvalidArgument("environment.caller_environment: required when inherit = CALLER");
        }

        return null;
    }

    private static ArcError? Stdin(StdinSpec? stdin)
    {
        if (stdin is null)
        {
            return null;
        }

        if (stdin.HasMode && (stdin.Mode == StdinMode.Unspecified || !Enum.IsDefined(stdin.Mode)))
        {
            return NodeErrors.InvalidArgument("stdin.mode: NONE, BYTES, FILE or STREAM");
        }

        if (stdin.HasData && stdin.Mode != StdinMode.Bytes)
        {
            return NodeErrors.InvalidArgument("stdin.data: BYTES only");
        }

        if (stdin.Data.Length > MiB)
        {
            return NodeErrors.InvalidArgument("stdin.data: <= 1 MiB");
        }

        if (stdin.Mode == StdinMode.File)
        {
            if (!stdin.HasFilePath || !Path.IsPathFullyQualified(stdin.FilePath))
            {
                return NodeErrors.InvalidArgument("stdin.file_path: absolute path required for FILE");
            }

            if (!File.Exists(stdin.FilePath))
            {
                return NodeErrors.Validation("path_not_found", "stdin.file_path");
            }
        }
        else if (stdin.HasFilePath)
        {
            return NodeErrors.InvalidArgument("stdin.file_path: FILE only");
        }

        return null;
    }

    private static ArcError? Limits(TaskSpec spec, Origin origin, ExecutionSettings settings)
    {
        if (spec.HasTimeoutMs && spec.TimeoutMs is < 1000 or > MaxTimeoutMs)
        {
            return NodeErrors.InvalidArgument("timeout_ms: 1 s..30 days");
        }

        if (spec.HasCpuTimeLimitMs && spec.CpuTimeLimitMs < 1000)
        {
            return NodeErrors.InvalidArgument("cpu_time_limit_ms: >= 1 s");
        }

        if (spec.HasPriority && (spec.Priority == Priority.Unspecified || !Enum.IsDefined(spec.Priority)))
        {
            return NodeErrors.InvalidArgument("priority: INTERACTIVE, HIGH, NORMAL, LOW or BACKGROUND");
        }

        if (spec.Priority == Priority.Interactive && origin != Origin.Human)
        {
            return NodeErrors.PermissionDenied("SubmitTask.priority INTERACTIVE (HUMAN origin or a session grant)");
        }

        if (spec.HasPool && !settings.Pools.Contains(spec.Pool, StringComparer.Ordinal))
        {
            return NodeErrors.InvalidArgument("pool: an existing pool");
        }

        if (spec.HasSideEffect && (spec.SideEffect == SideEffectClass.Unspecified || !Enum.IsDefined(spec.SideEffect)))
        {
            return NodeErrors.InvalidArgument("side_effect: PURE, IDEMPOTENT, SIDE_EFFECTING or UNKNOWN");
        }

        if (spec.Retry is { HasMaxAttempts: true, MaxAttempts: < 1 or > 5 })
        {
            return NodeErrors.InvalidArgument("retry.max_attempts: 1..5");
        }

        return null;
    }

    private static ArcError? Shape(TaskSpec spec, ReadOnlySpan<byte> nodeId)
    {
        if (spec.HasKind && spec.Kind is not (TaskKind.Command or TaskKind.Service))
        {
            return NodeErrors.InvalidArgument("kind: COMMAND or SERVICE");
        }

        var service = spec.Kind == TaskKind.Service;
        if (!service && (spec.Readiness is not null || spec.HasStopWithSession || spec.HasDetach))
        {
            return NodeErrors.InvalidArgument("readiness, stop_with_session, detach: SERVICE only");
        }

        if (spec.DependsOn.Count > 64)
        {
            return NodeErrors.InvalidArgument("depends_on: <= 64 dependencies");
        }

        var dependencies = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < spec.DependsOn.Count; index++)
        {
            var dependency = spec.DependsOn[index];
            if (dependency.TaskId is not { Value.Length: 16 } dependencyId)
            {
                return NodeErrors.InvalidDependency([], $"depends_on[{index}].task_id: required");
            }

            if (dependency.HasCondition && (dependency.Condition == DependencyCondition.Unspecified || !Enum.IsDefined(dependency.Condition)))
            {
                return NodeErrors.InvalidArgument($"depends_on[{index}].condition: SUCCEEDED, FINISHED or READY");
            }

            if (!dependencies.Add(Convert.ToHexString(dependencyId.Value.Span)))
            {
                return NodeErrors.InvalidDependency(dependencyId.Value.Span, $"depends_on[{index}]: the task is listed twice");
            }
        }

        if (spec.Concurrency is { } concurrency)
        {
            if (concurrency.HasAccess && !Enum.IsDefined(concurrency.Access))
            {
                return NodeErrors.InvalidArgument("concurrency.access: SHARED or EXCLUSIVE");
            }

            if (ArcForges.Node.Core.Scheduling.KeyHolders.FromSpec(concurrency.ExclusiveKeys, concurrency.SharedKeys).Error is { } keyError)
            {
                return NodeErrors.InvalidArgument(keyError);
            }
        }

        if (spec.Readiness is { } readiness)
        {
            switch (readiness.ConditionCase)
            {
                case ReadinessCondition.ConditionOneofCase.OutputRegex:
                    if (readiness.OutputRegex.Length is 0 or > 1024)
                    {
                        return NodeErrors.InvalidArgument("readiness.output_regex: 1..1024 chars");
                    }

                    try
                    {
                        _ = ArcForges.Node.Core.Scheduling.ServiceReadiness.Compile(readiness.OutputRegex);
                    }
                    catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
                    {
                        return NodeErrors.InvalidArgument("readiness.output_regex: an RE2-compatible pattern (" + NodeLog.OneLine(exception.Message) + ")");
                    }

                    break;
                case ReadinessCondition.ConditionOneofCase.TcpListenPort:
                    if (readiness.TcpListenPort is < 1 or > 65_535)
                    {
                        return NodeErrors.InvalidArgument("readiness.tcp_listen_port: 1..65535");
                    }

                    break;
                case ReadinessCondition.ConditionOneofCase.FileExists:
                    if (!Path.IsPathFullyQualified(readiness.FileExists))
                    {
                        return NodeErrors.InvalidArgument("readiness.file_exists: absolute path");
                    }

                    break;
            }

            if (readiness.HasReadinessTimeoutMs && readiness.ReadinessTimeoutMs is < 1_000 or > 3_600_000)
            {
                return NodeErrors.InvalidArgument("readiness.readiness_timeout_ms: 1 s..1 h");
            }
        }

        if (spec.Placement is { } placement)
        {
            var local = !placement.HasMode || placement.Mode == PlacementMode.LocalOnly
                || (placement.Mode == PlacementMode.SpecificNode && placement.NodeId is { } node && node.Value.Span.SequenceEqual(nodeId));
            if (!local || placement.RequiredLabels.Count > 0 || placement.RequiredToolchains.Count > 0)
            {
                return NodeErrors.InvalidArgument("placement: LOCAL_ONLY or this node (LAN placement arrives with its task)");
            }
        }

        if (spec.WorkspaceId is { Value.Length: > 0 })
        {
            return NodeErrors.InvalidArgument("workspace_id: no registered workspace with this ID (workspaces arrive with AF-WS-01)");
        }

        if (spec.Labels.Count > 32 || spec.Labels.Any(label => label.Key.Length is 0 or > 64 || label.Value.Length > 256))
        {
            return NodeErrors.InvalidArgument("labels: <= 32; keys 1..64 chars, values <= 256 chars");
        }

        if (spec.HasTitle && spec.Title.Length > 200)
        {
            return NodeErrors.InvalidArgument("title: <= 200 chars");
        }

        if (spec.ResultCache is { Enabled: true } && spec.SideEffect != SideEffectClass.Pure)
        {
            return NodeErrors.InvalidArgument("result_cache.enabled: only with side_effect = PURE");
        }

        return null;
    }

    private static ArcError? Resources(ResourceSpec? resources, ExecutionSettings settings, CapabilityReport capabilities)
    {
        if (resources is null)
        {
            return null;
        }

        if (resources.Hint is { } hint)
        {
            if (hint.HasCpuMillicores && hint.CpuMillicores is < 1 or > 1_024_000)
            {
                return NodeErrors.InvalidArgument("resources.hint.cpu_millicores: 1..1,024,000");
            }

            if (hint.HasMemExpectedBytes && (hint.MemExpectedBytes < MiB || (long)hint.MemExpectedBytes > settings.MaxTaskMemory))
            {
                return NodeErrors.InvalidArgument("resources.hint.mem_expected_bytes: 1 MiB..max_task_memory");
            }

            if (hint.HasMemCeilingBytes && ((long)hint.MemCeilingBytes > settings.MaxTaskMemory || (hint.HasMemExpectedBytes && hint.MemCeilingBytes < hint.MemExpectedBytes)))
            {
                return NodeErrors.InvalidArgument("resources.hint.mem_ceiling_bytes: >= mem_expected_bytes; <= max_task_memory");
            }
        }

        if (resources.RequireEnforcement.Distinct().Count() != resources.RequireEnforcement.Count
            || resources.RequireEnforcement.Any(resource => resource == EnforcedResource.Unspecified || !Enum.IsDefined(resource)))
        {
            return NodeErrors.InvalidArgument("resources.require_enforcement: unique known values");
        }

        foreach (var resource in resources.RequireEnforcement)
        {
            var available = resource switch
            {
                EnforcedResource.Cpu => capabilities.Cpu is CpuControl.EnforcedShareAndCap or CpuControl.EnforcedShare,
                EnforcedResource.Memory => capabilities.Memory is MemoryControl.EnforcedCommit or MemoryControl.EnforcedSoftAndHard,
                _ => capabilities.Pids == ProcessCountControl.Enforced,
            };
            if (!available)
            {
                return NodeErrors.EnforcementUnavailable(resource.ToString().ToLowerInvariant());
            }
        }

        if (resources.HasCancelGraceMs && resources.CancelGraceMs > 300_000)
        {
            return NodeErrors.InvalidArgument("resources.cancel_grace_ms: 0..300 s");
        }

        if (resources.HasStopSignal && OperatingSystem.IsWindows())
        {
            return NodeErrors.InvalidArgument("resources.stop_signal: Linux only");
        }

        return null;
    }

    private static ArcError? Output(TaskSpec spec)
    {
        if (spec.Output is not { } output)
        {
            return null;
        }

        if (output.HasCapture && (output.Capture == OutputCapture.Unspecified || !Enum.IsDefined(output.Capture)))
        {
            return NodeErrors.InvalidArgument("output.capture: FILES or DISCARD");
        }

        return output.HasRetentionDays && output.RetentionDays is < 1 or > 365 ? NodeErrors.InvalidArgument("output.retention_days: 1..365") : null;
    }

    private static long Size(Google.Protobuf.Collections.MapField<string, string> map) =>
        map.Sum(pair => (long)Encoding.UTF8.GetByteCount(pair.Key) + Encoding.UTF8.GetByteCount(pair.Value));
}
