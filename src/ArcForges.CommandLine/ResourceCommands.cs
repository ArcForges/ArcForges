// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges resources</c>, <c>ps</c> and <c>samples</c> (experience/cli.md C-03): the resource snapshot (once, or streamed with
/// <c>--watch</c>), the classified process list and the stored samples. Observed processes are never shown as controlled: only MANAGED
/// (and ADOPTED) processes are (03 section 9, R-RES-002).
/// </summary>
internal static class ResourceCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);

    /// <summary>The label names of <c>ps --label</c>.</summary>
    internal static readonly IReadOnlyDictionary<string, ProcessLabel> Labels = new Dictionary<string, ProcessLabel>(StringComparer.OrdinalIgnoreCase)
    {
        ["managed"] = ProcessLabel.Managed,
        ["adopted"] = ProcessLabel.Adopted,
        ["escaped"] = ProcessLabel.Escaped,
        ["bypassed"] = ProcessLabel.Bypassed,
        ["unmanaged"] = ProcessLabel.Unmanaged,
        ["guest"] = ProcessLabel.GuestVm,
        ["shared"] = ProcessLabel.SharedService,
        ["node"] = ProcessLabel.NodeSelf,
    };

    /// <summary>
    /// <c>adopt &lt;pid&gt; [--title t] [--pool p]</c>: <c>AdoptProcess</c> (HUMAN only; 04 section 10). The process is named by its ID and its
    /// start time, read here, so a reused ID is never adopted.
    /// </summary>
    public static Command Adopt(Func<ParseResult, Cli> factory)
    {
        var pid = new Argument<int>("pid") { Description = "The process ID" };
        var title = new Option<string?>("--title") { Description = "The adopted task's title (<= 200 characters)", HelpName = "t" };
        var pool = new Option<string?>("--pool") { Description = "The pool the adopted task belongs to (default: default)", HelpName = "p" };
        var command = new Command("adopt", "Place an existing process of yours under management (an ADOPTED task)") { pid, title, pool };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            if (ClientProcess.Identity(result.GetValue(pid)) is not { } process)
            {
                cli.Output.Error.WriteLine($"error: no process {result.GetValue(pid).ToString(CultureInfo.InvariantCulture)} (STATE/not_found)");
                return ExitCodes.NotFound;
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new ResourceServiceAdoptProcessRequest { Meta = Cli.Meta(), Process = process };
            if (result.GetValue(title) is { } text)
            {
                request.Title = text;
            }

            if (result.GetValue(pool) is { } name)
            {
                request.Pool = name;
            }

            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("AdoptProcess", request.Meta.CommandId, action, r => session.Channel.Resources.AdoptProcessAsync(r,
                deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
            }
            else
            {
                cli.Output.Line(string.Create(CultureInfo.InvariantCulture,
                    $"adopted as task {IdText.Format(response.Value.TaskId)} ({response.Value.AdoptedChildren} children adopted, {response.Value.FailedChildren} failed)"));
            }

            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary>
    /// <c>terminate &lt;pid&gt; [--reason r]</c>: <c>TerminateProcess</c> (HUMAN A, SCRIPT and AGENT need an approval): only a process the node
    /// manages, adopted or classified (ESCAPED, a leftover), named by its ID and start time.
    /// </summary>
    public static Command Terminate(Func<ParseResult, Cli> factory)
    {
        var pid = new Argument<int>("pid") { Description = "The process ID" };
        var reason = new Option<string?>("--reason") { Description = "Why (<= 500 characters, for the record)", HelpName = "r" };
        var command = new Command("terminate", "Terminate a process the node manages, adopted or found escaped") { pid, reason };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            if (ClientProcess.Identity(result.GetValue(pid)) is not { } process)
            {
                cli.Output.Error.WriteLine($"error: no process {result.GetValue(pid).ToString(CultureInfo.InvariantCulture)} (STATE/not_found)");
                return ExitCodes.NotFound;
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new ResourceServiceTerminateProcessRequest { Meta = Cli.Meta(), Process = process };
            if (result.GetValue(reason) is { } text)
            {
                request.Reason = text;
            }

            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("TerminateProcess", request.Meta.CommandId, action, r => session.Channel.Resources.TerminateProcessAsync(r,
                deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
            }
            else
            {
                cli.Output.Line(string.Create(CultureInfo.InvariantCulture, $"process {process.Pid} terminated"));
            }

            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary><c>resources [--watch [--interval 5s]]</c>: <c>GetResourceSnapshot</c> or <c>WatchResources</c>.</summary>
    public static Command Resources(Func<ParseResult, Cli> factory)
    {
        var watch = new Option<bool>("--watch") { Description = "Stream snapshots until interrupted" };
        var interval = new Option<string?>("--interval") { Description = "The interval of --watch (1s..60s; default 5s)", HelpName = "dur" };
        var command = new Command("resources", "Show capacity, reserves, unmanaged load, budgets, managed use and pressure") { watch, interval };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            TimeSpan? every = null;
            if (result.GetValue(interval) is { } text)
            {
                if (!Durations.TryParse(text, out var parsed) || parsed < TimeSpan.FromSeconds(1) || parsed > TimeSpan.FromSeconds(60))
                {
                    return cli.Output.Usage($"--interval: '{text}' is not a duration from 1s to 60s.");
                }

                every = parsed;
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            if (!result.GetValue(watch))
            {
                var meta = Cli.Meta();
                var response = await cli.CallAsync("GetResourceSnapshot", meta, () => session.Channel.Resources.GetResourceSnapshotAsync(
                    new ResourceServiceGetResourceSnapshotRequest { Meta = meta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
                if (response.Error is { } error)
                {
                    return cli.Output.Fail(error, meta.CorrelationId);
                }

                Print(cli, response.Value.Snapshot, document: true);
                return ExitCodes.Success;
            }

            var request = new ResourceServiceWatchResourcesRequest { Meta = Cli.Meta() };
            if (every is { } period)
            {
                request.IntervalMs = (ulong)period.TotalMilliseconds;
            }

            using var call = session.Channel.Resources.WatchResources(request, cancellationToken: cancellationToken);
            try
            {
                var first = true;
                await foreach (var frame in call.ResponseStream.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                {
                    switch (frame.FrameCase)
                    {
                        case ResourceServiceWatchResourcesFrame.FrameOneofCase.Error:
                            return cli.Output.Fail(frame.Error, request.Meta.CorrelationId);
                        case ResourceServiceWatchResourcesFrame.FrameOneofCase.Snapshot:
                            if (!first && !cli.Output.Json)
                            {
                                cli.Output.Line();
                            }

                            first = false;
                            Print(cli, frame.Snapshot, document: false);
                            await cli.Output.Out.FlushAsync(cancellationToken).ConfigureAwait(false);
                            break;
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return ExitCodes.Success;
            }
            catch (RpcException exception) when (exception.StatusCode == StatusCode.Cancelled && cancellationToken.IsCancellationRequested)
            {
                return ExitCodes.Success;
            }

            cli.Output.Error.WriteLine("arcforges: the node ended the stream");
            return ExitCodes.NodeUnreachable;
        });
        return command;
    }

    /// <summary><c>ps [--label l,...] [--session s] [--task t] [--top n]</c>: <c>ListProcesses</c>.</summary>
    public static Command Processes(Func<ParseResult, Cli> factory)
    {
        var label = new Option<string[]>("--label")
        {
            Description = "Labels to show (comma-separated or repeated): managed, adopted, escaped, bypassed, unmanaged, guest, shared, node",
            HelpName = "l",
        };
        var sessionOption = new Option<string?>("--session") { Description = "Only processes attributed to this session", HelpName = "s" };
        var task = new Option<string?>("--task") { Description = "Only processes of this task (ID or prefix)", HelpName = "t" };
        var top = new Option<int?>("--top") { Description = "At most this many processes, by CPU then memory (1..500; default 50)", HelpName = "n" };
        var command = new Command("ps", "List processes classified as managed, escaped, unmanaged or guest VM") { label, sessionOption, task, top };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var filter = new ProcessFilter();
            foreach (var name in (result.GetValue(label) ?? []).SelectMany(value => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
            {
                if (!Labels.TryGetValue(name, out var value))
                {
                    return cli.Output.Usage($"--label: '{name}' is not one of {string.Join(", ", Labels.Keys)}.");
                }

                filter.Labels.Add(value);
            }

            if (result.GetValue(top) is { } count)
            {
                if (count is < 1 or > 500)
                {
                    return cli.Output.Usage("--top: 1..500.");
                }

                filter.TopN = (uint)count;
            }

            if (result.GetValue(sessionOption) is { } sessionText)
            {
                if (!IdText.TryParse(sessionText, out var sessionId))
                {
                    return cli.Output.Usage($"--session: '{sessionText}' is not a session ID.");
                }

                filter.SessionId = new Id { Value = ByteString.CopyFrom(sessionId) };
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            if (result.GetValue(task) is { } taskText)
            {
                var (taskId, exit) = await TaskText.ResolveAsync(cli, session, taskText, cancellationToken).ConfigureAwait(false);
                if (taskId is null)
                {
                    return exit;
                }

                filter.TaskId = taskId;
            }

            var meta = Cli.Meta();
            var response = await cli.CallAsync("ListProcesses", meta, () => session.Channel.Resources.ListProcessesAsync(
                new ResourceServiceListProcessesRequest { Meta = meta, Filter = filter }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken))
                .ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            if (response.Value.Processes.Count == 0)
            {
                cli.Output.Note("no processes match");
                return ExitCodes.Success;
            }

            cli.Output.Table(["PID", "IMAGE", "LABEL", "CPU", "MEM", "TASK"], [.. response.Value.Processes.Select(process => (IReadOnlyList<string>)
            [
                process.Process.Pid.ToString(CultureInfo.InvariantCulture),
                process.Process.ImageName,
                LabelText(process),
                process.Usage.HasCpuMillicores ? Cores(process.Usage.CpuMillicores) : "-",
                StatusCommands.Size(process.Usage.MemBytes),
                process.TaskId is null ? "-" : IdText.Format(process.TaskId)[..8] + (process.CrossesVmBoundary ? " (crosses VM boundary)" : string.Empty),
            ])]);
            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary><c>samples [--attempt id] [--scope machine|managed|attempt] [--range 1h] [--max-points n]</c>: <c>GetSamples</c>.</summary>
    public static Command Samples(Func<ParseResult, Cli> factory)
    {
        var attempt = new Option<string?>("--attempt") { Description = "The attempt's samples (its ID or a unique prefix of at least 6 characters)", HelpName = "id" };
        var scope = new Option<string?>("--scope") { Description = "machine, managed or attempt (default: attempt with --attempt, else machine)", HelpName = "s" };
        scope.AcceptOnlyFromAmong("machine", "managed", "attempt");
        var range = new Option<string?>("--range") { Description = "How far back (default: the attempt's lifetime, or 1h)", HelpName = "dur" };
        var points = new Option<int?>("--max-points") { Description = "At most this many points (10..10000; default 1000)", HelpName = "n" };
        var command = new Command("samples", "Show stored resource samples of the machine, managed work or an attempt") { attempt, scope, range, points };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var request = new ResourceServiceGetSamplesRequest { Meta = Cli.Meta() };
            var attemptText = result.GetValue(attempt);
            request.Scope = result.GetValue(scope) switch
            {
                "machine" => SampleScope.Machine,
                "managed" => SampleScope.Managed,
                "attempt" => SampleScope.Attempt,
                _ => attemptText is null ? SampleScope.Machine : SampleScope.Attempt,
            };
            if (attemptText is not null && attemptText.Length < 6)
            {
                return cli.Output.Usage($"--attempt: '{attemptText}' is not an attempt ID or an ID prefix of at least 6 characters.");
            }

            if (result.GetValue(range) is { } rangeText)
            {
                if (!Durations.TryParse(rangeText, out var back) || back > TimeSpan.FromDays(30))
                {
                    return cli.Output.Usage($"--range: '{rangeText}' is not a duration up to 30d.");
                }

                var now = DateTimeOffset.UtcNow;
                request.Range = new TimeRangeUtc { From = ProtoTime.ToInstant(now - back), Until = ProtoTime.ToInstant(now) };
            }

            if (result.GetValue(points) is { } max)
            {
                request.MaxPoints = (uint)Math.Clamp(max, 0, 100_000);
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            if (attemptText is not null)
            {
                var (attemptId, exit) = await TaskText.ResolveAttemptAsync(cli, session, attemptText, cancellationToken).ConfigureAwait(false);
                if (attemptId is null)
                {
                    return exit;
                }

                request.AttemptId = attemptId;
            }

            var response = await cli.CallAsync("GetSamples", request.Meta, () => session.Channel.Resources.GetSamplesAsync(request,
                deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            if (response.Value.Samples.Count == 0)
            {
                cli.Output.Note("no samples in the range");
                return ExitCodes.Success;
            }

            cli.Output.Note(string.Create(CultureInfo.InvariantCulture, $"{response.Value.Samples.Count} samples, resolution {response.Value.ResolutionMs / 1000.0:0.#} s"));
            cli.Output.Table(["TIME", "CPU", "MEM", "PEAK", "PROCS"], [.. response.Value.Samples.Select(sample => (IReadOnlyList<string>)
            [
                ProtoTime.ToDateTimeOffset(sample.At)?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-",
                Cores(sample.Usage.CpuMillicores),
                StatusCommands.Size(sample.Usage.MemBytes),
                StatusCommands.Size(sample.Usage.MemPeakBytes),
                sample.Usage.ProcessCount.ToString(CultureInfo.InvariantCulture),
            ])]);
            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary>The human rows of a snapshot (also the resource lines of <c>status</c>).</summary>
    internal static List<(string Key, string Value)> Rows(ResourceSnapshot snapshot)
    {
        var rows = new List<(string Key, string Value)>
        {
            ("capacity", $"{Cores(snapshot.CapacityCpuMillicores)} cores, {StatusCommands.Size(snapshot.CapacityMemBytes)}"),
            ("reserved", $"{Cores(snapshot.ReserveCpuMillicores)} cores, {StatusCommands.Size(snapshot.ReserveMemBytes)}"),
            ("unmanaged", $"{Cores(snapshot.UnmanagedCpuMillicores)} cores, {StatusCommands.Size(snapshot.UnmanagedMemBytes)} (smoothed)"),
            ("managed", $"{Cores(snapshot.Managed?.CpuMillicores ?? 0)} cores, {StatusCommands.Size(snapshot.Managed?.MemBytes ?? 0)}"
                + string.Create(CultureInfo.InvariantCulture, $" ({snapshot.RunningAttempts} running, {snapshot.QueuedTasks} queued)")),
            ("node", $"{Cores(snapshot.NodeSelf?.CpuMillicores ?? 0)} cores, {StatusCommands.Size(snapshot.NodeSelf?.MemBytes ?? 0)}"),
            ("budget", $"{Cores(snapshot.BudgetCpuMillicores)} cores, {StatusCommands.Size(snapshot.BudgetMemBytes)}"),
            ("available", StatusCommands.Size(snapshot.AvailableMemBytes)),
            ("pressure", (snapshot.HasPressure ? Word(snapshot.Pressure) : "unknown")
                + (snapshot.PressureDetail is { Available: true } detail
                    ? string.Create(CultureInfo.InvariantCulture, $" (memory some avg10 {detail.MemorySomeAvg10:0.##}, cpu some avg10 {detail.CpuSomeAvg10:0.##})")
                    : string.Empty)),
        };
        foreach (var volume in snapshot.Volumes)
        {
            rows.Add(("volume " + volume.Mount, $"{StatusCommands.Size(volume.FreeBytes)} free of {StatusCommands.Size(volume.TotalBytes)} ({Word(volume.Level)})"));
        }

        if (snapshot.Capabilities is { } capabilities)
        {
            rows.Add(("enforcement", $"cpu {Word(capabilities.Cpu)}, memory {Word(capabilities.Memory)}"));
        }

        return rows;
    }

    private static void Print(Cli cli, ResourceSnapshot snapshot, bool document)
    {
        if (cli.Output.Json)
        {
            if (document)
            {
                cli.Output.Document(snapshot);
            }
            else
            {
                cli.Output.JsonLine(snapshot);
            }

            return;
        }

        if (cli.Output.Quiet)
        {
            cli.Output.Essential(Word(snapshot.Pressure));
            return;
        }

        cli.Output.KeyValues(Rows(snapshot));
    }

    private static string LabelText(ProcessView process) => Word(process.Label);

    private static string Cores(uint millicores) => (millicores / 1000.0).ToString("0.0", CultureInfo.InvariantCulture);

    private static string Word<T>(T value)
        where T : struct, Enum
    {
        var text = value.ToString();
        var builder = new System.Text.StringBuilder(text.Length + 4);
        for (var index = 0; index < text.Length; index++)
        {
            if (index > 0 && char.IsUpper(text[index]))
            {
                builder.Append('_');
            }

            builder.Append(char.ToUpperInvariant(text[index]));
        }

        return builder.ToString();
    }
}
