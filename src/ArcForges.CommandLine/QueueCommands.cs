// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges queue ...</c> (experience/cli.md C-02; queue.proto): the queue in admission order with the budget summary
/// (<c>GetQueue</c>), why a task waits (<c>ExplainTask</c>), the pools and their mutations (policy revisions), pausing and resuming pools,
/// and <c>queue parallelism &lt;global|pool:p|workspace:w|session:s&gt; &lt;auto|n|off&gt;</c> (<c>SetParallelism</c>, R-EXE-013).
/// </summary>
internal static class QueueCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);

    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var queue = new Command("queue", "Show the queue, explain waits, and manage pools and parallelism");
        queue.Subcommands.Add(Show(factory));
        queue.Subcommands.Add(Explain(factory));
        queue.Subcommands.Add(Pools(factory));
        var pool = new Command("pool", "Create, update or delete a pool (a policy revision)");
        pool.Subcommands.Add(PoolChange(factory, "create"));
        pool.Subcommands.Add(PoolChange(factory, "update"));
        pool.Subcommands.Add(PoolDelete(factory));
        queue.Subcommands.Add(pool);
        queue.Subcommands.Add(Pause(factory, pause: true));
        queue.Subcommands.Add(Pause(factory, pause: false));
        queue.Subcommands.Add(Parallelism(factory));
        return queue;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var pool = new Option<string?>("--pool") { Description = "Only this pool", HelpName = "p" };
        var command = new Command("show", "The pools, the queued tasks in admission order and the budget") { pool };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new QueueServiceGetQueueRequest { Meta = Cli.Meta() };
            if (result.GetValue(pool) is { } name)
            {
                request.Pool = name;
            }

            var response = await cli.CallAsync("GetQueue", request.Meta, () => session.Channel.Queue.GetQueueAsync(request, deadline: cli.Deadline(Unary),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            var budget = response.Value.Budget;
            cli.Output.KeyValues(
            [
                ("budget", $"{Cores(budget.BudgetCpuMillicores)} cores, {StatusCommands.Size(budget.BudgetMemBytes)}"),
                ("load", $"{Cores(budget.CpuLoadMillicores)} of {Cores(budget.CpuLimitMillicores)} cores granted, {StatusCommands.Size(budget.AccountedMemBytes)} accounted"),
                ("running", string.Create(CultureInfo.InvariantCulture, $"{budget.GlobalRunning} of {budget.GlobalMaxRunning}")),
                ("pressure", budget.Pressure.ToString().ToUpperInvariant()),
            ]);
            cli.Output.Line();
            PrintPools(cli, response.Value.Pools);
            cli.Output.Line();
            if (response.Value.Entries.Count == 0)
            {
                cli.Output.Line("no queued tasks");
                return ExitCodes.Success;
            }

            cli.Output.Table(["POS", "TASK", "POOL", "CLASS", "WAITS FOR", "MEM", "CPU", "WAITED", "TITLE"], [.. response.Value.Entries.Select(entry => (IReadOnlyList<string>)
            [
                entry.Queue.Position.ToString(CultureInfo.InvariantCulture),
                IdText.Format(entry.TaskId)[..8],
                entry.Pool,
                entry.EffectivePriority.ToString().ToUpperInvariant() + (entry.Aged ? " (aged)" : string.Empty),
                entry.Queue.BlockingReason + (entry.ReservedForLarge ? " (reserved)" : string.Empty),
                StatusCommands.Size(entry.Request.MemExpectedBytes),
                Cores(entry.Request.CpuMillicores),
                Waited(TimeSpan.FromMilliseconds(entry.Queue.WaitedMs)),
                entry.Title,
            ])]);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Explain(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("task") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var command = new Command("explain", "Why a task waits and what would admit it") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            var request = new QueueServiceExplainTaskRequest { Meta = Cli.Meta(), TaskId = taskId };
            var response = await cli.CallAsync("ExplainTask", request.Meta, () => session.Channel.Queue.ExplainTaskAsync(request, deadline: cli.Deadline(Unary),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            var explanation = response.Value.Explanation;
            if (cli.Output.Json)
            {
                cli.Output.Document(explanation);
                return ExitCodes.Success;
            }

            var rows = new List<(string Key, string Value)>
            {
                ("task", IdText.Format(explanation.TaskId)),
                ("state", TaskText.Word(explanation.State)),
            };
            if (explanation.HasBlockingReason)
            {
                rows.Add(("waits for", explanation.BlockingReason));
            }

            rows.Add(("why", explanation.Text));
            rows.Add(("feasibility", explanation.Feasibility));
            rows.Add(("request", $"{Cores(explanation.Request?.CpuMillicores ?? 0)} cores, {StatusCommands.Size(explanation.Request?.MemExpectedBytes ?? 0)} expected, "
                + $"{StatusCommands.Size(explanation.Request?.MemCeilingBytes ?? 0)} ceiling ({(explanation.Request?.Source ?? EstimateSource.Unspecified).ToString().ToUpperInvariant()})"));
            rows.Add(("available", $"{Cores(explanation.AvailableCpuMillicores)} cores, {StatusCommands.Size(explanation.AvailableMemBytes)}"));
            rows.Add(("pool", string.Create(CultureInfo.InvariantCulture, $"{explanation.PoolRunning} of max_parallel {explanation.PoolMaxParallel} running")));
            if (explanation.Position > 0)
            {
                rows.Add(("position", explanation.Position.ToString(CultureInfo.InvariantCulture)));
            }

            if (explanation.AgesAt is not null)
            {
                rows.Add(("ages", CliOutput.When(explanation.AgesAt)));
            }

            if (explanation.BlockingKeys.Count > 0)
            {
                rows.Add(("keys", string.Join(", ", explanation.BlockingKeys)));
            }

            if (explanation.WaitingOnTasks.Count > 0)
            {
                rows.Add(("waiting on", string.Join(", ", explanation.WaitingOnTasks.Select(task => IdText.Format(task)))));
            }

            rows.Add(("reservation", explanation.LargeReservationActive ? "active" : "none"));
            cli.Output.KeyValues(rows);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Pools(Func<ParseResult, Cli> factory)
    {
        var command = new Command("pools", "List the pools with their limits and live counts");
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new QueueServiceListPoolsRequest { Meta = Cli.Meta() };
            var response = await cli.CallAsync("ListPools", request.Meta, () => session.Channel.Queue.ListPoolsAsync(request, deadline: cli.Deadline(Unary),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
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
                PrintPools(cli, response.Value.Pools);
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command PoolChange(Func<ParseResult, Cli> factory, string verb)
    {
        var name = new Argument<string>("name") { Description = "The pool name (^[a-z][a-z0-9-]{0,31}$)" };
        var weight = new Option<int?>("--weight") { Description = "The round-robin weight (1..100)", HelpName = "n" };
        var max = new Option<string?>("--max") { Description = "Parallelism: auto, a number (1..256) or off (one at a time)", HelpName = "auto|n|off" };
        var priority = new Option<string?>("--priority") { Description = "The default priority: high, normal, low or background", HelpName = "class" };
        priority.AcceptOnlyFromAmong("high", "normal", "low", "background");
        var command = new Command(verb, verb == "create" ? "Create a pool" : "Change a pool's weight, parallelism or default priority") { name, weight, max, priority };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var (mode, fixedLimit) = result.GetValue(max) is { } maxText ? Mode(maxText, "--max") : ((ParallelismMode?)null, (uint?)null);
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            if (verb == "create")
            {
                var request = new QueueServiceCreatePoolRequest { Meta = Cli.Meta(), Name = result.GetValue(name)! };
                Fill(result.GetValue(weight), mode, fixedLimit, result.GetValue(priority), value => request.Weight = value, value => request.MaxParallelMode = value,
                    value => request.MaxParallelFixed = value, value => request.DefaultPriority = value);
                var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
                var response = await cli.MutateAsync("CreatePool", request.Meta.CommandId, action, r => session.Channel.Queue.CreatePoolAsync(r,
                    deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
                return response.Error is { } error ? cli.Output.Fail(error, request.Meta.CorrelationId) : Done(cli, response.Value, response.Value.PolicyRevision);
            }

            var update = new QueueServiceUpdatePoolRequest { Meta = Cli.Meta(), Name = result.GetValue(name)! };
            Fill(result.GetValue(weight), mode, fixedLimit, result.GetValue(priority), value => update.Weight = value, value => update.MaxParallelMode = value,
                value => update.MaxParallelFixed = value, value => update.DefaultPriority = value);
            var updateAction = CommandIds.Begin(update, r => r.Meta, (r, m) => r.Meta = m);
            var updated = await cli.MutateAsync("UpdatePool", update.Meta.CommandId, updateAction, r => session.Channel.Queue.UpdatePoolAsync(r,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            return updated.Error is { } updateError ? cli.Output.Fail(updateError, update.Meta.CorrelationId) : Done(cli, updated.Value, updated.Value.PolicyRevision);
        });
        return command;
    }

    private static Command PoolDelete(Func<ParseResult, Cli> factory)
    {
        var name = new Argument<string>("name") { Description = "An empty pool that is not built in" };
        var command = new Command("delete", "Delete an empty pool") { name };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new QueueServiceDeletePoolRequest { Meta = Cli.Meta(), Name = result.GetValue(name)! };
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("DeletePool", request.Meta.CommandId, action, r => session.Channel.Queue.DeletePoolAsync(r,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            return response.Error is { } error ? cli.Output.Fail(error, request.Meta.CorrelationId) : Done(cli, response.Value, response.Value.PolicyRevision);
        });
        return command;
    }

    private static Command Pause(Func<ParseResult, Cli> factory, bool pause)
    {
        var pool = new Argument<string?>("pool") { Arity = ArgumentArity.ZeroOrOne, Description = "The pool (or --all)" };
        var all = new Option<bool>("--all") { Description = "Every pool" };
        var command = new Command(pause ? "pause" : "resume", pause ? "Stop admitting tasks from a pool (running tasks continue)" : "Resume admission from a pool") { pool, all };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var name = result.GetValue(pool);
            if ((name is null) == !result.GetValue(all))
            {
                throw new UsageException("name a pool or give --all.");
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            if (pause)
            {
                var request = new QueueServicePausePoolRequest { Meta = Cli.Meta(), All = name is null };
                if (name is not null)
                {
                    request.Pool = name;
                }

                var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
                var response = await cli.MutateAsync("PausePool", request.Meta.CommandId, action, r => session.Channel.Queue.PausePoolAsync(r,
                    deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
                return response.Error is { } error ? cli.Output.Fail(error, request.Meta.CorrelationId) : Done(cli, response.Value, null, (name ?? "every pool") + " paused");
            }

            var resume = new QueueServiceResumePoolRequest { Meta = Cli.Meta(), All = name is null };
            if (name is not null)
            {
                resume.Pool = name;
            }

            var resumeAction = CommandIds.Begin(resume, r => r.Meta, (r, m) => r.Meta = m);
            var resumed = await cli.MutateAsync("ResumePool", resume.Meta.CommandId, resumeAction, r => session.Channel.Queue.ResumePoolAsync(r,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            return resumed.Error is { } resumeError ? cli.Output.Fail(resumeError, resume.Meta.CorrelationId) : Done(cli, resumed.Value, null, (name ?? "every pool") + " resumed");
        });
        return command;
    }

    private static Command Parallelism(Func<ParseResult, Cli> factory)
    {
        var scope = new Argument<string>("scope") { Description = "global, pool:<name>, workspace:<id> or session:<id>" };
        var limit = new Argument<string>("limit") { Description = "auto, a number (1..256) or off (one at a time)" };
        var command = new Command("parallelism", "Restrict or disable parallel execution for a scope (a policy revision)") { scope, limit };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var request = new QueueServiceSetParallelismRequest { Meta = Cli.Meta() };
            var scopeText = result.GetValue(scope)!;
            var colon = scopeText.IndexOf(':', StringComparison.Ordinal);
            var (kind, target) = colon < 0 ? (scopeText, string.Empty) : (scopeText[..colon], scopeText[(colon + 1)..]);
            request.Scope = kind.ToLowerInvariant() switch
            {
                "global" when target.Length == 0 => ParallelismScope.Global,
                "pool" when target.Length > 0 => ParallelismScope.Pool,
                "workspace" when target.Length > 0 => ParallelismScope.Workspace,
                "session" when target.Length > 0 => ParallelismScope.Session,
                _ => throw new UsageException($"scope: '{scopeText}' is not global, pool:<name>, workspace:<id> or session:<id>."),
            };
            if (target.Length > 0)
            {
                request.Target = target;
            }

            var (mode, fixedLimit) = Mode(result.GetValue(limit)!, "limit");
            request.Mode = mode!.Value;
            if (fixedLimit is { } value)
            {
                request.Fixed = value;
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("SetParallelism", request.Meta.CommandId, action, r => session.Channel.Queue.SetParallelismAsync(r,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            return response.Error is { } error ? cli.Output.Fail(error, request.Meta.CorrelationId) : Done(cli, response.Value, response.Value.PolicyRevision);
        });
        return command;
    }

    private static (ParallelismMode? Mode, uint? Fixed) Mode(string text, string option) => text.ToLowerInvariant() switch
    {
        "auto" => (ParallelismMode.Auto, null),
        "off" or "disabled" => (ParallelismMode.Disabled, null),
        _ when uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value is >= 1 and <= 256 => (ParallelismMode.Fixed, value),
        _ => throw new UsageException($"{option}: '{text}' is not auto, off or a number 1..256."),
    };

    private static void Fill(int? weight, ParallelismMode? mode, uint? fixedLimit, string? priority, Action<uint> setWeight, Action<ParallelismMode> setMode,
        Action<uint> setFixed, Action<Priority> setPriority)
    {
        if (weight is { } value)
        {
            setWeight(value is >= 1 and <= 100 ? (uint)value : throw new UsageException("--weight: 1..100."));
        }

        if (mode is { } parallelism)
        {
            setMode(parallelism);
        }

        if (fixedLimit is { } limit)
        {
            setFixed(limit);
        }

        if (priority is { } name)
        {
            setPriority(Enum.Parse<Priority>(name, ignoreCase: true));
        }
    }

    private static int Done(Cli cli, Google.Protobuf.IMessage value, Revision? revision, string? text = null)
    {
        if (cli.Output.Json)
        {
            cli.Output.Document(value);
        }
        else
        {
            cli.Output.Line(text ?? $"policy revision {revision?.Value.ToString(CultureInfo.InvariantCulture) ?? "-"}");
        }

        return ExitCodes.Success;
    }

    private static void PrintPools(Cli cli, IEnumerable<Pool> pools) =>
        cli.Output.Table(["POOL", "WEIGHT", "PARALLEL", "RUNNING", "QUEUED", "DEFAULT", "STATE"], [.. pools.Select(pool => (IReadOnlyList<string>)
        [
            pool.Name + (pool.BuiltIn ? " (built in)" : string.Empty),
            pool.Weight.ToString(CultureInfo.InvariantCulture),
            pool.MaxParallelMode switch
            {
                ParallelismMode.Fixed => pool.MaxParallelFixed.ToString(CultureInfo.InvariantCulture),
                ParallelismMode.Disabled => "off (1)",
                _ => "auto (" + pool.EffectiveMaxParallel.ToString(CultureInfo.InvariantCulture) + ")",
            },
            pool.Running.ToString(CultureInfo.InvariantCulture),
            pool.Queued.ToString(CultureInfo.InvariantCulture),
            pool.DefaultPriority.ToString().ToUpperInvariant(),
            pool.Paused ? "PAUSED" : "ADMITTING",
        ])]);

    private static string Cores(uint millicores) => (millicores / 1000.0).ToString("0.0#", CultureInfo.InvariantCulture);

    private static string Waited(TimeSpan waited) => waited.TotalSeconds < 60
        ? string.Create(CultureInfo.InvariantCulture, $"{waited.TotalSeconds:0}s")
        : waited.TotalMinutes < 60 ? string.Create(CultureInfo.InvariantCulture, $"{waited.TotalMinutes:0}m") : string.Create(CultureInfo.InvariantCulture, $"{waited.TotalHours:0.#}h");
}
