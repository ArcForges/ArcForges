// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.CommandLine.Parsing;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Grpc.Core;

namespace ArcForges.CommandLine;

internal static class SandboxRunCommands
{
    private static readonly TimeSpan UnaryDeadline = TimeSpan.FromSeconds(10);

    internal static Command Build(Func<ParseResult, Cli> factory)
    {
        var command = new Command("run", "Start and manage Runs in your Sandboxes");
        command.Subcommands.Add(Start(factory));
        command.Subcommands.Add(List(factory));
        command.Subcommands.Add(Inspect(factory));
        command.Subcommands.Add(Stop(factory));
        return command;
    }

    private static Command Start(Func<ParseResult, Cli> factory)
    {
        var sandbox = new Argument<string>("sandbox-id") { Description = "Sandbox ID" };
        var program = new Argument<string[]>("program")
        {
            Arity = ArgumentArity.OneOrMore,
            Description = "Program and exact arguments, after --",
        };
        var terminal = new Option<string?>("--terminal") { Description = "Terminal mode: auto, on, or off (default auto)" };
        terminal.AcceptOnlyFromAmong("auto", "on", "off");
        var directory = new Option<string?>("--cwd") { Description = "Working directory in the Sandbox" };
        var expected = new Option<long?>("--expected-revision") { Description = "Expected Sandbox configuration revision" };
        var mutation = new V2MutationOptions();
        var command = new Command("start", "Start explicit argv in a Sandbox and return the receipt")
        {
            sandbox, program, terminal, directory, expected,
        };
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            string[] argv = ReadArgv(result, program);
            var sandboxId = V2Cli.ReadId(result.GetValue(sandbox), "Sandbox ID");
            bool replay = mutation.IsReplay(result);
            var revision = ReadRevision(result.GetValue(expected), replay);
            string mode = result.GetValue(terminal) ?? "auto";
            if (replay && mode == "auto")
            {
                throw new UsageException("An exact Start replay requires the original --terminal on or off mode.");
            }

            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var connection = session.PinConnection();
            var deadline = cli.Deadline(UnaryDeadline);
            bool autoTerminal = mode == "auto" && !Console.IsInputRedirected && !Console.IsOutputRedirected;
            Sandbox? current = revision is null || autoTerminal
                ? await SandboxCommands.InspectAsync(session, sandboxId, deadline, cancellationToken).ConfigureAwait(false)
                : null;
            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            identity.Meta.ExpectedRev = revision ?? V2Cli.Require(current?.Revision, null);
            bool interactive = mode == "on" || autoTerminal && current!.Capabilities.Any(
                capability => capability.Key == "mxc.terminal.observation" && capability.State == CapabilityState.Available);
            identity = identity with { TerminalOption = interactive ? "on" : "off" };
            var request = new RunServiceStartRequest
            {
                Meta = identity.Meta,
                OwnerEpoch = identity.OwnerEpoch,
                SandboxId = sandboxId,
                TerminalMode = interactive ? TerminalMode.Interactive : TerminalMode.Pipes,
                TerminalSize = interactive ? new TerminalSize { Rows = 24, Columns = 80 } : null,
            };
            if (result.GetValue(directory) is { } workdir)
            {
                request.WorkingDirectory = workdir;
            }

            request.Argv.AddRange(argv);
            var response = await V2Cli.SendAsync(cli, "RunService.Start", identity,
                () => session.Runs.StartAsync(request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
            var value = V2Cli.Require(response.Value, response.Error, identity);
            if (value.Run is not { RunId.Value.Length: 16 } run || !sandboxId.Equals(run.SandboxId)
                || !MatchesOperation(value.Operation, identity, run.RunId, "RunService.Start")
                || value.Operation.State is not (OperationState.Accepted or OperationState.Succeeded))
            {
                return V2Cli.Fail(cli, V2Cli.UnknownEffect("start_acceptance_unconfirmed", identity.Meta.CorrelationId), identity);
            }

            return V2Cli.Print(cli, value, identity);
        });
        return command;
    }

    private static string[] ReadArgv(ParseResult result, Argument<string[]> program)
    {
        var argv = result.Tokens.SkipWhile(token => token.Type != TokenType.DoubleDash).Skip(1)
            .Select(token => token.Value).ToArray();
        if (argv.Length == 0 || result.GetValue(program)?.Length != argv.Length || string.IsNullOrWhiteSpace(argv[0]))
        {
            throw new UsageException("Provide the program and all its arguments after --.");
        }

        return argv;
    }

    private static Command List(Func<ParseResult, Cli> factory)
    {
        var sandbox = new Option<string>("--sandbox") { Required = true, Description = "Sandbox ID" };
        var limit = new Option<uint?>("--limit") { Description = "Page size from 1 to 200 (default 50)" };
        var cursor = new Option<string?>("--cursor") { Description = "Opaque continuation from the previous page" };
        var command = new Command("list", "List Runs for one Sandbox") { sandbox, limit, cursor };
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var request = new RunServiceListRequest
            {
                Meta = Cli.Meta(),
                SandboxId = V2Cli.ReadId(result.GetValue(sandbox), "Sandbox ID"),
            };
            if (result.GetValue(limit) is uint pageSize)
            {
                request.Limit = SandboxCommands.PageSize(pageSize);
            }

            if (result.GetValue(cursor) is { } next)
            {
                request.Cursor = next;
            }

            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var call = session.Runs.ListAsync(request, deadline: cli.Deadline(UnaryDeadline), cancellationToken: cancellationToken);
            var response = await call.ResponseAsync.ConfigureAwait(false);
            return V2Cli.Print(cli, V2Cli.Require(response.Value, response.Error));
        });
        return command;
    }

    private static Command Inspect(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("run-id") { Description = "Run ID" };
        var command = new Command("inspect", "Show Run state, limits and observed exit provenance") { id };
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var run = V2Cli.ReadId(result.GetValue(id), "Run ID");
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            var found = await InspectAsync(session, run, cli.Deadline(UnaryDeadline), cancellationToken).ConfigureAwait(false);
            return V2Cli.Print(cli, new RunServiceInspectValue { Run = found });
        });
        return command;
    }

    private static Command Stop(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("run-id") { Description = "Run ID" };
        var expected = new Option<long?>("--expected-revision") { Description = "Expected Run revision" };
        var grace = new Option<uint?>("--grace-ms") { Description = "Milliseconds before force-stop, from 0 to 60000 (default 5000)" };
        var mutation = new V2MutationOptions();
        var command = new Command("stop", "Stop a Run and observe its durable receipt") { id, expected, grace };
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var runId = V2Cli.ReadId(result.GetValue(id), "Run ID");
            var revision = ReadRevision(result.GetValue(expected), mutation.IsReplay(result));
            var graceMs = result.GetValue(grace);
            if (graceMs > 60_000)
            {
                throw new UsageException("--grace-ms must be from 0 to 60000.");
            }

            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var connection = session.PinConnection();
            var deadline = cli.Deadline(UnaryDeadline);
            var currentRevision = revision ?? V2Cli.Require(
                (await InspectAsync(session, runId, deadline, cancellationToken).ConfigureAwait(false)).Revision, null);
            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            var value = await StopAsync(cli, session, runId, currentRevision, identity, graceMs, deadline, cancellationToken)
                .ConfigureAwait(false);
            return V2Cli.Print(cli, value, identity);
        });
        return command;
    }

    internal static async Task<RunServiceStopValue> StopAsync(Cli cli, V2CliSession session, Id runId, Revision expected,
        V2CommandIdentity identity, uint? graceMs, DateTime deadline, CancellationToken cancellationToken)
    {
        identity.Meta.ExpectedRev = expected;
        var request = new RunServiceStopRequest { Meta = identity.Meta, OwnerEpoch = identity.OwnerEpoch, RunId = runId };
        if (graceMs is uint value)
        {
            request.GraceMs = value;
        }

        var response = await V2Cli.SendAsync(cli, "RunService.Stop", identity,
            () => session.Runs.StopAsync(request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var accepted = V2Cli.Require(response.Value, response.Error, identity);
        return await ObserveStopAsync(session, accepted, identity, runId, deadline, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<RunServiceStopValue> ObserveStopAsync(V2CliSession session, RunServiceStopValue value, V2CommandIdentity identity,
        Id runId, DateTime deadline, CancellationToken cancellationToken)
    {
        var operation = value.Operation;
        bool observedAfterStop = false;
        try
        {
            while (operation?.State == OperationState.Accepted && MatchesOperation(operation, identity, runId, "RunService.Stop"))
            {
                TimeSpan remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero)
                {
                    break;
                }

                await Task.Delay(remaining < TimeSpan.FromMilliseconds(100) ? remaining : TimeSpan.FromMilliseconds(100),
                    cancellationToken).ConfigureAwait(false);
                using var call = session.Node.GetOperationAsync(new NodeServiceGetOperationRequest
                {
                    Meta = Cli.Meta(),
                    CommandId = identity.CommandId,
                    OwnerEpoch = identity.OwnerEpoch,
                }, deadline: deadline, cancellationToken: cancellationToken);
                var response = await call.ResponseAsync.ConfigureAwait(false);
                operation = response.Value?.Operation;
                observedAfterStop = true;
            }
        }
        catch (RpcException)
        {
            return UnknownStop();
        }
        catch (OperationCanceledException)
        {
            return UnknownStop();
        }

        if (!MatchesOperation(operation, identity, runId, "RunService.Stop"))
        {
            return UnknownStop();
        }

        if (operation!.State is (OperationState.Failed or OperationState.Unknown) && operation.Error is { } failure)
        {
            return V2Cli.Require<RunServiceStopValue>(null, failure, identity);
        }

        if (operation.State != OperationState.Succeeded || operation.Effect is not (EffectCertainty.Happened or EffectCertainty.DidNotHappen)
            || !runId.Equals(value.Run?.RunId))
        {
            return UnknownStop();
        }

        if (observedAfterStop)
        {
            // The settled receipt proves Stop. Refresh the Run when it is still readable.
            using var call = session.Runs.InspectAsync(new RunServiceInspectRequest { Meta = Cli.Meta(), RunId = runId },
                deadline: deadline, cancellationToken: cancellationToken);
            try
            {
                var response = await call.ResponseAsync.ConfigureAwait(false);
                if (response.Value?.Run is { } current && runId.Equals(current.RunId))
                {
                    value.Run = current;
                }
            }
            catch (RpcException)
            {
                // Preserve the earlier observation alongside the settled receipt.
            }
            catch (OperationCanceledException)
            {
                // The receipt has already settled.
            }
        }

        value.Operation = operation;
        return value;

        RunServiceStopValue UnknownStop() => V2Cli.Require<RunServiceStopValue>(null,
            V2Cli.UnknownEffect("stop_outcome_unconfirmed", identity.Meta.CorrelationId), identity);
    }

    private static bool MatchesOperation(Operation? operation, V2CommandIdentity identity, Id runId, string method) =>
        operation is not null && identity.CommandId.Equals(operation.CommandId) && identity.OwnerEpoch.Equals(operation.OwnerEpoch)
        && operation.Method == method && runId.Equals(operation.AggregateId);

    internal static async Task<Run> InspectAsync(V2CliSession session, Id id, DateTime deadline, CancellationToken cancellationToken)
    {
        using var call = session.Runs.InspectAsync(new RunServiceInspectRequest { Meta = Cli.Meta(), RunId = id },
            deadline: deadline, cancellationToken: cancellationToken);
        var response = await call.ResponseAsync.ConfigureAwait(false);
        var run = V2Cli.Require(response.Value, response.Error).Run;
        return V2Cli.Require(id.Equals(run?.RunId) ? run : null, null);
    }

    private static Revision? ReadRevision(long? supplied, bool replay) => supplied is long value
        ? SandboxCommands.PositiveRevision(value)
        : replay ? throw new UsageException("An exact replay requires the original --expected-revision.") : null;
}
