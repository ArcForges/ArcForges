// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges node ...</c> (experience/cli.md C-10): run, stop, wait-ready, info, health, capabilities and rename. <c>node wipe</c>
/// (WipeNode) and <c>node self-test</c> (the enforcement platform layer) belong to later tasks and are not offered by this build.
/// </summary>
internal static class NodeCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);

    public static Command Build(Func<ParseResult, Cli> factory, NodeRunner nodeRunner)
    {
        var node = new Command("node", "Run, stop and inspect the node");
        node.Subcommands.Add(Run(factory, nodeRunner));
        node.Subcommands.Add(Stop(factory));
        node.Subcommands.Add(WaitReady(factory));
        node.Subcommands.Add(Info(factory));
        node.Subcommands.Add(Health(factory));
        node.Subcommands.Add(Capabilities(factory));
        node.Subcommands.Add(Rename(factory));
        return node;
    }

    /// <summary>
    /// <c>node run [--background] [--systemd]</c>: runs the node role in this process (exit 3 when a node already runs). With
    /// <c>--background</c> it starts the node detached instead (the supervisor on Windows; the user unit on Linux, or a
    /// <c>setsid</c> launch without a user manager) and returns once it is ready.
    /// </summary>
    private static Command Run(Func<ParseResult, Cli> factory, NodeRunner nodeRunner)
    {
        var background = new Option<bool>("--background") { Description = "Start the node detached and return once it is ready" };
        var systemd = new Option<bool>("--systemd") { Description = "Run under the systemd user unit (readiness and watchdog notifications)" };
        var command = new Command("run", "Run the node (exit 3 if it is already running)") { background, systemd };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            if (!result.GetValue(background))
            {
                return await nodeRunner(new NodeRunRequest(cli.TestMode, result.GetValue(systemd)), cancellationToken).ConfigureAwait(false);
            }

            try
            {
                await using var running = await cli.ConnectAsync(autoStart: false, cancellationToken).ConfigureAwait(false);
                cli.Output.Essential(running.Endpoint.Endpoint.Address);
                cli.Output.Error.WriteLine($"arcforges: the node is already running (endpoint {running.Endpoint.Endpoint.Address})");
                return ExitCodes.AlreadyRunning;
            }
            catch (NodeUnavailableException exception) when (exception.Reason == NodeUnavailableReason.NotRunning)
            {
            }

            var start = NodeAutoStart.StartExplicitly(cli.TestMode);
            if (start.Outcome != AutoStartOutcome.Started)
            {
                return cli.Output.Fail(new NodeUnavailableException(NodeUnavailableReason.AutoStartFailed,
                    "the node could not be started in the background (" + start.Detail + ")", "run 'arcforges node run' in a terminal"));
            }

            await using var session = await NodeClient.WaitForReadyAsync(
                new NodeConnectOptions { Kind = ClientKind.Cli, TestMode = cli.TestMode, ReadinessTimeout = TimeSpan.FromSeconds(15) }, cancellationToken)
                .ConfigureAwait(false);
            cli.Output.Note("node started (" + start.Detail + ")");
            cli.Output.Essential(session.Endpoint.Endpoint.Address);
            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary><c>node stop [--cancel-running] [--timeout d] [--reason r]</c>: <c>StopNode</c>, then waits until the node is gone.</summary>
    private static Command Stop(Func<ParseResult, Cli> factory)
    {
        var cancelRunning = new Option<bool>("--cancel-running") { Description = "Cancel running executions (otherwise they continue)" };
        var timeout = new Option<string?>("--timeout") { Description = "How long to wait for the node to stop (default 60s)", HelpName = "dur" };
        var reason = new Option<string?>("--reason") { Description = "Why the node is stopped (recorded)" };
        var command = new Command("stop", "Stop the node") { cancelRunning, timeout, reason };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var wait = ParseDuration(result.GetValue(timeout), TimeSpan.FromSeconds(60), "--timeout");
            NodeSession session;
            try
            {
                session = await cli.ConnectAsync(autoStart: false, cancellationToken).ConfigureAwait(false);
            }
            catch (NodeUnavailableException exception) when (exception.Reason == NodeUnavailableReason.NotRunning)
            {
                cli.Output.Line("The node is not running.");
                return ExitCodes.Success;
            }

            await using (session.ConfigureAwait(false))
            {
                var request = new NodeServiceStopNodeRequest
                {
                    Meta = Cli.Meta(),
                    CancelRunning = result.GetValue(cancelRunning),
                    TimeoutMs = (ulong)wait.TotalMilliseconds,
                };
                if (result.GetValue(reason) is { Length: > 0 } text)
                {
                    request.Reason = text;
                }

                var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
                var response = await cli.MutateAsync("StopNode", request.Meta.CommandId, action, r => session.Channel.Node.StopNodeAsync(r,
                    deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
                if (response.Error is { } error)
                {
                    return cli.Output.Fail(error, request.Meta.CorrelationId);
                }
            }

            if (!await WaitStoppedAsync(cli, wait, cancellationToken).ConfigureAwait(false))
            {
                cli.Output.Error.WriteLine($"arcforges: the stop was recorded, but the node was still running after {wait.TotalSeconds:0} s");
                return ExitCodes.Failed;
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(new System.Text.Json.Nodes.JsonObject { ["stopped"] = true });
            }
            else
            {
                cli.Output.Line("The node stopped.");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary><c>node wait-ready [--timeout d]</c>: polls the endpoint until the node answers its hello (default 30 s).</summary>
    private static Command WaitReady(Func<ParseResult, Cli> factory)
    {
        var timeout = new Option<string?>("--timeout") { Description = "How long to wait (default 30s)", HelpName = "dur" };
        var command = new Command("wait-ready", "Wait until the node is ready") { timeout };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var wait = ParseDuration(result.GetValue(timeout), TimeSpan.FromSeconds(30), "--timeout");
            await using var session = await NodeClient.WaitForReadyAsync(
                new NodeConnectOptions { Kind = ClientKind.Cli, TestMode = cli.TestMode, ReadinessTimeout = wait }, cancellationToken).ConfigureAwait(false);
            if (cli.Output.Json)
            {
                cli.Output.Document(new System.Text.Json.Nodes.JsonObject
                {
                    ["state"] = session.Hello.Node.State.ToString().ToUpperInvariant(),
                    ["endpoint"] = session.Endpoint.Endpoint.Address,
                });
            }
            else
            {
                cli.Output.Line("The node is ready (" + CliOutput.Word(session.Hello.Node.State) + ").");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Info(Func<ParseResult, Cli> factory)
    {
        var command = new Command("info", "Show the node's identity, version and state");
        Actions.Set(command, factory, async (cli, _, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var meta = Cli.Meta();
            var response = await cli.CallAsync("GetNodeInfo", meta, () => session.Channel.Node.GetNodeInfoAsync(
                new NodeServiceGetNodeInfoRequest { Meta = meta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(writer =>
                {
                    writer.WriteStartObject();
                    writer.WritePropertyName("node");
                    NodeInfoJson.Write(writer, response.Value.Node);
                    writer.WriteEndObject();
                });
            }
            else
            {
                cli.Output.KeyValues(StatusCommands.NodeRows(cli.Output, response.Value.Node, null));
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Health(Func<ParseResult, Cli> factory)
    {
        var command = new Command("health", "Show the node's quick health checks and local metrics");
        Actions.Set(command, factory, async (cli, _, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var meta = Cli.Meta();
            var response = await cli.CallAsync("GetHealth", meta, () => session.Channel.Node.GetHealthAsync(
                new NodeServiceGetHealthRequest { Meta = meta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, meta.CorrelationId);
            }

            var value = response.Value;
            if (cli.Output.Json)
            {
                cli.Output.Document(value);
                return ExitCodes.Success;
            }

            cli.Output.Line("state: " + cli.Output.State(value.State));
            cli.Output.Table(["CHECK", "STATUS", "SUMMARY"],
                [.. value.Checks.Select(check => (IReadOnlyList<string>)[check.CheckId, Status(check.Status), check.Summary])]);
            cli.Output.Line();
            cli.Output.Table(["METRIC", "VALUE"],
                [.. value.Metrics.Select(metric => (IReadOnlyList<string>)[
                    metric.Name + (metric.Labels.Count == 0 ? string.Empty : "{" + string.Join(",", metric.Labels.Select(label => label.Key + "=" + label.Value)) + "}"),
                    metric.Value.ToString("0.###", CultureInfo.InvariantCulture)])]);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Capabilities(Func<ParseResult, Cli> factory)
    {
        var reevaluate = new Option<bool>("--reevaluate") { Description = "Evaluate the capabilities again" };
        var command = new Command("capabilities", "Show the node's enforcement capabilities and platform facts") { reevaluate };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var meta = Cli.Meta();
            var response = await cli.CallAsync("GetCapabilities", meta, () => session.Channel.Node.GetCapabilitiesAsync(
                new NodeServiceGetCapabilitiesRequest { Meta = meta, Reevaluate = result.GetValue(reevaluate) }, deadline: cli.Deadline(TimeSpan.FromSeconds(30)),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, meta.CorrelationId);
            }

            var report = response.Value.Capabilities;
            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            cli.Output.Table(["CAPABILITY", "LEVEL", "REASON"],
            [
                ["cpu", Enum(report.Cpu.ToString()), report.CpuReason],
                ["memory", Enum(report.Memory.ToString()), report.MemoryReason],
                ["processes", Enum(report.Pids.ToString()), report.PidsReason],
                ["io", Enum(report.Io.ToString()), report.IoReason],
            ]);
            cli.Output.Line();
            cli.Output.KeyValues([.. report.PlatformFacts.Select(fact => (fact.Name, fact.Value))]);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Rename(Func<ParseResult, Cli> factory)
    {
        var name = new Argument<string>("name") { Description = "The new display name (1 to 64 printable characters)" };
        var command = new Command("rename", "Change the node's display name") { name };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new NodeServiceRenameNodeRequest { Meta = Cli.Meta(), Name = result.GetValue(name)! };
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("RenameNode", request.Meta.CommandId, action, r => session.Channel.Node.RenameNodeAsync(r,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
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
                cli.Output.Line("The node is now named " + response.Value.Node.Node.Name + ".");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary>Waits until no node answers on the endpoint (the stop completed) or the time is up.</summary>
    private static async Task<bool> WaitStoppedAsync(Cli cli, TimeSpan wait, CancellationToken cancellationToken)
    {
        var started = TimeProvider.System.GetTimestamp();
        while (TimeProvider.System.GetElapsedTime(started) < wait)
        {
            try
            {
                await using var probe = await cli.ConnectAsync(autoStart: false, cancellationToken).ConfigureAwait(false);
            }
            catch (NodeUnavailableException exception) when (exception.Reason == NodeUnavailableReason.NotRunning)
            {
                return true;
            }
            catch (NodeUnavailableException)
            {
                // Stopping, busy or refusing new hellos: still there.
            }

            await Task.Delay(200, cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    internal static TimeSpan ParseDuration(string? text, TimeSpan fallback, string option) => text is null
        ? fallback
        : Durations.TryParse(text, out var parsed) ? parsed : throw new UsageException($"{option}: '{text}' is not a duration (90s, 5m, 2h, 1d).");

    private static string Status(CheckStatus status) => status switch
    {
        CheckStatus.Pass => "pass",
        CheckStatus.Warn => "warn",
        CheckStatus.Fail => "FAIL",
        CheckStatus.Skipped => "skipped",
        _ => "-",
    };

    private static string Enum(string name) =>
        string.Concat(name.Select((character, index) => index > 0 && char.IsUpper(character) ? "_" + character : character.ToString())).ToUpperInvariant();
}
