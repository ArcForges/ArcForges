// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using V1 = ArcForges.Contracts.Node.V1;
using V2 = ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.CommandLine;

internal static class V2NodeCommands
{
    private static readonly TimeSpan UnaryDeadline = TimeSpan.FromSeconds(10);

    internal static Command Start(Func<ParseResult, Cli> factory)
    {
        var command = new Command("start", "Start the local Node and wait for readiness");
        V2Cli.Set(command, factory, async (cli, _, ct) =>
        {
            V2CliSession? session = null;
            try
            {
                session = await V2CliSession.OpenAsync(cli, ct, autoStart: false).ConfigureAwait(false);
            }
            catch (NodeUnavailableException error) when (error.Reason == NodeUnavailableReason.NotRunning)
            {
                // Only a missing service is eligible for explicit startup.
            }

            bool started = session is null;
            if (started)
            {
                ct.ThrowIfCancellationRequested();
                var start = NodeAutoStart.StartExplicitly(cli.TestMode);
                if (start.Outcome != AutoStartOutcome.Started)
                {
                    var error = start.Outcome == AutoStartOutcome.RefusedInSandbox
                        ? V2Cli.Error(ErrorCategory.Execution, "unsupported_combination", "local_node_service_start_forbidden_by_scope")
                        : V2Cli.Error(ErrorCategory.State, "node_unavailable", "local_node_start_failed");
                    return V2Cli.Fail(cli, error);
                }
            }

            if (session is null || session.LocalNode.State is V1.NodeLifecycleState.Starting or V1.NodeLifecycleState.Recovering)
            {
                if (session is not null)
                {
                    await session.DisposeAsync().ConfigureAwait(false);
                }

                session = await V2CliSession.WaitForReadyAsync(cli, ct).ConfigureAwait(false);
            }

            await using (session.ConfigureAwait(false))
            {
                using var pin = session.PinConnection();
                var status = await ReadStatusAsync(cli, session, ct).ConfigureAwait(false);
                status["started"] = started;
                return V2Cli.Print(cli, status);
            }
        });
        return command;
    }

    internal static Command Status(Func<ParseResult, Cli> factory)
    {
        var command = new Command("status", "Inspect the local Node service state and Sandbox Core handshake");
        V2Cli.Set(command, factory, async (cli, _, ct) =>
        {
            await using var session = await V2CliSession.OpenAsync(cli, ct, autoStart: false).ConfigureAwait(false);
            using var pin = session.PinConnection();
            return V2Cli.Print(cli, await ReadStatusAsync(cli, session, ct).ConfigureAwait(false));
        });
        return command;
    }

    internal static Command Doctor(Func<ParseResult, Cli> factory)
    {
        var sandboxOption = new Option<string?>("--sandbox") { Description = "Inspect a specific Sandbox profile and capabilities", HelpName = "id" };
        var command = new Command("doctor", "Inspect local Node readiness, qualified capabilities, and sampled resource budgets") { sandboxOption };
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            var sandboxId = result.GetValue(sandboxOption) is { } text ? V2Cli.ReadId(text, "--sandbox") : null;
            await using var session = await V2CliSession.OpenAsync(cli, ct, autoStart: false).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var report = await ReadStatusAsync(cli, session, ct).ConfigureAwait(false);

            var budget = new V2.ResourceServiceGetBudgetRequest { Meta = Cli.Meta(), ScopeKind = "node" };
            var resource = await cli.CallAsync("ResourceService.GetBudget", budget.Meta,
                () => session.Resources.GetBudgetAsync(budget, deadline: cli.Deadline(UnaryDeadline), cancellationToken: ct)).ConfigureAwait(false);
            report["resources"] = CliOutput.ToJsonNode(V2Cli.Require(V2Cli.Require(resource.Value, resource.Error).Snapshot, null));

            if (sandboxId is not null)
            {
                var inspect = new V2.SandboxServiceInspectRequest { Meta = Cli.Meta(), SandboxId = sandboxId };
                var reply = await cli.CallAsync("SandboxService.Inspect", inspect.Meta,
                    () => session.Sandboxes.InspectAsync(inspect, deadline: cli.Deadline(UnaryDeadline), cancellationToken: ct)).ConfigureAwait(false);
                var sandbox = V2Cli.Require(V2Cli.Require(reply.Value, reply.Error).Sandbox, null);
                report["sandbox"] = new JsonObject
                {
                    ["sandboxId"] = IdText.Format(sandbox.SandboxId),
                    ["state"] = sandbox.State == V2.SandboxState.RecoveryRequired ? "recovery_required" : sandbox.State.ToString().ToLowerInvariant(),
                    ["revision"] = sandbox.Revision?.Value,
                    ["profileId"] = sandbox.Config?.ProfileId,
                    ["profileVersion"] = sandbox.Config?.ProfileVersion,
                    ["capabilities"] = new JsonArray(sandbox.Capabilities.Select(CliOutput.ToJsonNode).ToArray()),
                };
            }

            return V2Cli.Print(cli, report);
        });
        return command;
    }

    private static async Task<JsonObject> ReadStatusAsync(Cli cli, V2CliSession session, CancellationToken ct)
    {
        var response = await session.HandshakeAsync(cli.Deadline(UnaryDeadline), ct).ConfigureAwait(false);
        var handshake = V2Cli.Require(response.Value, response.Error);
        var node = session.LocalNode;
        return new JsonObject
        {
            ["state"] = node.State.ToString().ToLowerInvariant(),
            ["nodeId"] = IdText.Format(node.Node.NodeId),
            ["version"] = node.Version,
            ["handshake"] = CliOutput.ToJsonNode(handshake),
        };
    }
}
