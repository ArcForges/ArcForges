// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Grpc.Core;
using Legacy = ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

internal static class V2NodeStopCommand
{
    internal static Command Build(Func<ParseResult, Cli> factory)
    {
        var stopRuns = new Option<bool>("--stop-runs") { Description = "Stop Runs found in the owned inventory before shutdown. Concurrent Starts may remain active." };
        var reason = new Option<string?>("--reason") { Description = "Record a reason for the service shutdown" };
        var command = new Command("stop", "Stop the local Node, leaving owned Runs active by default") { stopRuns, reason };
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            var time = cli.Timeout ?? TimeSpan.FromSeconds(60);
            if (time <= TimeSpan.Zero || time > TimeSpan.FromMinutes(10))
            {
                throw new UsageException("--timeout must be positive and at most 10 minutes.");
            }

            var stopReason = result.GetValue(reason);
            if (stopReason is { Length: > 200 })
            {
                throw new UsageException("--reason must contain at most 200 characters.");
            }

            return await StopAsync(cli, result.GetValue(stopRuns), stopReason, time, ct).ConfigureAwait(false);
        });
        return command;
    }

    private static async Task<int> StopAsync(Cli cli, bool stopRuns, string? reason, TimeSpan time, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + time;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(time);
        var token = budget.Token;
        V2CliSession session;
        try
        {
            session = await V2CliSession.OpenAsync(cli, token, autoStart: false).ConfigureAwait(false);
        }
        catch (NodeUnavailableException exception) when (!stopRuns && exception.Reason == NodeUnavailableReason.NotRunning)
        {
            if (!cli.Output.Json)
            {
                cli.Output.Essential("The node is not running.");
                return 0;
            }

            return V2Cli.Print(cli, new JsonObject { ["stopped"] = true, ["alreadyStopped"] = true });
        }

        var observations = new JsonObject();
        var request = new Legacy.NodeServiceStopNodeRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
        };
        if (reason is not null)
        {
            request.Reason = reason;
        }

        await using (session.ConfigureAwait(false))
        {
            using var connection = session.PinConnection();
            if (stopRuns)
            {
                try
                {
                    await StopOwnedRunsAsync(cli, session, deadline, observations, token).ConfigureAwait(false);
                }
                catch (V2CommandException exception)
                {
                    return V2Cli.Fail(cli, exception.Error, exception.Identity, observations: observations);
                }
                catch (RpcException exception)
                {
                    return V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.State, "node_unavailable", "run_inventory/" + exception.StatusCode),
                        observations: observations);
                }
                catch (OperationCanceledException)
                {
                    return V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.State, "node_unavailable", "run_inventory_cancelled"),
                        observations: observations);
                }
            }

            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero || token.IsCancellationRequested)
            {
                return V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.State, "node_unavailable", "shutdown_not_sent"), observations: observations);
            }

            request.TimeoutMs = (ulong)Math.Ceiling(remaining.TotalMilliseconds);
            observations["serviceStopCommandId"] = IdText.Format(request.Meta.CommandId);
            try
            {
                using var call = session.Lifecycle.StopNodeAsync(request, deadline: deadline, cancellationToken: token);
                var response = await call.ResponseAsync.ConfigureAwait(false);
                if (response.Error is { } error)
                {
                    return V2Cli.Fail(cli, error, observations: observations);
                }

                if (response.Value?.Receipt is not { Effect: EffectCertainty.Happened } receipt
                    || !request.Meta.CommandId.Equals(receipt.CommandId))
                {
                    return ServiceUnknown("shutdown_receipt_unconfirmed");
                }

                observations["serviceStopReceipt"] = CliOutput.ToJsonNode(receipt);
            }
            catch (RpcException exception)
            {
                return ServiceUnknown("StopNode/" + exception.StatusCode);
            }
            catch (OperationCanceledException)
            {
                return ServiceUnknown("shutdown_cancelled_after_dispatch");
            }
        }

        try
        {
            if (!await NodeCommands.WaitStoppedAsync(cli, deadline - DateTime.UtcNow, token).ConfigureAwait(false))
            {
                return ShutdownUnobserved("shutdown_not_observed");
            }
        }
        catch (OperationCanceledException)
        {
            return ShutdownUnobserved("shutdown_observation_cancelled");
        }

        observations["stopped"] = true;
        return V2Cli.Print(cli, observations);

        int ServiceUnknown(string detail)
        {
            var unknown = V2Cli.UnknownEffect(detail, request.Meta.CorrelationId);
            unknown.Retry = new RetryAdvice { Mode = RetryMode.Never };
            return V2Cli.Fail(cli, unknown, observations: observations);
        }

        int ShutdownUnobserved(string detail)
        {
            var error = V2Cli.Error(ErrorCategory.State, "node_unavailable", detail);
            error.CorrelationId = request.Meta.CorrelationId;
            error.Effect = EffectCertainty.Happened;
            observations["shutdownObserved"] = false;
            return V2Cli.Fail(cli, error, observations: observations);
        }
    }

    private static async Task StopOwnedRunsAsync(Cli cli, V2CliSession session, DateTime deadline, JsonObject observations, CancellationToken ct)
    {
        var handshake = await session.HandshakeAsync(deadline, ct).ConfigureAwait(false);
        var epoch = V2Cli.Require(V2Cli.Require(handshake.Value, handshake.Error).OwnerEpoch, null);
        var pending = await FindActiveRunsAsync(session, deadline, ct).ConfigureAwait(false);
        var receipts = new JsonArray();
        var remaining = new JsonArray();
        observations["runStopScope"] = "observed_inventory";
        observations["observedRunIds"] = new JsonArray(pending.Select(run => (JsonNode?)JsonValue.Create(IdText.Format(run.RunId))).ToArray());
        observations["runStops"] = receipts;
        foreach (var run in pending)
        {
            if (deadline <= DateTime.UtcNow)
            {
                throw new V2CommandException(V2Cli.Error(ErrorCategory.State, "node_unavailable", "run_stop_deadline_elapsed"), null);
            }

            var meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
            var identity = new V2CommandIdentity(epoch, meta.CommandId, meta);
            var runId = V2Cli.Require(run.RunId, null);
            var outcome = await SandboxRunCommands.StopAsync(cli, session, runId,
                V2Cli.Require(run.Revision, null), identity, graceMs: null, deadline, ct).ConfigureAwait(false);
            receipts.Add(CliOutput.ToJsonNode(outcome.Operation));

            // Only the identities observed above are subject to this request.
            if (!IsDrained(outcome.Run) && !IsDrained(await SandboxRunCommands.InspectAsync(session, runId, deadline, ct).ConfigureAwait(false)))
            {
                remaining.Add((JsonNode?)JsonValue.Create(IdText.Format(runId)));
            }
        }

        if (remaining.Count > 0)
        {
            observations["remainingRunIds"] = remaining;
            var error = V2Cli.UnknownEffect("observed_runs_remain_active_after_stop");
            error.Retry = new RetryAdvice { Mode = RetryMode.Never };
            throw new V2CommandException(error, null);
        }
    }

    private static bool IsDrained(Run? run) =>
        run is { State: RunState.Exited or RunState.Failed, Exit.GroupEmptyVerified: true };

    private static async Task<List<Run>> FindActiveRunsAsync(V2CliSession session, DateTime deadline, CancellationToken ct)
    {
        var sandboxes = new List<Id>();
        string cursor = string.Empty;
        do
        {
            using var call = session.Sandboxes.ListAsync(new SandboxServiceListRequest { Meta = Cli.Meta(), Limit = 200, Cursor = cursor },
                deadline: deadline, cancellationToken: ct);
            var response = await call.ResponseAsync.ConfigureAwait(false);
            var value = V2Cli.Require(response.Value, response.Error);
            sandboxes.AddRange(value.Sandboxes.Select(sandbox => V2Cli.Require(sandbox.SandboxId, null)));
            cursor = value.Page?.NextCursor ?? string.Empty;
        }
        while (cursor.Length > 0);

        var active = new List<Run>();
        foreach (var sandbox in sandboxes)
        {
            do
            {
                using var call = session.Runs.ListAsync(new RunServiceListRequest
                {
                    Meta = Cli.Meta(),
                    SandboxId = sandbox,
                    Limit = 200,
                    Cursor = cursor,
                }, deadline: deadline, cancellationToken: ct);
                var response = await call.ResponseAsync.ConfigureAwait(false);
                var value = V2Cli.Require(response.Value, response.Error);
                active.AddRange(value.Runs.Where(run => run.State is not (RunState.Exited or RunState.Failed)
                    || run.Exit?.GroupEmptyVerified != true));
                cursor = value.Page?.NextCursor ?? string.Empty;
            }
            while (cursor.Length > 0);
        }

        return active;
    }
}
