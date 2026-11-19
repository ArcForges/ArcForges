// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Grpc.Core;

namespace ArcForges.CommandLine;

internal static class SandboxResourceCommands
{
    private static readonly TimeSpan UnaryDeadline = TimeSpan.FromSeconds(10);

    internal static Command Build(Func<ParseResult, Cli> factory)
    {
        var group = new Command("resources", "View and configure resource budgets for the local Node, Sandboxes and Runs");
        group.Subcommands.Add(Show(factory));
        group.Subcommands.Add(Watch(factory));
        group.Subcommands.Add(SetPolicy(factory));
        return group;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var command = new Command("show", "Show sampled resource usage, budgets and actual limits");
        var scope = new ScopeOptions(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var (kind, id) = scope.Read(result);
            var request = new ResourceServiceGetBudgetRequest { Meta = Cli.Meta(), ScopeKind = kind, ScopeId = id };
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            var response = await cli.CallAsync("ResourceService.GetBudget", request.Meta, () => session.Resources.GetBudgetAsync(
                request, deadline: cli.Deadline(UnaryDeadline), cancellationToken: cancellationToken)).ConfigureAwait(false);
            var value = V2Cli.Require(response.Value, response.Error);
            return V2Cli.Print(cli, V2Cli.Require(value.Snapshot, null));
        });
        return command;
    }

    private static Command Watch(Func<ParseResult, Cli> factory)
    {
        var interval = new Option<string?>("--interval")
        {
            Description = "Interval between resource snapshots from 1s to 60s (default 5s)",
            HelpName = "duration",
        };
        var once = new Option<bool>("--once") { Description = "Exit after the first snapshot" };
        var command = new Command("watch", "Watch fresh resource snapshots") { interval, once };
        var scope = new ScopeOptions(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var (kind, id) = scope.Read(result);
            bool single = result.GetValue(once);
            var request = new ResourceServiceWatchUsageRequest { Meta = Cli.Meta(), ScopeKind = kind, ScopeId = id };
            if (result.GetValue(interval) is { } specified)
            {
                if (!Durations.TryParse(specified, out var period) || period < TimeSpan.FromSeconds(1) || period > TimeSpan.FromMinutes(1))
                {
                    throw new UsageException("--interval requires a duration from 1s to 60s.");
                }

                request.IntervalMs = (uint)period.TotalMilliseconds;
            }

            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            DateTime? deadline = cli.Timeout is null ? null : cli.Deadline(UnaryDeadline);
            using var call = session.Resources.WatchUsage(request, deadline: deadline, cancellationToken: cancellationToken);
            try
            {
                await foreach (var frame in call.ResponseStream.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (frame.Error is { } error)
                    {
                        return V2Cli.Fail(cli, error, stream: true);
                    }

                    V2Cli.PrintLine(cli, V2Cli.Require(frame.Snapshot, null));
                    await cli.Output.Out.FlushAsync(cancellationToken).ConfigureAwait(false);
                    if (single)
                    {
                        return 0;
                    }
                }
            }
            catch (OperationCanceledException) when (!single && cancellationToken.IsCancellationRequested)
            {
                return 0;
            }
            catch (RpcException failure) when (!single && failure.StatusCode == StatusCode.Cancelled && cancellationToken.IsCancellationRequested)
            {
                return 0;
            }

            if (single)
            {
                throw new RpcException(new Status(StatusCode.Unavailable, "The resource stream ended before its first snapshot."));
            }

            return 0;
        }, stream: true);
        return command;
    }

    private static Command SetPolicy(Func<ParseResult, Cli> factory)
    {
        var file = new Option<string>("--file") { Required = true, Description = "V2 resource policy JSON file", HelpName = "policy" };
        var revision = new Option<long>("--expected-revision") { Required = true, Description = "Current resource policy revision" };
        var command = new Command("set", "Set the desired resource policy and report actual enforcement") { file, revision };
        var scope = new ScopeOptions(command, required: true);
        var mutation = new V2MutationOptions();
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var (kind, id) = scope.Read(result);
            long expected = result.GetValue(revision);
            if (expected is <= 0 or long.MaxValue)
            {
                throw new UsageException("--expected-revision requires a positive revision below the maximum revision.");
            }

            var policy = await V2Cli.ReadJsonAsync(result.GetValue(file)!, ResourcePolicy.Parser, cancellationToken).ConfigureAwait(false);
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var pin = session.PinConnection();
            DateTime deadline = cli.Deadline(UnaryDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            identity.Meta.ExpectedRev = new Revision { Value = expected };
            var request = new ResourceServiceSetPolicyRequest
            {
                Meta = identity.Meta, OwnerEpoch = identity.OwnerEpoch, ScopeKind = kind, ScopeId = id, Policy = policy,
            };
            var response = await V2Cli.SendAsync(cli, "ResourceService.SetPolicy", identity,
                () => session.Resources.SetPolicyAsync(request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
            return V2Cli.Print(cli, V2Cli.Require(response.Value, response.Error, identity), identity);
        });
        return command;
    }

    private sealed class ScopeOptions
    {
        private readonly Option<string?> _scope = new("--scope") { Description = "Resource scope (node, sandbox or run)" };
        private readonly Option<string?> _id = new("--id") { Description = "Sandbox or Run ID for a scoped request" };

        internal ScopeOptions(Command command, bool required = false)
        {
            _scope.Required = required;
            _scope.AcceptOnlyFromAmong("node", "sandbox", "run");
            command.Options.Add(_scope);
            command.Options.Add(_id);
        }

        internal (string Kind, Id? Id) Read(ParseResult result)
        {
            string kind = result.GetValue(_scope) ?? "node";
            var id = result.GetValue(_id);
            if (kind == "node")
            {
                if (id is not null)
                {
                    throw new UsageException("--id applies only to a sandbox or run resource scope.");
                }

                return (kind, null);
            }

            return (kind, V2Cli.ReadId(id, "--id"));
        }
    }
}
