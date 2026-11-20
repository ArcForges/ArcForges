// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.CommandLine;

internal static class SandboxOperationCommands
{
    internal static Command Build(Func<ParseResult, Cli> factory)
    {
        var commandId = new Argument<string>("command-id") { Description = "Original durable command ID" };
        var epoch = new Option<string>("--owner-epoch")
        {
            Required = true,
            Description = "Original owner epoch printed when the command was sent",
            HelpName = "epoch",
        };
        var inspect = new Command("inspect", "Read the original operation state and retained effect") { commandId, epoch };
        V2Cli.Set(inspect, factory, async (cli, result, cancellationToken) =>
        {
            var request = new NodeServiceGetOperationRequest
            {
                Meta = Cli.Meta(),
                CommandId = V2Cli.ReadId(result.GetValue(commandId), "command-id"),
                OwnerEpoch = V2Cli.ReadId(result.GetValue(epoch), "--owner-epoch"),
            };
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            var response = await cli.CallAsync("NodeService.GetOperation", request.Meta, () => session.Node.GetOperationAsync(
                request, deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken)).ConfigureAwait(false);
            return V2Cli.Print(cli, V2Cli.Require(response.Value, response.Error));
        });
        var group = new Command("operation", "Inspect durable operation receipts");
        group.Subcommands.Add(inspect);
        return group;
    }
}
