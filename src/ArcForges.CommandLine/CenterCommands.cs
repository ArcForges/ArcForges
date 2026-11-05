// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges center show</c> and <c>arcforges center set &lt;url&gt; | --default</c> (AF-CTR-04 CTR4-NODE-01/15 as amended; Q18). The
/// change goes through <c>UpdateNodeSettings.center_url</c>, which node.proto makes "HUMAN only (no approval path)" and refuses "while the
/// node is signed in or signing in: STATE/invalid_state (state.state signed_in or signing_in, state.reason center_url)" (exit 1); an empty
/// value is "back to the official default (refused under --test-mode)".
/// </summary>
internal static class CenterCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);

    /// <summary>The <c>center</c> group.</summary>
    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var center = new Command("center", "The center this node signs in to");
        center.Subcommands.Add(Show(factory));
        center.Subcommands.Add(Set(factory));
        return center;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var command = new Command("show", "Print the configured center");
        Actions.Set(command, factory, async (cli, _, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var meta = Cli.Meta();
            var settings = await cli.CallAsync("GetNodeSettings", meta, () => session.Channel.Node.GetNodeSettingsAsync(
                new NodeServiceGetNodeSettingsRequest { Meta = meta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (settings.Error is { } error)
            {
                return cli.Output.Fail(error, meta.CorrelationId);
            }

            var configured = settings.Value.Settings.HasCenterUrl ? settings.Value.Settings.CenterUrl : null;
            var status = await AccountCommands.ReadStatusAsync(cli, session, cancellationToken).ConfigureAwait(false);
            var credential = status is { SignedIn: true, HasCenterUrl: true } ? status.CenterUrl : null;
            if (cli.Output.Json)
            {
                var document = new JsonObject { ["centerUrl"] = configured };
                if (credential is not null)
                {
                    document["credentialCenterUrl"] = credential;
                }

                cli.Output.Document(document);
                return ExitCodes.Success;
            }

            cli.Output.Line("Center: " + (configured ?? "none (set one with 'arcforges center set <url>')"));
            if (credential is not null && credential != configured)
            {
                cli.Output.Line("Signed in at: " + credential);
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Set(Func<ParseResult, Cli> factory)
    {
        var url = new Argument<string?>("url") { Description = "The center's URL (https; http only for localhost, 127.0.0.1 or [::1])", Arity = ArgumentArity.ZeroOrOne };
        var reset = new Option<bool>("--default") { Description = "Use the official center again" };
        var command = new Command("set", "Change the center (sign out first)") { url, reset };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var value = result.GetValue(url);
            var official = result.GetValue(reset);
            if ((value is null) == !official)
            {
                throw new UsageException("give either a URL or --default.");
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            for (var attempt = 0; ; attempt++)
            {
                var readMeta = Cli.Meta();
                var current = await cli.CallAsync("GetNodeSettings", readMeta, () => session.Channel.Node.GetNodeSettingsAsync(
                    new NodeServiceGetNodeSettingsRequest { Meta = readMeta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
                if (current.Error is { } readError)
                {
                    return cli.Output.Fail(readError, readMeta.CorrelationId);
                }

                var request = new NodeServiceUpdateNodeSettingsRequest { Meta = Cli.Meta(), CenterUrl = official ? string.Empty : value! };
                request.Meta.ExpectedRev = current.Value.Settings.Revision;
                var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
                var response = await cli.MutateAsync("UpdateNodeSettings", request.Meta.CommandId, action, r => session.Channel.Node.UpdateNodeSettingsAsync(r,
                    deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
                if (response.Error is { Code: "revision_conflict" } && attempt == 0)
                {
                    continue;
                }

                if (response.Error is { } error)
                {
                    if (!cli.Output.Json && error.Code == "invalid_state" && error.Details?.State is { } state)
                    {
                        cli.Output.Error.WriteLine("error: " + (state.State switch
                        {
                            "signed_in" => "the node is signed in; run 'arcforges logout' first",
                            "signing_in" => "a sign-in is in progress; finish or cancel it first",
                            _ => "the center cannot be changed now (" + state.Reason + ")",
                        }) + " (STATE/invalid_state)");
                        return ExitCodes.Failed;
                    }

                    return cli.Output.Fail(error, request.Meta.CorrelationId);
                }

                if (cli.Output.Json)
                {
                    cli.Output.Document(response.Value);
                }
                else
                {
                    cli.Output.Line("Center: " + response.Value.Settings.CenterUrl);
                    foreach (var warning in response.Meta.Warnings)
                    {
                        cli.Output.Note(warning);
                    }
                }

                return ExitCodes.Success;
            }
        });
        return command;
    }
}
