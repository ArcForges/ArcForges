// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Globalization;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges config list|get|set</c> (experience/cli.md C-10): the node.json settings through <c>GetNodeSettings</c> and
/// <c>UpdateNodeSettings</c>. Keys are the settings' JSON names: <c>dataRoot</c> and <c>configPath</c> (read-only here),
/// <c>logLevel</c> (error, warning, info, debug), <c>telemetryOptIn</c> (true, false) and <c>revision</c> (read-only).
/// </summary>
internal static class ConfigCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);

    private static readonly string[] Keys = ["dataRoot", "logLevel", "telemetryOptIn", "configPath", "revision"];

    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var config = new Command("config", "Read and change node settings (node.json)");
        config.Subcommands.Add(List(factory));
        config.Subcommands.Add(Get(factory));
        config.Subcommands.Add(Set(factory));
        return config;
    }

    private static Command List(Func<ParseResult, Cli> factory)
    {
        var command = new Command("list", "List the node settings");
        Actions.Set(command, factory, async (cli, _, cancellationToken) =>
        {
            var (settings, exit) = await ReadAsync(cli, cancellationToken).ConfigureAwait(false);
            if (settings is null)
            {
                return exit;
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(settings);
            }
            else
            {
                cli.Output.KeyValues([.. Keys.Select(key => (key, Value(settings, key)))]);
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Get(Func<ParseResult, Cli> factory)
    {
        var key = new Argument<string>("key") { Description = "dataRoot, logLevel, telemetryOptIn, configPath or revision" };
        key.AcceptOnlyFromAmong(Keys);
        var command = new Command("get", "Print one node setting") { key };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var (settings, exit) = await ReadAsync(cli, cancellationToken).ConfigureAwait(false);
            if (settings is null)
            {
                return exit;
            }

            var name = result.GetValue(key)!;
            if (cli.Output.Json)
            {
                cli.Output.Document(new JsonObject { [name] = Value(settings, name) });
            }
            else
            {
                cli.Output.Essential(Value(settings, name));
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Set(Func<ParseResult, Cli> factory)
    {
        var key = new Argument<string>("key") { Description = "logLevel or telemetryOptIn" };
        key.AcceptOnlyFromAmong(Keys);
        var value = new Argument<string>("value") { Description = "logLevel: error|warning|info|debug; telemetryOptIn: true|false" };
        var command = new Command("set", "Change one node setting") { key, value };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var name = result.GetValue(key)!;
            var text = result.GetValue(value)!;
            var request = new NodeServiceUpdateNodeSettingsRequest { Meta = Cli.Meta() };
            switch (name)
            {
                case "logLevel":
                    request.LogLevel = text.ToUpperInvariant() switch
                    {
                        "ERROR" => LogLevel.Error,
                        "WARNING" => LogLevel.Warning,
                        "INFO" => LogLevel.Info,
                        "DEBUG" => LogLevel.Debug,
                        _ => throw new UsageException($"logLevel: '{text}' is not error, warning, info or debug."),
                    };
                    break;
                case "telemetryOptIn":
                    request.TelemetryOptIn = bool.TryParse(text, out var flag) ? flag : throw new UsageException($"telemetryOptIn: '{text}' is not true or false.");
                    break;
                case "dataRoot":
                    throw new UsageException("dataRoot is read-only here; moving the data root is 'arcforges storage relocate'.");
                default:
                    throw new UsageException($"{name} is read-only.");
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var readMeta = Cli.Meta();
            var current = await cli.CallAsync("GetNodeSettings", readMeta, () => session.Channel.Node.GetNodeSettingsAsync(
                new NodeServiceGetNodeSettingsRequest { Meta = readMeta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (current.Error is { } readError)
            {
                return cli.Output.Fail(readError, readMeta.CorrelationId);
            }

            // UpdateNodeSettings is guarded by the revision that was read (meta.expected_rev).
            request.Meta.ExpectedRev = current.Value.Settings.Revision;
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("UpdateNodeSettings", request.Meta.CommandId, action, r => session.Channel.Node.UpdateNodeSettingsAsync(r,
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
                cli.Output.Line($"{name} = {Value(response.Value.Settings, name)} (revision {response.Value.Settings.Revision.Value})"
                    + (response.Value.RestartRequired ? "; restart the node to apply it" : string.Empty));
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static async Task<(NodeSettings? Settings, int Exit)> ReadAsync(Cli cli, CancellationToken cancellationToken)
    {
        await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
        var meta = Cli.Meta();
        var response = await cli.CallAsync("GetNodeSettings", meta, () => session.Channel.Node.GetNodeSettingsAsync(
            new NodeServiceGetNodeSettingsRequest { Meta = meta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return response.Error is { } error ? (null, cli.Output.Fail(error, meta.CorrelationId)) : (response.Value.Settings, ExitCodes.Success);
    }

    private static string Value(NodeSettings settings, string key) => key switch
    {
        "dataRoot" => settings.DataRoot,
        "logLevel" => settings.LogLevel.ToString().ToLowerInvariant(),
        "telemetryOptIn" => settings.TelemetryOptIn ? "true" : "false",
        "configPath" => settings.ConfigPath,
        "revision" => settings.Revision?.Value.ToString(CultureInfo.InvariantCulture) ?? "0",
        _ => string.Empty,
    };
}
