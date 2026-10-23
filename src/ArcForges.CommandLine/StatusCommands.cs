// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Globalization;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary><c>arcforges status</c> and <c>arcforges version</c> (experience/cli.md C-10).</summary>
internal static class StatusCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);

    /// <summary>
    /// <c>status</c>: connects (starting the node when it is absent, except in CI jobs and sandboxes), then <c>Hello</c> and
    /// <c>GetNodeInfo</c>; the human form adds the budget and pressure of <c>GetResourceSnapshot</c> (the JSON form, whose round trip
    /// 15 section 1 measures, stays one call).
    /// </summary>
    public static Command Status(Func<ParseResult, Cli> factory)
    {
        var command = new Command("status", "Show the node's state, starting it when it is not running");
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

            var node = response.Value.Node;
            if (cli.Output.Json)
            {
                // Written without protobuf reflection: the status round trip (15 section 1) is measured on this path.
                cli.Output.Document(writer =>
                {
                    writer.WriteStartObject();
                    writer.WritePropertyName("node");
                    NodeInfoJson.Write(writer, node);
                    writer.WriteString("assignedOrigin", session.Hello.AssignedOrigin.ToString().ToUpperInvariant());
                    writer.WriteBoolean("autoStarted", session.AutoStart is not null);
                    writer.WriteString("endpointSource", session.Endpoint.Source);
                    if (session.Hello.Warnings.Count > 0)
                    {
                        writer.WriteStartArray("warnings");
                        foreach (var warning in session.Hello.Warnings)
                        {
                            writer.WriteStringValue(warning);
                        }

                        writer.WriteEndArray();
                    }

                    writer.WriteEndObject();
                });
                return ExitCodes.Success;
            }

            if (session.AutoStart is { } started)
            {
                cli.Output.Note("the node was not running; started it (" + started.Detail + ")");
            }

            if (cli.Output.Quiet)
            {
                cli.Output.Essential(CliOutput.Word(node.State));
                return ExitCodes.Success;
            }

            var rows = NodeRows(cli.Output, node, session.Hello.AssignedOrigin);
            try
            {
                var resourceMeta = Cli.Meta();
                var resources = await cli.CallAsync("GetResourceSnapshot", resourceMeta, () => session.Channel.Resources.GetResourceSnapshotAsync(
                    new ResourceServiceGetResourceSnapshotRequest { Meta = resourceMeta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken))
                    .ConfigureAwait(false);
                if (resources.Value?.Snapshot is { HasBudgetCpuMillicores: true } snapshot)
                {
                    rows.AddRange(ResourceCommands.Rows(snapshot).Where(row => row.Key is "budget" or "pressure"));
                }
            }
            catch (Grpc.Core.RpcException exception) when (exception.StatusCode == Grpc.Core.StatusCode.Unimplemented)
            {
                // A node from before the resource monitor: the status shows the node alone.
            }

            cli.Output.KeyValues(rows);
            foreach (var warning in session.Hello.Warnings)
            {
                cli.Output.Note(warning);
            }

            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary><c>version</c>: the client and node versions and contract versions (the node only when it is running).</summary>
    public static Command Version(Func<ParseResult, Cli> factory)
    {
        var command = new Command("version", "Show client and node versions and contract versions");
        Actions.Set(command, factory, async (cli, _, cancellationToken) =>
        {
            NodeInfo? node = null;
            try
            {
                await using var session = await cli.ConnectAsync(autoStart: false, cancellationToken).ConfigureAwait(false);
                node = session.Hello.Node;
            }
            catch (NodeUnavailableException)
            {
                // The node is not running: only the client is reported.
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(new JsonObject
                {
                    ["client"] = new JsonObject
                    {
                        ["version"] = NodeContract.ProductVersion,
                        ["contractMajor"] = NodeContract.Major,
                        ["contractMinor"] = NodeContract.Minor,
                    },
                    ["node"] = node is null ? null : new JsonObject
                    {
                        ["version"] = node.Version,
                        ["contractMajor"] = node.ContractMajor,
                        ["contractMinor"] = node.ContractMinor,
                    },
                });
                return ExitCodes.Success;
            }

            cli.Output.KeyValues(
            [
                ("client", $"{NodeContract.ProductVersion} (node contract {NodeContract.Major}.{NodeContract.Minor})"),
                ("node", node is null ? "not running" : $"{node.Version} (node contract {node.ContractMajor}.{node.ContractMinor})"),
            ]);
            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary>The human rows of a node's information.</summary>
    internal static List<(string Key, string Value)> NodeRows(CliOutput output, NodeInfo node, Origin? origin)
    {
        var rows = new List<(string Key, string Value)>
        {
            ("node", $"{node.Node.Name} ({IdText.Format(node.Node.NodeId)})"),
            ("state", output.State(node.State) + (node.Capabilities is { } caps && caps.Cpu == CpuControl.ObserveOnly ? " (enforcement: observe only)" : string.Empty)),
            ("version", $"{node.Version} (contract {node.ContractMajor}.{node.ContractMinor})"),
            ("edition", node.Edition == Edition.Pro ? "Pro" : "Free"),
            ("started", CliOutput.When(node.StartedAt)),
            ("endpoint", node.Endpoint),
            ("data root", node.DataRoot),
            ("store", Size(node.StoreBytes)),
        };
        if (origin is { } assigned)
        {
            rows.Add(("origin", assigned.ToString().ToUpperInvariant()));
        }

        return rows;
    }

    internal static string Size(ulong bytes) => bytes switch
    {
        < 1024 => string.Create(CultureInfo.InvariantCulture, $"{bytes} B"),
        < 1024 * 1024 => string.Create(CultureInfo.InvariantCulture, $"{bytes / 1024.0:0.0} KiB"),
        < 1024UL * 1024 * 1024 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (1024.0 * 1024):0.0} MiB"),
        _ => string.Create(CultureInfo.InvariantCulture, $"{bytes / (1024.0 * 1024 * 1024):0.0} GiB"),
    };
}
