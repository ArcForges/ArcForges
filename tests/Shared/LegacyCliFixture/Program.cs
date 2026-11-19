// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.CommandLine.Invocation;
using ArcForges.Client;
using ArcForges.CommandLine;

namespace ArcForges.LegacyCliFixture;

/// <summary>Runs retained V1 client regressions against an independently started test Node.</summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (!args.TakeWhile(argument => argument != "--").Contains(NodeLocations.TestModeOption, StringComparer.Ordinal)
            || !HasIsolatedNodeLocation())
        {
            await Console.Error.WriteLineAsync("The legacy CLI fixture requires test mode and an isolated Node configuration and endpoint.")
                .ConfigureAwait(false);
            return ExitCodes.Usage;
        }

        return await RunAsync(args, Console.Out, Console.Error).ConfigureAwait(false);
    }

    internal static RootCommand Build(TextWriter output, TextWriter error)
    {
        var globals = new GlobalOptions();
        var root = new RootCommand("Retained ArcForges V1 CLI test fixture");
        globals.AddTo(root);
        Cli CreateCli(ParseResult result) => globals.Create(result, output, error);
        root.Subcommands.Add(RunCommand.Build(CreateCli));
        root.Subcommands.Add(TaskCommands.Build(CreateCli));
        root.Subcommands.Add(TaskCommands.Output(CreateCli));
        root.Subcommands.Add(QueueCommands.Build(CreateCli));
        root.Subcommands.Add(JobCommands.Build(CreateCli));
        root.Subcommands.Add(ResourceCommands.Resources(CreateCli));
        root.Subcommands.Add(ResourceCommands.Processes(CreateCli));
        root.Subcommands.Add(ResourceCommands.Samples(CreateCli));
        root.Subcommands.Add(ResourceCommands.Adopt(CreateCli));
        root.Subcommands.Add(ResourceCommands.Terminate(CreateCli));
        root.Subcommands.Add(LoginCommands.Build(CreateCli));
        return root;
    }

    internal static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
    {
        var root = Build(output, error);
        var result = root.Parse(args);
        if (result.Errors.Count > 0 && result.Action is ParseErrorAction)
        {
            foreach (var parseError in result.Errors)
            {
                await error.WriteLineAsync("error: " + parseError.Message).ConfigureAwait(false);
            }

            await error.WriteLineAsync("Run 'arcforges --help' for usage.").ConfigureAwait(false);
            return ExitCodes.Usage;
        }

        var command = result.CommandResult.Command;
        bool handlesInterrupts = command.Name is "run" or "login" or "output"
            || command.Parents.OfType<Command>().Any(parent => parent.Name == "tasks");
        return await result.InvokeAsync(new InvocationConfiguration
        {
            Output = output,
            Error = error,
            EnableDefaultExceptionHandler = false,
            ProcessTerminationTimeout = handlesInterrupts ? null : TimeSpan.FromSeconds(12),
        }).ConfigureAwait(false);
    }

    private static bool HasIsolatedNodeLocation()
    {
        if (NodeLocations.EndpointOverride(testMode: true) is null
            || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(NodeLocations.ConfigDirectoryVariable)))
        {
            return false;
        }

        try
        {
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            string config = NodeLocations.ConfigFile(testMode: true);
            string dataRoot = NodeLocations.ResolveDataRoot(testMode: true);
            string ordinaryDataRoot = NodeLocations.DefaultDataRoot();
            return File.Exists(config)
                && !string.Equals(config, NodeLocations.ConfigFile(testMode: false), comparison)
                && !string.Equals(dataRoot, ordinaryDataRoot, comparison)
                && !string.Equals(NodeLocations.Endpoint(testMode: true, dataRoot).Address,
                    NodeLocations.Endpoint(testMode: false, ordinaryDataRoot).Address, comparison);
        }
        catch (Exception failure) when (failure is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
