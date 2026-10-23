// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.CommandLine.Invocation;
using ArcForges.Client;

namespace ArcForges.CommandLine;

/// <summary>What <c>arcforges node run</c> asks the node role for.</summary>
/// <param name="TestMode">The <c>ARCFORGES_*</c> test hooks apply.</param>
/// <param name="Systemd">Started by the systemd user unit (<c>--systemd</c>).</param>
public sealed record NodeRunRequest(bool TestMode, bool Systemd);

/// <summary>Runs the node role in this process and returns its exit code (supplied by the host, AD-0003).</summary>
public delegate Task<int> NodeRunner(NodeRunRequest request, CancellationToken cancellationToken);

/// <summary>
/// The <c>arcforges</c> command line (experience/cli.md): <c>arcforges [global options] &lt;group&gt; &lt;command&gt; [arguments] [options]</c>,
/// parsed with System.CommandLine 2.x (F-N02: its Native AOT publish is warning-free and its cold start is within 15 section 1).
/// Global options may also follow the command. Usage errors exit 2.
/// </summary>
public static class CliApplication
{
    /// <summary>Parses and runs one command line; returns the exit code.</summary>
    public static async Task<int> RunAsync(string[] args, NodeRunner nodeRunner, TextWriter? output = null, TextWriter? error = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(nodeRunner);
        output ??= Console.Out;
        error ??= Console.Error;
        var globals = new GlobalOptions();
        var root = Build(globals, nodeRunner, output, error);
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

        // Ctrl+C and SIGTERM cancel the command's token; the wait covers the node's own shutdown budget (10 s). `run` and the `tasks`
        // commands handle Ctrl+C themselves (once cancels the task, twice detaches; cli.md C-01), so no termination timeout applies to them.
        var command = result.CommandResult.Command;
        var handlesInterrupts = command.Name == "run" || command.Parents.OfType<Command>().Any(parent => parent.Name == "tasks");
        return await result.InvokeAsync(new InvocationConfiguration
        {
            Output = output,
            Error = error,
            EnableDefaultExceptionHandler = false,
            ProcessTerminationTimeout = handlesInterrupts ? null : TimeSpan.FromSeconds(12),
        }).ConfigureAwait(false);
    }

    /// <summary>Builds the command tree (also used by the completion tests).</summary>
    internal static RootCommand Build(GlobalOptions globals, NodeRunner nodeRunner, TextWriter output, TextWriter error)
    {
        var root = new RootCommand("ArcForges: run, schedule and record local work under your control.");
        globals.AddTo(root);
        var factory = new Func<ParseResult, Cli>(result => globals.Create(result, output, error));
        root.Subcommands.Add(RunCommand.Build(factory));
        root.Subcommands.Add(TaskCommands.Build(factory));
        root.Subcommands.Add(StatusCommands.Status(factory));
        root.Subcommands.Add(ResourceCommands.Resources(factory));
        root.Subcommands.Add(ResourceCommands.Processes(factory));
        root.Subcommands.Add(ResourceCommands.Samples(factory));
        root.Subcommands.Add(QueueCommands.Build(factory));
        root.Subcommands.Add(PolicyCommands.Build(factory));
        root.Subcommands.Add(NodeCommands.Build(factory, nodeRunner));
        root.Subcommands.Add(ConfigCommands.Build(factory));
        root.Subcommands.Add(EventCommands.Build(factory));
        root.Subcommands.Add(JobCommands.Build(factory));
        root.Subcommands.Add(StatusCommands.Version(factory));
        root.Subcommands.Add(CompletionCommand.Build(output));
        root.SetAction(result =>
        {
            error.WriteLine("error: a command is required.");
            error.WriteLine("Run 'arcforges --help' for usage.");
            return ExitCodes.Usage;
        });
        return root;
    }
}

/// <summary>The global options (experience/cli.md section 1); they may appear before or after the command.</summary>
internal sealed class GlobalOptions
{
    public Option<bool> Json { get; } = new("--json") { Recursive = true, Description = "Machine output: one JSON document, or JSON Lines for streams" };

    public Option<bool> Quiet { get; } = new("--quiet", "-q") { Recursive = true, Description = "Only essential output" };

    public Option<bool> NoColor { get; } = new("--no-color") { Recursive = true, Description = "Disable colour (also with NO_COLOR or when stdout is not a terminal)" };

    public Option<bool> Yes { get; } = new("--yes", "-y") { Recursive = true, Description = "Answer yes to local confirmation prompts" };

    public Option<string?> Timeout { get; } = new("--timeout") { Recursive = true, Description = "Client deadline for unary calls (for example 30s)", HelpName = "dur" };

    public Option<bool> Verbose { get; } = new("--verbose", "-v") { Recursive = true, Description = "Show correlation IDs and timings" };

    public Option<bool> TestMode { get; } = new(NodeLocations.TestModeOption) { Recursive = true, Hidden = true };

    public void AddTo(RootCommand root)
    {
        root.Options.Add(Json);
        root.Options.Add(Quiet);
        root.Options.Add(NoColor);
        root.Options.Add(Yes);
        root.Options.Add(Timeout);
        root.Options.Add(Verbose);
        root.Options.Add(TestMode);
    }

    public Cli Create(ParseResult result, TextWriter output, TextWriter error)
    {
        var json = result.GetValue(Json);
        var noColor = result.GetValue(NoColor) || Environment.GetEnvironmentVariable("NO_COLOR") is { Length: > 0 } || Console.IsOutputRedirected;
        var width = Console.IsOutputRedirected ? 120 : SafeWidth();
        TimeSpan? timeout = null;
        if (result.GetValue(Timeout) is { } text)
        {
            timeout = Durations.TryParse(text, out var parsed) ? parsed : throw new UsageException($"--timeout: '{text}' is not a duration (90s, 5m, 2h, 1d).");
        }

        var cliOutput = new CliOutput(output, error, json, result.GetValue(Quiet), !json && !noColor, result.GetValue(Verbose), width);
        return new Cli(cliOutput, result.GetValue(TestMode), timeout, result.GetValue(Yes));
    }

    private static int SafeWidth()
    {
        try
        {
            return Console.WindowWidth > 0 ? Console.WindowWidth : 120;
        }
        catch (IOException)
        {
            return 120;
        }
    }
}

/// <summary>An invalid argument value found after parsing (exit 2).</summary>
internal sealed class UsageException(string message) : Exception(message);
