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
/// parsed with System.CommandLine 3.x (AFV2-ENV-01); current Native AOT and cold-start gates remain required.
/// Global options may also follow the command. Usage errors exit 2.
/// </summary>
public static class CliApplication
{
    /// <summary>Parses and runs one command line; returns the exit code.</summary>
    public static async Task<int> RunAsync(string[] args, NodeRunner nodeRunner, TextWriter? output = null, TextWriter? error = null,
        NodeUpdateRunner? updateRunner = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(nodeRunner);
        output ??= Console.Out;
        error ??= Console.Error;
        var globals = new GlobalOptions();
        var root = Build(globals, nodeRunner, output, error, updateRunner);
        var result = root.Parse(args);
        if (result.Errors.Count > 0 && result.Action is ParseErrorAction)
        {
            if (IsLocalV2(result.CommandResult.Command))
            {
                var cliOutput = new CliOutput(output, error, result.GetValue(globals.Json), quiet: false, color: false, verbose: false, width: 120);
                var cli = new Cli(cliOutput, testMode: false, timeout: null, yes: false);
                return V2Cli.Fail(cli, V2Cli.Error(ArcForges.Contracts.Foundation.V1.ErrorCategory.Validation,
                    "invalid_argument", "The command or options are invalid. Run the command with --help for usage."));
            }

            foreach (var parseError in result.Errors)
            {
                await error.WriteLineAsync("error: " + parseError.Message).ConfigureAwait(false);
            }

            await error.WriteLineAsync("Run 'arcforges --help' for usage.").ConfigureAwait(false);
            return ExitCodes.Usage;
        }

        var command = result.CommandResult.Command;
        // The fixed Node process and sign-in handle their own shutdown.
        var handlesInterrupts = command.Name == "login"
            || command.Name == "run" && command.Parents.OfType<Command>().Any(parent => parent.Name == "node")
            || command.Name is "start" or "attach" or "logs" && command.Parents.OfType<Command>().Any(parent => parent.Name == "run");
        return await result.InvokeAsync(new InvocationConfiguration
        {
            Output = output,
            Error = error,
            EnableDefaultExceptionHandler = false,
            ProcessTerminationTimeout = handlesInterrupts ? null : TimeSpan.FromSeconds(12),
        }).ConfigureAwait(false);
    }

    /// <summary>Builds the command tree (also used by the completion tests).</summary>
    internal static RootCommand Build(GlobalOptions globals, NodeRunner nodeRunner, TextWriter output, TextWriter error,
        NodeUpdateRunner? updateRunner = null)
    {
        var root = new RootCommand("Manage local Sandboxes and Runs.");
        globals.AddTo(root);
        var factory = new Func<ParseResult, Cli>(result => globals.Create(result, output, error));
        var sandboxes = SandboxCommands.Build(factory);
        DataCommands.AddTo(sandboxes, factory);
        root.Subcommands.Add(sandboxes);
        root.Subcommands.Add(SandboxRunCommands.Build(factory));
        root.Subcommands.Add(StatusCommands.Status(factory));
        root.Subcommands.Add(SandboxResourceCommands.Build(factory));
        root.Subcommands.Add(SandboxGrantCommands.Build(factory));
        root.Subcommands.Add(SandboxOperationCommands.Build(factory));
        root.Subcommands.Add(V2NodeCommands.Doctor(factory));
        root.Subcommands.Add(ApprovalCommands.Build(factory));
        root.Subcommands.Add(NodeCommands.Build(factory, nodeRunner));
        root.Subcommands.Add(ConfigCommands.Build(factory));
        root.Subcommands.Add(EventCommands.Build(factory));
        root.Subcommands.Add(LoginCommands.Build(factory));
        root.Subcommands.Add(AccountCommands.Logout(factory));
        root.Subcommands.Add(CenterCommands.Build(factory));
        root.Subcommands.Add(AccountCommands.Account(factory));
        root.Subcommands.Add(StatusCommands.Version(factory));
        if (updateRunner is not null)
        {
            root.Subcommands.Add(UpdateCommands.Build(factory, updateRunner));
        }

        root.Subcommands.Add(CompletionCommand.Build(output));
        root.SetAction(result =>
        {
            error.WriteLine("error: a command is required.");
            error.WriteLine("Run 'arcforges --help' for usage.");
            return ExitCodes.Usage;
        });
        return root;
    }

    private static bool IsLocalV2(Command command) =>
        IsLocalV2Group(command) || command.Parents.OfType<Command>().Any(IsLocalV2Group) ||
        (command.Name is "start" or "status" or "stop" && command.Parents.OfType<Command>().Any(parent => parent.Name == "node")) ||
        (command.Name is "status" or "connect" or "flow" or "cancel" or "disconnect" or "signout" &&
            command.Parents.OfType<Command>().Any(parent => parent.Name == "center"));

    private static bool IsLocalV2Group(Command command) => command.Name is "sandbox" or "run" or "resources" or "grant" or "operation" or "doctor" or "update";
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

    public Option<string?> WaitApproval { get; } = new("--wait-approval")
    {
        Recursive = true,
        Description = "Wait for an approval decision (for example 10m); this human wait is outside the routed retry window",
        HelpName = "dur",
    };

    public Option<bool> TestMode { get; } = new(NodeLocations.TestModeOption) { Recursive = true, Hidden = true };

    public void AddTo(RootCommand root)
    {
        root.Options.Add(Json);
        root.Options.Add(Quiet);
        root.Options.Add(NoColor);
        root.Options.Add(Yes);
        root.Options.Add(Timeout);
        root.Options.Add(Verbose);
        root.Options.Add(WaitApproval);
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

        TimeSpan? waitApproval = null;
        if (result.GetValue(WaitApproval) is { } wait)
        {
            waitApproval = Durations.TryParse(wait, out var parsed) ? parsed : throw new UsageException($"--wait-approval: '{wait}' is not a duration (90s, 5m, 2h, 1d).");
        }

        var cliOutput = new CliOutput(output, error, json, result.GetValue(Quiet), !json && !noColor, result.GetValue(Verbose), width);
        return new Cli(cliOutput, result.GetValue(TestMode), timeout, result.GetValue(Yes)) { WaitApproval = waitApproval };
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
