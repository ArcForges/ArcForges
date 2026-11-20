// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.CommandLine;

internal static class TerminalCommands
{
    private static readonly TimeSpan InspectionTimeout = TimeSpan.FromSeconds(10);

    internal static Command Attach(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("run-id") { Description = "Run ID" };
        var readOnly = new Option<bool>("--read-only") { Description = "Observe output without input or resize authority" };
        var takeover = new Option<bool>("--takeover") { Description = "Explicitly replace the existing writer lease" };
        var offset = new Option<ulong>("--offset") { Description = "Resume interactive terminal output at a byte offset" };
        var noEscape = NoDetachEscape();
        var command = new Command("attach", "Attach to an existing Run") { id, readOnly, takeover, noEscape, offset };
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            using var signals = new TerminalSignals(cancellationToken);
            cancellationToken = signals.Token;
            if (cli.Output.Json)
            {
                throw new UsageException("Attach uses raw output. Use run logs --json for machine-readable output.");
            }

            var observe = result.GetValue(readOnly);
            var replace = result.GetValue(takeover);
            if (observe && replace)
            {
                throw new UsageException("--read-only and --takeover are mutually exclusive.");
            }

            var runId = V2Cli.ReadId(result.GetValue(id), "Run ID");
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var run = await SandboxRunCommands.InspectAsync(session, runId, cli.Deadline(InspectionTimeout), cancellationToken)
                .ConfigureAwait(false);
            return await TerminalAttachment.AttachAsync(cli, session, run, observe, replace, !result.GetValue(noEscape),
                result.GetValue(offset), cancellationToken).ConfigureAwait(false);
        });
        return command;
    }

    internal static Command Detach(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("run-id") { Description = "Run ID" };
        var lease = new Option<string>("--lease") { Required = true, Description = "Lease ID printed by the local attachment" };
        var command = new Command("detach", "Ask the existing local attachment to release its lease") { id, lease };
        V2Cli.Set(command, factory, (cli, result, cancellationToken) => TerminalDetachRelay.RequestAsync(cli,
            V2Cli.ReadId(result.GetValue(id), "Run ID"), V2Cli.ReadId(result.GetValue(lease), "Lease ID"), cancellationToken));
        return command;
    }

    internal static Command Logs(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("run-id") { Description = "Run ID" };
        var follow = new Option<bool>("--follow") { Description = "Keep reading until the Run output settles" };
        var stream = new Option<string?>("--stream") { Description = "Read one stream: terminal, stdout or stderr" };
        stream.AcceptOnlyFromAmong("terminal", "stdout", "stderr");
        var offset = new Option<ulong>("--offset") { Description = "Start at a byte offset in the selected stream" };
        var command = new Command("logs", "Read retained Run output") { id, follow, stream, offset };
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            using var signals = new TerminalSignals(cancellationToken);
            cancellationToken = signals.Token;
            var runId = V2Cli.ReadId(result.GetValue(id), "Run ID");
            StreamKind? selected = result.GetValue(stream) switch
            {
                "terminal" => StreamKind.Terminal,
                "stdout" => StreamKind.Stdout,
                "stderr" => StreamKind.Stderr,
                _ => null,
            };
            var start = result.GetValue(offset);
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var run = await SandboxRunCommands.InspectAsync(session, runId, cli.Deadline(InspectionTimeout), cancellationToken)
                .ConfigureAwait(false);
            if (selected is null && start != 0 && run.TerminalMode == TerminalMode.Pipes)
            {
                throw new UsageException("Use --stream with an offset for a piped Run.");
            }

            try
            {
                await using var terminal = cli.Output.Json ? null : TerminalStreams.OpenCallerTerminal(run, writer: false);
                await TerminalStreams.DisplayAsync(cli, session, run, terminal, selected, start, result.GetValue(follow), cancellationToken)
                    .ConfigureAwait(false);
                return 0;
            }
            catch (IOException exception)
            {
                return V2Cli.Fail(cli, TerminalStreams.LocalTerminalFailure(exception), stream: true);
            }
        }, stream: true);
        return command;
    }

    internal static Option<bool> NoDetachEscape() =>
        new("--no-detach-escape") { Description = "Pass Ctrl+] sequences literally to an interactive Run" };
}
