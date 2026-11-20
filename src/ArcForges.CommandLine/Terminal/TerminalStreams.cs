// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.CommandLine;

internal static class TerminalStreams
{
    internal static async Task<Run?> DisplayAsync(Cli cli, V2CliSession session, Run run, ICallerTerminal? terminal,
        StreamKind? selected, ulong offset, bool follow, CancellationToken cancellationToken)
    {
        using var stdout = Console.OpenStandardOutput();
        using var stderr = Console.OpenStandardError();
        if (selected is not null || run.TerminalMode == TerminalMode.Interactive)
        {
            var kind = selected ?? StreamKind.Terminal;
            return await PumpAsync(kind, cancellationToken).ConfigureAwait(false);
        }

        using var display = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var output = PumpAsync(StreamKind.Stdout, display.Token);
        var errors = PumpAsync(StreamKind.Stderr, display.Token);
        try
        {
            var firstCompleted = await Task.WhenAny(output, errors).ConfigureAwait(false);
            await firstCompleted.ConfigureAwait(false);
            var views = await Task.WhenAll(output, errors).ConfigureAwait(false);
            var finished = views[0] ?? views[1];
            if (views[0] is { } first && views[1] is { } second && !Equals(first.Exit, second.Exit))
            {
                throw new V2CommandException(Unknown("terminal_stream_exit_mismatch"), null);
            }

            return finished;
        }
        finally
        {
            await display.CancelAsync().ConfigureAwait(false);
            await ObserveAsync(output).ConfigureAwait(false);
            await ObserveAsync(errors).ConfigureAwait(false);
        }

        Task<Run?> PumpAsync(StreamKind kind, CancellationToken ct) =>
            TerminalOutput.PumpAsync(cli, session, run, kind, offset, (data, token) =>
                kind == StreamKind.Terminal && terminal is not null
                    ? terminal.WriteAsync(data, token)
                    : new ValueTask((kind == StreamKind.Stderr ? stderr : stdout).WriteAsync(data, token).AsTask().WaitAsync(token)),
                follow, ct);
    }

    internal static ICallerTerminal? OpenCallerTerminal(Run run, bool writer) =>
        run.TerminalMode != TerminalMode.Interactive || Console.IsOutputRedirected ? null :
        OperatingSystem.IsWindows() ? WindowsCallerTerminal.Open(writer) :
        OperatingSystem.IsLinux() ? LinuxCallerTerminal.Open(writer) : null;

    internal static ICallerTerminal? OpenCookedInput(bool writer) =>
        !writer || Console.IsInputRedirected ? null :
        OperatingSystem.IsWindows() ? WindowsCallerTerminal.OpenCookedInput() :
        OperatingSystem.IsLinux() ? LinuxCallerTerminal.OpenCookedInput() : null;

    internal static ArcError LocalTerminalFailure(IOException exception) =>
        exception is CallerTerminalInUseException
            ? V2Cli.Error(ErrorCategory.Conflict, "busy", "caller_terminal_in_use")
            : Unknown($"local_terminal_io_{exception.HResult:x8}. {Messages.Plain(exception.Message)}");

    internal static ArcError Unknown(string reason)
    {
        var error = V2Cli.Error(ErrorCategory.Execution, "terminal_ack_unavailable", reason);
        error.Effect = EffectCertainty.Unknown;
        return error;
    }

    /// <summary>Consumes a task after its primary result has been selected.</summary>
    internal static async Task ObserveAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or IOException or Grpc.Core.RpcException or V2CommandException)
        {
        }
    }
}
