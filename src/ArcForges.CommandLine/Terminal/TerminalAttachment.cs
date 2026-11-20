// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Grpc.Core;

namespace ArcForges.CommandLine;

internal static class TerminalAttachment
{
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ReleaseTimeout = TimeSpan.FromSeconds(5);

    internal static bool HasCallerTerminal => !Console.IsInputRedirected && !Console.IsOutputRedirected;

    internal static ArcError CallerTerminalRequired() => V2Cli.Error(ErrorCategory.State, "terminal_unavailable",
        "Interactive writing requires a native local input and output terminal.");

    internal static async Task<int> AttachAsync(Cli cli, V2CliSession session, Run initial, bool readOnly, bool takeover,
        bool enableEscape, ulong offset, CancellationToken cancellationToken)
    {
        try
        {
            var run = await WaitForReadyAsync(cli, session, initial, cancellationToken).ConfigureAwait(false);
            if (offset != 0 && run.TerminalMode != TerminalMode.Interactive)
            {
                throw new UsageException("Use run logs --stream with an offset for a piped Run.");
            }

            if (run.State is RunState.Exited or RunState.Failed or RunState.Draining or RunState.Stopping)
            {
                await using var display = TerminalStreams.OpenCallerTerminal(run, writer: false);
                return Exit(cli, await TerminalStreams.DisplayAsync(cli, session, run, display, selected: null, offset,
                    follow: true, cancellationToken).ConfigureAwait(false));
            }

            if (run.TerminalMode == TerminalMode.Interactive && !readOnly && !HasCallerTerminal)
            {
                return V2Cli.Fail(cli, CallerTerminalRequired());
            }

            await using var terminal = TerminalStreams.OpenCallerTerminal(run, writer: !readOnly);
            await using var cookedInput = run.TerminalMode == TerminalMode.Pipes ? TerminalStreams.OpenCookedInput(!readOnly) : null;
            using var attachment = await TerminalLeaseSession.AcquireAsync(cli, session, run, readOnly, takeover, cancellationToken)
                .ConfigureAwait(false);
            return await ObserveAsync(cli, session, run, attachment, terminal, cookedInput, readOnly, enableEscape, offset, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IOException exception)
        {
            return V2Cli.Fail(cli, TerminalStreams.LocalTerminalFailure(exception));
        }
    }

    private static async Task<Run> WaitForReadyAsync(Cli cli, V2CliSession session, Run run, CancellationToken cancellationToken)
    {
        var deadline = cli.Deadline(ReadyTimeout);
        while (run.State == RunState.Starting)
        {
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                throw new V2CommandException(V2Cli.Error(ErrorCategory.Resource, "terminal_unavailable",
                    "The accepted Run did not reach terminal readiness within the deadline."), null);
            }

            await Task.Delay(remaining < TimeSpan.FromMilliseconds(100) ? remaining : TimeSpan.FromMilliseconds(100), cancellationToken)
                .ConfigureAwait(false);
            var observed = await SandboxRunCommands.InspectAsync(session, run.RunId, deadline, cancellationToken).ConfigureAwait(false);
            if (!StringComparer.Ordinal.Equals(run.Epoch, observed.Epoch))
            {
                throw new V2CommandException(TerminalStreams.Unknown("run_epoch_changed_before_attachment"), null);
            }

            run = observed;
        }

        if (run.State is RunState.RecoveryRequired or RunState.Unspecified)
        {
            throw new V2CommandException(TerminalStreams.Unknown("run_terminal_owner_unconfirmed"), null);
        }

        return run;
    }

    private static async Task<int> ObserveAsync(Cli cli, V2CliSession session, Run run, TerminalLeaseSession attachment,
        ICallerTerminal? terminal, ICallerTerminal? cookedInput, bool readOnly, bool enableEscape, ulong offset,
        CancellationToken cancellationToken)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = lifetime.Token;
        TerminalDetachRelay? relay = null;
        Task<Run?>? output = null;
        Task<bool>? input = null;
        Task? maintenance = null;
        Run? finished = null;
        bool interrupted = false;
        ArcError? failure = null;
        ArcError? releaseFailure = null;
        try
        {
            var writer = readOnly ? null : terminal;
            var resizer = writer;
            var size = writer?.GetSize();
            if (size is { } dimensions && !await TerminalInput.TryResizeAsync(cli, attachment, dimensions, token).ConfigureAwait(false))
            {
                resizer = null;
            }

            try
            {
                relay = await TerminalDetachRelay.OpenAsync(run.RunId, attachment.Lease.LeaseId, token).ConfigureAwait(false);
            }
            catch (V2CommandException exception) when (exception.Error.Details?.State?.Reason == "terminal_detach_endpoint_unavailable")
            {
                ReportRelayUnavailable(cli);
            }

            if (!cli.Output.Quiet)
            {
                var status = $"attached run {IdText.Format(run.RunId)} lease {IdText.Format(attachment.Lease.LeaseId)} " +
                    (readOnly ? "observer" : "writer");
                await cli.Output.Error.WriteLineAsync(status.AsMemory(), token).ConfigureAwait(false);
                await cli.Output.Error.FlushAsync(token).ConfigureAwait(false);
            }

            output = TerminalStreams.DisplayAsync(cli, session, run, terminal, selected: null, offset, follow: true, token);
            maintenance = TerminalInput.MaintainAsync(cli, attachment, resizer, size, token);
            var workers = new List<Task> { output, maintenance };
            if (relay is not null)
            {
                workers.Add(relay.Received);
            }

            if (!readOnly)
            {
                input = TerminalInput.ForwardAsync(attachment, writer ?? cookedInput, run.TerminalMode == TerminalMode.Pipes,
                    writer is not null && enableEscape, token);
                workers.Add(input);
            }

            Task completed;
            while (true)
            {
                completed = await Task.WhenAny(workers).ConfigureAwait(false);
                if (completed == input && !await input.ConfigureAwait(false))
                {
                    // EOF ends this input reader. The Run's output remains attached.
                    workers.Remove(completed);
                    continue;
                }

                if (relay is not null && completed == relay.Received && completed.IsFaulted && !token.IsCancellationRequested)
                {
                    workers.Remove(completed);
                    await TerminalStreams.ObserveAsync(relay.DisposeAsync().AsTask()).ConfigureAwait(false);
                    relay = null;
                    ReportRelayUnavailable(cli);
                    continue;
                }

                break;
            }

            await completed.ConfigureAwait(false);
            if (completed == output)
            {
                finished = await output.ConfigureAwait(false);
                if (finished is null)
                {
                    failure = TerminalStreams.Unknown("terminal_output_final_state_unobserved");
                }
            }
        }
        catch (V2CommandException exception)
        {
            failure = exception.Error;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested || input?.IsCanceled == true)
        {
            // A cooked native read can observe Ctrl+C before the signal callback runs.
            interrupted = true;
        }
        catch (RpcException exception)
        {
            failure = V2Cli.Error(ErrorCategory.State, "node_unavailable", exception.StatusCode.ToString());
        }
        catch (IOException exception)
        {
            failure = TerminalStreams.LocalTerminalFailure(exception);
        }
        finally
        {
            await lifetime.CancelAsync().ConfigureAwait(false);
            var inputFailure = await ObserveWorkerAsync(input).ConfigureAwait(false);
            var maintenanceFailure = await ObserveWorkerAsync(maintenance).ConfigureAwait(false);
            var outputFailure = await ObserveWorkerAsync(output).ConfigureAwait(false);
            var uncertainMutation = inputFailure?.Effect == EffectCertainty.Unknown ? inputFailure
                : maintenanceFailure?.Effect == EffectCertainty.Unknown ? maintenanceFailure : null;
            if (uncertainMutation is not null && failure is { } observation && observation.Code != uncertainMutation.Code)
            {
                cli.Output.Error.WriteLine($"Attachment observation {observation.Category}/{Messages.Plain(observation.Code)}");
            }

            failure = uncertainMutation ?? failure;
            failure ??= RelevantAfterExit(inputFailure, finished) ?? RelevantAfterExit(maintenanceFailure, finished) ?? outputFailure;
            if (finished is null || relay?.Received.IsCompletedSuccessfully == true)
            {
                using var release = new CancellationTokenSource(ReleaseTimeout);
                releaseFailure = await ObserveWorkerAsync(attachment.DetachAsync(release.Token)).ConfigureAwait(false);
                if (release.IsCancellationRequested && releaseFailure is null)
                {
                    releaseFailure = TerminalStreams.Unknown("terminal_release_deadline_elapsed");
                }
            }

            if (relay is not null)
            {
                await using var closingRelay = relay;
                if (relay.Received.IsCompletedSuccessfully)
                {
                    using var reply = new CancellationTokenSource(ReleaseTimeout);
                    await TerminalStreams.ObserveAsync(relay.ReplyAsync(releaseFailure, reply.Token)).ConfigureAwait(false);
                }
            }
        }

        if (failure is not null)
        {
            if (failure.Details?.State?.Reason == "terminal_acknowledgment_unavailable")
            {
                cli.Output.Error.WriteLine("The terminal request may have taken effect. Inspect the Run and attach explicitly to continue.");
            }

            if (releaseFailure is not null)
            {
                cli.Output.Error.WriteLine($"Detach result {releaseFailure.Category}/{Messages.Plain(releaseFailure.Code)}");
            }

            return V2Cli.Fail(cli, failure);
        }

        if (releaseFailure is not null && finished is null)
        {
            return V2Cli.Fail(cli, releaseFailure);
        }

        if (finished is not null)
        {
            return Exit(cli, finished);
        }

        if (interrupted || cancellationToken.IsCancellationRequested)
        {
            cli.Output.Error.WriteLine("Attachment interrupted. The Run remains under Node management.");
            return 130;
        }

        return 0;
    }

    private static ArcError? RelevantAfterExit(ArcError? error, Run? finished) =>
        finished is null || error?.Effect == EffectCertainty.Unknown ? error : null;

    private static void ReportRelayUnavailable(Cli cli) =>
        cli.Output.Note("The separate run detach command is unavailable for this attachment (terminal_detach_endpoint_unavailable).");

    private static async Task<ArcError?> ObserveWorkerAsync(Task? task)
    {
        if (task is null)
        {
            return null;
        }

        try
        {
            await task.ConfigureAwait(false);
            return null;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (V2CommandException exception)
        {
            return exception.Error;
        }
        catch (RpcException exception) when (exception.StatusCode == StatusCode.Cancelled)
        {
            return null;
        }
        catch (RpcException exception)
        {
            return V2Cli.Error(ErrorCategory.State, "node_unavailable", exception.StatusCode.ToString());
        }
        catch (IOException exception)
        {
            return TerminalStreams.LocalTerminalFailure(exception);
        }
    }

    private static int Exit(Cli cli, Run? run)
    {
        if (run?.Exit is not { GroupEmptyVerified: true, HasRawCode: true } exit ||
            exit.Source is not (ExitSource.Payload or ExitSource.OfficialExecutor) ||
            !OperatingSystem.IsWindows() && exit.RawCode is < 0 or > 255)
        {
            return V2Cli.Fail(cli, TerminalStreams.Unknown("trustworthy_run_exit_unavailable"));
        }

        bool confirmed = exit.Effect == EffectCertainty.Happened && exit.PayloadStarted == PayloadStartEvidence.Confirmed;
        if (exit.Source == ExitSource.OfficialExecutor)
        {
            var message = "The official executor reported exit " + exit.RawCode.ToString(CultureInfo.InvariantCulture) + ".";
            cli.Output.Note(confirmed ? message : message + " Payload start is unconfirmed.");
        }

        if (!confirmed && (exit.Source == ExitSource.Payload || exit.RawCode == 0))
        {
            return V2Cli.Fail(cli, TerminalStreams.Unknown("trustworthy_run_exit_unavailable"));
        }

        return exit.RawCode;
    }
}
