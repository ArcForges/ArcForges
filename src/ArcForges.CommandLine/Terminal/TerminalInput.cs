// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.CommandLine;

internal static class TerminalInput
{
    private const byte Escape = 0x1d;
    private static readonly TimeSpan RenewalInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ResizeInterval = TimeSpan.FromMilliseconds(150);

    internal static async Task<bool> ForwardAsync(TerminalLeaseSession attachment, ICallerTerminal? terminal, bool pipes,
        bool enableEscape, CancellationToken cancellationToken)
    {
        using var input = terminal is null ? Console.OpenStandardInput() : Stream.Null;
        var buffer = new byte[4096];
        var decoded = new byte[buffer.Length + 1];
        bool pendingEscape = false;
        while (true)
        {
            var count = terminal is null
                ? await input.ReadAsync(buffer.AsMemory(), cancellationToken).AsTask().WaitAsync(cancellationToken).ConfigureAwait(false)
                : await terminal.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (count == 0)
            {
                if (pendingEscape)
                {
                    decoded[0] = Escape;
                    await WriteAsync(attachment, decoded.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
                }

                if (pipes)
                {
                    await attachment.CloseInputAsync(cancellationToken).ConfigureAwait(false);
                }

                return false;
            }

            if (!enableEscape)
            {
                await WriteAsync(attachment, buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                continue;
            }

            var result = Decode(buffer.AsSpan(0, count), decoded, ref pendingEscape);
            await WriteAsync(attachment, decoded.AsMemory(0, result.Count), cancellationToken).ConfigureAwait(false);
            if (result.Detach)
            {
                return true;
            }
        }
    }

    internal static async Task MaintainAsync(Cli cli, TerminalLeaseSession attachment, ICallerTerminal? writer,
        CallerTerminalSize? previousSize, CancellationToken cancellationToken)
    {
        var renewedAt = Stopwatch.GetTimestamp();
        using var timer = new PeriodicTimer(writer is null ? RenewalInterval : ResizeInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            if (Stopwatch.GetElapsedTime(renewedAt) >= RenewalInterval)
            {
                await attachment.RenewAsync(cancellationToken).ConfigureAwait(false);
                renewedAt = Stopwatch.GetTimestamp();
            }

            if (writer?.GetSize() is { } current && current != previousSize)
            {
                if (!await TryResizeAsync(cli, attachment, current, cancellationToken).ConfigureAwait(false))
                {
                    writer = null;
                    timer.Period = RenewalInterval;
                }

                previousSize = current;
            }
        }
    }

    internal static async Task<bool> TryResizeAsync(Cli cli, TerminalLeaseSession attachment, CallerTerminalSize size,
        CancellationToken cancellationToken)
    {
        try
        {
            await attachment.ResizeAsync(size.Rows, size.Columns, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (V2CommandException exception) when (exception.Error is
        { Effect: EffectCertainty.DidNotHappen, Code: "terminal_unavailable", Details.State.Reason: "terminal_mode_unsupported" })
        {
            cli.Output.Note("The Run profile cannot resize this terminal (terminal_mode_unsupported). The previous dimensions still apply.");
            return false;
        }
    }

    private static async Task WriteAsync(TerminalLeaseSession attachment, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        while (!bytes.IsEmpty)
        {
            var accepted = await attachment.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            if (accepted == 0)
            {
                throw new V2CommandException(V2Cli.Error(ErrorCategory.Resource, "terminal_input_no_progress",
                    "No bytes from the current input frame were accepted."), null);
            }

            bytes = bytes[accepted..];
        }
    }

    private static (int Count, bool Detach) Decode(ReadOnlySpan<byte> input, Span<byte> output, ref bool pending)
    {
        int count = 0;
        foreach (var value in input)
        {
            if (pending)
            {
                pending = false;
                if (value == (byte)'d')
                {
                    return (count, Detach: true);
                }

                output[count++] = Escape;
                if (value == Escape)
                {
                    continue;
                }
            }

            if (value == Escape)
            {
                pending = true;
            }
            else
            {
                output[count++] = value;
            }
        }

        return (count, Detach: false);
    }
}
