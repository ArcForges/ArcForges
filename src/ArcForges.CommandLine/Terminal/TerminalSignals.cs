// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;

namespace ArcForges.CommandLine;

/// <summary>Lets the attached command finish its terminal restoration during local interruption.</summary>
internal sealed class TerminalSignals : IDisposable
{
    private readonly CancellationTokenSource _source;
    private readonly PosixSignalRegistration? _interrupt;
    private readonly PosixSignalRegistration? _terminate;
    private readonly PosixSignalRegistration? _hangup;
    private readonly ConsoleCancelEventHandler? _console;

    internal TerminalSignals(CancellationToken cancellationToken)
    {
        _source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            if (OperatingSystem.IsLinux())
            {
                _interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, Interrupt);
                _terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Interrupt);
                _hangup = PosixSignalRegistration.Create(PosixSignal.SIGHUP, Interrupt);
            }
            else if (OperatingSystem.IsWindows())
            {
                _console = (_, eventArgs) =>
                {
                    eventArgs.Cancel = true;
                    Cancel();
                };
                Console.CancelKeyPress += _console;
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal CancellationToken Token => _source.Token;

    public void Dispose()
    {
        _hangup?.Dispose();
        _terminate?.Dispose();
        _interrupt?.Dispose();
        if (_console is not null)
        {
            Console.CancelKeyPress -= _console;
        }

        _source.Dispose();
    }

    private void Interrupt(PosixSignalContext context)
    {
        context.Cancel = true;
        Cancel();
    }

    private void Cancel()
    {
        try
        {
            _source.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The handler can overlap the end of the invocation.
        }
    }
}
