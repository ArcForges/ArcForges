// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Client;

internal readonly record struct CallerTerminalSize(int Rows, int Columns);

internal sealed class CallerTerminalInUseException() : IOException("The caller terminal already has an active local attachment.");

/// <summary>Owns changes to the calling CLI's native terminal modes for an attachment.</summary>
internal interface ICallerTerminal : IAsyncDisposable
{
    CallerTerminalSize? GetSize();

    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken);

    ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken);
}
