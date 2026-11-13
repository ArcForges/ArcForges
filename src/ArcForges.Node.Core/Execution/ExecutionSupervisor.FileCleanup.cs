// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Execution;

public sealed partial class ExecutionSupervisor
{
    private readonly SemaphoreSlim _fileCleanupAdmission = new(1, 1);

    /// <summary>Coordinates a short file cleanup with task admission and launch, without stopping existing children.</summary>
    internal async Task<IDisposable> CoordinateFileCleanupAsync(CancellationToken token)
    {
        await _fileCleanupAdmission.WaitAsync(token).ConfigureAwait(false);
        return new FileCleanupAdmission(_fileCleanupAdmission);
    }

    private sealed class FileCleanupAdmission(SemaphoreSlim gate) : IDisposable
    {
        private SemaphoreSlim? _gate = gate;
        public void Dispose() => Interlocked.Exchange(ref _gate, null)?.Release();
    }
}
