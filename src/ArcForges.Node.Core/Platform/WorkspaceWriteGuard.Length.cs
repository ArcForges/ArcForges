// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspaceWriteGuard
{
    /// <summary>Observes length on the exact still-guarded target; no bytes are read or changed.</summary>
    internal long ObserveLength(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            CheckLocked();
            var length = RandomAccess.GetLength(_file!);
            CheckLocked();
            cancellationToken.ThrowIfCancellationRequested();
            if (length < 0) throw new WorkspacePathException("file_identity_changed");
            return length;
        }
    }
}
