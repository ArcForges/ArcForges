// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Files;

namespace ArcForges.Node.Core.Platform;

/// <summary>A guarded, bounded stage usable as a checked source; this does not grant authority for a target effect.</summary>
internal abstract class WorkspaceMutationStage : IDisposable
{
    internal abstract RegisteredWorkspaces.RootIdentity Identity { get; }
    internal abstract WorkspaceObjectIdentity ObjectIdentity { get; }
    internal abstract long Length { get; }
    internal abstract ReadOnlyMemory<byte> Sha256 { get; }
    internal abstract WorkspaceGuardedContent ReadVerified(CancellationToken cancellationToken);
    internal abstract void CheckIntact();
    internal abstract WorkspaceWriteGuard GuardForLinuxHandoff { get; }
    public abstract void Dispose();
}
