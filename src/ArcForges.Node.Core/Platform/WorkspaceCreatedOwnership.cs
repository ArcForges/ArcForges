// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Files;

namespace ArcForges.Node.Core.Platform;

/// <summary>Evidence taken after marking, flushing and rechecking the exact object held by an exclusive create.</summary>
internal sealed record WorkspaceCreatedOwnership(RegisteredWorkspaces.RootIdentity Identity, byte[]? Marker);

internal sealed partial class WorkspacePath
{
    /// <summary>Rechecks an existing record on the same guarded target before and after a controlled update.</summary>
    internal bool MatchesHeldOwnership(string path, WorkspaceWriteGuard guard, RegisteredWorkspaces.RootIdentity expectedIdentity,
        ReadOnlySpan<byte> marker, long size, ReadOnlySpan<byte> sha256, CancellationToken cancellationToken)
    {
        var checkNames = PrepareMutationNameCheck(path, guard.ObjectIdentity, cancellationToken);
        return guard.MatchesOwnership(expectedIdentity, marker, size, sha256, checkNames, cancellationToken);
    }

    /// <summary>
    /// Writes only a marker on the held, newly created Windows object. The coordinator remains responsible for the
    /// original caller, journal, receipt, transaction and before-effect authorization. An absent marker is not ownership.
    /// </summary>
    internal WorkspaceCreatedOwnership? MarkCreatedTarget(string path, WorkspaceCreatedTarget created, long size,
        ReadOnlySpan<byte> sha256, Action beforeEffect, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(created);
        ArgumentNullException.ThrowIfNull(beforeEffect);
        if (!OperatingSystem.IsWindows()) return null;
        var checkNames = PrepareMutationNameCheck(path, created.Identity, cancellationToken);
        return created.Guard.MarkCreatedTarget(size, sha256, checkNames, beforeEffect, cancellationToken);
    }
}

internal sealed partial class WorkspaceWriteGuard
{
    internal bool MatchesOwnership(RegisteredWorkspaces.RootIdentity expectedIdentity, ReadOnlySpan<byte> marker,
        long size, ReadOnlySpan<byte> sha256, Action checkNames, CancellationToken cancellationToken)
    {
        if (_privateStage || marker.Length != 32 || sha256.Length != 32 || size < 0) return false;
        lock (_sync)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CheckLocked();
            checkNames();
            var actualIdentity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(_file!), directory: false);
            if (actualIdentity.Platform != expectedIdentity.Platform ||
                !actualIdentity.Bytes.AsSpan().SequenceEqual(expectedIdentity.Bytes)) return false;
            var actualMarker = WorkspaceCreationMarker.Read(_file!, marker);
            if (actualMarker is null || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(marker, actualMarker) ||
                !MatchesExpectedContent(sha256, size, cancellationToken)) return false;
            checkNames();
            CheckLocked();
            return true;
        }
    }

    internal WorkspaceCreatedOwnership? MarkCreatedTarget(long size, ReadOnlySpan<byte> sha256, Action checkNames,
        Action beforeEffect, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() || _privateStage || size < 0 || sha256.Length != 32)
            throw new InvalidOperationException("A checked created Windows target is required.");
        lock (_sync)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CheckLocked();
            if (!MatchesExpectedContent(sha256, size, cancellationToken))
                throw new WorkspacePathException("file_identity_changed");
            checkNames();
            var attributes = WorkspacePath.WindowsAttributes(_file!);
            beforeEffect();
            cancellationToken.ThrowIfCancellationRequested();
            CheckLocked();
            checkNames();

            // This native metadata operation uses the exact creation handle, never another pathname.
            var marker = WorkspaceCreationMarker.TryWriteNew(_file!);
            CheckLocked();
            if (WorkspacePath.WindowsAttributes(_file!) != attributes ||
                !MatchesExpectedContent(sha256, size, cancellationToken))
                throw new WorkspacePathException("file_identity_changed");
            checkNames();
            CheckLocked();
            beforeEffect();
            cancellationToken.ThrowIfCancellationRequested();
            return new WorkspaceCreatedOwnership(
                RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(_file!), directory: false), marker);
        }
    }
}
