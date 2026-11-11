// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// A failure from a real held-handle component effect. Once an effect syscall may have begun, callers must retain the
/// journal and report UNKNOWN unless the outcome is independently proved; this exception never promises rollback.
/// </summary>
internal sealed class WorkspaceGuardedMutationException(bool possibleEffect, Exception inner)
    : IOException("The guarded file mutation did not complete.", inner)
{
    internal bool PossibleEffect { get; } = possibleEffect;
}

/// <summary>
/// Native building block only. It does not grant authority, make a journal, enforce the complete request deadline,
/// implement approval, or expose an RPC. Linux F_GETLEASE and write remain separate syscalls; a component success is
/// not a scheduling proof. The caller must commit PREPARED and retain the two verified stages before invoking it.
/// </summary>
internal sealed partial class WorkspacePath
{
    internal WorkspaceGuardedMutationResult ApplyExistingGuardedStage(string path, WorkspaceWriteGuard target,
        WorkspaceAnonymousStage intended, ReadOnlySpan<byte> expectedSha256, CancellationToken cancellationToken) =>
        ApplyExistingGuardedStage(path, target, intended, expectedSha256, afterFirstEffect: null, cancellationToken);

    // Callback is a test seam for coordinating a real namespace change after the first actual write.
    internal WorkspaceGuardedMutationResult ApplyExistingGuardedStage(string path, WorkspaceWriteGuard target,
        WorkspaceAnonymousStage intended, ReadOnlySpan<byte> expectedSha256, Action? afterFirstEffect, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(intended);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (expectedSha256.Length != 32) throw new ArgumentException("An expected SHA-256 has 32 bytes.", nameof(expectedSha256));
        var stagedObject = intended.ObjectIdentity;
        if (stagedObject.Volume != RootIdentity.Volume || OperatingSystem.IsLinux() && stagedObject.High != RootIdentity.High ||
            stagedObject.SameObject(target.ObjectIdentity))
            throw new WorkspacePathException("file_guard_unavailable");

        // Retain each checked directory through the effect and compare those identities again from the checked root.
        // This observes replacement; it is not the strict namespace lock needed by cleanup.
        var parts = Components(path);
        var parents = new List<(string Name, WorkspaceObjectIdentity Identity)>();
        for (var index = 1; index < parts.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var prefix = string.Join('/', parts.AsSpan(0, index).ToArray());
            var handle = OpenDirectory(prefix);
            var identity = Identity(handle);
            if (!identity.IsDirectory || identity.Links == 0) throw new WorkspacePathException("directory_identity_changed");
            parents.Add((prefix, identity));
        }

        void CheckNames()
        {
            cancellationToken.ThrowIfCancellationRequested();
            var root = Identity(RootHandle);
            if (!root.IsDirectory || root.Links == 0 || !RootIdentity.SameObject(root))
                throw new WorkspacePathException("root_changed");
            using var namedRoot = OpenRoot(RootPath, RootIdentity);
            foreach (var (name, original) in parents)
            {
                var observed = InspectEntry(name);
                if (observed.Kind != WorkspaceEntryType.Directory || !original.SameObject(observed.Identity))
                    throw new WorkspacePathException("directory_identity_changed");
            }

            var entry = InspectEntry(path);
            if (entry.Kind != WorkspaceEntryType.File || entry.Identity.Links != 1 ||
                !target.ObjectIdentity.SameObject(entry.Identity))
                throw new WorkspacePathException("file_identity_changed");
        }

        return target.ApplyStage(intended, expectedSha256, CheckNames, afterFirstEffect, cancellationToken);
    }
}

internal sealed record WorkspaceGuardedMutationResult(long Size, byte[] Sha256);

internal sealed partial class WorkspaceWriteGuard
{
    internal WorkspaceObjectIdentity ObjectIdentity => _identity;

    /// <summary>
    /// Reads and hashes the exact still-held stage, checks the original before the first effect, writes/truncates/flushes
    /// this same guarded target handle and rehashes it. Names are checked immediately before and after; no effect uses a name.
    /// </summary>
    internal WorkspaceGuardedMutationResult ApplyStage(WorkspaceAnonymousStage stage, ReadOnlySpan<byte> expectedSha256,
        Action checkNames, Action? afterFirstEffect, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stage);
        ArgumentNullException.ThrowIfNull(checkNames);
        var possibleEffect = false;
        try
        {
            using var source = stage.ReadVerified(cancellationToken);
            lock (_sync)
            {
                CheckLocked();
                cancellationToken.ThrowIfCancellationRequested();
                if (!MatchesExpectedHash(expectedSha256, cancellationToken))
                    throw new WorkspacePathException("hash_mismatch");
                stage.CheckIntact();
                checkNames();
                CheckLocked();
                cancellationToken.ThrowIfCancellationRequested();
                stage.CheckIntact();
                var file = _file!;
                for (var offset = 0; offset < source.Bytes.Length;)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    CheckLocked();
                    stage.CheckIntact();
                    var length = Math.Min(65_536, source.Bytes.Length - offset);
                    possibleEffect = true; // a failing write may still have changed bytes
                    RandomAccess.Write(file, source.Bytes.Span.Slice(offset, length), offset);
                    if (offset == 0) afterFirstEffect?.Invoke();
                    offset += length;
                    CheckLocked();
                    stage.CheckIntact();
                }

                cancellationToken.ThrowIfCancellationRequested();
                CheckLocked();
                stage.CheckIntact();
                possibleEffect = true; // length change is itself an effect, including for an empty result
                RandomAccess.SetLength(file, source.Bytes.Length);
                if (source.Bytes.Length == 0) afterFirstEffect?.Invoke();
                CheckLocked();
                stage.CheckIntact();
                RandomAccess.FlushToDisk(file);
                CheckLocked();
                stage.CheckIntact();
                using var result = ReadForMutation(cancellationToken);
                if (result.Bytes.Length != stage.Length || !CryptographicOperations.FixedTimeEquals(result.Sha256.Span, stage.Sha256.Span))
                    throw new WorkspacePathException("file_identity_changed");
                checkNames();
                CheckLocked();
                stage.CheckIntact();
                cancellationToken.ThrowIfCancellationRequested();
                return new WorkspaceGuardedMutationResult(result.Bytes.Length, result.Sha256.ToArray());
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            throw new WorkspaceGuardedMutationException(possibleEffect, exception);
        }
    }
}
