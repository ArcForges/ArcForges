// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// A synchronous same-volume private stage: Linux O_TMPFILE or a Windows delete-on-close object with a protected DACL.
/// Closing this node's handle does not prove that the object or bytes disappeared: another process may retain a metadata
/// reference and later reopen it. This component has no target-file effect, approval persistence, or API route and must not
/// be connected to file effects without the remaining access, resource, recovery and authorization checks in the design.
/// A lease observation does not establish the separate scheduling or namespace guarantees required for an effect.
/// </summary>
internal sealed class WorkspaceAnonymousStage : WorkspaceMutationStage
{
    private readonly WorkspaceWriteGuard _guard;
    private readonly byte[] _hash;

    internal WorkspaceAnonymousStage(WorkspaceWriteGuard guard, RegisteredWorkspaces.RootIdentity identity, long length, byte[] hash)
    {
        _guard = guard;
        Identity = identity;
        Length = length;
        _hash = hash;
    }

    internal override RegisteredWorkspaces.RootIdentity Identity { get; }

    internal override WorkspaceObjectIdentity ObjectIdentity => _guard.ObjectIdentity;

    internal override long Length { get; }

    internal override ReadOnlyMemory<byte> Sha256 => _hash;

    /// <summary>Rehashes the exact held object with its guard and verifies its length.</summary>
    internal bool Verify(CancellationToken cancellationToken) => _guard.MatchesExpectedContent(_hash, Length, cancellationToken);

    internal override WorkspaceGuardedContent ReadVerified(CancellationToken cancellationToken)
    {
        var content = _guard.ReadForMutation(cancellationToken);
        if (content.Bytes.Length == Length && CryptographicOperations.FixedTimeEquals(content.Sha256.Span, _hash))
            return content;
        content.Dispose();
        throw new WorkspacePathException("file_identity_changed");
    }

    internal override void CheckIntact() => _guard.CheckIntact();

    internal int DescriptorForTests() => _guard.AnonymousDescriptorForTests();

    public override void Dispose() => _guard.Dispose();
}

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Creates, writes and flushes a private same-volume stage, then acquires and verifies its native guard and exact bytes.
    /// Linux uses O_TMPFILE; Windows uses a fresh delete-on-close handle, whose name may be visible while it is held.
    /// A caller still needs a proven stage lifetime and access model, complete effect protocol and real deadline before any
    /// target effect. Neither form supplies durable named approval staging.
    /// </summary>
    internal WorkspaceAnonymousStage CreateAnonymousStage(ReadOnlySpan<byte> bytes, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        if (bytes.Length > 4 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(bytes));
        if (OperatingSystem.IsWindows())
            return CreateWindowsDeleteOnCloseStage(bytes, cancellationToken);
        if (!OperatingSystem.IsLinux())
            throw new WorkspacePathException("file_guard_unavailable");

        var started = Stopwatch.GetTimestamp();
        void CheckBudget()
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Stopwatch.GetElapsedTime(started) >= TimeSpan.FromSeconds(10))
                throw new WorkspacePathException("file_guard_expired");
        }

        var currentRoot = Identity(RootHandle);
        if (!currentRoot.IsDirectory || currentRoot.Links == 0 || !RootIdentity.SameObject(currentRoot))
            throw new WorkspacePathException("root_changed");

        var retained = false;
        int descriptor;
        try
        {
            RootHandle.DangerousAddRef(ref retained);
            // O_TMPFILE|O_EXCL forbids linking this stage into a directory; O_CLOEXEC keeps it out of child processes.
            descriptor = OpenAt(checked((int)RootHandle.DangerousGetHandle()), ".", 0x410000 | 0x80 | 0x80000 | 2, 0x180);
        }
        finally
        {
            if (retained) RootHandle.DangerousRelease();
        }

        if (descriptor < 0)
            throw new WorkspacePathException("file_guard_unavailable");

        SafeFileHandle? file = new(descriptor, ownsHandle: true);
        WorkspaceWriteGuard? guard = null;
        try
        {
            var identity = Identity(file);
            if (!identity.IsFile || identity.Links != 0 || (identity.Mode & 0x3f) != 0 ||
                identity.Volume != currentRoot.Volume || identity.High != currentRoot.High)
                throw new WorkspacePathException("file_guard_unavailable");

            var encoded = RegisteredWorkspaces.RootIdentity.EncodeAnonymousLinux(identity);
            for (var offset = 0; offset < bytes.Length;)
            {
                CheckBudget();
                var part = Math.Min(65_536, bytes.Length - offset);
                RandomAccess.Write(file, bytes.Slice(offset, part), offset);
                offset += part;
            }

            CheckBudget();
            RandomAccess.FlushToDisk(file);
            CheckBudget();
            var expected = SHA256.HashData(bytes);
            guard = WorkspaceWriteGuard.AcquireAnonymousStage(file);
            file = null; // the guard owns the same descriptor from this point.
            if (!guard.MatchesExpectedContent(expected, bytes.Length, cancellationToken))
                throw new WorkspacePathException("file_identity_changed");
            CheckBudget();
            var result = new WorkspaceAnonymousStage(guard, encoded, bytes.Length, expected);
            guard = null;
            return result;
        }
        finally
        {
            guard?.Dispose();
            file?.Dispose();
        }
    }
}
