// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Reopens only the recorded Linux stage under its verified directory, compares the real native identity, owner,
    /// restrictive mode and full bytes under a file lease. A lease is not a namespace lock or an atomic target-write
    /// primitive. The caller must separately revalidate the approved target, policy and effect guard.
    /// </summary>
    [SupportedOSPlatform("linux")]
    internal WorkspaceWriteGuard ReopenLinuxPrivateNamedStage(RegisteredWorkspaces.RootIdentity expected,
        string name, long expectedSize, ReadOnlySpan<byte> expectedSha256, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(expected);
        if (Components(name).Length != 1 || expected.Platform != 2 || expectedSize is < 0 or > 4 * 1024 * 1024 ||
            expectedSha256.Length != 32)
            throw new WorkspacePathException("file_guard_unavailable");
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(expected.Platform, expected.Bytes);
        cancellationToken.ThrowIfCancellationRequested();
        using var metadata = LinuxOpenAt2(RootHandle, name, noCrossMount: true);
        CheckVolume(metadata, _linuxFileSystemUuid);
        var before = LinuxIdentity(metadata, _linuxFileSystemUuid);
        if (!before.IsFile || before.Links != 1) throw new WorkspacePathException("file_identity_changed");
        var encodedBefore = RegisteredWorkspaces.RootIdentity.Encode(before, directory: false);
        if (encodedBefore.Platform != expected.Platform ||
            !CryptographicOperations.FixedTimeEquals(encodedBefore.Bytes, expected.Bytes))
            throw new WorkspacePathException("file_identity_changed");
        SafeFileHandle? file = null;
        WorkspaceWriteGuard? guard = null;
        try
        {
            file = LinuxReopenChecked(metadata, directory: false, _linuxFileSystemUuid, afterMetadataOpen: null, writable: true);
            var actual = Identity(file);
            if (!actual.IsFile || actual.Links != 1) throw new WorkspacePathException("file_identity_changed");
            var encoded = RegisteredWorkspaces.RootIdentity.Encode(actual, directory: false);
            if (!before.SameObject(actual) || encoded.Platform != expected.Platform ||
                !CryptographicOperations.FixedTimeEquals(encoded.Bytes, expected.Bytes))
                throw new WorkspacePathException("file_identity_changed");
            CheckPrivateLinuxNamedStageSecurity(file);
            guard = WorkspaceWriteGuard.AcquireLinuxNamedPrivateStage(file, CheckPrivateLinuxNamedStageSecurity);
            file = null;
            using var checkedRoot = OpenRoot(RootPath, RootIdentity);
            var named = InspectEntry(name);
            if (named.Kind != WorkspaceEntryType.File || named.Identity.Links != 1 || !actual.SameObject(named.Identity) ||
                !guard.MatchesExpectedContent(expectedSha256, expectedSize, cancellationToken))
                throw new WorkspacePathException("file_identity_changed");
            guard.CheckIntact();
            var result = guard;
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
