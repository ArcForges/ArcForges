// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Reopens an already recorded NTFS stage by its file ID, verifies the full recorded identity and private security,
    /// then hashes the exact held bytes under exclusive sharing. Caller supplies previously durable trusted metadata and
    /// revalidates the approval, target and policy separately; this method does not authorize or perform an effect.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal unsafe WorkspaceWriteGuard ReopenWindowsPrivateNamedStage(RegisteredWorkspaces.RootIdentity expected,
        string name, long expectedSize, ReadOnlySpan<byte> expectedSha256, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(expected);
        if (Components(name).Length != 1 || expected.Platform != 1 || expectedSize is < 0 or > 4 * 1024 * 1024 ||
            expectedSha256.Length != 32)
            throw new WorkspacePathException("file_guard_unavailable");
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(expected.Platform, expected.Bytes);
        cancellationToken.ThrowIfCancellationRequested();
        var storedVolume = BinaryPrimitives.ReadUInt64BigEndian(expected.Bytes.AsSpan(1, 8));
        var low = BinaryPrimitives.ReadUInt64BigEndian(expected.Bytes.AsSpan(9, 8));
        var high = BinaryPrimitives.ReadUInt64BigEndian(expected.Bytes.AsSpan(17, 8));
        if (storedVolume != RootIdentity.Volume || high != 0 || !WindowsStageIsNtfs(RootHandle))
            throw new WorkspacePathException("file_guard_unavailable");

        // FileIdType is the documented NTFS 64-bit identifier. The opened object's full identity, including the
        // 128-bit ID, volume and creation time, is compared below; an ID alone is never adopted as authority.
        var descriptor = new NativeFileIdDescriptor { Size = (uint)sizeof(NativeFileIdDescriptor), Type = 0, Low = low };
        var raw = OpenFileById(RootHandle, ref descriptor, 0xC0130000u, 0, 0, 0x80200000u);
        if (raw == 0 || raw == -1) throw new WorkspacePathException("file_guard_unavailable");
        SafeFileHandle? file = new(raw, ownsHandle: true);
        WorkspaceWriteGuard? guard = null;
        try
        {
            var actual = Identity(file);
            if (!actual.IsFile || actual.Links != 1) throw new WorkspacePathException("file_identity_changed");
            var encoded = RegisteredWorkspaces.RootIdentity.Encode(actual, directory: false);
            if (encoded.Platform != expected.Platform || !CryptographicOperations.FixedTimeEquals(encoded.Bytes, expected.Bytes) ||
                !WindowsStageIsNtfs(file))
                throw new WorkspacePathException("file_identity_changed");
            using var checkedRoot = OpenRoot(RootPath, RootIdentity);
            var expectedPath = Path.Combine(RootPath, name);
            if (!string.Equals(FinalPath(file, expectedPath), expectedPath, StringComparison.OrdinalIgnoreCase))
                throw new WorkspacePathException("file_identity_changed");
            using var current = System.Security.Principal.WindowsIdentity.GetCurrent();
            var owner = current.User ?? throw new WorkspacePathException("file_guard_unavailable");
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var ownerBytes = new byte[owner.BinaryLength];
            var systemBytes = new byte[system.BinaryLength];
            owner.GetBinaryForm(ownerBytes, 0);
            system.GetBinaryForm(systemBytes, 0);
            var samePrincipal = owner.Equals(system);
            CheckPrivateWindowsStageSecurity(file, ownerBytes, systemBytes, samePrincipal);
            guard = WorkspaceWriteGuard.AcquireWindowsPrivateStage(file,
                handle => CheckPrivateWindowsStageSecurity(handle, ownerBytes, systemBytes, samePrincipal));
            file = null;
            if (!guard.MatchesExpectedContent(expectedSha256, expectedSize, cancellationToken))
                throw new WorkspacePathException("file_identity_changed");
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

    [SupportedOSPlatform("windows")]
    private static unsafe bool WindowsStageIsNtfs(SafeFileHandle file)
    {
        var name = stackalloc char[32];
        new Span<char>(name, 32).Clear();
        return GetVolumeInformationByHandle(file, null, 0, null, null, null, name, 32) &&
            string.Equals(new string(name), "NTFS", StringComparison.OrdinalIgnoreCase);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileIdDescriptor
    {
        public uint Size;
        public int Type;
        public ulong Low;
        public ulong High;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenFileById(SafeFileHandle volumeHint, ref NativeFileIdDescriptor fileId,
        uint desiredAccess, uint shareMode, nint securityAttributes, uint flagsAndAttributes);

    [LibraryImport("kernel32.dll", EntryPoint = "GetVolumeInformationByHandleW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool GetVolumeInformationByHandle(SafeFileHandle file, char* volumeName, uint volumeNameLength,
        uint* serialNumber, uint* maximumComponentLength, uint* fileSystemFlags, char* fileSystemName, uint fileSystemNameLength);
}
