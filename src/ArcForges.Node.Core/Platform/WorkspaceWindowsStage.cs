// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
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
    /// Creates a fresh, delete-on-last-handle Windows stage relative to the checked root. The protected ACL and owner are
    /// inspected on the actual handle before any bytes are written. A metadata handle held elsewhere can outlive ours;
    /// closure of the node's handle alone is not proof that this object or its contents disappeared.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private unsafe WorkspaceAnonymousStage CreateWindowsDeleteOnCloseStage(ReadOnlySpan<byte> bytes, CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();
        void CheckBudget()
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Stopwatch.GetElapsedTime(started) >= TimeSpan.FromSeconds(10))
                throw new WorkspacePathException("file_guard_expired");
        }

        var root = Identity(RootHandle);
        if (!root.IsDirectory || root.Links == 0 || !RootIdentity.SameObject(root))
            throw new WorkspacePathException("root_changed");
        using var current = System.Security.Principal.WindowsIdentity.GetCurrent();
        var sid = current.User ?? throw new WorkspacePathException("file_guard_unavailable");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var ownerBytes = new byte[sid.BinaryLength];
        var systemBytes = new byte[system.BinaryLength];
        sid.GetBinaryForm(ownerBytes, 0);
        system.GetBinaryForm(systemBytes, 0);
        var samePrincipal = sid.Equals(system);
        var descriptorText = samePrincipal
            ? $"O:{sid.Value}D:P(A;;FA;;;SY)"
            : $"O:{sid.Value}D:P(A;;FA;;;SY)(A;;FA;;;{sid.Value})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(descriptorText, 1, out var descriptor, out _))
            throw new WorkspacePathException("file_guard_unavailable");

        SafeFileHandle? file = null;
        WorkspaceWriteGuard? guard = null;
        try
        {
            CheckBudget();
            var name = ".arcforges-stage-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            uint caseFlags;
            if (!GetCaseInformation(RootHandle, 23, &caseFlags, sizeof(uint)))
                throw new WorkspacePathException("case_semantics_unavailable");

            fixed (char* characters = name)
            {
                var unicode = new UnicodeString
                {
                    Length = checked((ushort)(name.Length * 2)),
                    MaximumLength = checked((ushort)(name.Length * 2)),
                    Buffer = (nint)characters,
                };
                var retained = false;
                try
                {
                    RootHandle.DangerousAddRef(ref retained);
                    var attributes = new ObjectAttributes
                    {
                        Length = (uint)sizeof(ObjectAttributes),
                        RootDirectory = RootHandle.DangerousGetHandle(),
                        ObjectName = (nint)(&unicode),
                        Attributes = (caseFlags & 1) == 0 ? 0x40u : 0u,
                        SecurityDescriptor = descriptor,
                    };
                    // GENERIC_READ|GENERIC_WRITE|DELETE|READ_CONTROL|SYNCHRONIZE, no sharing, FILE_CREATE;
                    // synchronous non-directory, open reparse point, and FILE_DELETE_ON_CLOSE on this exact handle.
                    var status = NtCreateFile(out var raw, 0xC0130000u, ref attributes, out _, 0, 0x100u, 0u, 2u,
                        0x20u | 0x40u | 0x1000u | 0x00200000u, 0, 0);
                    if (status < 0) throw new WorkspacePathException("file_guard_unavailable");
                    file = new SafeFileHandle(raw, ownsHandle: true);
                }
                finally
                {
                    if (retained) RootHandle.DangerousRelease();
                }
            }

            CheckBudget();
            var actual = Identity(file);
            if (!actual.IsFile || actual.Links != 1 || actual.Volume != root.Volume)
                throw new WorkspacePathException("file_guard_unavailable");
            CheckPrivateWindowsStageSecurity(file, ownerBytes, systemBytes, samePrincipal);
            var encoded = RegisteredWorkspaces.RootIdentity.Encode(actual, directory: false);
            for (var offset = 0; offset < bytes.Length;)
            {
                CheckBudget();
                var count = Math.Min(65_536, bytes.Length - offset);
                RandomAccess.Write(file, bytes.Slice(offset, count), offset);
                offset += count;
            }

            CheckBudget();
            RandomAccess.FlushToDisk(file);
            CheckBudget();
            var expected = SHA256.HashData(bytes);
            guard = WorkspaceWriteGuard.AcquireWindowsPrivateStage(file,
                handle => CheckPrivateWindowsStageSecurity(handle, ownerBytes, systemBytes, samePrincipal));
            file = null;
            if (!guard.MatchesExpectedContent(expected, bytes.Length, cancellationToken))
                throw new WorkspacePathException("file_identity_changed");
            CheckBudget();
            var stage = new WorkspaceAnonymousStage(guard, encoded, bytes.Length, expected);
            guard = null;
            return stage;
        }
        finally
        {
            guard?.Dispose();
            file?.Dispose();
            _ = LocalFree(descriptor);
        }
    }

    [SupportedOSPlatform("windows")]
    private static unsafe void CheckPrivateWindowsStageSecurity(SafeFileHandle file, byte[] ownerBytes, byte[] systemBytes, bool samePrincipal)
    {
        // OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION on the same held file, never a pathname.
        var error = GetSecurityInfo(file, 1, 5, out var owner, out _, out var dacl, out _, out var descriptor);
        if (error != 0 || descriptor == 0 || owner == 0 || dacl == 0)
        {
            if (descriptor != 0) _ = LocalFree(descriptor);
            throw new WorkspacePathException("file_guard_unavailable");
        }

        try
        {
            fixed (byte* expectedOwner = ownerBytes)
            fixed (byte* expectedSystem = systemBytes)
            {
                if (!IsValidSid(owner) || !EqualSid(owner, (nint)expectedOwner) ||
                    !GetSecurityDescriptorControl(descriptor, out var control, out _) ||
                    (control & 0x1004) != 0x1004 || !IsValidAcl(dacl) ||
                    !GetAclInformation(dacl, out var information, (uint)sizeof(AclSizeInformation), 2) ||
                    information.AceCount != (samePrincipal ? 1u : 2u))
                    throw new WorkspacePathException("file_guard_unavailable");

                var hasOwner = false;
                var hasSystem = false;
                for (uint index = 0; index < information.AceCount; index++)
                {
                    if (!GetAce(dacl, index, out var rawAce) || rawAce == 0)
                        throw new WorkspacePathException("file_guard_unavailable");
                    var ace = (byte*)rawAce;
                    var aceSize = *(ushort*)(ace + 2);
                    if (ace[0] != 0 || ace[1] != 0 || aceSize < 16 || *(uint*)(ace + 4) != 0x001f01ffu)
                        throw new WorkspacePathException("file_guard_unavailable");
                    var aceSid = (nint)(ace + 8);
                    if (!IsValidSid(aceSid) || GetLengthSid(aceSid) != aceSize - 8)
                        throw new WorkspacePathException("file_guard_unavailable");
                    if (EqualSid(aceSid, (nint)expectedOwner)) hasOwner = true;
                    else if (EqualSid(aceSid, (nint)expectedSystem)) hasSystem = true;
                    else throw new WorkspacePathException("file_guard_unavailable");
                }
                if (!hasOwner || (!samePrincipal && !hasSystem))
                    throw new WorkspacePathException("file_guard_unavailable");
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AclSizeInformation
    {
        public uint AceCount;
        public uint BytesInUse;
        public uint BytesFree;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out nint descriptor, out uint size);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint information,
        out nint owner, out nint group, out nint dacl, out nint sacl, out nint descriptor);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetSecurityDescriptorControl(nint descriptor, out ushort control, out uint revision);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetAclInformation(nint acl, out AclSizeInformation information, uint size, int informationClass);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetAce(nint acl, uint index, out nint ace);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsValidAcl(nint acl);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsValidSid(nint sid);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EqualSid(nint first, nint second);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetLengthSid(nint sid);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);
}
