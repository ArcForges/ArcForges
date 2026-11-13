// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Creates only an empty, transaction-private stage relative to the exact transferred parent. The caller must
    /// FULL-bind its actual identity before writing content. This handle is not a WorkspaceWriteGuard and must not
    /// be used after commit; ordinary recovery reopens and rehashes the recorded identity after actual worker exit.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static unsafe SafeFileHandle CreateWindowsTransactionalEmptyStage(SafeFileHandle parent,
        WindowsPrivateStageBinding binding, WindowsPrivateStageTransaction transaction)
    {
        binding.Validate();
        RequireWindowsStageDirectory(parent, binding.ParentIdentity);
        if (Components(binding.Name).Length != 1) throw new WorkspacePathException("path_invalid");
        using var principal = System.Security.Principal.WindowsIdentity.GetCurrent();
        var sid = principal.User ?? throw new WorkspacePathException("file_guard_unavailable");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var descriptorText = sid.Equals(system) ? $"O:{sid.Value}D:P(A;;FA;;;SY)" : $"O:{sid.Value}D:P(A;;FA;;;SY)(A;;FA;;;{sid.Value})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(descriptorText, 1, out var descriptor, out _))
            throw new WorkspacePathException("file_guard_unavailable");
        SafeFileHandle? file = null;
        try
        {
            uint caseFlags;
            if (!GetCaseInformation(parent, 23, &caseFlags, sizeof(uint)))
                throw new WorkspacePathException("case_semantics_unavailable");
            fixed (char* characters = binding.Name)
            {
                var unicode = new UnicodeString
                {
                    Length = checked((ushort)(binding.Name.Length * 2)),
                    MaximumLength = checked((ushort)(binding.Name.Length * 2)),
                    Buffer = (nint)characters,
                };
                var retained = false;
                try
                {
                    parent.DangerousAddRef(ref retained);
                    var attributes = new ObjectAttributes
                    {
                        Length = (uint)sizeof(ObjectAttributes),
                        RootDirectory = parent.DangerousGetHandle(),
                        ObjectName = (nint)(&unicode),
                        Attributes = (caseFlags & 1) == 0 ? 0x40u : 0u,
                        SecurityDescriptor = descriptor,
                    };
                    var previous = transaction.EnterCurrent();
                    try
                    {
                        var status = NtCreateFile(out var raw, 0xC0130000u, ref attributes, out _, 0, 0x80u, 0u, 2u,
                            0x2u | 0x20u | 0x40u | 0x00200000u, 0, 0);
                        if (status < 0) throw new WorkspacePathException("file_guard_unavailable");
                        file = new SafeFileHandle(raw, ownsHandle: true);
                    }
                    finally { WindowsPrivateStageTransaction.RestoreCurrent(previous); }
                }
                finally { if (retained) parent.DangerousRelease(); }
            }
            CheckWindowsTransactionalStage(file, parent, binding, transaction);
            if (RandomAccess.GetLength(file) != 0) throw new WorkspacePathException("file_identity_changed");
            var result = file;
            file = null;
            return result;
        }
        finally
        {
            file?.Dispose();
            _ = LocalFree(descriptor);
        }
    }

    [SupportedOSPlatform("windows")]
    internal static void RequireWindowsStageDirectory(SafeFileHandle directory, byte[] expected)
    {
        var actual = Identity(directory);
        if (!actual.IsDirectory || actual.Links == 0 || !WindowsStageIsNtfs(directory) ||
            !CryptographicOperations.FixedTimeEquals(RegisteredWorkspaces.RootIdentity.Encode(actual, directory: true).Bytes, expected))
            throw new WorkspacePathException("root_changed");
    }

    [SupportedOSPlatform("windows")]
    internal static void CheckWindowsTransactionalStage(SafeFileHandle file, SafeFileHandle parent,
        WindowsPrivateStageBinding binding, WindowsPrivateStageTransaction transaction)
    {
        transaction.RequireActive();
        RequireWindowsStageDirectory(parent, binding.ParentIdentity);
        var directory = Identity(parent);
        var actual = Identity(file);
        if (!actual.IsFile || actual.Links != 1 || actual.Volume != directory.Volume || !WindowsStageIsNtfs(file))
            throw new WorkspacePathException("file_identity_changed");
        using var principal = System.Security.Principal.WindowsIdentity.GetCurrent();
        var sid = principal.User ?? throw new WorkspacePathException("file_guard_unavailable");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var ownerBytes = new byte[sid.BinaryLength];
        var systemBytes = new byte[system.BinaryLength];
        sid.GetBinaryForm(ownerBytes, 0);
        system.GetBinaryForm(systemBytes, 0);
        CheckPrivateWindowsStageSecurity(file, ownerBytes, systemBytes, sid.Equals(system));
        transaction.RequireActive();
    }
}
