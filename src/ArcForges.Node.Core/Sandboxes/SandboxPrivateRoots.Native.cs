// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Node.Core.Sandboxes;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    internal static void CheckSandboxInstallationOverlap(WorkspacePath data)
    {
        using var installation = OpenRoot(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory));
        bool overlaps;
        if (OperatingSystem.IsWindows())
        {
            overlaps = data.WindowsRootAncestors().Any(ancestor => ancestor.SameObject(installation.RootIdentity)) ||
                installation.WindowsRootAncestors().Any(ancestor => ancestor.SameObject(data.RootIdentity));
        }
        else
        {
            overlaps = data.RootIdentity.SameObject(installation.RootIdentity) ||
                OverlapsLinuxPath(data.RootPath, installation.RootPath);

            // Equal devices can be visible through different bind roots. Compare origin paths only in that case.
            if (!overlaps && data.RootIdentity.Volume == installation.RootIdentity.Volume &&
                data.RootIdentity.High != installation.RootIdentity.High)
            {
                overlaps = OverlapsLinuxPath(LinuxMountOrigin(data), LinuxMountOrigin(installation));
            }
        }

        if (overlaps)
        {
            throw new SandboxPrivateRootException("private_data_root_overlaps_installation");
        }
    }

    private static bool OverlapsLinuxPath(string first, string second) =>
        AtOrBelowLinuxPath(first, second) || AtOrBelowLinuxPath(second, first);

    private static bool AtOrBelowLinuxPath(string path, string root) =>
        path.Equals(root, StringComparison.Ordinal) ||
        path.StartsWith(root.EndsWith('/') ? root : root + '/', StringComparison.Ordinal);

    private static string LinuxMountOrigin(WorkspacePath directory)
    {
        var id = directory.RootIdentity.High.ToString(CultureInfo.InvariantCulture);
        foreach (var line in File.ReadLines("/proc/self/mountinfo"))
        {
            var fields = line.Split(' ', 6);
            if (fields.Length < 6 || fields[0] != id)
            {
                continue;
            }

            var mountPoint = DecodeLinuxMountPath(fields[4]);
            var origin = DecodeLinuxMountPath(fields[3]);
            if (Path.IsPathFullyQualified(origin) && AtOrBelowLinuxPath(directory.RootPath, mountPoint))
            {
                return Path.GetFullPath(Path.GetRelativePath(mountPoint, directory.RootPath), origin);
            }

            break;
        }

        throw new SandboxPrivateRootException("private_data_root_location_unverified");
    }

    private static string DecodeLinuxMountPath(string path) => path.Replace(@"\040", " ", StringComparison.Ordinal)
        .Replace(@"\011", "\t", StringComparison.Ordinal).Replace(@"\012", "\n", StringComparison.Ordinal)
        .Replace(@"\134", "\\", StringComparison.Ordinal);

    /// <summary>Opens a managed directory relative to the checked parent, including a native mount/volume check.</summary>
    internal WorkspacePath OpenSandboxDirectory(string name, bool configuredRoot = false)
    {
        if (Components(name).Length != 1)
        {
            throw new SandboxPrivateRootException("private_root_name_invalid");
        }

        var directory = OpenDirectory(name);
        CheckSandboxDirectory(directory, configuredRoot);
        return OpenRoot(Path.Combine(RootPath, name), Identity(directory));
    }

    /// <summary>Creates precisely one directory without replacing or adopting any existing filesystem entry.</summary>
    internal WorkspacePath CreateSandboxDirectory(string name)
    {
        if (Components(name).Length != 1)
        {
            throw new SandboxPrivateRootException("private_root_name_invalid");
        }

        if (OperatingSystem.IsLinux())
        {
            var parent = checked((int)RootHandle.DangerousGetHandle());
            if (MakeRemovalDirectory(parent, name, 0x1c0) != 0)
            {
                if (Marshal.GetLastPInvokeError() == 17) // EEXIST
                {
                    throw new SandboxPrivateRootException("private_root_already_exists");
                }

                throw NativeFailure();
            }

            var created = OpenSandboxDirectory(name);
            if (SyncDirectory(parent) != 0)
            {
                created.Dispose();
                throw NativeFailure();
            }

            return created;
        }

        if (OperatingSystem.IsWindows())
        {
            return CreateWindowsSandboxDirectory(name);
        }

        throw new SandboxPrivateRootException("path_enforcement_unavailable");
    }

    internal static unsafe void CheckSandboxDirectory(SafeFileHandle directory, bool configuredRoot)
    {
        if (OperatingSystem.IsLinux())
        {
            const uint mask = 0x08 | 0x02; // STATX_UID | STATX_MODE
            var stat = stackalloc byte[256];
            if (Statx(checked((int)directory.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, mask, stat) != 0 ||
                (*(uint*)stat & mask) != mask || *(uint*)(stat + 20) != EffectiveUserId() ||
                *(ushort*)(stat + 28) != (0x4000 | 0x1c0))
            {
                throw new SandboxPrivateRootException("private_root_permissions");
            }

            return;
        }

        if (OperatingSystem.IsWindows())
        {
            CheckWindowsSandboxDirectory(directory, configuredRoot);
            return;
        }

        throw new SandboxPrivateRootException("path_enforcement_unavailable");
    }

    [SupportedOSPlatform("windows")]
    private unsafe WorkspacePath CreateWindowsSandboxDirectory(string name)
    {
        using var principal = System.Security.Principal.WindowsIdentity.GetCurrent();
        var owner = principal.User ?? throw new SandboxPrivateRootException("private_root_permissions");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var descriptorText = owner.Equals(system)
            ? $"O:{owner.Value}D:P(A;OICI;FA;;;SY)"
            : $"O:{owner.Value}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner.Value})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(descriptorText, 1, out var descriptor, out _))
        {
            throw new SandboxPrivateRootException("private_root_permissions");
        }

        try
        {
            uint flags;
            if (!GetCaseInformation(RootHandle, 23, &flags, sizeof(uint)))
            {
                throw new SandboxPrivateRootException("case_semantics_unavailable");
            }

            fixed (char* characters = name)
            {
                var length = checked((ushort)(name.Length * sizeof(char)));
                var unicode = new UnicodeString { Length = length, MaximumLength = length, Buffer = (nint)characters };
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = RootHandle.DangerousGetHandle(),
                    ObjectName = (nint)(&unicode),
                    Attributes = (flags & 1) == 0 ? 0x40u : 0u,
                    SecurityDescriptor = descriptor,
                };

                // FILE_CREATE, directory, write-through, synchronous, no reparse traversal.
                var status = NtCreateFile(out var raw, 0x00120081u, ref attributes, out _, 0, 0x10, 3, 2, 0x00200023, 0, 0);
                if (status < 0)
                {
                    var error = RtlNtStatusToDosError(status);
                    throw new SandboxPrivateRootException(error is 80 or 183
                        ? "private_root_already_exists"
                        : "native_" + error.ToString(CultureInfo.InvariantCulture));
                }

                using var directory = new SafeFileHandle(raw, ownsHandle: true);
                CheckVolume(directory);
                CheckWindowsSandboxSecurity(directory, owner, system, configuredRoot: false);
                return OpenRoot(Path.Combine(RootPath, name), Identity(directory));
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CheckWindowsSandboxDirectory(SafeFileHandle directory, bool configuredRoot)
    {
        using var principal = System.Security.Principal.WindowsIdentity.GetCurrent();
        var owner = principal.User ?? throw new SandboxPrivateRootException("private_root_permissions");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        try
        {
            using var security = OpenWindowsReadControl(directory, "private_root_permissions");
            CheckWindowsSandboxSecurity(security, owner, system, configuredRoot);
        }
        catch (WorkspacePathException error)
        {
            throw new SandboxPrivateRootException("private_root_permissions", inner: error);
        }
    }

    [SupportedOSPlatform("windows")]
    private static unsafe SafeFileHandle OpenWindowsReadControl(SafeFileHandle target, string refusal)
    {
        // An empty NT relative name reopens the held object itself with READ_CONTROL.
        // ReOpenFile refused that access when the original handle did not request it.
        var expected = Identity(target);
        var terminator = '\0';
        var name = new UnicodeString { Buffer = (nint)(&terminator) };
        var attributes = new ObjectAttributes
        {
            Length = (uint)sizeof(ObjectAttributes),
            RootDirectory = target.DangerousGetHandle(),
            ObjectName = (nint)(&name),
        };
        var options = 0x00200020u | (expected.IsDirectory ? 1u : 0x40u);
        var status = NtCreateFile(out var raw, 0x00120080u, ref attributes, out _, 0, 0, 3, 1, options, 0, 0);
        if (status < 0)
        {
            var native = RtlNtStatusToDosError(status);
            throw new WorkspacePathException(refusal,
                new WorkspacePathException("native_" + native.ToString(CultureInfo.InvariantCulture)));
        }

        var security = new SafeFileHandle(raw, ownsHandle: true);
        try
        {
            if (!Identity(security).SameObject(expected))
            {
                throw new WorkspacePathException(refusal, new WorkspacePathException("file_identity_changed"));
            }

            return security;
        }
        catch
        {
            security.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CheckWindowsSandboxSecurity(SafeFileHandle directory, SecurityIdentifier expectedOwner, SecurityIdentifier system,
        bool configuredRoot)
    {
        var error = GetSecurityInfo(directory, 1, 5, out var owner, out _, out var dacl, out _, out var descriptor);
        try
        {
            if (error != 0 || descriptor == 0 || owner == 0 || dacl == 0 || !IsValidSid(owner) ||
                !new SecurityIdentifier(owner).Equals(expectedOwner) || !IsValidAcl(dacl))
            {
                throw new SandboxPrivateRootException("private_root_permissions");
            }

            var length = unchecked((ushort)Marshal.ReadInt16(dacl, 2)); // ACL.AclSize
            if (length < 8)
            {
                throw new SandboxPrivateRootException("private_root_permissions");
            }

            var bytes = new byte[length];
            Marshal.Copy(dacl, bytes, 0, length);
            var acl = new RawAcl(bytes, 0);
            if (!configuredRoot)
            {
                CheckOwnedSandboxAcl(acl, descriptor, expectedOwner, system);
                return;
            }

            var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            foreach (var entry in acl)
            {
                if ((entry.AceFlags & AceFlags.InheritOnly) != 0)
                {
                    continue;
                }

                if (entry is not CommonAce { IsCallback: false } ace ||
                    (ace.AceQualifier != AceQualifier.AccessDenied &&
                        !ace.SecurityIdentifier.Equals(expectedOwner) && !ace.SecurityIdentifier.Equals(system) &&
                        !ace.SecurityIdentifier.Equals(administrators)))
                {
                    throw new SandboxPrivateRootException("private_root_permissions");
                }
            }
        }
        catch (ArgumentException errorDetail)
        {
            throw new SandboxPrivateRootException("private_root_permissions", inner: errorDetail);
        }
        finally
        {
            if (descriptor != 0)
            {
                _ = LocalFree(descriptor);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CheckOwnedSandboxAcl(RawAcl acl, nint descriptor, SecurityIdentifier owner, SecurityIdentifier system)
    {
        if (!GetSecurityDescriptorControl(descriptor, out var control, out _) || (control & 0x1004) != 0x1004 ||
            acl.Count != (owner.Equals(system) ? 1 : 2))
        {
            throw new SandboxPrivateRootException("private_root_permissions");
        }

        const AceFlags inheritance = AceFlags.ContainerInherit | AceFlags.ObjectInherit;
        var hasOwner = false;
        var hasSystem = false;
        foreach (var entry in acl)
        {
            if (entry is not CommonAce
                {
                    IsCallback: false, AceQualifier: AceQualifier.AccessAllowed,
                    AceFlags: inheritance, AccessMask: 0x001f01ff
                } ace)
            {
                throw new SandboxPrivateRootException("private_root_permissions");
            }

            hasOwner |= ace.SecurityIdentifier.Equals(owner);
            hasSystem |= ace.SecurityIdentifier.Equals(system);
        }

        if (!hasOwner || !hasSystem)
        {
            throw new SandboxPrivateRootException("private_root_permissions");
        }
    }
}
