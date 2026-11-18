// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    // Owners and principals trusted to maintain the node installation. Read access to an installation
    // is permitted; replacement, write and security-descriptor rights are restricted.
    internal static void CheckMxcTrustedObject(SafeFileHandle handle, bool ancestor = false, bool systemOnly = false)
    {
        if (OperatingSystem.IsWindows())
        {
            CheckMxcWindowsAcl(handle, ancestor);
        }
        else if (OperatingSystem.IsLinux())
        {
            CheckMxcLinuxMode(handle, systemOnly);
        }
        else
        {
            throw new WorkspacePathException("mxc_installation_protection_unavailable");
        }
    }


    internal static string CanonicalMxcGrantPath(SafeFileHandle target, string requestedPath)
    {
        if (OperatingSystem.IsWindows())
        {
            return FinalPath(target, requestedPath);
        }

        using var proc = LinuxProcFdDirectory();
        var descriptor = target.DangerousGetHandle().ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var bytes = new byte[16_384];
        var count = ReadLinkAt(checked((int)proc.DangerousGetHandle()), descriptor, bytes, (nuint)bytes.Length);
        if (count <= 0 || count >= bytes.Length)
        {
            throw new WorkspacePathException("canonical_path_unavailable");
        }

        return StrictUtf8.GetString(bytes, 0, checked((int)count));
    }

    [SupportedOSPlatform("linux")]
    internal static uint MxcEffectiveUserId() => EffectiveUserId();

    [SupportedOSPlatform("linux")]
    private static unsafe void CheckMxcLinuxMode(SafeFileHandle handle, bool systemOnly)
    {
        const uint required = 0x0a; // STATX_UID | STATX_MODE
        var buffer = stackalloc byte[256];
        if (Statx(checked((int)handle.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, required, buffer) != 0
            || (*(uint*)buffer & required) != required)
        {
            throw new WorkspacePathException("mxc_installation_protection_unavailable");
        }

        var uid = *(uint*)(buffer + 20);
        var mode = *(ushort*)(buffer + 28);
        if ((uid != 0 && (systemOnly || uid != EffectiveUserId())) || (mode & 0x12) != 0)
        {
            throw new WorkspacePathException("mxc_installation_unprotected");
        }
    }

    [SupportedOSPlatform("windows")]
    private static unsafe void CheckMxcWindowsAcl(SafeFileHandle handle, bool ancestor)
    {
        const string trustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        using var current = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = current.User ?? throw new WorkspacePathException("mxc_installation_protection_unavailable");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var installer = new SecurityIdentifier(trustedInstallerSid);
        bool TrustedSid(nint identity)
        {
            if (!IsValidSid(identity))
            {
                return false;
            }

            var sid = new SecurityIdentifier(identity);
            return sid == principal || sid == system || sid == administrators || sid == installer;
        }

        using var security = OpenWindowsReadControl(handle, "mxc_installation_protection_unavailable");

        var error = GetSecurityInfo(security, 1, 5, out var owner, out _, out var dacl, out _, out var descriptor);
        if (error != 0 || descriptor == 0 || owner == 0 || dacl == 0)
        {
            if (descriptor != 0) _ = LocalFree(descriptor);
            throw new WorkspacePathException("mxc_installation_protection_unavailable");
        }

        try
        {
            if (!TrustedSid(owner) || !IsValidAcl(dacl)
                || !GetAclInformation(dacl, out var information, (uint)sizeof(AclSizeInformation), 2))
            {
                throw new WorkspacePathException("mxc_installation_unprotected");
            }

            // A protected existing child cannot be replaced merely by adding a different child
            // to its ancestor. The actual installation directory cannot grant those rights.
            const uint genericWriteOrAll = 0x50000000;
            const uint changeOwnerDaclOrDelete = 0x000d0040;
            const uint changeEntryContentOrAttributes = 0x00000116;
            var writable = genericWriteOrAll | changeOwnerDaclOrDelete | (ancestor ? 0u : changeEntryContentOrAttributes);

            for (uint index = 0; index < information.AceCount; index++)
            {
                if (!GetAce(dacl, index, out var rawAce) || rawAce == 0)
                {
                    throw new WorkspacePathException("mxc_installation_protection_unavailable");
                }

                var ace = (byte*)rawAce;
                if (ace[0] is not (0 or 5 or 9 or 11) || (ace[1] & 0x08) != 0)
                {
                    continue;
                }

                var size = *(ushort*)(ace + 2);
                if (size < 8)
                {
                    throw new WorkspacePathException("mxc_installation_protection_unavailable");
                }

                if ((*(uint*)(ace + 4) & writable) != 0
                    && (ace[0] != 0 || size < 16 || !TrustedSid((nint)(ace + 8))))
                {
                    throw new WorkspacePathException("mxc_installation_unprotected");
                }
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }
}
