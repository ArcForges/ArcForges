// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Creates a previously absent direct child directory and returns the handle from that exact native create.
    /// This is provenance evidence only: it does not establish cleanup authority or a whole-tree guard.
    /// </summary>
    internal unsafe SafeFileHandle CreateWindowsAttemptDirectory(string name)
    {
        if (!OperatingSystem.IsWindows()) throw new WorkspacePathException("directory_identity_unavailable");
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Components(name).Length != 1) throw new WorkspacePathException("path_invalid");
        var parent = RootHandle;
        uint flags;
        if (!GetCaseInformation(parent, 23, &flags, sizeof(uint)))
            throw new WorkspacePathException("case_semantics_unavailable");

        SafeFileHandle? created = null;
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
                parent.DangerousAddRef(ref retained);
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = (nint)(&unicode),
                    Attributes = (flags & 1) == 0 ? 0x40u : 0u,
                };
                // FILE_CREATE, FILE_DIRECTORY_FILE, FILE_WRITE_THROUGH, synchronous and open-reparse-point.
                // No FILE_SHARE_DELETE is granted while the exact created handle is recorded.
                var status = NtCreateFile(out var raw, 0x00100081u, ref attributes, out _, 0, 0x10u, 3u, 2u,
                    0x00200023u, 0, 0);
                if (status < 0)
                    throw new WorkspacePathException("native_" + RtlNtStatusToDosError(status).ToString(CultureInfo.InvariantCulture));
                created = new SafeFileHandle(raw, ownsHandle: true);
            }
            finally
            {
                if (retained) parent.DangerousRelease();
            }
        }

        try
        {
            var file = created ?? throw new InvalidOperationException("The native directory handle is unavailable.");
            var identity = Identity(file);
            var named = InspectEntry(name);
            if (!identity.IsDirectory || identity.Links == 0 || identity.Volume != RootIdentity.Volume ||
                named.Kind != WorkspaceEntryType.Directory || !identity.SameObject(named.Identity))
                throw new WorkspacePathException("directory_identity_unavailable");
            created = null;
            return file;
        }
        finally
        {
            created?.Dispose();
        }
    }
}
