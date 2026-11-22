// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal readonly record struct SandboxRemovalBatchResult(int Removed, bool RootAbsent);

internal sealed partial class WorkspacePath
{
    private const int SandboxRemovalScanLimit = 10_000;
    private const int SandboxRemovalPageSize = 64;
    private const uint SandboxRemovalDeleteAccess = 0x80130080; // GENERIC_READ | DELETE | READ_CONTROL | SYNCHRONIZE | READ_ATTRIBUTES

    /// <summary>Checks deterministic Windows delete prerequisites on this held private parent before admission.</summary>
    [SupportedOSPlatform("windows")]
    internal unsafe void RequireSandboxDeleteWindowsGuard()
    {
        if (IntPtr.Size != 8)
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }

        CheckWindowsSandboxRemovalParent();
        uint caseFlags;
        if (!GetCaseInformation(RootHandle, 23, &caseFlags, sizeof(uint)))
        {
            throw new WorkspacePathException("case_semantics_unavailable");
        }
    }

    /// <summary>Quarantines the exact recorded root by its DELETE handle and the retained destination parent.</summary>
    [SupportedOSPlatform("windows")]
    internal unsafe WorkspaceObjectIdentity QuarantineSandboxWindows(string name, WorkspacePath quarantine,
        string quarantineName, WorkspaceObjectIdentity expected, Action applied, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(quarantine);
        ArgumentNullException.ThrowIfNull(applied);
        CheckWindowsSandboxRemovalParent();
        quarantine.CheckWindowsSandboxRemovalParent();
        RequireWindowsSandboxRemovalComponent(name);
        RequireWindowsSandboxRemovalComponent(quarantineName);
        if (IntPtr.Size != 8 || !expected.IsDirectory || expected.Links == 0 ||
            expected.Volume != RootIdentity.Volume || expected.Volume != quarantine.RootIdentity.Volume ||
            RootIdentity.SameObject(quarantine.RootIdentity))
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }

        cancellationToken.ThrowIfCancellationRequested();
        RequireWindowsSandboxRemovalNameAbsent(quarantine.RootHandle, quarantineName);
        var owner = ReadWindowsSandboxRemovalOwner();
        using var source = OpenWindowsSandboxRemovalLease(RootHandle, name, expected, owner, flushAccess: true);
        var targetParent = quarantine.RootHandle;
        int length = Encoding.Unicode.GetByteCount(quarantineName);
        var rename = new byte[checked(24 + length)];
        _ = Encoding.Unicode.GetBytes(quarantineName, rename.AsSpan(20, length));
        var retained = false;
        try
        {
            targetParent.DangerousAddRef(ref retained);
            cancellationToken.ThrowIfCancellationRequested();
            CheckWindowsSandboxRemovalLease(RootHandle, name, expected, owner, source);
            fixed (byte* buffer = rename)
            {
                // FILE_RENAME_INFORMATION with ReplaceIfExists=false and a single component relative to the held parent.
                *(nint*)(buffer + 8) = targetParent.DangerousGetHandle();
                *(uint*)(buffer + 16) = checked((uint)length);
                RequireWindowsSandboxDataStatus(SetRemovalInformation(source, out _, buffer, (uint)rename.Length, 10));
            }

            applied();
            RequireWindowsSandboxDataStatus(FlushRemovalBuffers(source, out _));
            CheckWindowsSandboxRemovalParent();
            quarantine.CheckWindowsSandboxRemovalParent();
            RequireWindowsSandboxRemovalNameAbsent(RootHandle, name);
            var moved = ReadWindowsSandboxRemovalName(targetParent, quarantineName);
            if (!expected.SameObject(moved) || !moved.IsDirectory || moved.Links == 0)
            {
                throw new WorkspacePathException("file_identity_changed");
            }

            return moved;
        }
        finally
        {
            if (retained)
            {
                targetParent.DangerousRelease();
            }
        }
    }

    /// <summary>Removes a bounded postorder batch under the exact private quarantined root.</summary>
    [SupportedOSPlatform("windows")]
    internal SandboxRemovalBatchResult RemoveSandboxQuarantineBatchWindows(string name, WorkspaceObjectIdentity expected,
        int maximumEntries, Action applied, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(applied);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumEntries, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumEntries, SandboxRemovalScanLimit);
        CheckWindowsSandboxRemovalParent();
        RequireWindowsSandboxRemovalComponent(name);
        if (!expected.IsDirectory || expected.Links == 0 || expected.Volume != RootIdentity.Volume)
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var owner = ReadWindowsSandboxRemovalOwner();
        var pending = new Stack<WindowsSandboxRemovalDirectory>();
        int removed = 0;
        int remaining = SandboxRemovalScanLimit;
        try
        {
            pending.Push(new(RootHandle, name, expected,
                OpenWindowsSandboxRemovalLease(RootHandle, name, expected, owner, flushAccess: false, shareTraversalReads: false)));
            while (pending.TryPeek(out var current) && removed < maximumEntries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (remaining <= 1)
                {
                    if (removed != 0)
                    {
                        break;
                    }

                    throw new WorkspacePathException("directory_enumeration_limit");
                }

                if (current.Names.Count == 0)
                {
                    CheckWindowsSandboxRemovalLease(current.Parent, current.Name, current.Identity, owner, current.Handle);
                    var listing = WorkspaceDirectoryEntries.ReadWindowsSandboxRemoval(current.Handle,
                        Math.Min(remaining - 1, SandboxRemovalPageSize), cancellationToken);
                    remaining -= listing.Names.Count + 1;
                    if (listing.Names.Count == 0)
                    {
                        // Give disposition a fresh lease on the same directory after closing its enumeration handle.
                        pending.Pop().Dispose();
                        cancellationToken.ThrowIfCancellationRequested();
                        using (var removal = OpenWindowsSandboxRemovalLease(current.Parent, current.Name,
                            current.Identity, owner, flushAccess: false, dispositionOnly: true))
                        {
                            SetWindowsSandboxRemovalDisposition(current.Parent, current.Name,
                                current.Identity, owner, removal, applied, cancellationToken);
                        }
                        RequireWindowsSandboxRemovalNameAbsent(current.Parent, current.Name);
                        removed++;
                        continue;
                    }

                    foreach (string entryName in listing.Names)
                    {
                        current.Names.Enqueue(entryName);
                    }
                }

                while (removed < maximumEntries && remaining > 1 && current.Names.TryDequeue(out string? childName))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    remaining--;
                    var child = ReadWindowsSandboxRemovalName(current.Handle, childName);
                    var childHandle = OpenWindowsSandboxRemovalLease(current.Handle, childName, child, owner, flushAccess: false);
                    if (child.IsDirectory)
                    {
                        pending.Push(new(current.Handle, childName, child, childHandle));
                        break;
                    }

                    using (childHandle)
                    {
                        SetWindowsSandboxRemovalDisposition(current.Handle, childName, child, owner, childHandle, applied,
                            cancellationToken);
                    }

                    RequireWindowsSandboxRemovalNameAbsent(current.Handle, childName);
                    removed++;
                }
            }

            CheckWindowsSandboxRemovalParent();
            return new SandboxRemovalBatchResult(removed, pending.Count == 0);
        }
        finally
        {
            while (pending.TryPop(out var directory))
            {
                directory.Dispose();
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private void CheckWindowsSandboxRemovalParent()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var current = Identity(RootHandle);
        if (!current.IsDirectory || current.Links == 0 || !RootIdentity.SameObject(current) || !WindowsStageIsNtfs(RootHandle))
        {
            throw new WorkspacePathException("directory_identity_changed");
        }

        CheckSandboxDirectory(RootHandle, configuredRoot: false);
    }

    private static void RequireWindowsSandboxRemovalComponent(string name)
    {
        if (Components(name).Length != 1)
        {
            throw new WorkspacePathException("path_invalid");
        }
    }

    private static WorkspaceObjectIdentity ReadWindowsSandboxRemovalName(SafeFileHandle parent, string name)
    {
        RequireWindowsSandboxRemovalComponent(name);
        var parentId = Identity(parent);
        using var entry = OpenWindowsEntryMetadata(parent, name);
        var observed = Identity(entry);
        if (!parentId.IsDirectory || parentId.Links == 0 || observed.Volume != parentId.Volume ||
            !(observed.IsDirectory && observed.Links != 0 || observed.IsFile && observed.Links == 1))
        {
            throw new WorkspacePathException("path_link_or_special");
        }

        return observed;
    }

    private static void RequireWindowsSandboxRemovalNameAbsent(SafeFileHandle parent, string name)
    {
        try
        {
            using var entry = OpenWindowsEntryMetadata(parent, name);
        }
        catch (WorkspacePathException failure) when (failure.Reason == "native_2")
        {
            return;
        }

        throw new WorkspacePathException("file_identity_changed");
    }

    [SupportedOSPlatform("windows")]
    private static unsafe SafeFileHandle OpenWindowsSandboxRemovalLease(SafeFileHandle parent, string name,
        WorkspaceObjectIdentity expected, byte[] owner, bool flushAccess, bool dispositionOnly = false, bool shareTraversalReads = true)
    {
        var before = ReadWindowsSandboxRemovalName(parent, name);
        if (!MatchesWindowsSandboxRemovalIdentity(expected, before))
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        uint caseFlags;
        if (!GetCaseInformation(parent, 23, &caseFlags, sizeof(uint)))
        {
            throw new WorkspacePathException("case_semantics_unavailable");
        }

        var retained = false;
        try
        {
            parent.DangerousAddRef(ref retained);
            fixed (char* text = name)
            {
                ushort length = checked((ushort)(name.Length * sizeof(char)));
                var unicode = new UnicodeString { Length = length, MaximumLength = length, Buffer = (nint)text };
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = (nint)(&unicode),
                    Attributes = (caseFlags & 1) == 0 ? 0x40u : 0u,
                };
                // Traversal pins its directory without delete access. Mutation uses a separate exclusive lease.
                bool traversal = expected.IsDirectory && !flushAccess && !dispositionOnly;
                uint access = traversal ? 0x00120081u : dispositionOnly ? 0x00130080u
                    : SandboxRemovalDeleteAccess | (flushAccess ? 0x40000000u : 0u);
                uint sharing = traversal && shareTraversalReads ? 1u : 0u; // FILE_SHARE_READ; the selected root stays exclusive.
                uint options = 0x00200020u | (expected.IsDirectory ? 1u : 0x40u) | (flushAccess ? 2u : 0u);
                RequireWindowsSandboxDataStatus(NtCreateFile(out var raw, access, ref attributes, out _, 0,
                    0, sharing, 1, options, 0, 0));
                var opened = new SafeFileHandle(raw, ownsHandle: true);
                try
                {
                    CheckWindowsSandboxRemovalLease(parent, name, expected, owner, opened);
                    return opened;
                }
                catch
                {
                    opened.Dispose();
                    throw;
                }
            }
        }
        finally
        {
            if (retained)
            {
                parent.DangerousRelease();
            }
        }
    }

    private static bool MatchesWindowsSandboxRemovalIdentity(WorkspaceObjectIdentity expected, WorkspaceObjectIdentity observed) =>
        expected.SameObject(observed) && expected.Mode == observed.Mode && expected.Links == observed.Links;

    private static void CheckWindowsSandboxRemovalLease(SafeFileHandle parent, string name,
        WorkspaceObjectIdentity expected, byte[] owner, SafeFileHandle file)
    {
        if (!MatchesWindowsSandboxRemovalIdentity(expected, Identity(file)) ||
            !MatchesWindowsSandboxRemovalIdentity(expected, ReadWindowsSandboxRemovalName(parent, name)))
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        RequireWindowsSandboxRemovalOwner(file, owner);
    }

    private static unsafe void SetWindowsSandboxRemovalDisposition(SafeFileHandle parent, string name,
        WorkspaceObjectIdentity expected, byte[] owner, SafeFileHandle file, Action applied, CancellationToken cancellationToken)
    {
        CheckWindowsSandboxRemovalLease(parent, name, expected, owner, file);
        if (expected.IsFile)
        {
            WorkspaceWriteGuard.RequireWindowsSandboxDataNoMappings(file);
        }

        cancellationToken.ThrowIfCancellationRequested();
        // The kernel accepts an ordinary directory only when empty. Close the marked handle before confirming absence.
        if (expected.IsDirectory)
        {
            uint flags = 1; // FILE_DISPOSITION_DELETE
            RequireWindowsSandboxDataStatus(SetRemovalInformation(file, out _, &flags, sizeof(uint), 64)); // FileDispositionInformationEx
        }
        else
        {
            byte delete = 1;
            RequireWindowsSandboxDataStatus(SetRemovalInformation(file, out _, &delete, sizeof(byte), 13));
        }
        applied();
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ReadWindowsSandboxRemovalOwner()
    {
        using var principal = System.Security.Principal.WindowsIdentity.GetCurrent();
        var user = principal.User ?? throw new WorkspacePathException("file_guard_unavailable");
        var owner = new byte[user.BinaryLength];
        user.GetBinaryForm(owner, 0);
        return owner;
    }

    private static unsafe void RequireWindowsSandboxRemovalOwner(SafeFileHandle file, byte[] expected)
    {
        uint error = GetSecurityInfo(file, 1, 1, out nint owner, out _, out _, out _, out nint descriptor);
        try
        {
            if (error != 0)
            {
                throw new WorkspacePathException("native_" + error.ToString(CultureInfo.InvariantCulture));
            }

            fixed (byte* sid = expected)
            {
                if (descriptor == 0 || owner == 0 || !IsValidSid(owner) || !EqualSid(owner, (nint)sid))
                {
                    throw new WorkspacePathException("file_guard_unavailable");
                }
            }
        }
        finally
        {
            if (descriptor != 0)
            {
                _ = LocalFree(descriptor);
            }
        }
    }

    private sealed class WindowsSandboxRemovalDirectory(SafeFileHandle parent, string name, WorkspaceObjectIdentity identity,
        SafeFileHandle handle) : IDisposable
    {
        internal SafeFileHandle Parent { get; } = parent;
        internal string Name { get; } = name;
        internal WorkspaceObjectIdentity Identity { get; } = identity;
        internal SafeFileHandle Handle { get; } = handle;
        internal Queue<string> Names { get; } = new();

        public void Dispose() => Handle.Dispose();
    }
}

internal static partial class WorkspaceDirectoryEntries
{
    internal static WorkspaceDirectoryPage ReadWindowsSandboxRemoval(SafeFileHandle directory, int maximum,
        CancellationToken cancellationToken)
    {
        var identity = WorkspacePath.Identity(directory);
        var stamp = WorkspacePath.FileStamp(directory);
        var names = new List<string>();
        bool truncated = WindowsRead(directory, names, maximum, cancellationToken);
        if (!identity.SameObject(WorkspacePath.Identity(directory)) || stamp != WorkspacePath.FileStamp(directory))
        {
            throw new WorkspacePathException("directory_changed");
        }

        names.Sort(StringComparer.Ordinal);
        return new WorkspaceDirectoryPage(names, truncated);
    }
}
