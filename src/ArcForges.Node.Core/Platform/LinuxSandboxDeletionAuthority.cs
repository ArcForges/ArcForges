// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>The startup-selected Linux storage authority for an administrator-provisioned, dedicated Node UID.</summary>
internal sealed class LinuxSandboxDeletionAuthority
{
    internal const string SelectionVariable = "ARCFORGES_LINUX_PROTECTED_STORAGE";
    internal const string ProvisioningStampName = "sandbox-deletion-provisioned.v1";

    private readonly WorkspaceObjectIdentity _dataIdentity;
    private readonly WorkspaceObjectIdentity _lockIdentity;
    private readonly uint _owner;
    private readonly byte[] _provisioningStamp;

    private LinuxSandboxDeletionAuthority(WorkspacePath anchor, WorkspaceObjectIdentity lockIdentity, uint owner)
    {
        DataRoot = anchor.RootPath;
        _dataIdentity = anchor.RootIdentity;
        _lockIdentity = lockIdentity;
        _owner = owner;
        _provisioningStamp = Encoding.ASCII.GetBytes(
            FormattableString.Invariant($"arcforges-sandbox-deletion-v1 {owner} {Convert.ToHexString(anchor.RootIdentity.InstanceToken.Span)} {Convert.ToHexString(lockIdentity.InstanceToken.Span)}\n"));
    }

    internal string DataRoot { get; }

    internal static LinuxSandboxDeletionAuthority? OpenIfProvisioned(string dataRoot)
    {
        const string prefix = "/var/lib/arcforges/";
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        var selection = Environment.GetEnvironmentVariable(SelectionVariable);
        if (string.IsNullOrEmpty(selection))
        {
            if (File.Exists(Path.Combine(dataRoot, ProvisioningStampName)))
            {
                throw new WorkspacePathException("linux_protected_storage_selection_required");
            }

            return null;
        }

        if (selection != "1" || !dataRoot.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new WorkspacePathException(WorkspacePath.LinuxSandboxDeletionGuardUnavailable);
        }

        var components = dataRoot[prefix.Length..].Split('/');
        if (components is not [var instance, "data"] || instance.Length is < 1 or > 64 ||
            !char.IsAsciiLetterOrDigit(instance[0]) ||
            !instance.All(static value => char.IsAsciiLetterOrDigit(value) || value is '-' or '_'))
        {
            throw new WorkspacePathException(WorkspacePath.LinuxSandboxDeletionGuardUnavailable);
        }

        var owner = WorkspacePath.GetLinuxCustodyPrincipal();
        using var anchor = WorkspacePath.OpenLinuxCustodyRoot(dataRoot, owner);
        using var lockFile = anchor.OpenLinuxCustodyLock(owner);
        return new LinuxSandboxDeletionAuthority(anchor, WorkspacePath.Identity(lockFile), owner);
    }

    [SupportedOSPlatform("linux")]
    internal SafeFileHandle OpenInstanceLock()
    {
        using var anchor = Reopen();
        return anchor.OpenLinuxCustodyLock(_owner, _lockIdentity);
    }

    [SupportedOSPlatform("linux")]
    internal void InitializeOrVerifyStore()
    {
        using var anchor = Reopen();
        using var lockFile = anchor.OpenLinuxCustodyLock(_owner, _lockIdentity);
        anchor.InitializeOrVerifyLinuxCustodyStamp(_owner, _provisioningStamp);
    }

    [SupportedOSPlatform("linux")]
    internal void RequirePath(WorkspacePath path)
    {
        using var anchor = Reopen();
        using var lockFile = anchor.OpenLinuxCustodyLock(_owner, _lockIdentity);
        anchor.VerifyLinuxCustodyStamp(_owner, _provisioningStamp);
        anchor.RequireLinuxCustodyPath(path);
    }

    [SupportedOSPlatform("linux")]
    private WorkspacePath Reopen()
    {
        if (WorkspacePath.GetLinuxCustodyPrincipal() != _owner)
        {
            throw new WorkspacePathException(WorkspacePath.LinuxSandboxDeletionGuardUnavailable);
        }

        return WorkspacePath.OpenLinuxCustodyRoot(DataRoot, _owner, _dataIdentity);
    }
}

internal sealed partial class WorkspacePath
{
    private const string LinuxCustodyRecordName = "sandbox-deletion-owner.v1";
    private const string LinuxCustodyStampStage = "sandbox-deletion-provisioned.stage";

    [SupportedOSPlatform("linux")]
    internal static uint GetLinuxCustodyPrincipal()
    {
        var owner = EffectiveUserId();
        using var proc = LinuxProcFdDirectory();
        var mapping = File.ReadAllText("/proc/self/uid_map").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (owner == 0 || mapping is not ["0", "0", "4294967295"])
        {
            throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
        }

        var ownerText = owner.ToString(CultureInfo.InvariantCulture);
        var identityChecked = false;
        var capabilitySets = 0;
        foreach (var line in File.ReadLines("/proc/thread-self/status"))
        {
            if (line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                var ids = line[4..].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                identityChecked = ids.Length == 4 && ids.All(id => id == ownerText);
            }
            else if (line.Length > 7 && line[..7] is "CapInh:" or "CapPrm:" or "CapEff:" or "CapAmb:")
            {
                if (!ulong.TryParse(line.AsSpan(7).Trim(), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var caps)
                    || caps != 0)
                {
                    throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
                }

                capabilitySets++;
            }
        }

        return identityChecked && capabilitySets == 4
            ? owner : throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
    }

    [SupportedOSPlatform("linux")]
    internal static WorkspacePath OpenLinuxCustodyRoot(string dataRoot, uint owner, WorkspaceObjectIdentity? expected = null)
    {
        var instancePath = Path.GetDirectoryName(dataRoot)!;
        using var slash = LinuxOpenSlash();
        RequireLinuxCustodyMode(slash, 0, file: false, exactPrivateMode: false);
        var relative = instancePath[1..].Split('/');
        for (var index = 1; index <= relative.Length; index++)
        {
            using var ancestor = LinuxOpenAt2(slash, string.Join('/', relative.AsSpan(0, index).ToArray()), noCrossMount: false);
            RequireLinuxCustodyMode(ancestor, 0, file: false, exactPrivateMode: false);
        }

        using var instance = OpenRoot(instancePath);
        RequireLinuxCustodyMode(instance.RootHandle, 0, file: false, exactPrivateMode: false);
        using var metadata = LinuxOpenAt2(instance.RootHandle, LinuxCustodyRecordName, noCrossMount: true);
        RequireLinuxCustodyMode(metadata, 0, file: true, exactPrivateMode: false);
        using var policy = LinuxReopenChecked(metadata, directory: false, instance._linuxFileSystemUuid, afterMetadataOpen: null);
        var contents = FormattableString.Invariant($"arcforges-sandbox-deletion-v1 {owner}\n");
        Span<byte> record = stackalloc byte[64];
        if (RandomAccess.GetLength(policy) != contents.Length ||
            RandomAccess.Read(policy, record[..contents.Length], 0) != contents.Length ||
            !record[..contents.Length].SequenceEqual(Encoding.ASCII.GetBytes(contents)))
        {
            throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
        }

        using var anchorMetadata = LinuxOpenAt2(instance.RootHandle, "data", noCrossMount: true);
        RequireLinuxCustodyMode(anchorMetadata, owner, file: false, exactPrivateMode: true);
        var instanceIdentity = instance.RootIdentity;
        var mount = instanceIdentity.High.ToString(CultureInfo.InvariantCulture);
        var mounts = File.ReadLines("/proc/self/mountinfo");
        if (!mounts.Any(line => line.StartsWith(mount + " ", StringComparison.Ordinal)
            && line.Split(" - ", 2, StringSplitOptions.None) is [_, var fileSystem]
            && fileSystem.StartsWith("ext4 ", StringComparison.Ordinal)))
        {
            throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
        }

        var named = LinuxIdentity(anchorMetadata, instance._linuxFileSystemUuid);
        if (expected is { } previous && !previous.SameObject(named))
        {
            throw new WorkspacePathException("directory_identity_changed");
        }

        return OpenRoot(dataRoot, named);
    }

    [SupportedOSPlatform("linux")]
    internal void InitializeOrVerifyLinuxCustodyStamp(uint owner, byte[] expected)
    {
        var parent = checked((int)RootHandle.DangerousGetHandle());
        try
        {
            VerifyLinuxCustodyStamp(owner, expected);
            // Retry the directory flush if a prior Node published the name but did not complete initialization.
            if (SyncDirectory(parent) != 0)
            {
                throw NativeFailure();
            }

            return;
        }
        catch (WorkspacePathException error) when (error.Reason == "native_2")
        {
            // A new profile starts with the dedicated lock only. A legacy store cannot be adopted by adding an owner record.
        }

        var entries = ReadLinuxSandboxDeleteNames(RootHandle, 3, CancellationToken.None);
        var stagedName = Encoding.ASCII.GetBytes(LinuxCustodyStampStage + '\0');
        var hasStage = entries.Any(entry => entry.AsSpan().SequenceEqual(stagedName));
        if (entries.Count != (hasStage ? 2 : 1) || !entries.Any(static entry => entry.AsSpan().SequenceEqual("node.lock\0"u8)))
        {
            throw new WorkspacePathException("linux_protected_storage_provenance_missing");
        }

        using var stage = OpenLinuxCustodyStampStage(owner, expected, parent, hasStage);
        RandomAccess.Write(stage, expected, 0);
        RandomAccess.FlushToDisk(stage);
        if (RenameRemovalAt(parent, LinuxCustodyStampStage, parent, LinuxSandboxDeletionAuthority.ProvisioningStampName, 1) != 0 ||
            SyncDirectory(parent) != 0)
        {
            throw NativeFailure();
        }
    }

    [SupportedOSPlatform("linux")]
    private SafeFileHandle OpenLinuxCustodyStampStage(uint owner, byte[] expected, int parent, bool hasStage)
    {
        if (hasStage)
        {
            using var metadata = LinuxOpenAt2(RootHandle, LinuxCustodyStampStage, noCrossMount: true);
            RequireLinuxCustodyMode(metadata, owner, file: true, exactPrivateMode: true);
            var existing = LinuxReopenChecked(metadata, directory: false, _linuxFileSystemUuid, afterMetadataOpen: null, writable: true);
            try
            {
                var length = RandomAccess.GetLength(existing);
                if (length > expected.Length)
                {
                    throw new WorkspacePathException("linux_protected_storage_provenance_changed");
                }

                Span<byte> prefix = stackalloc byte[checked((int)length)];
                if (RandomAccess.Read(existing, prefix, 0) != prefix.Length || !prefix.SequenceEqual(expected.AsSpan(0, prefix.Length)))
                {
                    throw new WorkspacePathException("linux_protected_storage_provenance_changed");
                }

                return existing;
            }
            catch
            {
                existing.Dispose();
                throw;
            }
        }

        const int createExclusiveNoFollow = 1 | 0x40 | 0x80 | 0x20000 | 0x80000;
        var descriptor = OpenAt(parent, LinuxCustodyStampStage, createExclusiveNoFollow, 0x180);
        if (descriptor < 0)
        {
            throw NativeFailure();
        }

        var stage = new SafeFileHandle(descriptor, ownsHandle: true);
        try
        {
            RequireLinuxCustodyMode(stage, owner, file: true, exactPrivateMode: true);
            return stage;
        }
        catch
        {
            stage.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("linux")]
    internal void VerifyLinuxCustodyStamp(uint owner, byte[] expected)
    {
        using var metadata = LinuxOpenAt2(RootHandle, LinuxSandboxDeletionAuthority.ProvisioningStampName, noCrossMount: true);
        RequireLinuxCustodyMode(metadata, owner, file: true, exactPrivateMode: true);
        using var stamp = LinuxReopenChecked(metadata, directory: false, _linuxFileSystemUuid, afterMetadataOpen: null);
        Span<byte> actual = stackalloc byte[expected.Length];
        if (RandomAccess.GetLength(stamp) != actual.Length || RandomAccess.Read(stamp, actual, 0) != actual.Length ||
            !actual.SequenceEqual(expected))
        {
            throw new WorkspacePathException("linux_protected_storage_provenance_changed");
        }
    }

    [SupportedOSPlatform("linux")]
    internal SafeFileHandle OpenLinuxCustodyLock(uint owner, WorkspaceObjectIdentity? expected = null)
    {
        using var metadata = LinuxOpenAt2(RootHandle, "node.lock", noCrossMount: true);
        RequireLinuxCustodyMode(metadata, owner, file: true, exactPrivateMode: true);
        if (expected is { } prior && !prior.SameObject(LinuxIdentity(metadata, _linuxFileSystemUuid)))
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        return LinuxReopenChecked(metadata, directory: false, _linuxFileSystemUuid, afterMetadataOpen: null, writable: true);
    }

    [SupportedOSPlatform("linux")]
    internal void RequireLinuxCustodyPath(WorkspacePath path)
    {
        var relative = Path.GetRelativePath(RootPath, path.RootPath);
        if (relative is not ("sandboxes" or "control" or "control/deletion-quarantine"))
        {
            throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
        }

        using var control = relative == "control/deletion-quarantine" ? LinuxOpenAt2(RootHandle, "control", noCrossMount: true) : null;
        if (control is not null)
        {
            RequireLinuxCustodyMode(control, EffectiveUserId(), file: false, exactPrivateMode: true);
        }

        using var named = LinuxOpenAt2(RootHandle, relative, noCrossMount: true);
        RequireLinuxCustodyMode(named, EffectiveUserId(), file: false, exactPrivateMode: true);
        var held = LinuxIdentity(path.RootHandle, _linuxFileSystemUuid);
        if (held.High != RootIdentity.High || held.Volume != RootIdentity.Volume ||
            !held.SameObject(path.RootIdentity) || !held.SameObject(LinuxIdentity(named, _linuxFileSystemUuid)))
        {
            throw new WorkspacePathException("directory_identity_changed");
        }
    }

    [SupportedOSPlatform("linux")]
    private static unsafe void RequireLinuxCustodyMode(SafeFileHandle handle, uint owner, bool file, bool exactPrivateMode)
    {
        const uint fields = 0x2 | 0x4 | 0x8; // statx mode, link count and UID.
        var stat = stackalloc byte[256];
        if (Statx(checked((int)handle.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, fields, stat) != 0)
        {
            throw NativeFailure();
        }

        var mode = *(ushort*)(stat + 28);
        var links = *(uint*)(stat + 16);
        if ((*(uint*)stat & fields) != fields || *(uint*)(stat + 20) != owner ||
            (mode & 0xf000) != (file ? 0x8000 : 0x4000) || links == 0 || (file && links != 1) ||
            (exactPrivateMode ? (mode & 0xfff) != (file ? 0x180 : 0x1c0) : (mode & 0x12) != 0))
        {
            throw new WorkspacePathException(LinuxSandboxDeletionGuardUnavailable);
        }
    }
}
