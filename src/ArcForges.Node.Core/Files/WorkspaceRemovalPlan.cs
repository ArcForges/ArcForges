// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Files;

/// <summary>A closed refusal from a metadata-only, handle-anchored removal plan.</summary>
internal sealed class WorkspaceRemovalPlanException(string reason, Exception? inner = null) : IOException(reason, inner)
{
    internal string Reason { get; } = reason;
}

/// <summary>The native evidence for one planned object. No file data is read or retained.</summary>
internal sealed record WorkspaceRemovalEntry(
    string Path,
    WorkspaceEntryType Kind,
    ulong Size,
    RegisteredWorkspaces.RootIdentity NativeIdentity,
    WorkspaceFileStamp Stamp,
    uint Mode,
    uint Links,
    byte[] IdentitySha256,
    byte[] FingerprintSha256);

internal sealed record WorkspaceRemovalSnapshot(
    RegisteredWorkspaces.RootIdentity RootIdentity,
    IReadOnlyList<WorkspaceRemovalEntry> Entries,
    ulong TotalBytes);

/// <summary>
/// Read-only planning for one exact object beneath an already authorized workspace. Checked directory handles are held
/// by the workspace use, and all names are opened without following links. Observable changes refuse the plan. This is
/// not a namespace lock and cannot authorize a cleanup effect; execution must independently meet the stricter guard.
/// </summary>
internal static class WorkspaceRemovalPlan
{
    internal const int MaximumDescendants = 1_000;
    internal const ulong MaximumTotalBytes = 67_108_864;

    internal static WorkspaceRemovalSnapshot Capture(WorkspacePath root, string path, CancellationToken cancellationToken = default) =>
        Capture(root, path, afterEnumeration: null, cancellationToken);

    // Coordinates changes to real test-owned entries. Production does not supply a callback.
    internal static WorkspaceRemovalSnapshot Capture(WorkspacePath root, string path, Action? afterEnumeration,
        CancellationToken cancellationToken) => CaptureCore(root, path, allowRoot: false, afterEnumeration, cancellationToken);

    /// <summary>
    /// Captures an already held directory only after its complete recorded identity matches the actual handle.
    /// Every descendant is subsequently resolved beneath that same handle; this does not authorize cleanup.
    /// </summary>
    internal static WorkspaceRemovalSnapshot CaptureCheckedRoot(WorkspacePath root, int platform, byte[] expectedIdentity,
        CancellationToken cancellationToken = default) =>
        CaptureCheckedRoot(root, platform, expectedIdentity, afterEnumeration: null, cancellationToken);

    // Test-owned coordination only, as for Capture above. Production never supplies this callback.
    internal static WorkspaceRemovalSnapshot CaptureCheckedRoot(WorkspacePath root, int platform, byte[] expectedIdentity,
        Action? afterEnumeration, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        VerifyCheckedRoot(root, platform, expectedIdentity);
        try
        {
            return CaptureCore(root, "", allowRoot: true, afterEnumeration, cancellationToken);
        }
        finally
        {
            // A budget/access/cancellation refusal must not classify an unverified or replaced target either.
            VerifyCheckedRoot(root, platform, expectedIdentity);
        }
    }

    /// <summary>A borrowed, read-only observation window. Dispose validates before the owning transaction can return.</summary>
    internal sealed class CheckedRootWindow : IDisposable
    {
        private readonly WorkspacePath _root;
        private readonly int _platform;
        private readonly byte[] _identity;
        internal CheckedRootWindow(WorkspacePath root, int platform, byte[] identity)
        {
            _root = root;
            _platform = platform;
            _identity = identity.ToArray();
            Verify();
        }
        internal Exception? FailedObservation { get; private set; }
        internal void Verify()
        {
            try { VerifyCheckedRoot(_root, _platform, _identity); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
            {
                FailedObservation = error;
                throw;
            }
        }
        public void Dispose()
        {
            // The first failed final observation already invalidated this window. Its caller can only refuse
            // or unwind; repeating that same failure must not overwrite a definite pre-insert refusal.
            if (FailedObservation is null) Verify();
        }
    }

    internal static void VerifyCheckedRoot(WorkspacePath root, int platform, byte[] expectedIdentity)
    {
        var held = WorkspacePath.Identity(root.RootHandle);
        var encoded = RegisteredWorkspaces.RootIdentity.Encode(held);
        if (!root.RootIdentity.SameObject(held) || encoded.Platform != platform ||
            !CryptographicOperations.FixedTimeEquals(encoded.Bytes, expectedIdentity))
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
        try
        {
            using var named = WorkspacePath.OpenRoot(root.RootPath, root.RootIdentity);
            if (!root.RootIdentity.SameObject(named.RootIdentity))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
        }
        catch (WorkspacePathException error) when (error.Reason is "root_changed" or "native_2" or "native_3" or "native_20" or "root_not_directory")
        {
            throw new WorkspaceRemovalPlanException("planned_tree_changed", error);
        }
    }

    private static WorkspaceRemovalSnapshot CaptureCore(WorkspacePath root, string path, bool allowRoot,
        Action? afterEnumeration, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(root);
        _ = WorkspacePath.Components(path, allowRoot);
        var entries = new List<(WorkspaceRemovalEntry Entry, WorkspaceEntryMetadata Native)>();
        var directories = new Dictionary<string, (string[] Names, SafeFileHandle Handle)>(StringComparer.Ordinal);
        var pending = new Stack<string>();
        pending.Push(path);
        ulong total = 0;
        while (pending.TryPop(out var current))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entries.Count >= MaximumDescendants + 1)
                throw new WorkspaceRemovalPlanException(root.HasPrivateStageFiles ? "file_access_denied" : "removal_descendants");
            WorkspaceEntryMetadata entry;
            try
            {
                entry = root.InspectEntry(current, allowRoot);
            }
            catch (WorkspacePathException exception) when (entries.Count > 0 && (exception.Reason is "native_2" or "native_3" or "native_20"))
            {
                throw new WorkspaceRemovalPlanException("planned_tree_changed", exception);
            }

            // Metadata is private too. Match the opened identity before type/link/size classification so a
            // renamed or hard-linked stage cannot appear in a plan or reveal its size through a limit error.
            if (root.IsPrivateStageFile(entry.Identity))
                throw new WorkspaceRemovalPlanException("file_access_denied");
            if (entry.Kind is not (WorkspaceEntryType.File or WorkspaceEntryType.Directory) ||
                entry.Kind == WorkspaceEntryType.File && entry.Identity.Links != 1 ||
                entry.Kind == WorkspaceEntryType.Directory && entry.Identity.Links == 0)
                throw new WorkspaceRemovalPlanException("path_link_or_special");

            var size = entry.Kind == WorkspaceEntryType.File
                ? entry.Size ?? throw new WorkspaceRemovalPlanException("file_metadata_unavailable")
                : 0UL;
            if (size > MaximumTotalBytes - total)
                throw new WorkspaceRemovalPlanException("removal_total_bytes");
            total += size;
            var encoded = RegisteredWorkspaces.RootIdentity.Encode(entry.Identity, directory: entry.Kind == WorkspaceEntryType.Directory);
            var identity = IdentityDigest(encoded);
            var fingerprint = Fingerprint(identity, entry);
            entries.Add((new WorkspaceRemovalEntry(current, entry.Kind, size, encoded, entry.Stamp, entry.Identity.Mode,
                entry.Identity.Links, identity, fingerprint), entry));

            if (entry.Kind != WorkspaceEntryType.Directory) continue;
            var handle = root.OpenDirectory(current);
            if (!entry.Identity.SameObject(WorkspacePath.Identity(handle)) || entry.Stamp != WorkspacePath.FileStamp(handle))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");

            var remaining = MaximumDescendants + 1 - entries.Count - pending.Count;
            var page = ReadDirectory(root, current, Math.Max(1, remaining), cancellationToken);
            // Unqualified child names may include a private alias; do not expose its contribution to this limit.
            if (page.Truncated || page.Names.Count > remaining)
                throw new WorkspaceRemovalPlanException(root.HasPrivateStageFiles ? "file_access_denied" : "removal_descendants");
            var names = page.Names.ToArray();
            directories.Add(current, (names, handle));
            for (var index = names.Length - 1; index >= 0; index--)
            {
                var child = current.Length == 0 ? names[index] : current + "/" + names[index];
                try { _ = WorkspacePath.Components(child); }
                catch (WorkspacePathException exception)
                {
                    throw new WorkspaceRemovalPlanException("path_enforcement_unavailable", exception);
                }

                pending.Push(child);
            }
        }

        afterEnumeration?.Invoke();
        foreach (var (item, original) in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WorkspaceEntryMetadata current;
            try
            {
                current = root.InspectEntry(item.Path, allowRoot);
            }
            catch (WorkspacePathException exception)
            {
                throw new WorkspaceRemovalPlanException("planned_tree_changed", exception);
            }

            if (root.IsPrivateStageFile(current.Identity))
                throw new WorkspaceRemovalPlanException("file_access_denied");
            if (current.Kind != original.Kind || !current.Identity.SameObject(original.Identity) ||
                current.Identity.Links != original.Identity.Links || current.Identity.Mode != original.Identity.Mode ||
                current.Stamp != original.Stamp || current.Size != original.Size)
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            if (current.Kind != WorkspaceEntryType.Directory) continue;
            var directory = directories[item.Path];
            if (!current.Identity.SameObject(WorkspacePath.Identity(directory.Handle)) ||
                current.Stamp != WorkspacePath.FileStamp(directory.Handle))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            var again = ReadDirectory(root, item.Path, Math.Max(1, directory.Names.Length), cancellationToken);
            if (again.Truncated || !directory.Names.SequenceEqual(again.Names, StringComparer.Ordinal))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
        }

        // The held anchor identifies the inspected tree, but its registered name may have moved while the plan
        // was read. Reopen that name with the existing no-follow root contract and require the same native identity.
        try
        {
            using var verifiedRoot = WorkspacePath.OpenRoot(root.RootPath, root.RootIdentity);
            if (!root.RootIdentity.SameObject(verifiedRoot.RootIdentity))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
        }
        catch (WorkspacePathException exception) when (exception.Reason is "root_changed" or "native_2" or "native_3" or "native_20")
        {
            throw new WorkspaceRemovalPlanException("planned_tree_changed", exception);
        }

        return new WorkspaceRemovalSnapshot(RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity),
            entries.Select(pair => pair.Entry).ToArray(), total);
    }

    private static WorkspaceDirectoryPage ReadDirectory(WorkspacePath root, string path, int maximum, CancellationToken cancellationToken)
    {
        try { return WorkspaceDirectoryEntries.Read(root, path, maximum, cancellationToken); }
        catch (WorkspacePathException exception) when (exception.Reason is "path_invalid" or "path_reserved" or "path_utf8_invalid")
        {
            // An existing child name is a filesystem observation, not an invalid caller-supplied target.
            throw new WorkspaceRemovalPlanException("path_enforcement_unavailable", exception);
        }
    }

    private static byte[] IdentityDigest(RegisteredWorkspaces.RootIdentity identity)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges removal-object identity v1\0"u8);
        Span<byte> platform = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(platform, identity.Platform);
        hash.AppendData(platform);
        hash.AppendData(identity.Bytes);
        return hash.GetHashAndReset();
    }

    private static byte[] Fingerprint(ReadOnlySpan<byte> identity, WorkspaceEntryMetadata entry)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges removal-object fingerprint v1\0"u8);
        hash.AppendData(identity);
        Span<byte> frame = stackalloc byte[40];
        BinaryPrimitives.WriteInt32BigEndian(frame[0..4], (int)entry.Kind);
        BinaryPrimitives.WriteUInt32BigEndian(frame[4..8], entry.Identity.Mode);
        BinaryPrimitives.WriteUInt32BigEndian(frame[8..12], entry.Identity.Links);
        BinaryPrimitives.WriteInt64BigEndian(frame[12..20], entry.Stamp.Size);
        BinaryPrimitives.WriteInt64BigEndian(frame[20..28], entry.Stamp.Modification);
        BinaryPrimitives.WriteUInt32BigEndian(frame[28..32], entry.Stamp.ModificationNanoseconds);
        BinaryPrimitives.WriteInt64BigEndian(frame[32..40], entry.Stamp.Change);
        hash.AppendData(frame);
        Span<byte> nanos = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(nanos, entry.Stamp.ChangeNanoseconds);
        hash.AppendData(nanos);
        return hash.GetHashAndReset();
    }
}
