// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>The native exclusive create observed an occupied name and created no object.</summary>
internal sealed class WorkspaceCreateCollisionException(WorkspaceObjectIdentity parent, string relativePath,
    RegisteredWorkspaces.RootIdentity stageIdentity) : IOException("The requested absent name is already occupied.")
{
    internal WorkspaceObjectIdentity Parent { get; } = parent;
    internal string RelativePath { get; } = relativePath;
    internal RegisteredWorkspaces.RootIdentity StageIdentity { get; } = stageIdentity;
}

/// <summary>The native create may have taken effect; the coordinator must retain its journal and report UNKNOWN.</summary>
internal sealed class WorkspaceCreateUncertainException(Exception inner)
    : IOException("The exclusive file creation did not complete with a verified identity.", inner);

/// <summary>
/// Owns the exact newly created guarded handle, including an original Linux OFD returned by its owned worker.
/// This object is a native building block, not authority,
/// a journal, a receipt, or a public endpoint.
/// </summary>
internal sealed class WorkspaceCreatedTarget(WorkspaceWriteGuard guard) : IDisposable
{
    internal WorkspaceWriteGuard Guard { get; } = guard;
    internal WorkspaceObjectIdentity Identity => Guard.ObjectIdentity;
    public void Dispose() => Guard.Dispose();
}

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Atomically creates only a previously absent final name relative to its verified parent, without replacement,
    /// retaining the newly created object under a no-sharing handle. A coordinator must durably record PREPARED,
    /// independently establish caller authorization and recheck its deadline before calling this method; creation
    /// itself is an effect. The intended stage is rehashed and guarded before that effect.
    /// </summary>
    internal WorkspaceCreatedTarget CreateWindowsNewTarget(string path, WorkspaceObjectIdentity preparedParent,
        WorkspaceMutationStage intended, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new WorkspacePathException("file_guard_unavailable");
        return CreateWindowsNewTarget(path, preparedParent, intended, afterChecks: null, cancellationToken);
    }

    // The callback coordinates a real competing create in a test-owned directory; production passes null.
    internal WorkspaceCreatedTarget CreateWindowsNewTarget(string path, WorkspaceObjectIdentity preparedParent,
        WorkspaceMutationStage intended, Action? afterChecks, CancellationToken cancellationToken) =>
        CreateWindowsNewTarget(path, preparedParent, intended, afterChecks, beforeEffect: null, cancellationToken);

    internal unsafe WorkspaceCreatedTarget CreateWindowsNewTarget(string path, WorkspaceObjectIdentity preparedParent,
        WorkspaceMutationStage intended, Action? afterChecks, Action? beforeEffect, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new WorkspacePathException("file_guard_unavailable");
        ArgumentNullException.ThrowIfNull(intended);
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path);
        var parents = new List<(string Name, WorkspaceObjectIdentity Identity)>();
        for (var index = 1; index < parts.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var prefix = string.Join('/', parts.AsSpan(0, index).ToArray());
            var directory = OpenDirectory(prefix);
            var identity = Identity(directory);
            if (!identity.IsDirectory || identity.Links == 0) throw new WorkspacePathException("directory_identity_changed");
            parents.Add((prefix, identity));
        }

        var parent = parents.Count == 0 ? RootHandle : OpenDirectory(parents[^1].Name);
        var parentIdentity = Identity(parent);
        if (!parentIdentity.IsDirectory || !preparedParent.SameObject(parentIdentity) || parentIdentity.Links == 0)
            throw new WorkspacePathException("parent_identity_changed");

        void CheckNames(WorkspaceObjectIdentity? created)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var root = Identity(RootHandle);
            if (!root.IsDirectory || root.Links == 0 || !RootIdentity.SameObject(root))
                throw new WorkspacePathException("root_changed");
            using var namedRoot = OpenRoot(RootPath, RootIdentity);
            foreach (var (name, original) in parents)
            {
                var entry = InspectEntry(name);
                if (entry.Kind != WorkspaceEntryType.Directory || !original.SameObject(entry.Identity))
                    throw new WorkspacePathException("directory_identity_changed");
            }
            if (!preparedParent.SameObject(Identity(parent)))
                throw new WorkspacePathException("parent_identity_changed");
            if (created is { } target)
            {
                var entry = InspectEntry(path);
                if (entry.Kind != WorkspaceEntryType.File || entry.Identity.Links != 1 || !target.SameObject(entry.Identity))
                    throw new WorkspacePathException("file_identity_changed");
            }
        }

        // The stage bytes are not stored in the journal; its exact held handle is rehashed before any target effect.
        using var verifiedStage = intended.ReadVerified(cancellationToken);
        if (intended.ObjectIdentity.Volume != RootIdentity.Volume)
            throw new WorkspacePathException("file_guard_unavailable");
        CheckNames(created: null);
        intended.CheckIntact();
        cancellationToken.ThrowIfCancellationRequested();
        uint caseFlags;
        if (!GetCaseInformation(parent, 23, &caseFlags, sizeof(uint)))
            throw new WorkspacePathException("case_semantics_unavailable");

        SafeFileHandle? file = null;
        WorkspaceWriteGuard? guard = null;
        var possibleEffect = false;
        try
        {
            afterChecks?.Invoke();
            beforeEffect?.Invoke();
            CheckNames(created: null);
            intended.CheckIntact();
            cancellationToken.ThrowIfCancellationRequested();
            var name = parts[^1];
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
                        Attributes = (caseFlags & 1) == 0 ? 0x40u : 0u,
                    };
                    // A syscall which began may have an effect even if its result is unavailable. The documented
                    // FILE_CREATE collision is the one explicit no-create result recognized below.
                    possibleEffect = true;
                    var status = NtCreateFile(out var raw, 0xC0120000u, ref attributes, out _, 0, 0x20u, 0u, 2u,
                        0x20u | 0x40u | 0x00200000u, 0, 0);
                    if (status == unchecked((int)0xC0000035u))
                        throw new WorkspaceCreateCollisionException(parentIdentity, path, intended.Identity);
                    if (status < 0) throw new WorkspacePathException("file_access_denied");
                    file = new SafeFileHandle(raw, ownsHandle: true);
                }
                finally
                {
                    if (retained) parent.DangerousRelease();
                }
            }

            var created = Identity(file);
            if (!created.IsFile || created.Links != 1 || created.Volume != RootIdentity.Volume || RandomAccess.GetLength(file) != 0)
                throw new WorkspacePathException("file_identity_changed");
            guard = WorkspaceWriteGuard.Acquire(file);
            file = null;
            guard.CheckIntact();
            intended.CheckIntact();
            CheckNames(created);
            var result = new WorkspaceCreatedTarget(guard);
            guard = null;
            return result;
        }
        catch (WorkspaceCreateCollisionException)
        {
            throw;
        }
        catch (Exception exception) when (possibleEffect && exception is not OutOfMemoryException and not StackOverflowException)
        {
            throw new WorkspaceCreateUncertainException(exception);
        }
        finally
        {
            guard?.Dispose();
            file?.Dispose();
        }
    }
}
