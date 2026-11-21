// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Sandboxes;

/// <summary>The Node's private backing directory for one durable Sandbox.</summary>
internal sealed record SandboxPrivateRoot(string RelativePath, string Identity);

/// <summary>Ownership refusal, with the exact newly created root when it can be journaled after partial creation.</summary>
internal sealed class SandboxPrivateRootException(string reason, SandboxPrivateRoot? partialRoot = null, Exception? inner = null)
    : IOException(reason, inner)
{
    internal string Reason { get; } = reason;

    internal SandboxPrivateRoot? PartialRoot { get; } = partialRoot;
}

/// <summary>Retains validated directory handles while the caller holds the Sandbox ownership guard.</summary>
internal sealed class SandboxPrivateRootLease(WorkspacePath dataRoot, WorkspacePath parent, WorkspacePath root,
    IReadOnlyList<string> writablePaths) : IDisposable
{
    internal string RootPath => root.RootPath;

    internal WorkspacePath OwnedWorkspace => root;

    internal WorkspacePath OwnedParent => parent;

    internal WorkspacePath OwnedAnchor => dataRoot;

    internal void ReleaseOwnedRoot()
    {
        root.Dispose();
        // Release the original child lookup while retaining the verified parent for the native mutation.
        parent.EndRemovalTraversal();
    }

    internal WorkspacePath OpenTransferStaging() => SandboxPrivateRoots.OpenTransferStaging(dataRoot);

    internal IReadOnlyList<string> WritablePaths { get; } = writablePaths;

    public void Dispose()
    {
        root.Dispose();
        parent.Dispose();
        dataRoot.Dispose();
    }
}

/// <summary>Creates and reopens private Sandbox data without using a display name or accepting a preexisting root.</summary>
internal sealed class SandboxPrivateRoots(string dataRoot, LinuxSandboxDeletionAuthority? linuxDeletionAuthority = null)
    : ISandboxDeletionEffects
{
    private const string ParentName = "sandboxes";
    internal const string DeletionQuarantineName = "deletion-quarantine";
    private static readonly string[] WritableNames = ["home", "config", "cache", "tmp", "work", "data"];
    internal static IReadOnlyList<string> OwnedDataDirectoryNames { get; } = Array.AsReadOnly(WritableNames);
    private static readonly string[] ProtectedDirectories = ["store", "control", "credentials"];

    public void RequireFreshDeletion(string sandboxId, string originalIdentity)
    {
        using var held = Inspect(sandboxId, originalIdentity);
        RequireDeletionPlatform(held, sandboxId);
    }

    public void RequireDeletionContinuation(string sandboxId, string originalIdentity, string deletionId, string? quarantineIdentity)
    {
        using var held = InspectDeletion(sandboxId, originalIdentity, deletionId, quarantineIdentity);
        RequireDeletionPlatform(held, quarantineIdentity is null ? sandboxId : deletionId);
    }

    private void RequireDeletionPlatform(SandboxPrivateRootLease held, string name)
    {
        if (OperatingSystem.IsWindows())
        {
            held.OwnedParent.RequireSandboxDeleteWindowsGuard();
            return;
        }

        if (OperatingSystem.IsLinux())
        {
            if (linuxDeletionAuthority is { } authority)
            {
                using var control = held.OwnedAnchor.OpenSandboxDirectory("control", configuredRoot: true);
                authority.RequirePath(control);
                WorkspacePath? quarantine = null;
                try
                {
                    quarantine = control.OpenSandboxDirectory(DeletionQuarantineName);
                }
                catch (WorkspacePathException error) when (WorkspacePath.IsMissingRemovalEntry(error))
                {
                    // A fresh store may not have created quarantine yet. The worker creates it under this checked control directory.
                }

                using (quarantine)
                {
                    if (quarantine is not null)
                    {
                        authority.RequirePath(quarantine);
                    }
                }

                held.OwnedParent.RequireAdmittedSandboxDeleteLinuxGuard(name, held.OwnedWorkspace.RootIdentity, authority);
            }
            else
            {
                held.OwnedParent.RequireSandboxDeleteLinuxGuard(name, held.OwnedWorkspace.RootIdentity);
            }

            return;
        }

        throw new WorkspacePathException("path_enforcement_unavailable");
    }

    private LinuxSandboxDeletionAuthority RequireLinuxDeletionAuthority() => linuxDeletionAuthority
        ?? throw new WorkspacePathException(WorkspacePath.LinuxSandboxDeletionGuardUnavailable);

    internal static WorkspacePath OpenTransferStaging(WorkspacePath dataRoot)
    {
        using var control = EnsureManagedDirectory(dataRoot, "control", configuredRoot: true);
        return EnsureManagedDirectory(control, "sandbox-transfers");
    }

    internal WorkspacePath OpenTransferStaging()
    {
        using var anchor = OpenDataRoot(requireControl: true);
        using var control = anchor.OpenSandboxDirectory("control", configuredRoot: true);
        return control.OpenSandboxDirectory("sandbox-transfers");
    }

    internal static string RelativePath(string sandboxId)
    {
        if (!IsLowerHex(sandboxId, 32))
        {
            throw new SandboxPrivateRootException("sandbox_id_invalid");
        }

        return $"{ParentName}/{sandboxId}";
    }

    /// <summary>Provisions the trusted control directory independently of any Sandbox.</summary>
    internal void PrepareControlPaths()
    {
        try
        {
            using var anchor = OpenDataRoot();
            using var control = EnsureManagedDirectory(anchor, "control", configuredRoot: true);
        }
        catch (WorkspacePathException error)
        {
            throw new SandboxPrivateRootException(error.Reason, inner: error);
        }
    }

    /// <summary>Rechecks an existing trusted control directory without creating filesystem state.</summary>
    internal void ValidateControlPaths()
    {
        try
        {
            using var anchor = OpenDataRoot(requireControl: true);
        }
        catch (WorkspacePathException error)
        {
            throw new SandboxPrivateRootException(error.Reason, inner: error);
        }
    }

    /// <summary>Creates a new root after the caller durably reserves this ID. The marker belongs in the protected store.</summary>
    internal SandboxPrivateRoot Provision(string sandboxId)
    {
        var relativePath = RelativePath(sandboxId);
        SandboxPrivateRoot? created = null;
        try
        {
            using var anchor = OpenDataRoot();
            using var parent = EnsureManagedDirectory(anchor, ParentName);
            using var root = parent.CreateSandboxDirectory(sandboxId);
            var marker = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            created = new SandboxPrivateRoot(relativePath, Identity(sandboxId, marker, anchor, parent, root));
            foreach (var name in WritableNames)
            {
                using var directory = root.CreateSandboxDirectory(name);
            }

            using var logs = root.CreateSandboxDirectory("logs");
            return created;
        }
        catch (SandboxPrivateRootException error) when (created is not null)
        {
            throw new SandboxPrivateRootException(error.Reason, created, error);
        }
        catch (WorkspacePathException error)
        {
            throw new SandboxPrivateRootException(error.Reason, created, error);
        }
        catch (RegisteredWorkspaceException error)
        {
            throw new SandboxPrivateRootException("private_root_identity_unavailable", created, error);
        }
    }

    /// <summary>Verifies the stored identity and current privacy before any path is used.</summary>
    internal SandboxPrivateRootLease Inspect(string sandboxId, string expectedIdentity)
    {
        _ = RelativePath(sandboxId);
        var marker = ReadMarker(sandboxId, expectedIdentity);
        WorkspacePath? anchor = null;
        WorkspacePath? parent = null;
        WorkspacePath? root = null;
        try
        {
            anchor = OpenDataRoot();
            parent = anchor.OpenSandboxDirectory(ParentName);
            root = parent.OpenSandboxDirectory(sandboxId);
            if (!string.Equals(expectedIdentity, Identity(sandboxId, marker, anchor, parent, root), StringComparison.Ordinal))
            {
                throw new SandboxPrivateRootException("private_root_identity_changed");
            }

            foreach (var name in WritableNames)
            {
                WorkspacePath.CheckSandboxDirectory(root.OpenDirectory(name), configuredRoot: false);
            }

            WorkspacePath.CheckSandboxDirectory(root.OpenDirectory("logs"), configuredRoot: false);
            var paths = Array.AsReadOnly(WritableNames.Select(name => Path.Combine(root.RootPath, name)).ToArray());
            var lease = new SandboxPrivateRootLease(anchor, parent, root, paths);
            anchor = parent = root = null;
            return lease;
        }
        catch (WorkspacePathException error)
        {
            throw new SandboxPrivateRootException(error.Reason, inner: error);
        }
        catch (RegisteredWorkspaceException error)
        {
            throw new SandboxPrivateRootException("private_root_identity_unavailable", inner: error);
        }
        finally
        {
            root?.Dispose();
            parent?.Dispose();
            anchor?.Dispose();
        }
    }

    /// <summary>Holds the exact journaled directory in its recorded location during resume authorization.</summary>
    internal SandboxPrivateRootLease InspectDeletion(string sandboxId, string originalIdentity, string deletionId,
        string? quarantineIdentity)
    {
        if (!IsLowerHex(deletionId, 32))
        {
            throw new SandboxPrivateRootException("deletion_identity_invalid");
        }

        var marker = ReadMarker(sandboxId, originalIdentity);
        WorkspacePath? anchor = null;
        WorkspacePath? originalParent = null;
        WorkspacePath? parent = null;
        WorkspacePath? root = null;
        try
        {
            anchor = OpenDataRoot(requireControl: true);
            originalParent = anchor.OpenSandboxDirectory(ParentName);
            using var control = anchor.OpenSandboxDirectory("control", configuredRoot: true);
            if (quarantineIdentity is null)
            {
                RequireNoQuarantine(control, deletionId);
                root = originalParent.OpenSandboxDirectory(sandboxId);
            }
            else
            {
                if (!originalParent.InspectRemovalAbsent(sandboxId))
                {
                    throw new SandboxPrivateRootException("deletion_original_location_occupied");
                }

                parent = control.OpenSandboxDirectory(DeletionQuarantineName);
                root = parent.OpenSandboxDirectory(deletionId);
                if (quarantineIdentity != Identity(deletionId, marker, anchor, parent, root))
                {
                    throw new SandboxPrivateRootException("deletion_quarantine_identity_changed");
                }
            }

            // The moved object must also match the original native identity.
            if (originalIdentity != Identity(sandboxId, marker, anchor, originalParent, root))
            {
                throw new SandboxPrivateRootException("private_root_identity_changed");
            }

            if (parent is null)
            {
                parent = originalParent;
                originalParent = null;
            }

            var lease = new SandboxPrivateRootLease(anchor, parent, root, []);
            anchor = parent = root = null;
            return lease;
        }
        catch (WorkspacePathException error)
        {
            throw new SandboxPrivateRootException(error.Reason, inner: error);
        }
        catch (RegisteredWorkspaceException error)
        {
            throw new SandboxPrivateRootException("private_root_identity_unavailable", inner: error);
        }
        finally
        {
            root?.Dispose();
            parent?.Dispose();
            originalParent?.Dispose();
            anchor?.Dispose();
        }
    }

    private static void RequireNoQuarantine(WorkspacePath control, string deletionId)
    {
        WorkspacePath parent;
        try
        {
            parent = control.OpenSandboxDirectory(DeletionQuarantineName);
        }
        catch (WorkspacePathException error) when (WorkspacePath.IsMissingRemovalEntry(error))
        {
            return;
        }

        using (parent)
        {
            if (!parent.InspectRemovalAbsent(deletionId))
            {
                throw new SandboxPrivateRootException("deletion_quarantine_location_occupied");
            }
        }
    }

    public string QuarantineDeletion(string sandboxId, string originalIdentity, string deletionId, Action applied,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            throw new SandboxPrivateRootException("path_enforcement_unavailable");
        }

        using var original = Inspect(sandboxId, originalIdentity);
        var expected = original.OwnedWorkspace.RootIdentity;
        using var control = original.OwnedAnchor.OpenSandboxDirectory("control", configuredRoot: true);
        if (OperatingSystem.IsLinux())
        {
            var authority = RequireLinuxDeletionAuthority();
            authority.RequirePath(control);
            authority.RequirePath(original.OwnedParent);
        }

        using var quarantine = EnsureManagedDirectory(control, DeletionQuarantineName);
        original.ReleaseOwnedRoot();
        var movedIdentity = OperatingSystem.IsLinux()
            ? original.OwnedParent.QuarantineSandboxLinux(sandboxId, quarantine, deletionId, expected,
                RequireLinuxDeletionAuthority(), applied, cancellationToken)
            : OperatingSystem.IsWindows()
                ? original.OwnedParent.QuarantineSandboxWindows(sandboxId, quarantine, deletionId, expected,
                    applied, cancellationToken)
                : throw new SandboxPrivateRootException("path_enforcement_unavailable");
        using var moved = quarantine.OpenSandboxDirectory(deletionId);
        if (!expected.SameObject(movedIdentity) || !expected.SameObject(moved.RootIdentity)
            || !original.OwnedParent.InspectRemovalAbsent(sandboxId))
        {
            throw new SandboxPrivateRootException("deletion_quarantine_identity_changed");
        }

        return Identity(deletionId, ReadMarker(sandboxId, originalIdentity), original.OwnedAnchor, quarantine, moved);
    }

    public string ObserveQuarantinedDeletion(string sandboxId, string originalIdentity, string deletionId)
    {
        var marker = ReadMarker(sandboxId, originalIdentity);
        using var anchor = OpenDataRoot(requireControl: true);
        using var source = anchor.OpenSandboxDirectory(ParentName);
        using var control = anchor.OpenSandboxDirectory("control", configuredRoot: true);
        using var quarantine = control.OpenSandboxDirectory(DeletionQuarantineName);
        if (OperatingSystem.IsLinux())
        {
            var authority = RequireLinuxDeletionAuthority();
            authority.RequirePath(source);
            authority.RequirePath(quarantine);
        }

        using var root = quarantine.OpenSandboxDirectory(deletionId);
        if (!source.InspectRemovalAbsent(sandboxId) || originalIdentity != Identity(sandboxId, marker, anchor, source, root))
        {
            throw new SandboxPrivateRootException("deletion_quarantine_identity_changed");
        }

        if (OperatingSystem.IsLinux())
        {
            var authority = RequireLinuxDeletionAuthority();
            source.SyncAdmittedSandboxDeleteLinuxParent(authority);
            quarantine.SyncAdmittedSandboxDeleteLinuxParent(authority);
        }

        return Identity(deletionId, marker, anchor, quarantine, root);
    }

    public void VerifyRecordedRemoval(string sandboxId, string originalIdentity, string deletionId, string quarantineIdentity)
    {
        var marker = ReadMarker(sandboxId, originalIdentity);
        if (ReadMarker(deletionId, quarantineIdentity) != marker)
        {
            throw new SandboxPrivateRootException("deletion_quarantine_identity_changed");
        }

        using var anchor = OpenDataRoot(requireControl: true);
        using var source = anchor.OpenSandboxDirectory(ParentName);
        using var control = anchor.OpenSandboxDirectory("control", configuredRoot: true);
        using var quarantine = control.OpenSandboxDirectory(DeletionQuarantineName);
        if (OperatingSystem.IsLinux())
        {
            var authority = RequireLinuxDeletionAuthority();
            authority.RequirePath(source);
            authority.RequirePath(quarantine);
        }

        if (!originalIdentity.StartsWith(IdentityPrefix(sandboxId, marker, anchor, source), StringComparison.Ordinal)
            || !quarantineIdentity.StartsWith(IdentityPrefix(deletionId, marker, anchor, quarantine), StringComparison.Ordinal)
            || !source.InspectRemovalAbsent(sandboxId) || !quarantine.InspectRemovalAbsent(deletionId))
        {
            throw new SandboxPrivateRootException("deletion_verified_locations_changed");
        }
    }

    public SandboxRemovalBatchResult RemoveDeletionBatch(string sandboxId, string originalIdentity, string deletionId,
        string quarantineIdentity, int maximumEntries, Action applied, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            throw new SandboxPrivateRootException("path_enforcement_unavailable");
        }

        using var held = InspectDeletion(sandboxId, originalIdentity, deletionId, quarantineIdentity);
        var expected = held.OwnedWorkspace.RootIdentity;
        held.ReleaseOwnedRoot();
        var batch = OperatingSystem.IsLinux()
            ? held.OwnedParent.RemoveSandboxQuarantineBatchLinux(deletionId, expected, maximumEntries,
                RequireLinuxDeletionAuthority(), applied, cancellationToken)
            : OperatingSystem.IsWindows()
                ? held.OwnedParent.RemoveSandboxQuarantineBatchWindows(deletionId, expected, maximumEntries,
                    applied, cancellationToken)
                : throw new SandboxPrivateRootException("path_enforcement_unavailable");
        if (batch.RootAbsent)
        {
            using var source = held.OwnedAnchor.OpenSandboxDirectory(ParentName);
            if (OperatingSystem.IsLinux())
            {
                RequireLinuxDeletionAuthority().RequirePath(source);
            }

            var marker = ReadMarker(sandboxId, originalIdentity);
            if (!originalIdentity.StartsWith(IdentityPrefix(sandboxId, marker, held.OwnedAnchor, source), StringComparison.Ordinal)
                || !source.InspectRemovalAbsent(sandboxId))
            {
                throw new SandboxPrivateRootException("deletion_original_location_changed");
            }
        }

        return batch;
    }

    private WorkspacePath OpenDataRoot(bool requireControl = false)
    {
        if (string.IsNullOrWhiteSpace(dataRoot) || !Path.IsPathFullyQualified(dataRoot))
        {
            throw new SandboxPrivateRootException("private_data_root_invalid");
        }

        var path = Path.TrimEndingDirectorySeparator(dataRoot);
        if (string.Equals(path, Path.GetPathRoot(path), StringComparison.OrdinalIgnoreCase))
        {
            throw new SandboxPrivateRootException("private_data_root_invalid");
        }

        var anchor = WorkspacePath.OpenRoot(path);
        try
        {
            WorkspacePath.CheckSandboxInstallationOverlap(anchor);
            WorkspacePath.CheckSandboxDirectory(anchor.RootHandle, configuredRoot: true);
            foreach (var name in ProtectedDirectories)
            {
                CheckProtectedDirectory(anchor, name, requireControl && name == "control");
            }

            return anchor;
        }
        catch
        {
            anchor.Dispose();
            throw;
        }
    }

    private static void CheckProtectedDirectory(WorkspacePath anchor, string name, bool required)
    {
        try
        {
            using var directory = anchor.OpenSandboxDirectory(name, configuredRoot: true);
        }
        catch (WorkspacePathException error) when (!required && error.Reason is ("native_2" or "native_3"))
        {
            // The Node can use an external secret store or a different protected control endpoint.
        }
    }

    private static WorkspacePath EnsureManagedDirectory(WorkspacePath anchor, string name, bool configuredRoot = false)
    {
        try
        {
            return anchor.OpenSandboxDirectory(name, configuredRoot);
        }
        catch (WorkspacePathException error) when (error.Reason is "native_2" or "native_3")
        {
            try
            {
                return anchor.CreateSandboxDirectory(name);
            }
            catch (SandboxPrivateRootException raced) when (raced.Reason == "private_root_already_exists")
            {
                // A concurrent first call may have established the shared directory. Verify its native privacy.
                return anchor.OpenSandboxDirectory(name, configuredRoot);
            }
        }
    }

    private static string Identity(string sandboxId, string marker, WorkspacePath anchor, WorkspacePath parent, WorkspacePath root)
        => IdentityPrefix(sandboxId, marker, anchor, parent) + Convert.ToBase64String(RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity).Bytes);

    private static string IdentityPrefix(string sandboxId, string marker, WorkspacePath anchor, WorkspacePath parent)
    {
        var dataIdentity = RegisteredWorkspaces.RootIdentity.Encode(anchor.RootIdentity);
        var parentIdentity = RegisteredWorkspaces.RootIdentity.Encode(parent.RootIdentity);
        return FormattableString.Invariant($"1:{sandboxId}:{marker}:{dataIdentity.Platform}:{Convert.ToBase64String(dataIdentity.Bytes)}:{Convert.ToBase64String(parentIdentity.Bytes)}:");
    }

    private static string ReadMarker(string sandboxId, string identity)
    {
        if (identity is null || identity.Length > 400)
        {
            throw new SandboxPrivateRootException("private_root_identity_invalid");
        }

        var fields = identity.Split(':');
        if (fields.Length != 7 || fields[0] != "1" || fields[1] != sandboxId || !IsLowerHex(fields[2], 64))
        {
            throw new SandboxPrivateRootException("private_root_identity_invalid");
        }

        return fields[2];
    }

    private static bool IsLowerHex(string text, int length) =>
        text is not null && text.Length == length && text.All(static value => value is >= '0' and <= '9' or >= 'a' and <= 'f');
}
