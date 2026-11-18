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

    internal IReadOnlyList<string> WritablePaths { get; } = writablePaths;

    public void Dispose()
    {
        root.Dispose();
        parent.Dispose();
        dataRoot.Dispose();
    }
}

/// <summary>Creates and reopens private Sandbox data without using a display name or accepting a preexisting root.</summary>
internal sealed class SandboxPrivateRoots(string dataRoot)
{
    private const string ParentName = "sandboxes";
    private static readonly string[] WritableNames = ["home", "config", "cache", "tmp", "work", "data"];
    private static readonly string[] ProtectedDirectories = ["store", "control", "credentials"];

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
    {
        var dataIdentity = RegisteredWorkspaces.RootIdentity.Encode(anchor.RootIdentity);
        var parentIdentity = RegisteredWorkspaces.RootIdentity.Encode(parent.RootIdentity);
        var sandboxIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        return FormattableString.Invariant($"1:{sandboxId}:{marker}:{dataIdentity.Platform}:{Convert.ToBase64String(dataIdentity.Bytes)}:{Convert.ToBase64String(parentIdentity.Bytes)}:{Convert.ToBase64String(sandboxIdentity.Bytes)}");
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
