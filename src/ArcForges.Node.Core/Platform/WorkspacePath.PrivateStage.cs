// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    private RegisteredWorkspaces.RootIdentity[] _privateStageFiles = [];
    private bool _privateStageProtectionInstalled;

    /// <summary>
    /// Installs the already durable private-file identities for this workspace use before any data open. Identity,
    /// not a pathname, blocks a stage moved or hard-linked into an otherwise readable registered root. The caller must
    /// obtain a complete, validated registry snapshot in the same serialized store operation as the file request.
    /// This component alone does not create or persist a stage, grant an approval, or establish startup integration.
    /// </summary>
    internal void ProtectPrivateStageFiles(IReadOnlyCollection<RegisteredWorkspaces.RootIdentity> identities)
    {
        ArgumentNullException.ThrowIfNull(identities);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_privateStageProtectionInstalled || identities.Count > 128)
            throw new WorkspacePathException("file_access_denied");
        var copy = new RegisteredWorkspaces.RootIdentity[identities.Count];
        var index = 0;
        foreach (var identity in identities)
        {
            if (identity is null) throw new WorkspacePathException("file_access_denied");
            RegisteredWorkspaces.RootIdentity.ValidateEncoding(identity.Platform, identity.Bytes);
            copy[index++] = new RegisteredWorkspaces.RootIdentity(identity.Platform, identity.Bytes.ToArray());
        }
        _privateStageFiles = copy;
        _privateStageProtectionInstalled = true;
    }

    /// <summary>Tests the opened native file identity, including a file with a newly added hard link.</summary>
    internal bool IsPrivateStageFile(WorkspaceObjectIdentity identity)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_privateStageFiles.Length == 0 || !identity.IsFile) return false;
        // Link count is not object identity. Matching must still work when a same-user process adds another name.
        var encoded = RegisteredWorkspaces.RootIdentity.Encode(identity with { Links = 1 }, directory: false);
        return _privateStageFiles.Any(item => item.Platform == encoded.Platform &&
            CryptographicOperations.FixedTimeEquals(item.Bytes, encoded.Bytes));
    }

    private void RefusePrivateStageFile(WorkspaceObjectIdentity identity)
    {
        if (IsPrivateStageFile(identity)) throw new WorkspacePathException("file_access_denied");
    }
}
