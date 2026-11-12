// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Node.Store;

/// <summary>
/// Connection-local, transaction-scoped native target observations. No witness is stored in the database or accepted
/// from an RPC. Only trusted node code may record one after it has inspected the held parent and target objects.
/// </summary>
internal sealed class FileTargetHoldWitnesses
{
    private readonly List<Witness> _witnesses = [];

    internal void Add(byte[] command, byte[] held, byte[] workspace, string path, byte[] root, byte[] parent,
        byte[] target, byte[] digest, byte[] caller, long kind)
    {
        if (command.Length != 16 || held.Length != 16 || workspace.Length != 16 || string.IsNullOrEmpty(path) ||
            root.Length is < 16 or > 256 || parent.Length is < 16 or > 256 || target.Length is < 16 or > 256 ||
            digest.Length != 32 || caller.Length is < 1 or > 256 || kind is not (1 or 2) || _witnesses.Count >= 64)
            throw new ArgumentException("A bounded, fully bound target observation is required.");
        _witnesses.Add(new Witness(command.ToArray(), held.ToArray(), workspace.ToArray(), path, root.ToArray(),
            parent.ToArray(), target.ToArray(), digest.ToArray(), caller.ToArray(), kind));
    }

    internal long Matches(byte[]? command, byte[]? held, byte[]? workspace, string? path, byte[]? root, byte[]? parent,
        byte[]? target, byte[]? digest, byte[]? caller, long kind)
    {
        if (command is null || held is null || workspace is null || path is null || root is null || parent is null ||
            target is null || digest is null || caller is null)
            return 0;
        return _witnesses.Any(witness => witness.Command.AsSpan().SequenceEqual(command) &&
            witness.Held.AsSpan().SequenceEqual(held) && witness.Workspace.AsSpan().SequenceEqual(workspace) &&
            string.Equals(witness.Path, path, StringComparison.Ordinal) && witness.Root.AsSpan().SequenceEqual(root) &&
            witness.Parent.AsSpan().SequenceEqual(parent) && witness.Target.AsSpan().SequenceEqual(target) &&
            witness.Digest.AsSpan().SequenceEqual(digest) && witness.Caller.AsSpan().SequenceEqual(caller) &&
            witness.Kind == kind) ? 1 : 0;
    }

    internal void Clear() => _witnesses.Clear();

    private sealed record Witness(byte[] Command, byte[] Held, byte[] Workspace, string Path, byte[] Root, byte[] Parent,
        byte[] Target, byte[] Digest, byte[] Caller, long Kind);
}
