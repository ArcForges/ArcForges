// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Files;

internal static partial class FileMutationJournal
{
    /// <summary>
    /// Holds follow a native target identity across workspace registrations and renames. If the held name and the
    /// candidate have the same native parent, an already opened parent can also resolve the held name using the actual
    /// filesystem's case and alias semantics. Missing or unverifiable observations conservatively retain the hold.
    /// This is node-side serialization; it does not lock a filesystem namespace against another process.
    /// </summary>
    internal static bool HasTargetHold(StoreReader reader, int platform, byte[] parentIdentity, byte[]? targetIdentity,
        string relativePath, WorkspacePath? selectedRoot)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(parentIdentity);
        var candidateParts = WorkspacePath.Components(relativePath);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, parentIdentity);
        if (targetIdentity is not null) RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, targetIdentity);

        SafeFileHandle? parent = null;
        var parentChecked = false;
        using var command = reader.CreateCommand("""
            SELECT identity_platform, parent_identity, target_identity, relative_path, kind
            FROM file_operation_journal WHERE held = 1 ORDER BY created_at, command_id LIMIT 65;
            """);
        using var rows = command.ExecuteReader();
        var count = 0;
        while (rows.Read())
        {
            if (++count > 64 || rows.IsDBNull(1) || rows.IsDBNull(3) || rows.GetInt32(4) == 3) return true;
            var heldPlatform = rows.GetInt32(0);
            var heldParent = (byte[])rows.GetValue(1);
            var heldTarget = rows.IsDBNull(2) ? null : (byte[])rows.GetValue(2);
            var heldPath = rows.GetString(3);
            if (heldPlatform != platform) return true;
            RegisteredWorkspaces.RootIdentity.ValidateEncoding(heldPlatform, heldParent);
            if (heldTarget is not null) RegisteredWorkspaces.RootIdentity.ValidateEncoding(heldPlatform, heldTarget);
            if (targetIdentity is not null && heldTarget is not null &&
                SameNativeObject(platform, targetIdentity, heldTarget))
                return true;
            if (!SameNativeObject(platform, parentIdentity, heldParent)) continue;

            // No observable existing candidate means two names might be native aliases. Do not invent a negative
            // comparison or create anything to find out. The original hold remains until HUMAN acknowledgment.
            if (selectedRoot is null || targetIdentity is null) return true;
            try
            {
                if (!parentChecked)
                {
                    var parentPath = candidateParts.Length == 1 ? "" : string.Join('/', candidateParts[..^1]);
                    parent = selectedRoot.OpenDirectory(parentPath);
                    var actual = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(parent));
                    if (actual.Platform != platform || !SameNativeObject(platform, parentIdentity, actual.Bytes)) return true;
                    parentChecked = true;
                }
                var heldParts = WorkspacePath.Components(heldPath);
                var observed = selectedRoot.InspectHeldParentChild(parent!, heldParts[^1]);
                var encoded = RegisteredWorkspaces.RootIdentity.Encode(observed with { Links = 1 }, directory: false);
                if (encoded.Platform != platform || SameNativeObject(platform, targetIdentity, encoded.Bytes)) return true;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                ArgumentException or NotSupportedException)
            {
                // An absent, inaccessible or changed name cannot establish that this candidate is independent.
                return true;
            }
        }
        return false;
    }

    // Ignore mutable Windows creation time and Linux birth time when deciding whether a live hold may name the same
    // native object. A reused native identity can conservatively hold an unrelated object; it must never bypass a hold.
    private static bool SameNativeObject(int platform, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => platform switch
    {
        1 when left.Length == 33 && right.Length == 33 => left[..25].SequenceEqual(right[..25]),
        2 when left.Length == 53 && right.Length == 53 =>
            left[..9].SequenceEqual(right[..9]) && left[21..].SequenceEqual(right[21..]),
        _ => throw new InvalidDataException("Unsupported held native identity."),
    };
}
