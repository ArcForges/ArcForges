// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Files;

/// <summary>A recorded local stage location; confirmation is only an identity observation at the time of this check.</summary>
internal sealed record PrivateStageLocation(int Slot, string Path, bool Confirmed, bool HasIdentity);

internal static class PrivateStageLocations
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private const string WarningPrefix = "arcforges.file-stage.v1:";

    /// <summary>
    /// Returns only local recovery metadata, never stage bytes. The caller must authenticate a local HUMAN independently
    /// and must not place these locations in a routed response, persisted operation or audit log.
    /// </summary>
    internal static IReadOnlyList<PrivateStageLocation> ForVerifiedHuman(StoreReader reader, ReadOnlySpan<byte> commandId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        StoreIds.Validate(commandId, nameof(commandId));
        if (!PrivateStageRegistry.HasSchema(reader)) return [];
        var records = new List<(int Slot, string Path, int? Platform, byte[]? File, byte[]? Parent)>();
        using (var command = reader.CreateCommand("""
            SELECT slot, stage_path, identity_platform, native_identity, parent_identity
            FROM file_private_stage_object WHERE command_id = $id ORDER BY slot;
            """))
        {
            command.Parameters.AddWithValue("$id", commandId.ToArray());
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                if (records.Count >= 2) throw new InvalidDataException("Too many recorded file stages.");
                var path = rows.GetString(1);
                if (!Path.IsPathFullyQualified(path) || path.Contains('\0') || StrictUtf8.GetByteCount(path) is < 1 or > 4096)
                    throw new InvalidDataException("The recorded file stage path is invalid.");
                records.Add((rows.GetInt32(0), path, rows.IsDBNull(2) ? null : rows.GetInt32(2),
                    rows.IsDBNull(3) ? null : (byte[])rows.GetValue(3), rows.IsDBNull(4) ? null : (byte[])rows.GetValue(4)));
            }
        }

        var result = new List<PrivateStageLocation>(records.Count);
        foreach (var record in records)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var confirmed = false;
            if (record.Platform is { } platform && record.File is { } file && record.Parent is { } parent)
            {
                try
                {
                    RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, file);
                    RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, parent);
                    var directoryName = Path.GetDirectoryName(record.Path);
                    var name = Path.GetFileName(record.Path);
                    if (!string.IsNullOrEmpty(directoryName) && !string.IsNullOrEmpty(name))
                    {
                        using var directory = WorkspacePath.OpenRoot(directoryName);
                        var actualParent = RegisteredWorkspaces.RootIdentity.Encode(directory.RootIdentity);
                        if (actualParent.Platform == platform && CryptographicOperations.FixedTimeEquals(actualParent.Bytes, parent))
                        {
                            // Metadata only. Link count is not identity; a newly added hard link must not hide the object.
                            var entry = directory.InspectEntry(name);
                            if (entry.Kind == WorkspaceEntryType.File)
                            {
                                var actualFile = RegisteredWorkspaces.RootIdentity.Encode(entry.Identity with { Links = 1 }, directory: false);
                                confirmed = actualFile.Platform == platform && CryptographicOperations.FixedTimeEquals(actualFile.Bytes, file);
                            }
                        }
                    }
                }
                catch (Exception exception) when (exception is IOException or RegisteredWorkspaceException or UnauthorizedAccessException or ArgumentException)
                {
                    // A missing, moved, inaccessible or replaced object is not an identity-confirmed current location.
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            result.Add(new PrivateStageLocation(record.Slot, record.Path, confirmed, record.Platform is not null));
        }
        return result;
    }

    /// <summary>Bounded, ASCII-only warning transport in the existing 450.1 local response metadata.</summary>
    internal static string ToWarning(PrivateStageLocation location)
    {
        ArgumentNullException.ThrowIfNull(location);
        if (location.Slot is not (1 or 2)) throw new ArgumentOutOfRangeException(nameof(location));
        var bytes = StrictUtf8.GetBytes(location.Path);
        if (bytes.Length is < 1 or > 4096) throw new ArgumentException("Invalid file stage path.", nameof(location));
        return WarningPrefix + location.Slot.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" +
            (location.Confirmed ? "confirmed" : location.HasIdentity ? "last-known" : "unbound") + ":" + Convert.ToBase64String(bytes);
    }
}
