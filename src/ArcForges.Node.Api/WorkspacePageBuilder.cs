// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Api;

/// <summary>Constructs a bounded workspace page and a node-, filter- and inventory-generation-bound continuation.</summary>
internal static class WorkspacePageBuilder
{
    internal const int MaximumBytes = 131_072;

    internal static WorkspaceServiceListWorkspacesResponse Build(ResponseMeta meta, IReadOnlyList<Workspace> records, bool more,
        ReadOnlySpan<byte> nodeId, byte kinds, long revision, ReadOnlySpan<byte> key)
    {
        ArgumentNullException.ThrowIfNull(meta);
        ArgumentNullException.ThrowIfNull(records);
        if (records.Count > 500 || records.Count == 0 && more || nodeId.Length != 16 || kinds is 0 or > 7 || revision < 0 || key.Length != 32)
        {
            throw new ArgumentException("A workspace page has a node, filter, inventory generation and at most 500 records.");
        }

        var response = new WorkspaceServiceListWorkspacesResponse
        {
            Meta = meta,
            Value = new WorkspaceServiceListWorkspacesValue { Page = new PageState { HasMore = false } },
        };
        var selected = response.Value.Workspaces;
        byte[]? previous = null;
        for (var index = 0; index < records.Count; index++)
        {
            var record = records[index];
            if (record.WorkspaceId is not { Value.Length: 16 } id || previous is not null && previous.AsSpan().SequenceCompareTo(id.Value.Span) >= 0)
            {
                throw new ArgumentException("Workspace page IDs must be valid and strictly increasing.", nameof(records));
            }

            previous = id.Value.ToByteArray();
            selected.Add(record);
            var hasMore = more || index + 1 < records.Count;
            response.Value.Page.HasMore = hasMore;
            if (hasMore)
            {
                response.Value.Page.NextCursor = Cursor(nodeId, kinds, revision, key, id.Value.Span);
            }
            else
            {
                response.Value.Page.ClearNextCursor();
            }

            response.Audit = WorkspaceAuditMetadata.ForRecords(selected);
            if (response.CalculateSize() <= MaximumBytes)
            {
                continue;
            }

            selected.RemoveAt(selected.Count - 1);
            if (selected.Count == 0)
            {
                throw new ArgumentException("One workspace record cannot fit the bounded response.", nameof(records));
            }

            response.Value.Page.HasMore = true;
            response.Value.Page.NextCursor = Cursor(nodeId, kinds, revision, key, selected[^1].WorkspaceId.Value.Span);
            response.Audit = WorkspaceAuditMetadata.ForRecords(selected);
            if (response.CalculateSize() > MaximumBytes)
            {
                throw new ArgumentException("The bounded response metadata cannot fit.", nameof(meta));
            }

            return response;
        }

        response.Audit = WorkspaceAuditMetadata.ForRecords(selected);
        if (response.CalculateSize() > MaximumBytes)
        {
            throw new ArgumentException("The bounded response metadata cannot fit.", nameof(meta));
        }

        return response;
    }

    /// <summary>Authenticates and decodes a canonical cursor; the caller must compare its generation to its SQLite snapshot.</summary>
    internal static bool TryCursor(string text, ReadOnlySpan<byte> nodeId, byte kinds, ReadOnlySpan<byte> key, out byte[]? after, out long revision)
    {
        after = null;
        revision = -1;
        if (text is null || text.Length != 99 || nodeId.Length != 16 || kinds is 0 or > 7 || key.Length != 32)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[74];
        var encoded = text.Replace('-', '+').Replace('_', '/') + "=";
        if (!Convert.TryFromBase64String(encoded, bytes, out var written) || written != bytes.Length ||
            bytes[0] != 2 || bytes[1] != kinds || !bytes.Slice(2, 16).SequenceEqual(nodeId) ||
            !string.Equals(text, Encode(bytes), StringComparison.Ordinal) ||
            !CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(key, bytes[..42]), bytes[42..]))
        {
            return false;
        }

        revision = BinaryPrimitives.ReadInt64BigEndian(bytes[18..26]);
        if (revision < 0)
        {
            return false;
        }

        after = bytes[26..42].ToArray();
        return true;
    }

    private static string Cursor(ReadOnlySpan<byte> nodeId, byte kinds, long revision, ReadOnlySpan<byte> key, ReadOnlySpan<byte> id)
    {
        Span<byte> bytes = stackalloc byte[74];
        bytes[0] = 2;
        bytes[1] = kinds;
        nodeId.CopyTo(bytes[2..18]);
        BinaryPrimitives.WriteInt64BigEndian(bytes[18..26], revision);
        id.CopyTo(bytes[26..42]);
        HMACSHA256.HashData(key, bytes[..42]).CopyTo(bytes[42..]);
        return Encode(bytes);
    }

    private static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
