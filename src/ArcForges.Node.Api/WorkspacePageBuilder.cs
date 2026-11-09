// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Api;

/// <summary>
/// Constructs the exact bounded workspace-list envelope from an already verified, ordered page. It does not read the
/// filesystem, decide permissions or prove Git status; the caller supplies actual projected records for this response.
/// </summary>
internal static class WorkspacePageBuilder
{
    internal const int MaximumBytes = 131_072;

    internal static WorkspaceServiceListWorkspacesResponse Build(ResponseMeta meta, IReadOnlyList<Workspace> records, bool more,
        ReadOnlySpan<byte> nodeId, byte kinds)
    {
        ArgumentNullException.ThrowIfNull(meta);
        ArgumentNullException.ThrowIfNull(records);
        if (records.Count > 500 || records.Count == 0 && more || nodeId.Length != 16 || kinds is 0 or > 7)
        {
            throw new ArgumentException("A workspace page has a node, a kind filter and at most 500 records.");
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
                response.Value.Page.NextCursor = Cursor(nodeId, kinds, id.Value.Span);
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
            response.Value.Page.NextCursor = Cursor(nodeId, kinds, selected[^1].WorkspaceId.Value.Span);
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

    /// <summary>Decodes only a canonical cursor for this node and the same kind filter.</summary>
    internal static bool TryCursor(string text, ReadOnlySpan<byte> nodeId, byte kinds, out byte[]? after)
    {
        after = null;
        if (text is null || text.Length != 46 || nodeId.Length != 16 || kinds is 0 or > 7)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[34];
        var encoded = text.Replace('-', '+').Replace('_', '/') + "==";
        if (!Convert.TryFromBase64String(encoded, bytes, out var written) || written != bytes.Length ||
            bytes[0] != 1 || bytes[1] != kinds || !bytes.Slice(2, 16).SequenceEqual(nodeId) ||
            !string.Equals(text, Encode(bytes), StringComparison.Ordinal))
        {
            return false;
        }

        after = bytes[18..].ToArray();
        return true;
    }

    private static string Cursor(ReadOnlySpan<byte> nodeId, byte kinds, ReadOnlySpan<byte> id)
    {
        Span<byte> bytes = stackalloc byte[34];
        bytes[0] = 1;
        bytes[1] = kinds;
        nodeId.CopyTo(bytes[2..18]);
        id.CopyTo(bytes[18..]);
        return Encode(bytes);
    }

    private static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
