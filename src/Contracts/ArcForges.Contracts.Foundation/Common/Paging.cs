// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Contracts.Foundation;

/// <summary>A cursor page request for a local query.</summary>
public sealed partial record LocalPageQuery
{
    /// <summary>The opaque cursor to continue from. Null asks for the first page.</summary>
    public string? After { get; init; }

    /// <summary>How many items to return. The serving side enforces its own ceiling.</summary>
    public int Limit { get; init; } = 50;
}

/// <summary>
/// A page of results from a local query.
/// </summary>
/// <typeparam name="T">The item type.</typeparam>
/// <remarks>
/// This shape belongs to LocalRpc and in-process queries only. The public API uses
/// <see cref="CursorPageDto{T}"/>, which deliberately has no <c>hasMore</c>: two ways of saying "there is
/// more" drift apart, so the public wire keeps only the cursor.
/// </remarks>
public sealed partial record LocalPage<T>
{
    public required IReadOnlyList<T> Items { get; init; }

    /// <summary>The cursor for the next page. Null on the last page.</summary>
    public string? NextCursor { get; init; }

    /// <summary>Whether more items follow.</summary>
    public bool HasMore { get; init; }
}

/// <summary>
/// A page of results from the public API.
/// </summary>
/// <typeparam name="T">The item type.</typeparam>
/// <remarks>
/// <para>
/// <see cref="NextCursor"/> being null means the last page. There is no <c>hasMore</c> flag: it would be a
/// second, driftable statement of the same fact.
/// </para>
/// <para>
/// The cursor is an opaque token. Clients must not parse it, and offset paging is not offered, because an
/// offset drifts as rows are inserted.
/// </para>
/// </remarks>
public sealed partial record CursorPageDto<T>
{
    public required IReadOnlyList<T> Items { get; init; }

    /// <summary>The opaque cursor for the next page. Null on the last page.</summary>
    public string? NextCursor { get; init; }

    /// <summary>The server's clock when the page was produced, as a UTC instant.</summary>
    public required DateTimeOffset ServerTimeUtc { get; init; }

    /// <summary>
    /// How far the projection behind this page had been applied, when the page is served from a projection.
    /// </summary>
    /// <remarks>
    /// A watermark is a <see cref="Sequence"/>: <see cref="Sequence.None"/> means nothing has been applied
    /// yet (architecture §5.1). Null means the page is not served from a projection at all.
    /// </remarks>
    public Sequence? ProjectionWatermark { get; init; }
}
