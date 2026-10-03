// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.LocalRpc;

/// <summary>
/// The bounds of brokered large-data transfers (annex 09 section 4): at most three output slots of at most 64 MiB per
/// invocation, one private copy of at most 64 MiB per session, copied in bounded chunks, a 30 second session lease and a
/// 5 second cancel grace period. A limit may be lowered, never raised past the profile.
/// </summary>
public sealed record LocalRpcBrokerLimits
{
    /// <summary>The most output slots one invocation preallocates (3).</summary>
    public const int MaxSlots = 3;

    /// <summary>The largest slot, and so the largest private copy (64 MiB).</summary>
    public const long MaxSlotBytes = 64L * 1024 * 1024;

    /// <summary>The longest session lease (30 s).</summary>
    public static readonly TimeSpan MaxSessionLease = TimeSpan.FromSeconds(30);

    /// <summary>The longest cancel grace period (5 s).</summary>
    public static readonly TimeSpan MaxCancelGrace = TimeSpan.FromSeconds(5);

    /// <summary>The bytes the parent copies and digests per step, 4 KiB through 4 MiB (default 256 KiB). Cancellation, expiry and the pair are checked between steps.</summary>
    public int ChunkBytes { get; init; } = 256 * 1024;

    /// <summary>The session lease, positive and at most 30 s (default 30 s). It is renewed, never extended past this length from the renewal.</summary>
    public TimeSpan SessionLease { get; init; } = MaxSessionLease;

    /// <summary>How long a cancelled session waits for the owner to close it before it is closed and the helper is to be terminated, positive and at most 5 s (default 5 s).</summary>
    public TimeSpan CancelGrace { get; init; } = MaxCancelGrace;

    /// <summary>The most sessions one registry holds at once, 1 through 64 (default 8, the connection bound). Memory is bounded by this times one 64 MiB copy.</summary>
    public int MaxSessions { get; init; } = 8;

    internal LocalRpcBrokerLimits Validated()
    {
        if (ChunkBytes is < 4096 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(ChunkBytes), ChunkBytes, "The chunk size is 4 KiB through 4 MiB.");
        }

        if (SessionLease <= TimeSpan.Zero || SessionLease > MaxSessionLease)
        {
            throw new ArgumentOutOfRangeException(nameof(SessionLease), SessionLease, "The session lease is positive and at most 30 seconds.");
        }

        if (CancelGrace <= TimeSpan.Zero || CancelGrace > MaxCancelGrace)
        {
            throw new ArgumentOutOfRangeException(nameof(CancelGrace), CancelGrace, "The cancel grace period is positive and at most 5 seconds.");
        }

        if (MaxSessions is < 1 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxSessions), MaxSessions, "The session bound is 1 through 64.");
        }

        return this;
    }
}
