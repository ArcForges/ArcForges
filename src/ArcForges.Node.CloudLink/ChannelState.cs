// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.CloudLink;

/// <summary>The SM-RELAY state and its closed reason (account.proto <c>AccountStatus.relay</c> and <c>relay_reason</c>).</summary>
/// <param name="State">The state.</param>
/// <param name="Reason">The reason, one of <see cref="ChannelReasons"/>.</param>
internal sealed record ChannelStatus(RelayState State, string Reason);

/// <summary>The closed vocabulary of <c>AccountStatus.relay_reason</c> (AF-CTR-05 N1).</summary>
internal static class ChannelReasons
{
    // DISABLED
    public const string SignedOut = "signed_out";
    public const string LinkDisabled = "cloud_link_disabled";
    public const string CredentialUnusable = "credential_unusable";
    public const string NodeKeyMissing = "node_key_missing";
    public const string NotConfigured = "channel_not_configured";

    // CONNECTING, CONNECTED
    public const string Connecting = "connecting";
    public const string Connected = "connected";

    // BACKOFF
    public const string NetworkFailure = "network_failure";
    public const string CredentialExpired = "credential_expired";
    public const string HeartbeatTimeout = "heartbeat_timeout";
    public const string Replaced = "replaced";
    public const string FrameTooLarge = "frame_too_large";
    public const string RateLimited = "rate_limited";
    public const string CenterShuttingDown = "center_shutting_down";
    public const string ProtocolError = "protocol_error";

    // REFUSED
    public const string Refused = "refused";
    public const string KillSwitch = "kill_switch";

    /// <summary>Every reason (a repository and a unit test pin the list).</summary>
    public static IReadOnlyList<string> All { get; } =
    [
        SignedOut, LinkDisabled, CredentialUnusable, NodeKeyMissing, NotConfigured, Connecting, Connected, NetworkFailure, CredentialExpired,
        HeartbeatTimeout, Replaced, FrameTooLarge, RateLimited, CenterShuttingDown, ProtocolError, Refused, KillSwitch,
    ];
}

/// <summary>What the loop does after a channel ended (Plan CTR5-NODE-02; relay.proto RelayClose).</summary>
/// <param name="State">BACKOFF or REFUSED.</param>
/// <param name="Reason">The closed reason.</param>
/// <param name="RefreshFirst">A refresh of the node credential before the next attempt (4401, a 401 before the upgrade).</param>
/// <param name="Delay">A delay the center asked for (4500 <c>reconnect_after_ms</c>), or <see langword="null"/> for the node's own backoff.</param>
internal sealed record ChannelEnd(RelayState State, string Reason, bool RefreshFirst = false, TimeSpan? Delay = null);

/// <summary>The timing rules of SM-RELAY (pure functions; the loop passes its random source).</summary>
internal static class ChannelPolicy
{
    /// <summary>The first and the largest backoff ceiling (1 s doubling to 60 s).</summary>
    public static readonly (TimeSpan First, TimeSpan Cap) BackoffBounds = (TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(60));

    /// <summary>A connection that stayed up this long resets the backoff.</summary>
    public static readonly TimeSpan StableAfter = TimeSpan.FromSeconds(60);

    /// <summary>REFUSED retries after this long (or at a credential refresh).</summary>
    public static readonly TimeSpan RefusedRetry = TimeSpan.FromHours(1);

    /// <summary>The heartbeat deadline before the center's limits arrive (relay.proto default 60 s).</summary>
    public static readonly TimeSpan DefaultHeartbeatDeadline = TimeSpan.FromSeconds(60);

    /// <summary>The longest wait for the center's challenge and acceptance (the center's own hello deadline is 10 s).</summary>
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(15);

    /// <summary>The longest <c>reconnect_after_ms</c> honoured (relay.proto: 0..300,000).</summary>
    public static readonly TimeSpan MaxReconnectAfter = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The backoff before attempt <paramref name="failures"/> (1 for the first failure): full jitter between 1 s and the ceiling
    /// min(60 s, 2^failures s); <paramref name="unit"/> in [0, 1] is the random draw.
    /// </summary>
    public static TimeSpan Backoff(int failures, double unit)
    {
        var exponent = Math.Clamp(failures, 1, 6);
        var ceiling = TimeSpan.FromSeconds(Math.Min(BackoffBounds.Cap.TotalSeconds, Math.Pow(2, exponent)));
        var draw = Math.Clamp(unit, 0, 1);
        return BackoffBounds.First + (ceiling - BackoffBounds.First) * draw;
    }

    /// <summary>The loop's next step after the center closed with <paramref name="code"/> (relay.proto RelayClose; SM-RELAY).</summary>
    public static ChannelEnd Closed(int code, uint? reconnectAfterMs) => code switch
    {
        4401 => new ChannelEnd(RelayState.Backoff, ChannelReasons.CredentialExpired, RefreshFirst: true),
        4403 => new ChannelEnd(RelayState.Refused, ChannelReasons.Refused),
        4408 => new ChannelEnd(RelayState.Backoff, ChannelReasons.HeartbeatTimeout),
        4409 => new ChannelEnd(RelayState.Backoff, ChannelReasons.Replaced),
        4413 => new ChannelEnd(RelayState.Backoff, ChannelReasons.FrameTooLarge),
        4429 => new ChannelEnd(RelayState.Backoff, ChannelReasons.RateLimited),
        4500 => new ChannelEnd(RelayState.Backoff, ChannelReasons.CenterShuttingDown,
            Delay: reconnectAfterMs is { } after ? TimeSpan.FromMilliseconds(Math.Min(after, MaxReconnectAfter.TotalMilliseconds)) : null),
        4503 => new ChannelEnd(RelayState.Refused, ChannelReasons.KillSwitch),

        // An abnormal close (1006, 1011) is treated like 4500; anything else is a network failure.
        1006 or 1011 => new ChannelEnd(RelayState.Backoff, ChannelReasons.CenterShuttingDown),
        _ => new ChannelEnd(RelayState.Backoff, ChannelReasons.NetworkFailure),
    };

    /// <summary>The loop's next step after a refusal before the upgrade (Plan PN-3: the status and the center's header).</summary>
    public static ChannelEnd Refused(ChannelConnectFailure failure) => failure switch
    {
        ChannelConnectFailure.Unauthenticated => new ChannelEnd(RelayState.Backoff, ChannelReasons.CredentialExpired, RefreshFirst: true),
        ChannelConnectFailure.Refused => new ChannelEnd(RelayState.Refused, ChannelReasons.Refused),
        ChannelConnectFailure.RateLimited => new ChannelEnd(RelayState.Backoff, ChannelReasons.RateLimited),
        _ => new ChannelEnd(RelayState.Backoff, ChannelReasons.NetworkFailure),
    };
}
