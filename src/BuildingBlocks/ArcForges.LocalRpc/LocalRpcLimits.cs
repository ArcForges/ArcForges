// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.LocalRpc;

/// <summary>Transport-level bounds. Call queueing, fairness and overload belong to the bounds layer above.</summary>
public sealed record LocalRpcLimits
{
    /// <summary>The ordinary request/response bound of the private helper profile (4 MiB).</summary>
    public const int DefaultMaxMessageBytes = 4 * 1024 * 1024;

    /// <summary>Largest accepted gRPC message in either direction, 1 KiB through 4 MiB.</summary>
    public int MaxMessageBytes { get; init; } = DefaultMaxMessageBytes;

    /// <summary>Most connections served at once. Further peers wait in the OS backlog and are accepted as slots free; they are never reset.</summary>
    public int MaxConnections { get; init; } = 8;

    /// <summary>Longest wait for an OS stream to connect before a client call sees a transport failure.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Longest wait for in-flight calls to finish when a server stops.</summary>
    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(5);

    internal LocalRpcLimits Validated()
    {
        if (MaxMessageBytes is < 1024 or > DefaultMaxMessageBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxMessageBytes), MaxMessageBytes, "The message bound is 1 KiB through 4 MiB.");
        }

        if (MaxConnections is < 1 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxConnections), MaxConnections, "The connection bound is 1 through 64.");
        }

        if (ConnectTimeout <= TimeSpan.Zero || ConnectTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(ConnectTimeout), ConnectTimeout, "The connect timeout is positive and at most one minute.");
        }

        if (ShutdownTimeout < TimeSpan.Zero || ShutdownTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(ShutdownTimeout), ShutdownTimeout, "The shutdown timeout is zero through one minute.");
        }

        return this;
    }
}
