// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Platform;

/// <summary>
/// The guards' view of the node heartbeat (06 section 5): the heartbeat is stale while its <c>(instance, seq)</c> has not changed for the
/// takeover time, measured on the watcher's own monotonic clock (wall-clock changes do not matter). A node that restarts in a loop
/// renews only once it enforces, so restarts faster than the takeover time leave the guards in charge. The Windows supervisor uses the
/// same rule with 30 s, counting from the node's first heartbeat.
/// </summary>
public sealed class HeartbeatWatch
{
    private readonly string _path;
    private readonly TimeProvider _clock;
    private string? _token;
    private long _changedAt;

    /// <summary>Starts watching; the heartbeat counts as last changed now.</summary>
    public HeartbeatWatch(string path, TimeSpan takeover, TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
        Takeover = takeover;
        _clock = clock ?? TimeProvider.System;
        _changedAt = _clock.GetTimestamp();
        _token = NodeHeartbeat.TryRead(path)?.Token;
        InitialToken = _token;
    }

    /// <summary>The takeover time.</summary>
    public TimeSpan Takeover { get; }

    /// <summary>The heartbeat identity present when watching began (a previous node instance's, or none).</summary>
    public string? InitialToken { get; }

    /// <summary>The last heartbeat read.</summary>
    public NodeHeartbeat? Last { get; private set; }

    /// <summary>True once a heartbeat other than <see cref="InitialToken"/> was seen.</summary>
    public bool SawRenewal { get; private set; }

    /// <summary>How long the heartbeat has not changed.</summary>
    public TimeSpan Age => _clock.GetElapsedTime(_changedAt);

    /// <summary>Whether the heartbeat is stale now.</summary>
    public bool Stale => Age >= Takeover;

    /// <summary>Reads the heartbeat; returns true when it changed since the last poll.</summary>
    public bool Poll()
    {
        var heartbeat = NodeHeartbeat.TryRead(_path);
        if (heartbeat is null)
        {
            // Absent or being replaced: no change.
            return false;
        }

        Last = heartbeat;
        if (string.Equals(heartbeat.Token, _token, StringComparison.Ordinal))
        {
            return false;
        }

        _token = heartbeat.Token;
        _changedAt = _clock.GetTimestamp();
        SawRenewal = true;
        return true;
    }
}
