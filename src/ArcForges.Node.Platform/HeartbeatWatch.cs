// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;

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
    private readonly byte[] _buffer = new byte[1024];
    private readonly byte[] _previous = new byte[1024];
    private int _previousLength;
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

    /// <summary>
    /// Reads the heartbeat; returns true when it changed since the last poll. The file is read into a reused buffer and parsed only when
    /// its bytes changed, so a resident guard polling it several times a second allocates next to nothing while the node runs (15 section
    /// 2: the disk guard's footprint).
    /// </summary>
    public bool Poll()
    {
        int length;
        try
        {
            using var handle = File.OpenHandle(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            length = RandomAccess.Read(handle, _buffer, 0);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Absent or being replaced: no change.
            return false;
        }

        if (length == 0 || length == _buffer.Length)
        {
            // Empty, or larger than any heartbeat this version writes: read it the general way.
            return Accept(NodeHeartbeat.TryRead(_path));
        }

        if (Last is not null && _buffer.AsSpan(0, length).SequenceEqual(_previous.AsSpan(0, _previousLength)))
        {
            return false;
        }

        NodeHeartbeat? heartbeat;
        try
        {
            heartbeat = JsonSerializer.Deserialize(_buffer.AsSpan(0, length), HelperJsonContext.Default.NodeHeartbeat);
        }
        catch (JsonException)
        {
            return false;
        }

        if (heartbeat is not null)
        {
            _buffer.AsSpan(0, length).CopyTo(_previous);
            _previousLength = length;
        }

        return Accept(heartbeat);
    }

    private bool Accept(NodeHeartbeat? heartbeat)
    {
        if (heartbeat is null)
        {
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
