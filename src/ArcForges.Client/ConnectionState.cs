// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Client;

/// <summary>The state of a client's connection to its node (architecture 12 section 1).</summary>
public enum ConnectionState
{
    /// <summary>The first connection is being opened.</summary>
    Connecting = 0,

    /// <summary>Connected and the client hello succeeded.</summary>
    Connected = 1,

    /// <summary>The connection was lost; reconnecting with backoff (0.5 s to 10 s, jittered).</summary>
    Reconnecting = 2,

    /// <summary>The node is not running (and auto-start is not allowed or failed).</summary>
    NodeStopped = 3,

    /// <summary>The node refused the client's contract major version.</summary>
    Incompatible = 4,

    /// <summary>The node refused the connection (another user, or a peer it could not identify).</summary>
    AccessDenied = 5,
}

/// <summary>Tracks <see cref="ConnectionState"/> and raises <see cref="Changed"/> on every transition.</summary>
public sealed class ConnectionStateTracker
{
    private readonly Lock _gate = new();

    /// <summary>The current state.</summary>
    public ConnectionState State { get; private set; } = ConnectionState.Connecting;

    /// <summary>Raised after the state changed, with the previous and the new state.</summary>
    public event EventHandler<ConnectionStateChange>? Changed;

    /// <summary>Moves to <paramref name="next"/>; returns false when the state was already <paramref name="next"/>.</summary>
    public bool MoveTo(ConnectionState next)
    {
        ConnectionState previous;
        lock (_gate)
        {
            previous = State;
            if (previous == next)
            {
                return false;
            }

            State = next;
        }

        Changed?.Invoke(this, new ConnectionStateChange(previous, next));
        return true;
    }
}

/// <summary>One transition of <see cref="ConnectionStateTracker"/>.</summary>
public sealed record ConnectionStateChange(ConnectionState Previous, ConnectionState Current);

/// <summary>
/// The reconnect schedule of <see cref="ConnectionState.Reconnecting"/>: the ceiling starts at 0.5 s and doubles up to 10 s,
/// and each wait is drawn uniformly between half the ceiling and the ceiling (jitter, so many clients do not reconnect in step).
/// </summary>
public sealed class ReconnectBackoff
{
    /// <summary>The first ceiling (0.5 s).</summary>
    public static readonly TimeSpan Initial = TimeSpan.FromMilliseconds(500);

    /// <summary>The largest ceiling (10 s).</summary>
    public static readonly TimeSpan Maximum = TimeSpan.FromSeconds(10);

    private readonly Func<double> _random;

    /// <summary>Creates a schedule; <paramref name="random"/> returns values in zero through one (tests pin it).</summary>
    public ReconnectBackoff(Func<double>? random = null) => _random = random ?? Random.Shared.NextDouble;

    /// <summary>The ceiling of the wait after the given failed attempt (1 is the first).</summary>
    public static TimeSpan Ceiling(int attempt)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(attempt, 1);
        var ceiling = Initial;
        for (var step = 1; step < attempt && ceiling < Maximum; step++)
        {
            ceiling *= 2;
        }

        return ceiling < Maximum ? ceiling : Maximum;
    }

    /// <summary>The wait after the given failed attempt.</summary>
    public TimeSpan Next(int attempt)
    {
        var ceiling = Ceiling(attempt);
        var draw = Math.Clamp(_random(), 0.0, 1.0);
        return (ceiling / 2) + ((ceiling / 2) * draw);
    }
}
