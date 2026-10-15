// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Text;
using ArcForges.Client;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// The service manager's notification socket (<c>sd_notify</c>, used by the <c>Type=notify</c> user unit of 13 section 3.4):
/// <c>READY=1</c> once the node is ready, <c>WATCHDOG=1</c> pings and <c>STOPPING=1</c> at shutdown. Without <c>NOTIFY_SOCKET</c>
/// (not started by systemd) every call does nothing.
/// </summary>
public sealed class SystemdNotifier : IDisposable
{
    private readonly Socket? _socket;
    private readonly UnixDomainSocketEndPoint? _target;

    private SystemdNotifier(Socket? socket, UnixDomainSocketEndPoint? target)
    {
        _socket = socket;
        _target = target;
    }

    /// <summary>True when systemd asked for notifications.</summary>
    public bool Enabled => _socket is not null;

    /// <summary>The watchdog interval systemd expects pings within, or <see langword="null"/> when it set none.</summary>
    public TimeSpan? WatchdogInterval { get; private init; }

    /// <summary>Opens the notification socket named by <c>NOTIFY_SOCKET</c>, if any.</summary>
    public static SystemdNotifier FromEnvironment()
    {
        if (OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("NOTIFY_SOCKET") is not { Length: > 1 } address)
        {
            return new SystemdNotifier(null, null);
        }

        // An abstract socket is written with a leading '@'.
        var path = address[0] == '@' ? "\0" + address[1..] : address;
        var socket = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
        TimeSpan? watchdog = null;
        if (long.TryParse(Environment.GetEnvironmentVariable("WATCHDOG_USEC"), out var microseconds) && microseconds > 0
            && (Environment.GetEnvironmentVariable("WATCHDOG_PID") is not { Length: > 0 } pid || pid == Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)))
        {
            watchdog = TimeSpan.FromTicks(microseconds * 10);
        }

        return new SystemdNotifier(socket, new UnixDomainSocketEndPoint(path)) { WatchdogInterval = watchdog };
    }

    /// <summary>Sends one notification (for example <c>READY=1</c>); failures are ignored, as with <c>sd_notify</c>.</summary>
    public void Notify(string state)
    {
        if (_socket is null || _target is null)
        {
            return;
        }

        try
        {
            _socket.SendTo(Encoding.UTF8.GetBytes(state), _target);
        }
        catch (SocketException)
        {
        }
    }

    /// <inheritdoc />
    public void Dispose() => _socket?.Dispose();
}

/// <summary>
/// The Windows readiness event <c>Local\ArcForges.Node.&lt;hash&gt;.Ready</c> (02 section 2 step 9): a manual-reset event the node sets
/// when it is ready and resets when it stops, so a client that started it can wait for readiness without polling.
/// </summary>
public sealed class WindowsReadyEvent : IDisposable
{
    private readonly EventWaitHandle _event;

    private WindowsReadyEvent(EventWaitHandle handle) => _event = handle;

    /// <summary>Creates (or opens) the event of this node instance, not set (Windows only: named events).</summary>
    public static WindowsReadyEvent Create(string instanceKey)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The readiness event is the Windows mechanism; Linux uses sd_notify.");
        }

        var handle = new EventWaitHandle(false, EventResetMode.ManualReset, NodeLocations.NodeReadyEventName(instanceKey));
        handle.Reset();
        return new WindowsReadyEvent(handle);
    }

    /// <summary>Signals readiness.</summary>
    public void Set() => _event.Set();

    /// <summary>Clears readiness (the node is stopping).</summary>
    public void Reset() => _event.Reset();

    /// <inheritdoc />
    public void Dispose() => _event.Dispose();
}
