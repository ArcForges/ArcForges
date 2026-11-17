// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.MxcProbe;

[SupportedOSPlatform("windows")]
internal static class WindowsNetworkCases
{
    private const string Protocol = "MXC-WIN-04";
    private const int WorkloadDeadlineMs = 4000;
    // Retain the real control owner if its bounded remote teardown is unresolved.
    internal static WindowsRemoteNetworkPeer? UnresolvedPeer { get; private set; }

    // HostLoopback.allow is an independent native capability and bypasses
    // fine-grained loopback egress rules. External egress uses it denied.
    internal static WindowsNetworkChoice DenyEgress { get; } = WindowsNetworkChoice.DenyAll;

    internal static WindowsNetworkChoice SelectedEgress(WindowsNetworkEndpoint endpoint) => EgressRule(endpoint, endpoint.Address);

    private static WindowsNetworkChoice EgressRule(WindowsNetworkEndpoint endpoint, IPAddress permittedAddress) => new(Allow:
    [
        new WindowsPolicyNetworkRule
        {
            To = [new() { Cidr = permittedAddress + "/32" }],
            Ports = [new() { Protocol = endpoint.Protocol, Port = checked((uint)endpoint.Port) }],
        },
    ]);

    internal static async Task<List<WindowsQualificationCase>> RunAsync(string stage, string work)
    {
        Require(UnresolvedPeer is null, "network_peer_cleanup_already_unresolved");
        WindowsRemoteNetworkPeer? peer = null;
        List<WindowsQualificationCase>? results = null;
        Exception? primary = null;
        // Git-delivered code runs on the designated H22 peer. SSH carries only
        // its trusted control protocol; the contained workload uses TCP/UDP.
        try
        {
            peer = await WindowsRemoteNetworkPeer.StartAsync().ConfigureAwait(false);
            results = await RunCasesAsync(stage, work, peer).ConfigureAwait(false);
        }
        catch (WindowsRemoteNetworkPeerLaunchException error) { UnresolvedPeer = error.CleanupOwner; primary = error; }
        catch (Exception error) { primary = error; }
        if (peer is not null)
        {
            try
            {
                await peer.DisposeAsync().ConfigureAwait(false);
                Require(peer.CleanupConfirmed, "network_peer_cleanup_not_confirmed");
                if (primary is not null) primary.Data["remotePeerFinalCleanupConfirmed"] = true;
            }
            catch (Exception cleanup)
            {
                UnresolvedPeer = peer;
                primary ??= cleanup;
                primary.Data["remotePeerFinalCleanupConfirmed"] = false;
                primary.Data["remotePeerCleanupErrorType"] = cleanup.GetType().Name;
                primary.Data["remotePeerCleanupHResult"] = cleanup.HResult;
            }
        }
        if (primary is not null) ExceptionDispatchInfo.Capture(primary).Throw();
        return results!;
    }

    private static async Task<List<WindowsQualificationCase>> RunCasesAsync(string stage, string work, WindowsRemoteNetworkPeer peer)
    {
        var results = new List<WindowsQualificationCase>();
        // UDP on the exact same IP/port distinguishes protocol permission from
        // a port-only allow. The alternate TCP port is another live H22 endpoint.
        await using var tcp = WindowsNetworkEndpoint.ForRemotePeer(peer, "tcp");
        await using var udp = WindowsNetworkEndpoint.ForRemotePeer(peer, "udp");
        await using var otherPort = WindowsNetworkEndpoint.ForRemotePeer(peer, "tcp", otherTcpPort: true);
        foreach (var endpoint in new[] { tcp, udp, otherPort })
            await endpoint.CalibrateAsync().ConfigureAwait(false);

        results.Add(await EgressAsync("network-deny-all-tcp", stage, work, tcp, DenyEgress, allowed: false).ConfigureAwait(false));
        results.Add(await EgressAsync("network-deny-all-udp", stage, work, udp, DenyEgress, allowed: false).ConfigureAwait(false));
        var selectedTcp = SelectedEgress(tcp);
        results.Add(await EgressAsync("network-selected-tcp", stage, work, tcp, selectedTcp, allowed: true).ConfigureAwait(false));
        results.Add(await EgressAsync("network-selected-udp", stage, work, udp, SelectedEgress(udp), allowed: true).ConfigureAwait(false));
        results.Add(await EgressAsync("network-denied-port", stage, work, otherPort, selectedTcp, allowed: false).ConfigureAwait(false));
        results.Add(await EgressAsync("network-denied-protocol", stage, work, udp, selectedTcp, allowed: false).ConfigureAwait(false));
        // Keep the actual controlled destination unchanged, but allow a different
        // CIDR. No connection or binding to an unrelated host is needed.
        results.Add(await EgressAsync("network-denied-address", stage, work, tcp, EgressRule(tcp, IPAddress.Parse("192.0.2.1")), allowed: false).ConfigureAwait(false));
        // These two cases specifically test the independent host-loopback
        // capability against healthy local sockets, with an exact egress allow.
        await using var localTcp = WindowsNetworkEndpoint.StartTcp(IPAddress.Loopback);
        await using var localUdp = WindowsNetworkEndpoint.StartUdp(IPAddress.Loopback, localTcp.Port);
        await localTcp.CalibrateAsync().ConfigureAwait(false);
        await localUdp.CalibrateAsync().ConfigureAwait(false);
        results.Add(await EgressAsync("network-host-loopback-denied-tcp", stage, work, localTcp,
            SelectedEgress(localTcp), allowed: false).ConfigureAwait(false));
        results.Add(await EgressAsync("network-host-loopback-denied-udp", stage, work, localUdp,
            SelectedEgress(localUdp), allowed: false).ConfigureAwait(false));
        // Host-loopback ingress is separate from selected outbound permission.
        foreach (var transport in new[] { "tcp", "udp" })
        {
            results.Add(await IngressAsync("network-ingress-denied-" + transport, stage, work, transport, allowed: false).ConfigureAwait(false));
            results.Add(await IngressAsync("network-ingress-loopback-" + transport, stage, work, transport, allowed: true).ConfigureAwait(false));
        }

        return results;
    }

    private static async Task<WindowsQualificationCase> EgressAsync(string name, string stage, string work,
        WindowsNetworkEndpoint endpoint, WindowsNetworkChoice choice, bool allowed)
    {
        endpoint.RequireHealthy();
        var before = endpoint.Observe();
        var mode = endpoint.Protocol == "tcp" ? "tcp-connect" : "udp-send";
        var (policy, events) = CreatePolicy(name, stage, work, ["network", mode, endpoint.Address.ToString(),
            endpoint.Port.ToString(CultureInfo.InvariantCulture), WorkloadDeadlineMs.ToString(CultureInfo.InvariantCulture)], choice);
        var result = await WindowsQualification.RunCaseAsync(name, stage, policy, async (session, capture) =>
        {
            var attempt = await capture.WaitForEventAsync("network-attempt", TimeSpan.FromSeconds(8)).ConfigureAwait(false);
            var addressDigest = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(endpoint.Address.ToString())));
            Require(attempt.GetProperty("mode").GetString() == mode && attempt.GetProperty("port").GetInt32() == endpoint.Port
                && attempt.GetProperty("addressSha256").GetString() == addressDigest,
                "controlled_network_attempt_missing");
            if (allowed)
            {
                var reply = await WaitForEgressReplyAsync(capture, mode, TimeSpan.FromSeconds(8)).ConfigureAwait(false);
                Require(reply.GetProperty("mode").GetString() == mode && reply.GetProperty("replyMatch").GetBoolean(), "network_reply_mismatch");
            }
            else
            {
                var exit = await session.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                await RequireNetworkRefusalAsync(capture, exit.RawExitCode).ConfigureAwait(false);
            }

            endpoint.RequireHealthy();
            var after = endpoint.Observe();
            Require(allowed
                    ? after.AcceptedOrReceived == before.AcceptedOrReceived + 1 && after.MatchedRequests == before.MatchedRequests + 1
                    : after.AcceptedOrReceived == before.AcceptedOrReceived && after.MatchedRequests == before.MatchedRequests,
                allowed ? "external_endpoint_did_not_confirm_request" : "denied_traffic_reached_external_endpoint");
        }, expectedExecutorExit: allowed ? 0U : null, fixtureEventsDirectory: events).ConfigureAwait(false);
        result.Protocol = Protocol;
        await AppendObservationAsync(result, policy, endpoint, before, allowed).ConfigureAwait(false);
        return result;
    }

    private static async Task<JsonElement> WaitForEgressReplyAsync(WindowsTerminalCapture capture, string mode, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < timeout)
        {
            foreach (var item in capture.ReadFixtureEvents())
            {
                var name = item.GetProperty("event").GetString();
                if (name == "network" && item.GetProperty("mode").GetString() == mode) return item;
                if (name == "deadline") throw new WindowsQualificationCheckException("selected_egress_fixture_deadline");
                if (name is "error" or "network-observation-failed")
                    throw new WindowsQualificationCheckException(item.TryGetProperty("nativeErrorCode", out var native)
                        && native.GetInt32() == (int)SocketError.AccessDenied
                        ? "selected_egress_socket_access_denied" : "selected_egress_fixture_failed");
            }

            await Task.Delay(10).ConfigureAwait(false);
        }

        throw new WindowsQualificationCheckException("selected_egress_outcome_missing");
    }

    private static async Task RequireNetworkRefusalAsync(WindowsTerminalCapture capture, uint rawExit)
    {
        if (rawExit == 124)
        {
            var deadline = await capture.WaitForEventAsync("deadline", TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            Require(deadline.GetProperty("reason").GetString() == "fixture-deadline", "network_deadline_not_observed");
            return;
        }

        Require(rawExit == 70, "network_denial_exit_unexpected");
        var error = await capture.WaitForEventAsync("error", TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        Require(error.GetProperty("errorType").GetString() == nameof(SocketException)
            && error.TryGetProperty("nativeErrorCode", out var native) && native.GetInt32() == (int)SocketError.AccessDenied,
            "network_denial_not_access_denied");
        // A refused connection, bad address, crashed endpoint or arbitrary fixture
        // failure is not proof that this policy denied network access.
    }

    private static async Task<WindowsQualificationCase> IngressAsync(string name, string stage, string work, string transport, bool allowed)
    {
        // Reserve and release only our own socket to select a port. A bind race
        // in the payload is an actual case failure, never treated as a denial.
        var port = WindowsNetworkEndpoint.UnusedLoopbackPort(transport);
        var mode = transport == "tcp" ? "tcp-listen" : "udp-listen";
        var choice = new WindowsNetworkChoice(HostLoopback: allowed ? "allow" : "deny");
        var (policy, events) = CreatePolicy(name, stage, work, ["network", mode, IPAddress.Loopback.ToString(),
            port.ToString(CultureInfo.InvariantCulture), WorkloadDeadlineMs.ToString(CultureInfo.InvariantCulture)], choice);
        var attempted = false;
        var listenerReady = false;
        var payloadReceived = false;
        var connected = false;
        var replyMatch = false;
        var sentBytes = 0;
        int? nativeError = null;
        var result = await WindowsQualification.RunCaseAsync(name, stage, policy, async (session, capture) =>
        {
            var ready = await capture.WaitForEventAsync("network-ready", TimeSpan.FromSeconds(8)).ConfigureAwait(false);
            Require(ready.GetProperty("mode").GetString() == mode && ready.GetProperty("port").GetInt32() == port, "inbound_listener_not_ready");
            listenerReady = true;
            attempted = true;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                if (transport == "tcp")
                {
                    using var client = new TcpClient(AddressFamily.InterNetwork);
                    await client.ConnectAsync(IPAddress.Loopback, port, deadline.Token).ConfigureAwait(false);
                    connected = true;
                    sentBytes = await WindowsNetworkEndpoint.ExchangeAsync(client.GetStream(), deadline.Token).ConfigureAwait(false);
                    replyMatch = sentBytes == WindowsNetworkEndpoint.SentinelLength;
                }
                else
                {
                    using var client = new UdpClient(AddressFamily.InterNetwork);
                    client.Connect(IPAddress.Loopback, port);
                    sentBytes = await client.SendAsync(WindowsNetworkEndpoint.Sentinel, deadline.Token).ConfigureAwait(false);
                    var reply = await client.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                    replyMatch = reply.Buffer.AsSpan().SequenceEqual(WindowsNetworkEndpoint.Sentinel.Span);
                }
            }
            catch (SocketException error)
            {
                nativeError = error.NativeErrorCode;
                // A ready, live listener rules out accepting arbitrary fixture
                // startup failures. Keep connection-refused as a failure here.
                Require(!allowed && error.SocketErrorCode is SocketError.AccessDenied or SocketError.TimedOut, "inbound_external_socket_failure");
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested && !allowed) { }

            Require(allowed ? replyMatch : !connected && !replyMatch, "inbound_policy_effect_mismatch");
            if (allowed)
            {
                var reply = await capture.WaitForEventAsync("network", TimeSpan.FromSeconds(6)).ConfigureAwait(false);
                Require(reply.GetProperty("mode").GetString() == mode && reply.GetProperty("replyMatch").GetBoolean(), "inbound_payload_did_not_confirm_request");
                payloadReceived = HasInboundReceipt(capture, mode);
                Require(payloadReceived, "inbound_payload_receipt_missing");
            }
            else
            {
                var exit = await session.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                payloadReceived = HasInboundReceipt(capture, mode);
                Require(!payloadReceived, "denied_inbound_reached_payload");
                await RequireNetworkRefusalAsync(capture, exit.RawExitCode).ConfigureAwait(false);
            }
        }, expectedExecutorExit: allowed ? 0U : null, fixtureEventsDirectory: events).ConfigureAwait(false);
        result.Protocol = Protocol;
        await AppendMetadataAsync(result, policy, writer =>
        {
            writer.WriteString("direction", "host_loopback_ingress");
            writer.WriteString("protocol", transport);
            writer.WriteNumber("port", port);
            writer.WriteBoolean("allowed", allowed);
            writer.WriteBoolean("payloadListenerReady", listenerReady);
            writer.WriteBoolean("payloadReceivedBeforeReply", payloadReceived);
            writer.WriteBoolean("hostAttempted", attempted);
            writer.WriteBoolean("tcpConnected", connected);
            writer.WriteNumber("hostSentBytes", sentBytes);
            writer.WriteBoolean("hostReplyMatched", replyMatch);
            if (nativeError is { } error) writer.WriteNumber("hostNativeError", error);
            writer.WriteBoolean("udpSendAloneProvesAdmission", false);
        }).ConfigureAwait(false);
        return result;
    }

    private static bool HasInboundReceipt(WindowsTerminalCapture capture, string mode)
    {
        var events = capture.ReadFixtureEvents();
        // A missing/unreadable/truncated observation log is never evidence of no
        // inbound delivery. The ready marker must still be present in this Run.
        Require(events.Any(value => value.GetProperty("event").GetString() == "network-ready"
            && value.GetProperty("mode").GetString() == mode), "inbound_observation_log_incomplete");
        return events.Any(value => value.GetProperty("event").GetString() == "network-received"
            && value.GetProperty("mode").GetString() == mode);
    }

    private static (WindowsPolicyArtifact Policy, string EventsDirectory) CreatePolicy(string name, string stage, string work, IReadOnlyList<string> args, WindowsNetworkChoice network)
    {
        var root = Path.Combine(work, name);
        Directory.CreateDirectory(root);
        var fixture = Path.Combine(root, "workspace 工作区");
        var paths = new WindowsOwnedPaths(Path.Combine(fixture, "home"), Path.Combine(fixture, "config"), Path.Combine(fixture, "cache"),
            Path.Combine(fixture, "temp"), Path.Combine(fixture, "work"), Path.Combine(fixture, "data"));
        foreach (var path in new[] { paths.Home, paths.Config, paths.Cache, paths.Temp, paths.Work, paths.Data }) Directory.CreateDirectory(path);
        var control = Path.Combine(root, "private control");
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", .. args],
            paths, [stage, Environment.SystemDirectory], [control], network);
        var events = WindowsQualification.EnableFixtureEvents(request, paths.Work);
        return (WindowsPolicy.WritePrivate(control, request), events);
    }

    private static Task AppendObservationAsync(WindowsQualificationCase result, WindowsPolicyArtifact policy,
        WindowsNetworkEndpoint endpoint, WindowsNetworkObservation before, bool allowed) => AppendMetadataAsync(result, policy, writer =>
    {
        var after = endpoint.Observe();
        writer.WriteString("direction", endpoint.IsRemote ? "egress_to_owned_h22_peer" : "egress_to_owned_local_loopback");
        writer.WriteBoolean("peerIsHostLoopback", IPAddress.IsLoopback(endpoint.Address));
        endpoint.WritePeerIdentity(writer);
        writer.WriteString("protocol", endpoint.Protocol);
        writer.WriteString("controlledAddress", endpoint.Address.ToString());
        writer.WriteNumber("port", endpoint.Port);
        writer.WriteBoolean("allowed", allowed);
        writer.WriteBoolean("hostCalibrationPassed", endpoint.CalibrationPassed);
        writer.WriteNumber("beforeAcceptedOrReceived", before.AcceptedOrReceived);
        writer.WriteNumber("afterAcceptedOrReceived", after.AcceptedOrReceived);
        writer.WriteNumber("beforeMatchedRequests", before.MatchedRequests);
        writer.WriteNumber("afterMatchedRequests", after.MatchedRequests);
        writer.WriteBoolean("endpointHealthy", endpoint.Failure is null);
        if (endpoint.Failure is { } error) writer.WriteString("endpointFailureType", error.GetType().Name);
        writer.WriteBoolean("udpSendAloneProvesAdmission", false);
    });

    private static async Task AppendMetadataAsync(WindowsQualificationCase result, WindowsPolicyArtifact policy, Action<Utf8JsonWriter> write)
    {
        try
        {
            using var bytes = new MemoryStream();
            using (var writer = new Utf8JsonWriter(bytes))
            {
                writer.WriteStartObject();
                write(writer);
                writer.WriteEndObject();
            }

            var data = bytes.ToArray();
            const string file = "network-observation.json";
            await using var output = new FileStream(Path.Combine(policy.ControlDirectory, file), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            await output.WriteAsync(data).ConfigureAwait(false);
            result.PrivateDiagnostics.Add(new(file, Convert.ToHexStringLower(SHA256.HashData(data)), data.Length));
        }
        catch (Exception error)
        {
            result.Passed = false;
            result.EvidenceFailure = WindowsQualification.ObserveFailure(error);
        }
    }

    private static void Require(bool condition, string code)
    {
        if (!condition) throw new WindowsQualificationCheckException(code);
    }
}

internal sealed record WindowsNetworkObservation(long AcceptedOrReceived, long MatchedRequests);

// Real local ingress sockets or an actual H22 peer. Remote data does not pass
// through SSH; snapshots are peer counters over its fixed control protocol.
// No host network configuration is changed.
[SupportedOSPlatform("windows")]
internal sealed class WindowsNetworkEndpoint : IAsyncDisposable
{
    private static readonly byte[] SentinelBytes = "AFV2_NET_SENTINEL\n"u8.ToArray();
    private readonly TcpListener? _tcp;
    private readonly UdpClient? _udp;
    private readonly WindowsRemoteNetworkPeer? _remote;
    private readonly bool _otherTcpPort;
    private readonly bool _ownsRemote;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _serve;
    private long _received;
    private long _matched;
    private Exception? _failure;
    private WindowsNetworkObservation? _lastObservation;
    private bool _disposed;

    private WindowsNetworkEndpoint(TcpListener? tcp, UdpClient? udp)
    {
        _tcp = tcp;
        _udp = udp;
        var endpoint = (IPEndPoint)(tcp?.LocalEndpoint ?? udp!.Client.LocalEndPoint!);
        Address = endpoint.Address;
        Port = endpoint.Port;
        Protocol = tcp is null ? "udp" : "tcp";
        _serve = ServeAsync();
    }

    private WindowsNetworkEndpoint(WindowsRemoteNetworkPeer peer, string protocol, bool otherTcpPort, bool ownsRemote)
    {
        _remote = peer;
        _otherTcpPort = otherTcpPort;
        _ownsRemote = ownsRemote;
        Address = peer.Address;
        Port = otherTcpPort ? peer.OtherTcpPort : peer.Port;
        Protocol = protocol;
        _serve = Task.CompletedTask;
    }

    internal static ReadOnlyMemory<byte> Sentinel => SentinelBytes;
    internal static int SentinelLength => SentinelBytes.Length;
    internal IPAddress Address { get; }
    internal int Port { get; }
    internal string Protocol { get; }
    internal bool IsRemote => _remote is not null;
    internal bool PeerCleanupConfirmed => _remote?.CleanupConfirmed ?? _disposed;
    internal bool CalibrationPassed { get; private set; }
    internal Exception? Failure => Volatile.Read(ref _failure);
    internal WindowsNetworkObservation Observe()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_remote is null) return _lastObservation = new(Interlocked.Read(ref _received), Interlocked.Read(ref _matched));
        try
        {
            // Preserve the driver's synchronous observer surface. The serialized
            // peer control exchange itself has a fixed five-second bound.
            var actual = _remote.SnapshotAsync().GetAwaiter().GetResult();
            _lastObservation = Protocol == "udp" ? new(actual.UdpReceived, actual.UdpMatched)
                : _otherTcpPort ? new(actual.OtherTcpAccepted, actual.OtherTcpMatched) : new(actual.TcpAccepted, actual.TcpMatched);
            if (!actual.PeerHealthy) throw new IOException("The actual H-22 peer reported an endpoint failure.");
            return _lastObservation;
        }
        catch (Exception error) { Volatile.Write(ref _failure, error); throw; }
    }

    internal static WindowsNetworkEndpoint ForRemotePeer(WindowsRemoteNetworkPeer peer, string protocol, bool otherTcpPort = false)
    {
        ArgumentNullException.ThrowIfNull(peer);
        if (protocol is not ("tcp" or "udp") || (otherTcpPort && protocol != "tcp"))
            throw new ArgumentException("Expected the controlled TCP/UDP endpoint or its alternate TCP port.", nameof(protocol));
        return new(peer, protocol, otherTcpPort, ownsRemote: false);
    }

    internal static async Task<WindowsNetworkEndpoint> StartControlledTcpAsync()
    {
        var peer = await WindowsRemoteNetworkPeer.StartAsync().ConfigureAwait(false);
        return new(peer, "tcp", otherTcpPort: false, ownsRemote: true);
    }

    internal void WritePeerIdentity(Utf8JsonWriter writer)
    {
        if (_remote is null)
        {
            using var process = Process.GetCurrentProcess();
            writer.WriteNumber("peerProcessId", Environment.ProcessId);
            writer.WriteString("peerProcessStartUtc", process.StartTime.ToUniversalTime());
            writer.WriteString("peerControl", "trusted_driver_owned_sockets");
            writer.WriteString("peerData", "same_windows_loopback_tcp_udp");
            writer.WriteBoolean("peerOutsideProcessContainer", true);
            return;
        }
        writer.WriteNumber("peerProtocolVersion", _remote.ProtocolVersion);
        writer.WriteString("peerSourceSha256", _remote.SourceSha256);
        writer.WriteNumber("peerProcessId", _remote.PeerProcessId);
        writer.WriteString("peerControl", "fixed_h22_ssh_stdio");
        writer.WriteString("peerData", "direct_tcp_udp_no_tunnel");
    }

    internal static WindowsNetworkEndpoint StartTcp(IPAddress address, int port = 0)
    {
        ValidateEndpoint(address, port);
        var listener = new TcpListener(address, port);
        try { listener.Start(4); return new(listener, null); }
        catch { listener.Stop(); throw; }
    }

    internal static WindowsNetworkEndpoint StartUdp(IPAddress address, int port = 0)
    {
        ValidateEndpoint(address, port);
        return new(null, new UdpClient(new IPEndPoint(address, port)));
    }

    internal static int UnusedLoopbackPort(string protocol)
    {
        if (protocol == "tcp")
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            try { listener.Start(1); return ((IPEndPoint)listener.LocalEndpoint).Port; }
            finally { listener.Stop(); }
        }

        if (protocol != "udp") throw new ArgumentException("Expected tcp or udp.", nameof(protocol));
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
    }

    internal async Task CalibrateAsync()
    {
        var phase = "network_calibration_peer_unhealthy";
        WindowsNetworkObservation? before = null;
        var watch = Stopwatch.StartNew();
        var phaseWatch = Stopwatch.StartNew();
        var connectMs = -1L;
        var sendMs = -1L;
        var receiveMs = -1L;
        var sentBytes = 0;
        var receivedBytes = 0;
        IPEndPoint? localEndpoint = null;
        string? localObservationFailure = null;
        CancellationToken ioBudget = default;
        void ObserveLocalEndpoint(Socket socket)
        {
            try { localEndpoint = socket.LocalEndPoint as IPEndPoint; }
            catch (Exception observationError) { localObservationFailure = observationError.GetType().Name; }
        }
        try
        {
            RequireHealthy();
            before = _remote is null ? Observe() : _lastObservation;
            // Preserve the original single three-second I/O budget.
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            ioBudget = deadline.Token;
            if (Protocol == "tcp")
            {
                using var client = new TcpClient(AddressFamily.InterNetwork);
                phase = "network_calibration_tcp_connect";
                phaseWatch.Restart();
                try { await client.ConnectAsync(Address, Port, deadline.Token).ConfigureAwait(false); }
                finally { ObserveLocalEndpoint(client.Client); }
                connectMs = phaseWatch.ElapsedMilliseconds;
                var stream = client.GetStream();
                phase = "network_calibration_tcp_send";
                phaseWatch.Restart();
                await stream.WriteAsync(Sentinel, deadline.Token).ConfigureAwait(false);
                sentBytes = SentinelLength;
                sendMs = phaseWatch.ElapsedMilliseconds;
                phase = "network_calibration_tcp_receive";
                phaseWatch.Restart();
                var received = new byte[SentinelLength];
                while (receivedBytes < received.Length)
                {
                    var count = await stream.ReadAsync(received.AsMemory(receivedBytes), deadline.Token).ConfigureAwait(false);
                    if (count == 0) break;
                    receivedBytes += count;
                }
                receiveMs = phaseWatch.ElapsedMilliseconds;
                phase = "network_calibration_tcp_mismatch";
                phaseWatch.Restart();
                if (receivedBytes != SentinelLength || !received.AsSpan().SequenceEqual(Sentinel.Span))
                    throw new InvalidDataException("Controlled TCP reply differed from the fixed sentinel.");
            }
            else
            {
                using var client = new UdpClient(AddressFamily.InterNetwork);
                phase = "network_calibration_udp_connect";
                phaseWatch.Restart();
                client.Connect(Address, Port);
                ObserveLocalEndpoint(client.Client);
                connectMs = phaseWatch.ElapsedMilliseconds;
                phase = "network_calibration_udp_send";
                phaseWatch.Restart();
                sentBytes = await client.SendAsync(Sentinel, deadline.Token).ConfigureAwait(false);
                sendMs = phaseWatch.ElapsedMilliseconds;
                phase = "network_calibration_udp_receive";
                phaseWatch.Restart();
                var reply = await client.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                receivedBytes = reply.Buffer.Length;
                receiveMs = phaseWatch.ElapsedMilliseconds;
                phase = "network_calibration_udp_mismatch";
                phaseWatch.Restart();
                if (!reply.Buffer.AsSpan().SequenceEqual(Sentinel.Span)) throw new InvalidDataException("Controlled UDP reply differed from the fixed sentinel.");
            }

            phase = "network_calibration_peer_unhealthy";
            RequireHealthy();
            CalibrationPassed = true;
        }
        catch (Exception error)
        {
            var failure = new WindowsQualificationCheckException(phase, error);
            failure.Data["networkCalibrationPhase"] = phase;
            failure.Data["networkCalibrationProtocol"] = Protocol;
            failure.Data["networkCalibrationElapsedMs"] = watch.ElapsedMilliseconds;
            failure.Data["networkCalibrationFailurePhaseElapsedMs"] = phaseWatch.ElapsedMilliseconds;
            failure.Data["networkCalibrationConnectMs"] = connectMs;
            failure.Data["networkCalibrationSendMs"] = sendMs;
            failure.Data["networkCalibrationReceiveMs"] = receiveMs;
            failure.Data["networkCalibrationSentBytes"] = sentBytes;
            failure.Data["networkCalibrationReceivedBytes"] = receivedBytes;
            failure.Data["networkCalibrationIoBudgetMs"] = 3000;
            failure.Data["networkCalibrationIoBudgetExpired"] = ioBudget.IsCancellationRequested;
            failure.Data["networkCalibrationOriginalErrorType"] = error.GetType().Name;
            failure.Data["networkCalibrationOriginalHResult"] = error.HResult;
            failure.Data["networkCalibrationLocalEndpointObserved"] = localEndpoint is not null;
            if (localEndpoint is not null)
            {
                failure.Data["networkCalibrationLocalAddress"] = localEndpoint.Address.ToString();
                failure.Data["networkCalibrationLocalPort"] = localEndpoint.Port;
            }
            if (localObservationFailure is not null) failure.Data["networkCalibrationLocalEndpointErrorType"] = localObservationFailure;
            failure.Data["networkCalibrationBeforeCountersAvailable"] = before is not null;
            if (before is not null)
            {
                failure.Data["networkCalibrationBeforeAcceptedOrReceived"] = before.AcceptedOrReceived;
                failure.Data["networkCalibrationBeforeMatchedRequests"] = before.MatchedRequests;
            }

            // Keep the original failure. A separate fresh snapshot may diagnose
            // delivery, but its own failure is never replaced with zero counts.
            WindowsNetworkObservation? after = null;
            var last = _lastObservation;
            try { after = Observe(); }
            catch (Exception counterError)
            {
                failure.Data["networkCalibrationCounterErrorType"] = counterError.GetType().Name;
                if (!ReferenceEquals(last, _lastObservation)) after = _lastObservation;
            }

            failure.Data["networkCalibrationAfterCountersAvailable"] = after is not null;
            if (after is not null)
            {
                failure.Data["networkCalibrationAfterAcceptedOrReceived"] = after.AcceptedOrReceived;
                failure.Data["networkCalibrationAfterMatchedRequests"] = after.MatchedRequests;
            }

            Exception? original = error;
            for (var depth = 0; original is not null && depth < 3; depth++, original = original.InnerException)
            {
                if (original is Win32Exception native) failure.Data["networkCalibrationNativeErrorCode"] = native.NativeErrorCode;
                if (original is SocketException socket) failure.Data["networkCalibrationSocketErrorCode"] = (int)socket.SocketErrorCode;
            }

            if (_remote is not null)
            {
                failure.Data["networkCalibrationPeerProtocolVersion"] = _remote.ProtocolVersion;
                failure.Data["networkCalibrationPeerSourceSha256"] = _remote.SourceSha256;
                failure.Data["networkCalibrationPeerProcessId"] = _remote.PeerProcessId;
            }

            throw failure;
        }
    }

    internal void RequireHealthy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Failure is { } error) throw new IOException("The owned controlled network endpoint failed.", error);
        if (_remote is not null) _ = Observe();
    }

    private async Task ServeAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                if (_tcp is not null)
                {
                    using var peer = await _tcp.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                    Interlocked.Increment(ref _received);
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                    deadline.CancelAfter(TimeSpan.FromSeconds(10));
                    var data = await ReadSentinelAsync(peer.GetStream(), deadline.Token).ConfigureAwait(false);
                    if (data.AsSpan().SequenceEqual(Sentinel.Span))
                    {
                        Interlocked.Increment(ref _matched);
                        await peer.GetStream().WriteAsync(Sentinel, deadline.Token).ConfigureAwait(false);
                    }
                }
                else
                {
                    var packet = await _udp!.ReceiveAsync(_stop.Token).ConfigureAwait(false);
                    Interlocked.Increment(ref _received);
                    if (packet.Buffer.AsSpan().SequenceEqual(Sentinel.Span))
                    {
                        Interlocked.Increment(ref _matched);
                        _ = await _udp.SendAsync(Sentinel, packet.RemoteEndPoint, _stop.Token).ConfigureAwait(false);
                    }
                }
            }
        }
        catch (Exception error) when (_stop.IsCancellationRequested && error is OperationCanceledException or ObjectDisposedException or SocketException) { }
        catch (Exception error) { Volatile.Write(ref _failure, error); }
    }

    internal static async Task<int> ExchangeAsync(Stream stream, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Sentinel, cancellationToken).ConfigureAwait(false);
        var received = await ReadSentinelAsync(stream, cancellationToken).ConfigureAwait(false);
        return received.AsSpan().SequenceEqual(Sentinel.Span) ? received.Length : 0;
    }

    private static async Task<byte[]> ReadSentinelAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[SentinelLength];
        var received = 0;
        while (received < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(received), cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            received += count;
        }

        return received == buffer.Length ? buffer : buffer[..received];
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        if (_remote is not null)
        {
            // Shared wrappers leave sibling endpoints alive. RunAsync owns their
            // common peer; a combined-run wrapper instead owns its own peer.
            if (_ownsRemote) await _remote.DisposeAsync().ConfigureAwait(false);
            _stop.Dispose();
            _disposed = true;
            return;
        }
        _stop.Cancel();
        _tcp?.Stop();
        _udp?.Dispose();
        await _serve.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        _stop.Dispose();
        _disposed = true;
    }

    private static void ValidateEndpoint(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork || port is < 0 or > 65535
            || !IPAddress.IsLoopback(address))
            throw new ArgumentOutOfRangeException(nameof(address), "The local fixture binds only IPv4 loopback.");
    }
}
