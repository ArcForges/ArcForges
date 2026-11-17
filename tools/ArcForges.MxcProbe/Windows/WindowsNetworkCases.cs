// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.MxcProbe;

[SupportedOSPlatform("windows")]
internal static class WindowsNetworkCases
{
    private const string Protocol = "MXC-WIN-04";
    private const int WorkloadDeadlineMs = 4000;

    internal static WindowsNetworkChoice SelectedEgress(WindowsNetworkEndpoint endpoint) => EgressRule(endpoint, endpoint.Address);

    private static WindowsNetworkChoice EgressRule(WindowsNetworkEndpoint endpoint, IPAddress permittedAddress) => new(Allow:
    [
        new WindowsPolicyNetworkRule
        {
            To = [new() { Cidr = permittedAddress + "/32" }],
            Ports = [new() { Protocol = endpoint.Protocol, Port = checked((uint)endpoint.Port) }],
        },
    ]);

    internal static IPAddress ControlledAddress()
    {
        // The coordinator explicitly selects an already assigned local address.
        // Never infer a proxy/VPN/NIC, install an address, or silently substitute
        // loopback; local unicast may still be classified as host loopback by PSEC.
        var text = Environment.GetEnvironmentVariable("AFV2_MXC_NETWORK_BIND_ADDRESS");
        Require(IPAddress.TryParse(text, out var address) && address.AddressFamily == AddressFamily.InterNetwork
            && !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any), "controlled_nonloopback_ipv4_address_required");
        Require(NetworkInterface.GetAllNetworkInterfaces().SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
            .Any(item => item.Address.Equals(address)), "controlled_nonloopback_address_not_assigned");
        return address!;
    }

    internal static async Task<List<WindowsQualificationCase>> RunAsync(string stage, string work)
    {
        var results = new List<WindowsQualificationCase>();
        var address = ControlledAddress();
        // UDP on the exact same IP/port distinguishes protocol permission from
        // a port-only allow. Alternate port/IP are owned independent negatives.
        await using var tcp = WindowsNetworkEndpoint.StartTcp(address);
        await using var udp = WindowsNetworkEndpoint.StartUdp(address, tcp.Port);
        await using var otherPort = WindowsNetworkEndpoint.StartTcp(address);
        foreach (var endpoint in new[] { tcp, udp, otherPort })
            await endpoint.CalibrateAsync().ConfigureAwait(false);

        results.Add(await EgressAsync("network-deny-all-tcp", stage, work, tcp, WindowsNetworkChoice.DenyAll, allowed: false).ConfigureAwait(false));
        results.Add(await EgressAsync("network-deny-all-udp", stage, work, udp, WindowsNetworkChoice.DenyAll, allowed: false).ConfigureAwait(false));
        var selectedTcp = SelectedEgress(tcp);
        results.Add(await EgressAsync("network-selected-tcp", stage, work, tcp, selectedTcp, allowed: true).ConfigureAwait(false));
        results.Add(await EgressAsync("network-selected-udp", stage, work, udp, SelectedEgress(udp), allowed: true).ConfigureAwait(false));
        results.Add(await EgressAsync("network-denied-port", stage, work, otherPort, selectedTcp, allowed: false).ConfigureAwait(false));
        results.Add(await EgressAsync("network-denied-protocol", stage, work, udp, selectedTcp, allowed: false).ConfigureAwait(false));
        // Keep the actual controlled destination unchanged, but allow a different
        // CIDR. No connection or binding to an unrelated host is needed.
        results.Add(await EgressAsync("network-denied-address", stage, work, tcp, EgressRule(tcp, IPAddress.Loopback), allowed: false).ConfigureAwait(false));
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
        writer.WriteString("direction", "egress_to_owned_local_nonloopback");
        writer.WriteBoolean("localNonloopbackMayStillBeHostLoopbackClassified", true);
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

// Host-side real sockets. Bind loopback or the coordinator's explicitly selected,
// already assigned IPv4 address. No host network configuration is changed.
[SupportedOSPlatform("windows")]
internal sealed class WindowsNetworkEndpoint : IAsyncDisposable
{
    private static readonly byte[] SentinelBytes = "AFV2_NET_SENTINEL\n"u8.ToArray();
    private readonly TcpListener? _tcp;
    private readonly UdpClient? _udp;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _serve;
    private long _received;
    private long _matched;
    private Exception? _failure;
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

    internal static ReadOnlyMemory<byte> Sentinel => SentinelBytes;
    internal static int SentinelLength => SentinelBytes.Length;
    internal IPAddress Address { get; }
    internal int Port { get; }
    internal string Protocol { get; }
    internal bool CalibrationPassed { get; private set; }
    internal Exception? Failure => Volatile.Read(ref _failure);
    internal WindowsNetworkObservation Observe() => new(Interlocked.Read(ref _received), Interlocked.Read(ref _matched));

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
        RequireHealthy();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        if (_tcp is not null)
        {
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(Address, Port, deadline.Token).ConfigureAwait(false);
            if (await ExchangeAsync(client.GetStream(), deadline.Token).ConfigureAwait(false) != SentinelLength)
                throw new IOException("Host-side controlled TCP endpoint calibration failed.");
        }
        else
        {
            using var client = new UdpClient(AddressFamily.InterNetwork);
            client.Connect(Address, Port);
            _ = await client.SendAsync(Sentinel, deadline.Token).ConfigureAwait(false);
            var reply = await client.ReceiveAsync(deadline.Token).ConfigureAwait(false);
            if (!reply.Buffer.AsSpan().SequenceEqual(Sentinel.Span)) throw new IOException("Host-side controlled UDP endpoint calibration failed.");
        }

        RequireHealthy();
        CalibrationPassed = true;
    }

    internal void RequireHealthy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Failure is { } error) throw new IOException("The owned controlled network endpoint failed.", error);
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
            || (!IPAddress.IsLoopback(address) && !address.Equals(WindowsNetworkCases.ControlledAddress())))
            throw new ArgumentOutOfRangeException(nameof(address), "The fixture binds only loopback or the explicitly selected assigned IPv4 address.");
    }
}
