// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.MxcProbe.Linux;

[SupportedOSPlatform("linux")]
internal static class LinuxNetworkCases
{
    private const int DurationMs = 4000;

    internal static NetworkPolicy Selected(IPAddress address, int port, NetworkProtocol protocol) => new()
    {
        Egress = new NetworkEgressPolicy
        {
            Default = NetworkAction.Deny,
            Allow = [new NetworkRulePolicy
            {
                To = [new NetworkPeerPolicy(address + (address.AddressFamily == AddressFamily.InterNetwork ? "/32" : "/128"))],
                Ports = [new NetworkPortPolicy { Protocol = protocol, Port = checked((ushort)port) }],
            }],
        },
        Ingress = new NetworkIngressPolicy { Default = NetworkAction.Deny, HostLoopback = NetworkAction.Deny },
    };

    internal static async Task<List<LinuxCaseResult>> RunAsync(LinuxOwnerConfiguration config, LinuxEvidence log)
    {
        var results = new List<LinuxCaseResult>();
        string group = LinuxCgroup.ProcessControlGroup(Environment.ProcessId);
        Require(group.EndsWith('/' + config.UnitName, StringComparison.Ordinal), "network_owner_service_identity_mismatch");
        using var scope = LinuxCgroup.Open(group);
        await using var peer = LinuxControlledNetworkPeer.StartIPv4(log);
        await peer.CalibrateAsync("tcp").ConfigureAwait(false);
        await peer.CalibrateAsync("udp").ConfigureAwait(false);
        await peer.CalibrateAsync("tcp", otherTcpPort: true).ConfigureAwait(false);
        log.Phase("network_peer", "host_calibrated", new(StringComparer.Ordinal)
        {
            ["placement"] = "owner_host_namespace_same_service_cgroup",
            ["dataPath"] = "same_h22_local_route_not_cross_machine",
            ["addressSha256"] = AddressHash(peer.Address),
            ["port"] = Number(peer.Port),
            ["otherTcpPort"] = Number(peer.OtherTcpPort),
        });
        var deny = new NetworkPolicy
        {
            Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
            Ingress = new NetworkIngressPolicy { Default = NetworkAction.Deny, HostLoopback = NetworkAction.Deny },
        };
        results.Add(await RunCaseAsync("network_default_deny_tcp", config, log, scope, peer, "tcp-connect", peer.Port, deny, allowed: false, helperMode: false).ConfigureAwait(false));
        if (Unresolved(results)) return results;
        results.Add(await RunCaseAsync("network_default_deny_udp", config, log, scope, peer, "udp-send", peer.Port, deny, allowed: false, helperMode: false).ConfigureAwait(false));
        if (Unresolved(results)) return results;
        var selected = Selected(peer.Address, peer.Port, NetworkProtocol.Tcp);
        var first = await RunCaseAsync("network_selected_tcp", config, log, scope, peer, "tcp-connect", peer.Port, selected, allowed: true, helperMode: true).ConfigureAwait(false);
        results.Add(first);
        if (Unresolved(results) || first.Facts.GetValueOrDefault("failurePhase") == "spawn")
        {
            log.Phase("network_remaining_cases", "not_run", new() { ["reason"] = "selected_spawn_or_cleanup_failed" });
            return results;
        }
        results.Add(await RunCaseAsync("network_selected_udp", config, log, scope, peer, "udp-send", peer.Port,
            Selected(peer.Address, peer.Port, NetworkProtocol.Udp), allowed: true, helperMode: true).ConfigureAwait(false));
        if (Unresolved(results)) return results;
        results.Add(await RunCaseAsync("network_denied_port", config, log, scope, peer, "tcp-connect", peer.OtherTcpPort, selected, allowed: false, helperMode: true).ConfigureAwait(false));
        if (Unresolved(results)) return results;
        results.Add(await RunCaseAsync("network_denied_protocol", config, log, scope, peer, "udp-send", peer.Port, selected, allowed: false, helperMode: true).ConfigureAwait(false));
        if (Unresolved(results)) return results;
        // Same actual destination; the sole allow names another CIDR. This does
        // not confuse an independently denied host-loopback path with IP matching.
        results.Add(await RunCaseAsync("network_denied_address", config, log, scope, peer, "tcp-connect", peer.Port,
            Selected(IPAddress.Loopback, peer.Port, NetworkProtocol.Tcp), allowed: false, helperMode: true).ConfigureAwait(false));
        if (Unresolved(results)) return results;
        results.Add(await RunCaseAsync("network_listener_not_host_reachable", config, log, scope, peer, "tcp-listen",
            UnusedHostPort(peer.Address), deny, allowed: false, helperMode: false, listener: true).ConfigureAwait(false));
        if (Unresolved(results)) return results;
        try
        {
            await using var ipv6 = LinuxControlledNetworkPeer.StartIPv6(log);
            await ipv6.CalibrateAsync("tcp").ConfigureAwait(false);
            results.Add(await RunCaseAsync("network_ipv6_allow_stays_unreachable", config, log, scope, ipv6, "tcp-connect", ipv6.Port,
                Selected(ipv6.Address, ipv6.Port, NetworkProtocol.Tcp), allowed: false, helperMode: true, ipv6: true).ConfigureAwait(false));
        }
        catch (Exception error)
        {
            log.Failure("network_ipv6_host_prerequisite", error);
            results.Add(new("network_ipv6_host_prerequisite", false, new(StringComparer.Ordinal)
            {
                ["status"] = "prerequisite_unavailable_not_a_sandbox_pass",
                ["failureType"] = error.GetType().Name,
                ["failureCode"] = error is LinuxProbeException probe ? probe.Code : "host_ipv6_calibration_failed",
            }));
        }
        return results;
    }

    private static bool Unresolved(List<LinuxCaseResult> results) => results.Any(item => item.Facts.GetValueOrDefault("nativeDispose") == "unresolved");

    private static async Task<LinuxCaseResult> RunCaseAsync(string id, LinuxOwnerConfiguration config, LinuxEvidence log,
        LinuxCgroup scope, LinuxControlledNetworkPeer peer, string mode, int port, NetworkPolicy network,
        bool allowed, bool helperMode, bool listener = false, bool ipv6 = false)
    {
        var facts = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["protocol"] = "MXC-LNX-04",
            ["mode"] = mode,
            ["allowed"] = allowed.ToString(),
            ["networkHelpersRequested"] = helperMode.ToString(),
            ["peerPlacement"] = "host_netns_same_owner_cgroup",
            ["hostCalibrationPassed"] = peer.Calibrated.ToString(),
            ["peerAddressSha256"] = AddressHash(peer.Address),
        };
        var data = Path.Combine(config.Work, id);
        var control = Path.Combine(config.Control, id);
        LinuxSdkSession? session = null;
        var passed = false;
        var phase = "prepare";
        var before = peer.Snapshot();
        try
        {
            log.Phase(id, "begin", facts);
            Require(!Directory.Exists(data) && !Directory.Exists(control), "network_fresh_case_required");
            Directory.CreateDirectory(data, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.CreateDirectory(control, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var initial = scope.Read();
            Require(!initial.Removed && initial.ProcessIds.Length == 1 && initial.ProcessIds[0] == Environment.ProcessId,
                "network_prior_scope_not_reconciled");
            facts["cgroupInode"] = Number(initial.Inode);
            facts["cgroupMountId"] = Number(initial.MountId);
            facts["memoryMaxBytes"] = initial.MemoryMaxBytes?.ToString(CultureInfo.InvariantCulture) ?? "unavailable";
            facts["pidsMax"] = initial.PidsMax?.ToString(CultureInfo.InvariantCulture) ?? "unavailable";
            var address = listener ? IPAddress.Loopback : peer.Address;
            var request = LinuxRequestFactory.Create(Environment.ProcessPath!, ["--linux-workload", "network", mode,
                address.ToString(), Number(port), Number(DurationMs), "gated"], data, control, 30_000);
            request.Network = network;
            phase = "spawn";
            session = LinuxSdkSession.Start(request, terminal: true, log, id);
            facts["sdkProcessId"] = Number(session.ProcessId);
            phase = "namespace_observation";
            _ = await LinuxTerminalCases.WaitForEventAsync(data, "network-ready-for-observation", TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            var announced = await LinuxTerminalCases.WaitForEventAsync(data, "network-namespace", TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            var payload = ObserveNamespaces(scope, announced, helperMode, log, id, facts);
            if (ipv6)
            {
                phase = "ipv6_namespace_routes";
                var configured = File.ReadAllLines($"/proc/{payload.Pid.ToString(CultureInfo.InvariantCulture)}/net/if_inet6")
                    .Select(line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                    .Where(fields => fields.Length == 6 && fields[5] != "lo")
                    .Select(fields => new IPAddress(Convert.FromHexString(fields[0])))
                    .Count(address => !address.IsIPv6LinkLocal && !address.IsIPv6Multicast && !IPAddress.IsLoopback(address));
                facts["ipv6RoutableAddresses"] = Number(configured);
                Require(configured == 0, "selected_namespace_unexpected_ipv6_connectivity");
            }
            phase = "release_fixture";
            await session.WriteInputAsync("continue\n"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            if (listener)
            {
                phase = "host_ingress_attempt";
                _ = await LinuxTerminalCases.WaitForEventAsync(data, "network-ready", TimeSpan.FromSeconds(3)).ConfigureAwait(false);
                Require(LinuxCgroup.ProcessStartTicks(payload.Pid) == payload.StartTicks, "network_listener_identity_lost");
                using var client = new TcpClient(peer.Address.AddressFamily);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                try
                {
                    await client.ConnectAsync(peer.Address, port, deadline.Token).ConfigureAwait(false);
                    throw new LinuxProbeException("sandbox_listener_became_host_reachable");
                }
                catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    facts["hostIngressResult"] = "connection_refused_while_private_listener_alive";
                    facts["hostIngressNativeCode"] = Number(error.NativeErrorCode);
                }
            }
            phase = "native_wait";
            var exit = await session.WaitAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            facts["exitCode"] = Number(exit.ExitCode);
            facts["timedOut"] = exit.TimedOut.ToString();
            facts["exitSource"] = exit.ExitSource;
            Require(!exit.TimedOut && exit.Drained && exit.NativeProcessAbsent, "network_native_wait_or_drain_incomplete");
            phase = "network_effect";
            var events = LinuxTerminalCases.ReadEvents(data);
            var attempts = events.Where(item => Event(item, "network-attempt")).ToArray();
            Require(attempts.Length == 1 && attempts[0].GetProperty("mode").GetString() == mode
                && attempts[0].GetProperty("port").GetInt32() == port
                && attempts[0].GetProperty("addressSha256").GetString() == AddressHash(address), "network_attempt_identity_mismatch");
            var after = peer.Snapshot();
            WriteCounts(facts, before, after, mode, port == peer.OtherTcpPort);
            peer.RequireHealthy();
            if (allowed)
            {
                Require(exit.ExitCode == 0 && events.Any(item => Event(item, "network") && item.GetProperty("replyMatch").GetBoolean()), "network_payload_reply_missing");
                Require(Delta(before, after, mode, port == peer.OtherTcpPort) == (1L, 1L), "network_host_did_not_receive_sentinel");
            }
            else
            {
                Require(Delta(before, after, mode, port == peer.OtherTcpPort) == (0L, 0L), "denied_network_reached_host_peer");
                Require(!events.Any(item => Event(item, "network-received")), "denied_inbound_reached_payload");
                RequireRefusal(events, exit.ExitCode);
            }
            passed = true;
        }
        catch (Exception error)
        {
            facts["failurePhase"] = phase;
            facts["failureType"] = error.GetType().Name;
            facts["failureCode"] = error is LinuxProbeException probe ? probe.Code : "network_operation_failed";
            log.Failure(id + "_" + phase, error);
            if (error is LinuxSdkLaunchException launch) session = launch.CleanupOwner;
        }
        finally
        {
            // Preserve real external counters even when launch or namespace
            // observation failed before a normal outcome was available.
            try { WriteCounts(facts, before, peer.Snapshot(), mode, port == peer.OtherTcpPort); }
            catch (Exception error) { passed = false; log.Failure(id + "_peer_counters", error); }
            if (session is not null)
            {
                try
                {
                    await session.DisposeAsync().ConfigureAwait(false);
                    await RequireOwnerOnlyAsync(scope, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                    facts["nativeDispose"] = "completed_and_only_exact_owner_remains";
                }
                catch (Exception error)
                {
                    passed = false;
                    facts["nativeDispose"] = "unresolved";
                    log.Failure(id + "_cleanup", error, cleanup: true);
                }
            }
        }
        log.Phase(id, passed ? "passed" : "failed", facts);
        return new(id, passed, facts);
    }

    private sealed record ObservedPayload(int Pid, ulong StartTicks);

    private static ObservedPayload ObserveNamespaces(LinuxCgroup scope, JsonElement announced, bool helpers,
        LinuxEvidence log, string id, Dictionary<string, string> facts)
    {
        var ownerNet = NamespaceInode(Environment.ProcessId, "net");
        var payloadNet = announced.GetProperty("netInode").GetUInt64();
        var payloadNsPid = announced.GetProperty("pid").GetInt32();
        Require(payloadNet != ownerNet, "network_host_namespace_fallback_detected");
        var matches = new List<ObservedPayload>();
        var slirp = 0;
        foreach (var pid in scope.Read().ProcessIds)
        {
            try
            {
                var start = LinuxCgroup.ProcessStartTicks(pid);
                var group = LinuxCgroup.ProcessControlGroup(pid);
                Require(group == scope.ControlGroup || group.StartsWith(scope.ControlGroup + '/', StringComparison.Ordinal), "network_descendant_outside_scope");
                var network = NamespaceInode(pid, "net");
                var image = Path.GetFileName(new FileInfo($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/exe").LinkTarget);
                var role = image switch
                {
                    "bwrap" => "bwrap",
                    "slirp4netns" => "slirp4netns",
                    "sh" or "dash" or "bash" => "shell",
                    "ip" or "unshare" or "nsenter" or "xtables-nft-multi" or "xtables-legacy-multi" => "network_setup_helper",
                    "arcforges-mxc-probe" => "probe",
                    _ => "other_owned_process",
                };
                if (role == "slirp4netns") slirp++;
                var status = File.ReadLines($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/status")
                    .SingleOrDefault(line => line.StartsWith("NSpid:", StringComparison.Ordinal));
                Require(status is not null, "network_nspid_unavailable");
                var namespacePid = int.Parse(status!.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[^1], CultureInfo.InvariantCulture);
                if (network == payloadNet && namespacePid == payloadNsPid && role == "probe")
                    matches.Add(new(pid, start));
                Require(LinuxCgroup.ProcessStartTicks(pid) == start, "network_process_identity_changed_during_observation");
                log.Phase(id + "_process", "observed", new(StringComparer.Ordinal)
                {
                    ["hostPid"] = Number(pid),
                    ["startTicks"] = Number(start),
                    ["role"] = role,
                    ["netInode"] = Number(network),
                    ["scopeInode"] = Number(scope.Inode),
                });
            }
            catch (FileNotFoundException) { log.Phase(id + "_process", "gone_before_observation"); }
            catch (DirectoryNotFoundException) { log.Phase(id + "_process", "gone_before_observation"); }
        }
        Require(matches.Count == 1, "network_payload_host_identity_not_unique");
        Require(helpers ? slirp > 0 : slirp == 0, helpers ? "network_slirp_helper_not_observed" : "deny_all_unexpected_slirp_helper");
        facts["ownerNetInode"] = Number(ownerNet);
        facts["payloadNetInode"] = Number(payloadNet);
        facts["payloadHostPid"] = Number(matches[0].Pid);
        facts["payloadStartTicks"] = Number(matches[0].StartTicks);
        facts["slirpProcessesObserved"] = Number(slirp);
        facts["namespaceEvidence"] = "host_proc_and_held_cgroup_not_payload_text_alone";
        return matches[0];
    }

    private static async Task RequireOwnerOnlyAsync(LinuxCgroup scope, TimeSpan timeout)
    {
        var identity = LinuxCgroup.ProcessStartTicks(Environment.ProcessId);
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < timeout)
        {
            var observed = scope.Read();
            if (!observed.Removed && observed.ProcessIds.Length == 1 && observed.ProcessIds[0] == Environment.ProcessId
                && LinuxCgroup.ProcessStartTicks(Environment.ProcessId) == identity) return;
            await Task.Delay(10).ConfigureAwait(false);
        }
        throw new LinuxProbeException("network_helpers_remain_in_owned_scope");
    }

    private static void RequireRefusal(JsonElement[] events, int exit)
    {
        if (exit == 124 && events.Any(item => Event(item, "deadline") && item.GetProperty("reason").GetString() == "fixture-deadline")) return;
        Require(exit == 70, "network_refusal_exit_unexpected");
        var errors = events.Where(item => Event(item, "error")).ToArray();
        Require(errors.Length == 1 && errors[0].GetProperty("errorType").GetString() == nameof(SocketException), "network_refusal_not_a_socket_result");
        Require(errors[0].TryGetProperty("socketErrorCode", out var code)
            && (SocketError)code.GetInt32() is SocketError.AccessDenied or SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.TimedOut or SocketError.AddressFamilyNotSupported,
            "network_refusal_not_policy_or_namespace_result");
    }

    private static (long Received, long Matched) Delta(LinuxNetworkPeerObservation before, LinuxNetworkPeerObservation after, string mode, bool other)
        => mode == "udp-send" ? (after.UdpReceived - before.UdpReceived, after.UdpMatched - before.UdpMatched)
            : other ? (after.OtherTcpAccepted - before.OtherTcpAccepted, after.OtherTcpMatched - before.OtherTcpMatched)
            : (after.TcpAccepted - before.TcpAccepted, after.TcpMatched - before.TcpMatched);

    private static void WriteCounts(Dictionary<string, string> facts, LinuxNetworkPeerObservation before, LinuxNetworkPeerObservation after, string mode, bool other)
    {
        var delta = Delta(before, after, mode, other);
        facts["peerReceivedDelta"] = Number(delta.Received);
        facts["peerMatchedDelta"] = Number(delta.Matched);
    }

    private static int UnusedHostPort(IPAddress address)
    {
        var socket = new TcpListener(address, 0);
        try { socket.Start(1); return ((IPEndPoint)socket.LocalEndpoint).Port; }
        finally { socket.Stop(); }
    }

    private static ulong NamespaceInode(int pid, string name)
    {
        var value = new FileInfo($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/ns/{name}").LinkTarget
            ?? throw new LinuxProbeException("network_namespace_identity_unavailable");
        Require(value.Length < 64 && value.StartsWith(name + ":[", StringComparison.Ordinal) && value.EndsWith(']'), "network_namespace_identity_invalid");
        return ulong.Parse(value.AsSpan(name.Length + 2, value.Length - name.Length - 3), NumberStyles.None, CultureInfo.InvariantCulture);
    }

    private static bool Event(JsonElement item, string name) => item.GetProperty("event").GetString() == name;
    private static string AddressHash(IPAddress address) => Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(address.ToString())));
    private static string Number<T>(T value) where T : IFormattable => value.ToString(null, CultureInfo.InvariantCulture);
    private static void Require(bool condition, string code) { if (!condition) throw new LinuxProbeException(code); }
}

internal sealed record LinuxNetworkPeerObservation(long TcpAccepted, long TcpMatched, long UdpReceived, long UdpMatched,
    long OtherTcpAccepted, long OtherTcpMatched);

// These sockets run in the owner host namespace, on owner threads, in the same
// delegated service cgroup. Only same-host clients receive synthetic replies;
// this is not a public listener service or a cross-machine connectivity test.
[SupportedOSPlatform("linux")]
internal sealed class LinuxControlledNetworkPeer : IAsyncDisposable
{
    private static readonly byte[] Sentinel = "AFV2_NET_SENTINEL\n"u8.ToArray();
    private readonly TcpListener _tcp;
    private readonly TcpListener _other;
    private readonly UdpClient _udp;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task[] _loops;
    private readonly LinuxEvidence _log;
    private long _tcpAccepted, _tcpMatched, _udpReceived, _udpMatched, _otherAccepted, _otherMatched;
    private Exception? _failure;
    private bool _disposed;

    private LinuxControlledNetworkPeer(IPAddress address, LinuxEvidence log)
    {
        Address = address;
        _log = log;
        _tcp = new(address, 0);
        _other = new(address, 0);
        UdpClient? udp = null;
        try
        {
            _tcp.Start(4);
            Port = ((IPEndPoint)_tcp.LocalEndpoint).Port;
            udp = new(new IPEndPoint(address, Port));
            _other.Start(4);
            OtherTcpPort = ((IPEndPoint)_other.LocalEndpoint).Port;
            _udp = udp;
            _loops = [ServeTcpAsync(_tcp, false), ServeTcpAsync(_other, true), ServeUdpAsync()];
        }
        catch { _tcp.Stop(); _other.Stop(); udp?.Dispose(); _stop.Dispose(); throw; }
    }

    internal IPAddress Address { get; }
    internal int Port { get; }
    internal int OtherTcpPort { get; }
    internal bool Calibrated { get; private set; }
    internal LinuxNetworkPeerObservation Snapshot() => new(Interlocked.Read(ref _tcpAccepted), Interlocked.Read(ref _tcpMatched),
        Interlocked.Read(ref _udpReceived), Interlocked.Read(ref _udpMatched), Interlocked.Read(ref _otherAccepted), Interlocked.Read(ref _otherMatched));

    internal static LinuxControlledNetworkPeer StartIPv4(LinuxEvidence log) => Start(AddressFamily.InterNetwork, log);
    internal static LinuxControlledNetworkPeer StartIPv6(LinuxEvidence log) => Start(AddressFamily.InterNetworkV6, log);

    private static LinuxControlledNetworkPeer Start(AddressFamily family, LinuxEvidence log)
    {
        var phase = family == AddressFamily.InterNetwork ? "network_peer_ipv4_start" : "network_peer_ipv6_start";
        try { return new(LocalAddress(family), log); }
        catch (Exception error) { log.Failure(phase, error); throw new LinuxProbeException(phase, error); }
    }

    internal async Task CalibrateAsync(string protocol, bool otherTcpPort = false)
    {
        RequireHealthy();
        var phase = "network_peer_calibration_start";
        var before = Snapshot();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            if (protocol == "tcp")
            {
                using var client = new TcpClient(Address.AddressFamily);
                phase = "network_peer_tcp_connect";
                await client.ConnectAsync(Address, otherTcpPort ? OtherTcpPort : Port, timeout.Token).ConfigureAwait(false);
                phase = "network_peer_tcp_exchange";
                await client.GetStream().WriteAsync(Sentinel, timeout.Token).ConfigureAwait(false);
                var reply = await ReadAsync(client.GetStream(), timeout.Token).ConfigureAwait(false);
                if (!reply.AsSpan().SequenceEqual(Sentinel)) throw new LinuxProbeException("network_peer_tcp_reply_mismatch");
            }
            else if (protocol == "udp")
            {
                using var client = new UdpClient(Address.AddressFamily);
                client.Connect(Address, Port);
                phase = "network_peer_udp_send";
                _ = await client.SendAsync(Sentinel, timeout.Token).ConfigureAwait(false);
                phase = "network_peer_udp_receive";
                var reply = await client.ReceiveAsync(timeout.Token).ConfigureAwait(false);
                if (!reply.Buffer.AsSpan().SequenceEqual(Sentinel)) throw new LinuxProbeException("network_peer_udp_reply_mismatch");
            }
            else throw new ArgumentException("Expected tcp or udp.", nameof(protocol));
            RequireHealthy();
            Calibrated = true;
            _log.Phase(phase, "host_calibrated");
        }
        catch (Exception error) { _log.Failure(phase, error); throw new LinuxProbeException(phase, error); }
        finally
        {
            var after = Snapshot();
            _log.Phase(phase + "_counters", "observed", new(StringComparer.Ordinal)
            {
                ["protocol"] = protocol,
                ["alternateTcpPort"] = otherTcpPort.ToString(),
                ["beforeTcpAccepted"] = before.TcpAccepted.ToString(CultureInfo.InvariantCulture),
                ["afterTcpAccepted"] = after.TcpAccepted.ToString(CultureInfo.InvariantCulture),
                ["beforeTcpMatched"] = before.TcpMatched.ToString(CultureInfo.InvariantCulture),
                ["afterTcpMatched"] = after.TcpMatched.ToString(CultureInfo.InvariantCulture),
                ["beforeUdpReceived"] = before.UdpReceived.ToString(CultureInfo.InvariantCulture),
                ["afterUdpReceived"] = after.UdpReceived.ToString(CultureInfo.InvariantCulture),
                ["beforeUdpMatched"] = before.UdpMatched.ToString(CultureInfo.InvariantCulture),
                ["afterUdpMatched"] = after.UdpMatched.ToString(CultureInfo.InvariantCulture),
                ["beforeOtherTcpAccepted"] = before.OtherTcpAccepted.ToString(CultureInfo.InvariantCulture),
                ["afterOtherTcpAccepted"] = after.OtherTcpAccepted.ToString(CultureInfo.InvariantCulture),
                ["beforeOtherTcpMatched"] = before.OtherTcpMatched.ToString(CultureInfo.InvariantCulture),
                ["afterOtherTcpMatched"] = after.OtherTcpMatched.ToString(CultureInfo.InvariantCulture),
            });
        }
    }

    internal void RequireHealthy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Volatile.Read(ref _failure) is { } error) throw new LinuxProbeException("network_host_peer_failed", error);
    }

    private bool LocalSource(IPEndPoint remote) => remote.Address.Equals(Address) || IPAddress.IsLoopback(remote.Address);

    private async Task ServeTcpAsync(TcpListener listener, bool other)
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                if (!LocalSource((IPEndPoint)client.Client.RemoteEndPoint!)) continue;
                if (other) Interlocked.Increment(ref _otherAccepted); else Interlocked.Increment(ref _tcpAccepted);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(4));
                var bytes = await ReadAsync(client.GetStream(), timeout.Token).ConfigureAwait(false);
                if (bytes.AsSpan().SequenceEqual(Sentinel))
                {
                    if (other) Interlocked.Increment(ref _otherMatched); else Interlocked.Increment(ref _tcpMatched);
                    await client.GetStream().WriteAsync(Sentinel, timeout.Token).ConfigureAwait(false);
                }
            }
        }
        catch (Exception error) when (_stop.IsCancellationRequested && error is OperationCanceledException or ObjectDisposedException or SocketException) { }
        catch (Exception error) { Volatile.Write(ref _failure, error); }
    }

    private async Task ServeUdpAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var packet = await _udp.ReceiveAsync(_stop.Token).ConfigureAwait(false);
                if (!LocalSource(packet.RemoteEndPoint)) continue;
                Interlocked.Increment(ref _udpReceived);
                if (packet.Buffer.AsSpan().SequenceEqual(Sentinel))
                {
                    Interlocked.Increment(ref _udpMatched);
                    _ = await _udp.SendAsync(Sentinel, packet.RemoteEndPoint, _stop.Token).ConfigureAwait(false);
                }
            }
        }
        catch (Exception error) when (_stop.IsCancellationRequested && error is OperationCanceledException or ObjectDisposedException or SocketException) { }
        catch (Exception error) { Volatile.Write(ref _failure, error); }
    }

    private static async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancellation)
    {
        var buffer = new byte[Sentinel.Length];
        var length = 0;
        while (length < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(length), cancellation).ConfigureAwait(false);
            if (count == 0) break;
            length += count;
        }
        return length == buffer.Length ? buffer : buffer[..length];
    }

    private static IPAddress LocalAddress(AddressFamily family)
    {
        var routes = File.ReadAllLines("/proc/net/route");
        if (routes.Length > 256) throw new LinuxProbeException("network_route_observation_bound");
        var interfaces = routes.Skip(1).Select(line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            .Where(fields => fields.Length >= 8 && fields[1] == "00000000" && fields[7] == "00000000")
            .Select(fields => fields[0]).Distinct(StringComparer.Ordinal).ToArray();
        if (interfaces.Length != 1) throw new LinuxProbeException("network_default_interface_not_unique");
        var adapter = NetworkInterface.GetAllNetworkInterfaces().SingleOrDefault(item => item.Name == interfaces[0])
            ?? throw new LinuxProbeException("network_default_interface_unavailable");
        var addresses = adapter.GetIPProperties().UnicastAddresses.Select(item => item.Address)
            .Where(address => address.AddressFamily == family && !IPAddress.IsLoopback(address)
                && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any)
                && !address.IsIPv6LinkLocal && !address.IsIPv6Multicast
                && !(family == AddressFamily.InterNetwork && address.GetAddressBytes()[0] == 169 && address.GetAddressBytes()[1] == 254))
            .Distinct().ToArray();
        if (addresses.Length != 1) throw new LinuxProbeException(family == AddressFamily.InterNetworkV6 ? "network_host_ipv6_peer_unavailable" : "network_host_ipv4_not_unique");
        return addresses[0];
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _stop.Cancel();
        _tcp.Stop();
        _other.Stop();
        _udp.Dispose();
        await Task.WhenAll(_loops).WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        _stop.Dispose();
        _disposed = true;
        _log.Phase("network_peer_cleanup", "owned_sockets_closed");
    }
}
