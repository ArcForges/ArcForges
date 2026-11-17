// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.MxcProbe.Linux;

// These are private experiment inputs, never product configuration or receipts.
internal sealed record LinuxLifecycleSetup(string RunId, string OwnerEpoch, string ControllerKey,
    string ObserverKey, string Scenario, string ReadOnlyFile, string ControlFile, string NeighborFile, string OutsideFile)
{
    public override string ToString() => "LinuxLifecycleSetup (capabilities omitted)";
}

internal sealed record LinuxLifecycleReady(string RunId, string OwnerEpoch, int OwnerPid, string BootId,
    ulong OwnerStartTicks, string ControlGroup, ulong CgroupInode, ulong CgroupMountId, string SocketName);
internal sealed record LinuxLifecycleHello(string RunId, string OwnerEpoch, long Generation, string ClientId,
    int ClientPid, ulong ClientStartTicks, bool Observer, string Nonce);
internal sealed record LinuxLifecycleChallenge(string Nonce, string Proof);
internal sealed record LinuxLifecycleProof(string Proof);
internal sealed record LinuxLifecycleRequest(string Operation, long Sequence, int Rows = 24, int Columns = 80, long Cursor = 0);
internal sealed record LinuxLifecycleResponse(bool Ok, string? Error, LinuxLifecycleSnapshot Snapshot, byte[]? Output = null);
internal sealed record LinuxLifecycleSnapshot(string RunId, string OwnerEpoch, int OwnerPid, string BootId,
    ulong OwnerStartTicks, long NodeGeneration, long ControlEpoch, string State, uint? NativePid,
    ulong? NativeStartTicks, double NativeSpawnMs, int? NativeExit, string ExitSource, bool NativeProcessAbsent, bool StreamsDrained,
    bool CleanupConfirmed, bool DataDeletionAllowed, long OutputCursor, bool WriterHeld, long PeerTcpDelta, bool? NetworkReplyMatched);
internal sealed record LinuxLifecycleClientConfiguration(string RunId, string OwnerEpoch, string Key,
    bool Observer, long Generation, string ClientId, LinuxLifecycleReady? Owner, string Boundary,
    string ReadyPath, string LogPath)
{
    public override string ToString() => "LinuxLifecycleClientConfiguration (capability omitted)";
}
internal sealed record LinuxLifecycleClientReady(int ClientPid, ulong ClientStartTicks,
    string Boundary, LinuxLifecycleSnapshot? Snapshot);

// A fixed, bounded P1 experiment channel. Abstract AF_UNIX has no filesystem ACL:
// both endpoints check actual SO_PEERCRED/process creation identity and prove
// possession of distinct controller/observer keys before sending any command.
[SupportedOSPlatform("linux")]
internal static partial class LinuxOwnerChannel
{
    private const int MaximumFrame = 65_536;

    internal static async Task<List<LinuxCaseResult>> RunOwnerAsync(LinuxOwnerConfiguration config, LinuxEvidence log)
    {
        var setupPath = Path.Combine(config.Control, "channel-config.json");
        LinuxCgroup.VerifyPrivatePath(setupPath, false);
        var setup = LinuxQualification.ReadJson(setupPath, LinuxLifecycleJson.Default.LinuxLifecycleSetup);
        Require(setup.RunId == config.RunId && Guid.TryParseExact(setup.OwnerEpoch, "N", out _), "channel_identity_invalid");
        Require(config.Group == "lifecycle_" + setup.Scenario && setup.Scenario is "terminal" or "rootexit" or "persist_write" or "persist_read" or "combined_deny" or "combined_selected", "channel_scenario_invalid");
        Require(Convert.FromBase64String(setup.ControllerKey).Length == 32 && Convert.FromBase64String(setup.ObserverKey).Length == 32
            && setup.ControllerKey != setup.ObserverKey, "channel_keys_invalid");
        await using var owner = new Owner(config, setup, log);
        return await owner.RunAsync().ConfigureAwait(false);
    }

    internal static async Task<int> RunNodeClientAsync(string path)
    {
        LinuxEvidence? log = null;
        try
        {
            LinuxCgroup.VerifyPrivatePath(path, false);
            var config = LinuxQualification.ReadJson(path, LinuxLifecycleJson.Default.LinuxLifecycleClientConfiguration);
            Require(Path.GetDirectoryName(path) == Path.GetDirectoryName(config.ReadyPath)
                && Path.GetDirectoryName(path) == Path.GetDirectoryName(config.LogPath), "node_private_paths_invalid");
            Require(config.Boundary is "prepared" or "scope_created" or "owner_ack" or "native_created" or "active" or "cleaning" or "final" or "center", "node_boundary_invalid");
            log = new LinuxEvidence(config.LogPath, config.RunId);
            log.Phase("node_start", "begin", new() { ["boundary"] = config.Boundary, ["generation"] = Text(config.Generation) });
            LinuxLifecycleSnapshot? snapshot = null;
            await using var client = config.Owner is null ? null : await Client.ConnectAsync(config.Owner, config.Key,
                config.Generation, config.ClientId, config.Observer).ConfigureAwait(false);
            if (client is not null)
            {
                snapshot = (await client.SendAsync("status").ConfigureAwait(false)).Snapshot;
                if (!config.Observer)
                {
                    snapshot = (await client.RequireAsync("bind").ConfigureAwait(false)).Snapshot;
                    if (config.Boundary is "native_created" or "active" or "cleaning" or "final")
                        snapshot = (await client.RequireAsync("start").ConfigureAwait(false)).Snapshot;
                    if (config.Boundary is "active" or "cleaning" or "final")
                        snapshot = (await client.RequireAsync("activate").ConfigureAwait(false)).Snapshot;
                    if (config.Boundary is "cleaning" or "final")
                        snapshot = (await client.RequireAsync("stop").ConfigureAwait(false)).Snapshot;
                    if (config.Boundary == "final")
                        snapshot = (await client.RequireAsync("finalize").ConfigureAwait(false)).Snapshot;
                    if (config.Boundary is "owner_ack" or "native_created" or "active")
                        snapshot = (await client.RequireAsync("acquire").ConfigureAwait(false)).Snapshot;
                }
            }
            else Require(config.Boundary is "prepared" or "scope_created", "node_without_owner_invalid");
            LinuxQualification.WriteJson(config.ReadyPath, new LinuxLifecycleClientReady(Environment.ProcessId,
                LinuxCgroup.ProcessStartTicks(Environment.ProcessId), config.Boundary, snapshot), LinuxLifecycleJson.Default.LinuxLifecycleClientReady);
            log.Phase("node_boundary", "held", new() { ["boundary"] = config.Boundary, ["state"] = snapshot?.State ?? "no_channel" });
            // The external driver kills this actual process. No client owns the
            // SDK lifetime, and closing this connection never disposes the SDK.
            await Task.Delay(TimeSpan.FromSeconds(90)).ConfigureAwait(false);
            return 0;
        }
        catch (Exception error)
        {
            if (log is not null) log.Failure("node_client", error);
            else Console.Error.WriteLine("linux_node_client_failed:type=" + error.GetType().Name + ":hresult=" + error.HResult.ToString("X8", CultureInfo.InvariantCulture));
            return 1;
        }
        finally { log?.Dispose(); }
    }

    internal sealed class Client : IAsyncDisposable
    {
        private readonly Socket _socket;
        private readonly NetworkStream _stream;
        private long _sequence;
        private Client(Socket socket) { _socket = socket; _stream = new NetworkStream(socket, ownsSocket: false); }

        internal static async Task<Client> ConnectAsync(LinuxLifecycleReady owner, string encodedKey, long generation,
            string clientId, bool observer = false)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            Client? client = null;
            byte[] key = [];
            string phase = "arguments";
            try
            {
                Require(Guid.TryParseExact(clientId, "N", out _) && generation is >= 1 and <= 64, "channel_client_identity_invalid");
                phase = "connect";
                await socket.ConnectAsync(new UnixDomainSocketEndPoint("\0" + owner.SocketName), deadline.Token).ConfigureAwait(false);
                // NetworkStream requires an already-connected socket. Construct
                // it only after ConnectAsync, retaining socket cleanup on failure.
                phase = "connected_stream";
                client = new Client(socket);
                phase = "peer_identity";
                var peer = Peer(socket);
                Require(peer.UserId == LinuxCgroup.UserId && peer.ProcessId == owner.OwnerPid
                    && LinuxCgroup.BootId() == owner.BootId && LinuxCgroup.ProcessStartTicks(peer.ProcessId) == owner.OwnerStartTicks,
                    "channel_owner_peer_identity_mismatch");
                key = Convert.FromBase64String(encodedKey);
                Require(key.Length == 32, "channel_client_key_invalid");
                var hello = new LinuxLifecycleHello(owner.RunId, owner.OwnerEpoch, generation, clientId,
                    Environment.ProcessId, LinuxCgroup.ProcessStartTicks(Environment.ProcessId), observer, Nonce());
                phase = "server_challenge";
                await WriteFrameAsync(client._stream, hello, LinuxLifecycleJson.Default.LinuxLifecycleHello, deadline.Token).ConfigureAwait(false);
                var challenge = await ReadFrameAsync(client._stream, LinuxLifecycleJson.Default.LinuxLifecycleChallenge, deadline.Token).ConfigureAwait(false);
                Require(Verify(key, hello, owner, challenge.Nonce, "server", challenge.Proof), "channel_server_proof_invalid");
                phase = "client_proof";
                await WriteFrameAsync(client._stream, new LinuxLifecycleProof(Mac(key, hello, owner, challenge.Nonce, "client")),
                    LinuxLifecycleJson.Default.LinuxLifecycleProof, deadline.Token).ConfigureAwait(false);
                return client;
            }
            catch (Exception primary)
            {
                try
                {
                    if (client is not null) await client.DisposeAsync().ConfigureAwait(false);
                    else socket.Dispose();
                }
                catch (Exception cleanup)
                {
                    throw new LinuxProbeException("channel_" + phase + "_and_cleanup_failed", new AggregateException(primary, cleanup));
                }
                throw new LinuxProbeException("channel_" + phase + "_failed", primary);
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }

        internal async Task<LinuxLifecycleResponse> SendAsync(string operation, int rows = 24, int columns = 80, long cursor = 0)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            await WriteFrameAsync(_stream, new LinuxLifecycleRequest(operation, ++_sequence, rows, columns, cursor),
                LinuxLifecycleJson.Default.LinuxLifecycleRequest, deadline.Token).ConfigureAwait(false);
            return await ReadFrameAsync(_stream, LinuxLifecycleJson.Default.LinuxLifecycleResponse, deadline.Token).ConfigureAwait(false);
        }

        internal async Task<LinuxLifecycleResponse> RequireAsync(string operation, int rows = 24, int columns = 80, long cursor = 0)
        {
            var response = await SendAsync(operation, rows, columns, cursor).ConfigureAwait(false);
            if (!response.Ok) throw new LinuxProbeException(response.Error ?? "channel_operation_rejected");
            return response;
        }

        public async ValueTask DisposeAsync() { await _stream.DisposeAsync().ConfigureAwait(false); _socket.Dispose(); }
    }

    private sealed class Owner : IAsyncDisposable
    {
        private readonly LinuxOwnerConfiguration _config;
        private readonly LinuxLifecycleSetup _setup;
        private readonly LinuxEvidence _log;
        private readonly LinuxCgroup _scope;
        private readonly LinuxLifecycleReady _ready;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly CancellationTokenSource _stop = new(TimeSpan.FromSeconds(180));
        private readonly byte[] _controllerKey;
        private readonly byte[] _observerKey;
        private readonly List<Task> _connections = [];
        private readonly Socket _listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        private LinuxSdkSession? _session;
        private LinuxSdkExit? _exit;
        private uint? _nativePid;
        private ulong? _nativeStartTicks;
        private double _spawnMs;
        private LinuxControlledNetworkPeer? _peer;
        private long _peerBaseline;
        private string _state = "prepared";
        private string? _writer;
        private long _generation;
        private long _controlEpoch;
        private bool _final;
        private bool _failureOutputRecorded;

        internal Owner(LinuxOwnerConfiguration config, LinuxLifecycleSetup setup, LinuxEvidence log)
        {
            _config = config; _setup = setup; _log = log;
            _controllerKey = Convert.FromBase64String(setup.ControllerKey); _observerKey = Convert.FromBase64String(setup.ObserverKey);
            string group = LinuxCgroup.ProcessControlGroup(Environment.ProcessId);
            _scope = LinuxCgroup.Open(group);
            _ready = new(setup.RunId, setup.OwnerEpoch, Environment.ProcessId, LinuxCgroup.BootId(),
                LinuxCgroup.ProcessStartTicks(Environment.ProcessId), group, _scope.Inode, _scope.MountId, "afv2-mxc03-" + setup.RunId);
        }

        internal async Task<List<LinuxCaseResult>> RunAsync()
        {
            _log.Phase("lifecycle_channel", "before_listen");
            _listener.Bind(new UnixDomainSocketEndPoint("\0" + _ready.SocketName));
            _listener.Listen(4);
            LinuxQualification.WriteJson(Path.Combine(_config.Control, "channel-ready.json"), _ready, LinuxLifecycleJson.Default.LinuxLifecycleReady);
            _log.Phase("lifecycle_channel", "ready", new() { ["ownerStartTicks"] = Text(_ready.OwnerStartTicks), ["cgroupInode"] = Text(_ready.CgroupInode) });
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var socket = await _listener.AcceptAsync(_stop.Token).ConfigureAwait(false);
                    _connections.RemoveAll(task => task.IsCompletedSuccessfully);
                    if (_connections.Count >= 8) { socket.Dispose(); _log.Phase("lifecycle_channel", "connection_bound_rejected"); continue; }
                    _connections.Add(ServeAsync(socket));
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            await Task.WhenAll(_connections).ConfigureAwait(false);
            return [new LinuxCaseResult("LNX05-owner-channel", _final,
                new() { ["state"] = _state, ["ownerStartTicks"] = Text(_ready.OwnerStartTicks), ["nodeGeneration"] = Text(_generation) })];
        }

        private async Task ServeAsync(Socket socket)
        {
            using (socket)
            await using (var stream = new NetworkStream(socket, ownsSocket: false))
            {
                string? clientId = null;
                try
                {
                    using var authentication = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                    authentication.CancelAfter(TimeSpan.FromSeconds(5));
                    var peer = Peer(socket);
                    var hello = await ReadFrameAsync(stream, LinuxLifecycleJson.Default.LinuxLifecycleHello, authentication.Token).ConfigureAwait(false);
                    Require(peer.UserId == LinuxCgroup.UserId && peer.ProcessId == hello.ClientPid
                        && LinuxCgroup.ProcessStartTicks(peer.ProcessId) == hello.ClientStartTicks,
                        "channel_client_peer_identity_mismatch");
                    Require(hello.RunId == _ready.RunId && hello.OwnerEpoch == _ready.OwnerEpoch
                        && Guid.TryParseExact(hello.ClientId, "N", out _) && hello.Generation is >= 1 and <= 64
                        && IsNonce(hello.Nonce), "channel_hello_identity_mismatch");
                    var key = hello.Observer ? _observerKey : _controllerKey;
                    var nonce = Nonce();
                    await WriteFrameAsync(stream, new LinuxLifecycleChallenge(nonce, Mac(key, hello, _ready, nonce, "server")),
                        LinuxLifecycleJson.Default.LinuxLifecycleChallenge, authentication.Token).ConfigureAwait(false);
                    var proof = await ReadFrameAsync(stream, LinuxLifecycleJson.Default.LinuxLifecycleProof, authentication.Token).ConfigureAwait(false);
                    Require(Verify(key, hello, _ready, nonce, "client", proof.Proof), "channel_client_proof_invalid");
                    clientId = hello.ClientId;
                    _log.Phase("lifecycle_authentication", "authenticated", new() { ["clientPid"] = Text(peer.ProcessId), ["clientStartTicks"] = Text(hello.ClientStartTicks), ["observer"] = hello.Observer.ToString() });
                    long sequence = 0;
                    for (int count = 0; count < 64 && !_stop.IsCancellationRequested; count++)
                    {
                        var request = await ReadFrameAsync(stream, LinuxLifecycleJson.Default.LinuxLifecycleRequest, _stop.Token).ConfigureAwait(false);
                        Require(request.Sequence == ++sequence, "channel_sequence_invalid");
                        var response = await ExecuteAsync(hello, request).ConfigureAwait(false);
                        await WriteFrameAsync(stream, response, LinuxLifecycleJson.Default.LinuxLifecycleResponse, _stop.Token).ConfigureAwait(false);
                        if (request.Operation == "quit" && response.Ok) { await _stop.CancelAsync().ConfigureAwait(false); break; }
                    }
                }
                catch (Exception error) when (error is IOException or SocketException or OperationCanceledException or LinuxProbeException or InvalidDataException or JsonException)
                {
                    if (error is not EndOfStreamException && error is not OperationCanceledException)
                        _log.Failure("lifecycle_connection", error);
                }
                finally
                {
                    await _gate.WaitAsync().ConfigureAwait(false);
                    try { if (_writer == clientId) { _writer = null; _log.Phase("lifecycle_writer", "disconnected"); } }
                    finally { _gate.Release(); }
                }
            }
        }

        private async Task<LinuxLifecycleResponse> ExecuteAsync(LinuxLifecycleHello hello, LinuxLifecycleRequest request)
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                _log.Phase("lifecycle_command", "begin", new() { ["operation"] = SafeOperation(request.Operation), ["generation"] = Text(hello.Generation), ["state"] = _state });
                if (request.Operation is "status" or "read") return Response(true, null, request.Operation == "read" ? ReadOutput(request.Cursor) : null);
                if (hello.Observer) return Response(false, "observer_mutation_denied");
                if (request.Operation == "bind")
                {
                    if (_writer is not null && _writer != hello.ClientId) return Response(false, "writer_busy");
                    if (hello.Generation < _generation) return Response(false, "stale_node_generation");
                    if (hello.Generation > _generation) { _generation = hello.Generation; _controlEpoch++; _writer = null; }
                    return Response(true);
                }
                if (hello.Generation != _generation) return Response(false, "stale_node_generation");
                switch (request.Operation)
                {
                    case "start":
                        if (_state != "prepared") return Response(false, "start_already_consumed");
                        await StartAsync().ConfigureAwait(false); break;
                    case "activate":
                        if (_session is null) return Response(false, "native_session_absent");
                        string marker = _setup.Scenario.StartsWith("persist_", StringComparison.Ordinal) ? "persistence"
                            : _setup.Scenario == "rootexit" ? "root-exit-with-child" : "terminal-ready";
                        _ = await LinuxTerminalCases.WaitForEventAsync(_config.Work, marker, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                        _state = "active"; break;
                    case "acquire":
                        if (_writer is not null && _writer != hello.ClientId) return Response(false, "writer_busy");
                        _writer = hello.ClientId; break;
                    case "resize":
                        if (_writer != hello.ClientId || _session is null) return Response(false, "writer_required");
                        if (request.Rows is < 1 or > 500 || request.Columns is < 1 or > 500) return Response(false, "dimensions_invalid");
                        _session.Resize(request.Rows, request.Columns); break;
                    case "input_q":
                        if (_writer != hello.ClientId || _session is null) return Response(false, "writer_required");
                        await _session.WriteInputAsync("q"u8.ToArray(), TimeSpan.FromSeconds(3)).ConfigureAwait(false); break;
                    case "detach":
                        if (_writer != hello.ClientId) return Response(false, "writer_required");
                        _writer = null; break;
                    case "stop":
                        await StopNativeAsync().ConfigureAwait(false); break;
                    case "finish_natural":
                        if (_session is null) return Response(false, "native_session_absent");
                        _exit = await _session.WaitAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                        if (_exit.TimedOut) { RecordFailureOutput("lifecycle_natural_exit"); return Response(false, "natural_exit_deadline"); }
                        await _session.DisposeAsync().ConfigureAwait(false); _session = null; _state = "cleaning"; break;
                    case "finalize":
                        if (!OnlyOwnerRemains() || _session is not null || _exit is null) { _state = "recovery_required"; return Response(false, "cleanup_unresolved"); }
                        _peer?.RequireHealthy();
                        _state = "final"; _final = true; break;
                    case "quit":
                        if (!_final) return Response(false, "final_record_required"); break;
                    case "delete_candidate":
                        if (!_final) return Response(false, "cleanup_unresolved");
                        File.Delete(Path.Combine(_config.Work, "deletion-candidate.txt")); break;
                    default: return Response(false, "operation_unsupported");
                }
                SaveState();
                _log.Phase("lifecycle_command", "completed", new() { ["operation"] = request.Operation, ["state"] = _state });
                return Response(true);
            }
            catch (Exception error)
            {
                _log.Failure("lifecycle_command_" + SafeOperation(request.Operation), error);
                RecordFailureOutput("lifecycle_command_" + SafeOperation(request.Operation));
                _state = "recovery_required";
                SaveState();
                return Response(false, error is LinuxProbeException probe ? probe.Code : "native_operation_failed");
            }
            finally { _gate.Release(); }
        }

        private async Task StartAsync()
        {
            string[] args;
            if (_setup.Scenario.StartsWith("combined_", StringComparison.Ordinal))
            {
                _peer = LinuxControlledNetworkPeer.StartIPv4(_log);
                await _peer.CalibrateAsync("tcp").ConfigureAwait(false);
                _peerBaseline = _peer.Snapshot().TcpMatched;
                args = ["--linux-workload", "combined", "30000", "32", "2", _peer.Address.ToString(), Text(_peer.Port),
                    Path.Combine(_config.Work, "writable.txt"), _setup.ReadOnlyFile, _setup.ControlFile, _setup.NeighborFile, _setup.OutsideFile];
            }
            else if (_setup.Scenario == "rootexit") args = ["--linux-workload", "root-exit-child", "10000", "1500"];
            else if (_setup.Scenario.StartsWith("persist_", StringComparison.Ordinal)) args = ["--linux-workload", "persistence", _setup.Scenario == "persist_write" ? "write" : "read", Path.Combine(_config.Work, "persistent-sentinel.txt")];
            else args = ["--linux-workload", "terminal", "raw", "30000"];
            var request = LinuxRequestFactory.Create(Path.Combine(AppContext.BaseDirectory, "arcforges-mxc-probe"), args, _config.Work, _config.Control, 60_000);
            if (_setup.Scenario.StartsWith("combined_", StringComparison.Ordinal))
            {
                request.Filesystem!.ReadonlyPaths.Add(Path.GetDirectoryName(_setup.ReadOnlyFile)!);
                if (_setup.Scenario == "combined_selected") request.Network = LinuxNetworkCases.Selected(_peer!.Address, _peer.Port, NetworkProtocol.Tcp);
            }
            _state = "starting"; SaveState();
            _failureOutputRecorded = false;
            try { _session = LinuxSdkSession.Start(request, true, _log, "lifecycle_sdk"); }
            catch (LinuxSdkLaunchException error)
            {
                // Keep the actual unresolved owner reachable for diagnostics
                // and cleanup; a failed assignment must not discard its handles.
                _session = error.CleanupOwner;
                RecordFailureOutput("lifecycle_native_start");
                throw;
            }
            _nativePid = _session.ProcessId;
            _spawnMs = _session.SpawnMs;
            try { _nativeStartTicks = LinuxCgroup.ProcessStartTicks(checked((int)_nativePid.Value)); }
            catch (Exception error) when (error is LinuxProbeException or IOException or Win32Exception)
            { _log.Failure("lifecycle_native_start_identity", error); }
            SaveState();
        }

        private async Task StopNativeAsync()
        {
            if (_session is null) { if (_exit is not null) { _state = "cleaning"; return; } throw new LinuxProbeException("native_session_absent"); }
            if (_state == "recovery_required") RecordFailureOutput("lifecycle_native_recovery");
            _state = "cleaning"; SaveState();
            Exception? primary = null;
            Exception? disposalFailure = null;
            try { _exit = await _session.StopAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false); }
            catch (Exception error) { primary = error; _log.Failure("lifecycle_native_stop", error); RecordFailureOutput("lifecycle_native_stop"); }
            try { await _session.DisposeAsync().ConfigureAwait(false); _session = null; }
            catch (Exception cleanup) { disposalFailure = cleanup; _log.Failure("lifecycle_native_dispose", cleanup, cleanup: true); RecordFailureOutput("lifecycle_native_dispose"); }
            if (primary is not null && disposalFailure is not null)
                throw new LinuxProbeException("native_stop_and_dispose_failed", new AggregateException(primary, disposalFailure));
            if (primary is not null) throw new LinuxProbeException("native_stop_failed", primary);
            if (disposalFailure is not null) throw new LinuxProbeException("native_dispose_failed", disposalFailure);
        }

        private void RecordFailureOutput(string phase)
        {
            if (_session is null || _failureOutputRecorded) return;
            _failureOutputRecorded = true;
            // Only these fixed synthetic qualification fixtures use this owner.
            // Private bounded bytes are diagnostic input, never trusted state.
            foreach (bool stderr in new[] { false, true })
            {
                try
                {
                    var page = _session.ReadOutput(0, 32_768, stderr);
                    _log.Detail(phase + "/failure_output", stderr ? "lifecycle_stderr" : "lifecycle_stdout", page.Data);
                    _log.Phase(phase + "/failure_output", "bounded_snapshot_before_dispose", new(StringComparer.Ordinal)
                    {
                        ["stream"] = stderr ? "stderr" : "stdout",
                        ["startSequence"] = Text(page.StartSequence),
                        ["nextSequence"] = Text(page.NextSequence),
                        ["availableFrom"] = Text(page.AvailableFrom),
                        ["availableUntil"] = Text(page.AvailableUntil),
                        ["gapFrom"] = page.GapFrom is { } from ? Text(from) : "none",
                        ["gapUntil"] = page.GapUntil is { } until ? Text(until) : "none",
                        ["endOfStream"] = page.EndOfStream.ToString(CultureInfo.InvariantCulture),
                        ["drainFailureCode"] = page.FailureCode ?? "none",
                    });
                }
                catch (Exception evidenceError) { _log.Failure(phase + "/failure_output", evidenceError); }
            }
        }

        private bool OnlyOwnerRemains()
        {
            var current = _scope.Read();
            return !current.Removed && current.ProcessIds.SequenceEqual([Environment.ProcessId]);
        }

        private byte[] ReadOutput(long cursor)
        {
            if (cursor < 0 || _session is null) return [];
            return _session.ReadOutput(cursor, 4096).Data;
        }

        private LinuxLifecycleSnapshot Snapshot()
        {
            long cursor = _session?.ReadOutput(0, 1).AvailableUntil ?? _exit?.StdoutBytes ?? 0;
            bool? matched = null;
            if (_setup.Scenario.StartsWith("combined_", StringComparison.Ordinal) && Directory.Exists(Path.Combine(_config.Work, "observations")))
            {
                try
                {
                    var events = LinuxTerminalCases.ReadEvents(_config.Work);
                    foreach (var item in events)
                        if (item.GetProperty("event").GetString() == "network") matched = item.GetProperty("replyMatch").GetBoolean();
                }
                catch (Exception error) when (error is IOException or JsonException or LinuxProbeException)
                { _log.Phase("lifecycle_payload_observation", "unavailable", new() { ["type"] = error.GetType().Name }); }
            }
            return new(_setup.RunId, _setup.OwnerEpoch, _ready.OwnerPid, _ready.BootId, _ready.OwnerStartTicks,
                _generation, _controlEpoch, _state, _nativePid, _nativeStartTicks, _spawnMs, _exit?.ExitCode, _exit?.ExitSource ?? "unknown",
                _exit?.NativeProcessAbsent ?? false, _exit?.Drained ?? false, _final, _final, cursor, _writer is not null,
                (_peer?.Snapshot().TcpMatched ?? 0) - _peerBaseline, matched);
        }

        private LinuxLifecycleResponse Response(bool ok, string? error = null, byte[]? output = null) => new(ok, error, Snapshot(), output);

        private void SaveState()
        {
            // No key, lease, terminal input or acknowledgement is persisted.
            var path = Path.Combine(_config.Control, "lifecycle-state.json");
            var temporary = path + "." + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture) + ".pending";
            LinuxQualification.WriteJson(temporary, Snapshot(), LinuxLifecycleJson.Default.LinuxLifecycleSnapshot);
            File.Move(temporary, path, overwrite: true);
        }

        public async ValueTask DisposeAsync()
        {
            Exception? nativeFailure = null;
            Exception? peerFailure = null;
            try
            {
                await _stop.CancelAsync().ConfigureAwait(false);
                _listener.Dispose();
                if (_session is not null)
                {
                    try { await StopNativeAsync().ConfigureAwait(false); }
                    catch (Exception cleanup) { nativeFailure = cleanup; _log.Failure("lifecycle_owner_dispose", cleanup, cleanup: true); }
                }
                if (_peer is not null)
                {
                    try { await _peer.DisposeAsync().ConfigureAwait(false); }
                    catch (Exception cleanup) { peerFailure = cleanup; _log.Failure("lifecycle_peer_dispose", cleanup, cleanup: true); }
                }
            }
            finally
            {
                _scope.Dispose(); _gate.Dispose(); _stop.Dispose();
                CryptographicOperations.ZeroMemory(_controllerKey); CryptographicOperations.ZeroMemory(_observerKey);
            }
            if (nativeFailure is not null && peerFailure is not null)
                throw new LinuxProbeException("owner_native_and_peer_cleanup_failed", new AggregateException(nativeFailure, peerFailure));
            if (nativeFailure is not null) throw new LinuxProbeException("owner_native_cleanup_failed", nativeFailure);
            if (peerFailure is not null) throw new LinuxProbeException("owner_peer_cleanup_failed", peerFailure);
        }
    }

    private static string SafeOperation(string operation) => operation is "status" or "read" or "bind" or "start" or "activate" or "acquire" or "resize" or "input_q" or "detach" or "stop" or "finish_natural" or "finalize" or "quit" or "delete_candidate" ? operation : "unsupported";
    private static string Text<T>(T value) where T : IFormattable => value.ToString(null, CultureInfo.InvariantCulture);
    private static string Nonce() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static bool IsNonce(string value) { Span<byte> bytes = stackalloc byte[32]; return value.Length == 44 && Convert.TryFromBase64String(value, bytes, out var length) && length == 32; }
    private static string Mac(byte[] key, LinuxLifecycleHello hello, LinuxLifecycleReady owner, string nonce, string side)
    {
        var value = string.Join('\n', "afv2-linux-lifecycle-r1", side, hello.RunId, hello.OwnerEpoch, Text(hello.Generation), hello.ClientId,
            Text(hello.ClientPid), Text(hello.ClientStartTicks), hello.Observer ? "observer" : "controller", hello.Nonce,
            owner.BootId, Text(owner.OwnerPid), Text(owner.OwnerStartTicks), Text(owner.CgroupInode), Text(owner.CgroupMountId), nonce);
        return Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
    }
    private static bool Verify(byte[] key, LinuxLifecycleHello hello, LinuxLifecycleReady owner, string nonce, string side, string proof)
    {
        Span<byte> given = stackalloc byte[32];
        return IsNonce(nonce) && Convert.TryFromBase64String(proof, given, out var count) && count == 32
            && CryptographicOperations.FixedTimeEquals(given, Convert.FromBase64String(Mac(key, hello, owner, nonce, side)));
    }

    private static PeerCredentials Peer(Socket socket)
    {
        uint length = 12;
        bool held = false;
        try
        {
            socket.SafeHandle.DangerousAddRef(ref held);
            if (GetPeerCredentials(socket.SafeHandle.DangerousGetHandle().ToInt32(), 1, 17, out var peer, ref length) != 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Reading the native Unix peer identity failed.");
            Require(length == 12, "channel_peer_identity_size_invalid");
            return peer;
        }
        finally { if (held) socket.SafeHandle.DangerousRelease(); }
    }

    private static async Task WriteFrameAsync<T>(Stream stream, T value, JsonTypeInfo<T> type, CancellationToken token)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, type);
        Require(bytes.Length is > 0 and <= MaximumFrame, "channel_frame_bound");
        var prefix = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(prefix, bytes.Length);
        await stream.WriteAsync(prefix, token).ConfigureAwait(false); await stream.WriteAsync(bytes, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }
    private static async Task<T> ReadFrameAsync<T>(Stream stream, JsonTypeInfo<T> type, CancellationToken token)
    {
        var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        Require(length is > 0 and <= MaximumFrame, "channel_frame_bound");
        var bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        return JsonSerializer.Deserialize(bytes, type) ?? throw new LinuxProbeException("channel_null_frame");
    }
    private static void Require(bool value, string code) { if (!value) throw new LinuxProbeException(code); }
    [StructLayout(LayoutKind.Sequential)] private struct PeerCredentials { internal int ProcessId; internal uint UserId, GroupId; }
    [LibraryImport("libc", EntryPoint = "getsockopt", SetLastError = true)] private static partial int GetPeerCredentials(int descriptor, int level, int option, out PeerCredentials peer, ref uint length);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(LinuxLifecycleSetup))]
[JsonSerializable(typeof(LinuxLifecycleReady))]
[JsonSerializable(typeof(LinuxLifecycleHello))]
[JsonSerializable(typeof(LinuxLifecycleChallenge))]
[JsonSerializable(typeof(LinuxLifecycleProof))]
[JsonSerializable(typeof(LinuxLifecycleRequest))]
[JsonSerializable(typeof(LinuxLifecycleResponse))]
[JsonSerializable(typeof(LinuxLifecycleSnapshot))]
[JsonSerializable(typeof(LinuxLifecycleClientConfiguration))]
[JsonSerializable(typeof(LinuxLifecycleClientReady))]
internal sealed partial class LinuxLifecycleJson : JsonSerializerContext;
