// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.MxcProbe;

internal sealed record WindowsRemoteNetworkSnapshot(long TcpAccepted, long TcpMatched, long UdpReceived, long UdpMatched,
    long OtherTcpAccepted, long OtherTcpMatched, bool PeerHealthy, string? ErrorCode);

internal sealed class WindowsRemoteNetworkPeerLaunchException(Exception startup, Exception cleanup, WindowsRemoteNetworkPeer cleanupOwner)
    : Exception("Controlled peer startup failed and its SSH ownership remains unresolved.", new AggregateException(startup, cleanup))
{
    internal WindowsRemoteNetworkPeer CleanupOwner { get; } = cleanupOwner;
}

// The trusted experiment driver owns this SSH control process. This is a fixed
// socket peer, never an alternate Linux verification venue or an SSH tunnel.
[SupportedOSPlatform("windows")]
internal sealed class WindowsRemoteNetworkPeer : IAsyncDisposable
{
    private const int Version = 1;
    private const int DeadlineSeconds = 240;
    private const int MaximumLineCharacters = 4096;
    private const string AssignedAddressSource = "default_route_assigned_global_ipv4";
    private const string RemotePython = "/home/sammiller/.local/share/arcforges/toolchains/python/cpython-3.15.2-linux-x86_64-gnu/bin/python";
    private static readonly string ScriptHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Script)));
    private readonly Process _ssh;
    private readonly SemaphoreSlim _control = new(1, 1);
    private readonly CancellationTokenSource _closing = new();
    private readonly StringBuilder _line = new();
    private readonly char[] _character = new char[1];
    private Task _stderrDrain = Task.CompletedTask;
    private bool _started;
    private bool _closeRequested;
    private bool _closedAcknowledged;
    private bool _disposed;
    private bool _cleanupConfirmed;
    private long _stderrBytes;
    private string? _stderrHash;
    private string? _stderrFailure;
    private string _stage = "ssh_start";
    private string? _observedSourceSha256;
    private int? _observedProtocolVersion;
    private WindowsRemoteNetworkSnapshot? _lastSnapshot;
    private int? _sshExitCode;

    private WindowsRemoteNetworkPeer(Process ssh) => _ssh = ssh;

    internal IPAddress Address { get; private set; } = IPAddress.None;
    internal int Port { get; private set; }
    internal int OtherTcpPort { get; private set; }
    internal int ProtocolVersion { get; } = Version;
    internal string SourceSha256 { get; } = ScriptHash;
    internal int PeerProcessId { get; private set; }
    internal string? AddressSource { get; private set; }
    internal string? InterfaceName { get; private set; }
    internal int DefaultInterfaceCandidateCount { get; private set; }
    internal int AddressCandidateCount { get; private set; }
    internal string? RemoteErrorPhase { get; private set; }
    internal string? RemoteExceptionType { get; private set; }
    internal int? RemoteErrno { get; private set; }
    internal int? RemoteScriptLine { get; private set; }
    internal long StderrBytes => Interlocked.Read(ref _stderrBytes);
    internal string? StderrSha256 => _stderrHash;
    internal string? StderrFailureCode => _stderrFailure;
    internal bool CleanupConfirmed => _cleanupConfirmed;

    internal static async Task<WindowsRemoteNetworkPeer> StartAsync()
    {
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("The existing native Windows OpenSSH client is required.");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            StandardInputEncoding = new UTF8Encoding(false),
        };
        foreach (var arg in new[] { "-4", "-T", "-a", "-x", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "netcup", RemotePython, "-u", "-c" }) start.ArgumentList.Add(arg);
        // This remote-shell expression contains only a fixed Python loader and
        // base64 alphabet. No user path, address, command or credential enters it.
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(Script));
        start.ArgumentList.Add("\"import base64;source=base64.b64decode('" + encoded
            + "');exec(compile(source,'afv2-network-peer-v1','exec'),{'AFV2_SCRIPT_SOURCE':source})\"");
        var peer = new WindowsRemoteNetworkPeer(new Process { StartInfo = start });
        try
        {
            if (!peer._ssh.Start()) throw new IOException("The controlled SSH client did not start.");
            peer._started = true;
            peer._ssh.StandardInput.NewLine = "\n";
            peer._stderrDrain = peer.DrainStderrAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            peer._stage = "ready_read";
            using var message = await peer.ReadMessageAsync(deadline.Token).ConfigureAwait(false);
            peer._stage = "ready_validation";
            peer.VerifyEnvelope(message.RootElement);
            if (message.RootElement.GetProperty("kind").GetString() == "closed")
            {
                peer._closedAcknowledged = message.RootElement.GetProperty("listenersClosed").GetBoolean();
                peer._lastSnapshot = ReadSnapshot(message.RootElement);
                throw peer.Failure("peer_ready_closed_" + (peer._lastSnapshot.ErrorCode ?? "without_peer_error"));
            }
            Require(message.RootElement.GetProperty("kind").GetString() == "ready", "Controlled peer readiness is missing.");
            Require(peer.AddressSource == AssignedAddressSource && peer.DefaultInterfaceCandidateCount == 1
                && peer.AddressCandidateCount == 1 && peer.InterfaceName is { Length: > 0 }, "Controlled peer assigned address is not unique.");
            var addressText = message.RootElement.GetProperty("address").GetString();
            Require(IPAddress.TryParse(addressText, out var address) && address.AddressFamily == AddressFamily.InterNetwork
                && !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any) && address.GetAddressBytes()[0] < 224,
                "Controlled peer did not report its actual nonloopback IPv4 server endpoint.");
            peer.Address = address!;
            peer.Port = ValidPort(message.RootElement.GetProperty("port").GetInt32());
            peer.OtherTcpPort = ValidPort(message.RootElement.GetProperty("otherTcpPort").GetInt32());
            peer.PeerProcessId = message.RootElement.GetProperty("peerProcessId").GetInt32();
            Require(peer.Port != peer.OtherTcpPort && peer.PeerProcessId > 0
                && message.RootElement.GetProperty("deadlineSeconds").GetInt32() == DeadlineSeconds,
                "Controlled peer endpoint or lifetime readback is invalid.");
            return peer;
        }
        catch (Exception startup)
        {
            var code = startup is WindowsQualificationCheckException check ? check.Code : "peer_" + peer._stage + "_failed";
            try { await peer.DisposeAsync().ConfigureAwait(false); }
            catch (Exception cleanup)
            {
                var primary = peer.Failure(code, startup);
                var unresolved = new WindowsRemoteNetworkPeerLaunchException(primary, cleanup, peer);
                foreach (System.Collections.DictionaryEntry item in primary.Data) unresolved.Data[item.Key] = item.Value;
                throw unresolved;
            }
            throw peer.Failure(code, startup);
        }
    }

    internal async Task<WindowsRemoteNetworkSnapshot> SnapshotAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed || _closeRequested, this);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_closing.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        await _control.WaitAsync(deadline.Token).ConfigureAwait(false);
        try
        {
            _stage = "snapshot_write";
            await _ssh.StandardInput.WriteLineAsync("snapshot".AsMemory(), deadline.Token).ConfigureAwait(false);
            await _ssh.StandardInput.FlushAsync(deadline.Token).ConfigureAwait(false);
            _stage = "snapshot_read";
            using var message = await ReadMessageAsync(deadline.Token).ConfigureAwait(false);
            _stage = "snapshot_validation";
            VerifyEnvelope(message.RootElement);
            if (message.RootElement.GetProperty("kind").GetString() == "closed")
            {
                _closedAcknowledged = message.RootElement.GetProperty("listenersClosed").GetBoolean();
                _lastSnapshot = ReadSnapshot(message.RootElement);
                throw Failure("peer_snapshot_closed_" + (_lastSnapshot.ErrorCode ?? "without_peer_error"));
            }
            Require(message.RootElement.GetProperty("kind").GetString() == "snapshot", "Controlled peer snapshot is missing.");
            _lastSnapshot = ReadSnapshot(message.RootElement);
            return _lastSnapshot;
        }
        catch (Exception error) { throw Failure(error is WindowsQualificationCheckException check ? check.Code : "peer_" + _stage + "_failed", error); }
        finally { _control.Release(); }
    }

    private async Task<JsonDocument> ReadMessageAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var read = await _ssh.StandardOutput.ReadAsync(_character.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("Controlled SSH peer ended its JSON stream.");
            if (_character[0] == '\n')
            {
                var text = _line.ToString();
                _line.Clear();
                return JsonDocument.Parse(text, new() { MaxDepth = 4 });
            }
            if (_line.Length >= MaximumLineCharacters) throw new InvalidDataException("Controlled peer exceeded its bounded JSON line.");
            _line.Append(_character[0]);
        }
    }

    private void VerifyEnvelope(JsonElement value)
    {
        Require(value.ValueKind == JsonValueKind.Object, "Controlled peer envelope is invalid.");
        _observedProtocolVersion = value.GetProperty("protocolVersion").GetInt32();
        var observed = value.GetProperty("sourceSha256").GetString();
        _observedSourceSha256 = observed is { Length: 64 } && observed.All(char.IsAsciiHexDigit) ? observed.ToLowerInvariant() : null;
        AddressSource = value.GetProperty("addressSource").GetString() == AssignedAddressSource ? AssignedAddressSource : null;
        var interfaceName = value.GetProperty("interfaceName").GetString();
        InterfaceName = interfaceName is { Length: > 0 and <= 64 } && interfaceName.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '-' or '_' or '.' or ':' or '@') ? interfaceName : null;
        DefaultInterfaceCandidateCount = value.GetProperty("defaultInterfaceCandidateCount").GetInt32();
        AddressCandidateCount = value.GetProperty("addressCandidateCount").GetInt32();
        if (value.TryGetProperty("errorPhase", out var phase)) RemoteErrorPhase = AllowedErrorPhase(phase.GetString());
        if (value.TryGetProperty("exceptionType", out var type))
        {
            var name = type.GetString();
            RemoteExceptionType = name is { Length: > 0 and <= 64 } && name.All(character => char.IsAsciiLetterOrDigit(character) || character == '_') ? name : null;
        }
        if (value.TryGetProperty("nativeErrno", out var errno)) RemoteErrno = errno.ValueKind == JsonValueKind.Number && errno.TryGetInt32(out var nativeNumber) ? nativeNumber : null;
        if (value.TryGetProperty("scriptLine", out var line)) RemoteScriptLine = line.ValueKind == JsonValueKind.Number && line.TryGetInt32(out var sourceLine) && sourceLine is > 0 and <= 10000 ? sourceLine : null;
        Require(_observedProtocolVersion == ProtocolVersion && _observedSourceSha256 == SourceSha256,
            "Controlled peer protocol or executed script hash differs.");
    }

    private static WindowsRemoteNetworkSnapshot ReadSnapshot(JsonElement value)
    {
        var snapshot = new WindowsRemoteNetworkSnapshot(value.GetProperty("tcpAccepted").GetInt64(), value.GetProperty("tcpMatched").GetInt64(),
            value.GetProperty("udpReceived").GetInt64(), value.GetProperty("udpMatched").GetInt64(), value.GetProperty("otherTcpAccepted").GetInt64(),
            value.GetProperty("otherTcpMatched").GetInt64(), value.GetProperty("peerHealthy").GetBoolean(), AllowedPeerError(value.GetProperty("errorCode").GetString()));
        Require(snapshot.TcpAccepted >= snapshot.TcpMatched && snapshot.TcpMatched >= 0
            && snapshot.UdpReceived >= snapshot.UdpMatched && snapshot.UdpMatched >= 0
            && snapshot.OtherTcpAccepted >= snapshot.OtherTcpMatched && snapshot.OtherTcpMatched >= 0,
            "Controlled peer counters are invalid.");
        return snapshot;
    }

    private async Task DrainStderrAsync()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[4096];
        try
        {
            while (true)
            {
                var count = await _ssh.StandardError.BaseStream.ReadAsync(buffer).ConfigureAwait(false);
                if (count == 0) break;
                // No stderr body, username, config or arbitrary message is
                // retained or exported. Memory stays bounded while draining.
                hash.AppendData(buffer, 0, count);
                Interlocked.Add(ref _stderrBytes, count);
            }
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException)
        {
            _stderrFailure = "stderr_drain_failed";
        }
        finally { _stderrHash = Convert.ToHexStringLower(hash.GetHashAndReset()); }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        if (!_started) { _ssh.Dispose(); _closing.Dispose(); _control.Dispose(); _disposed = true; return; }
        _closeRequested = true;
        await _closing.CancelAsync().ConfigureAwait(false);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await _control.WaitAsync(deadline.Token).ConfigureAwait(false);
        try
        {
            if (!_ssh.HasExited)
            {
                try
                {
                    await _ssh.StandardInput.WriteLineAsync("close".AsMemory(), deadline.Token).ConfigureAwait(false);
                    await _ssh.StandardInput.FlushAsync(deadline.Token).ConfigureAwait(false);
                }
                catch (IOException) { /* EOF still triggers the script's finally. */ }
                finally { _ssh.StandardInput.Close(); }
            }
            // A canceled snapshot may have left one response in flight; retain
            // partial line state and require the actual final close record.
            while (!_closedAcknowledged)
            {
                using var message = await ReadMessageAsync(deadline.Token).ConfigureAwait(false);
                VerifyEnvelope(message.RootElement);
                if (message.RootElement.GetProperty("kind").GetString() != "closed") continue;
                _lastSnapshot = ReadSnapshot(message.RootElement);
                _closedAcknowledged = message.RootElement.GetProperty("listenersClosed").GetBoolean();
            }
            await _ssh.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            await _stderrDrain.WaitAsync(deadline.Token).ConfigureAwait(false);
            Require(_closedAcknowledged, "Controlled peer listener cleanup was not acknowledged.");
            _sshExitCode = _ssh.ExitCode;
            _cleanupConfirmed = true;
        }
        catch
        {
            // Killing the owned local SSH process is bounded escalation, not
            // proof that the remote listeners closed. Retain this owner on any
            // unresolved failure; the remote script also has its hard deadline.
            if (!_ssh.HasExited)
            {
                _ssh.Kill();
                using var killDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _ssh.WaitForExitAsync(killDeadline.Token).ConfigureAwait(false);
            }
            throw;
        }
        finally { _control.Release(); }
        _disposed = true;
        _ssh.Dispose();
        _closing.Dispose();
        _control.Dispose();
    }

    private static int ValidPort(int port) => port is >= 1 and <= 65535 ? port : throw new InvalidDataException("Controlled peer reported an invalid port.");
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }

    private static string? AllowedPeerError(string? code) => code switch
    {
        null => null,
        "peer_protocol_failed" or "peer_socket_failed" or "peer_failed" or "hard_deadline_elapsed" => code,
        "default_route_query_failed" or "default_route_query_timeout" or "default_route_json_invalid"
            or "interface_address_query_failed" or "interface_address_query_timeout" or "interface_address_json_invalid"
            or "iproute_unavailable" or "default_route_interface_not_unique" or "interface_name_invalid"
            or "assigned_ipv4_not_unique" or "assigned_ipv4_invalid" or "control_bound_exceeded" or "unknown_control" => code,
        _ => "unrecognized_peer_error",
    };

    private static string? AllowedErrorPhase(string? phase) => phase switch
    {
        null => null,
        "setup_default_route" or "setup_interface_address" or "setup_address_selection" or "bind_tcp_udp" or "bind_other_tcp"
            or "register_io" or "select_io" or "control" or "accept_tcp" or "receive_udp" or "client_read" or "client_write"
            or "expire_clients" or "hard_deadline" => phase,
        _ => "unrecognized_phase",
    };

    private WindowsQualificationCheckException Failure(string code, Exception? inner = null)
    {
        var error = new WindowsQualificationCheckException(code, inner);
        // These explicit safe values are available to the existing receipt
        // writer. Never serialize arbitrary exception Data, stderr or messages.
        error.Data["remotePeerFailureCode"] = code;
        error.Data["remotePeerStage"] = _stage;
        error.Data["remotePeerExpectedSourceSha256"] = SourceSha256;
        error.Data["remotePeerObservedSourceSha256"] = _observedSourceSha256;
        error.Data["remotePeerObservedProtocolVersion"] = _observedProtocolVersion;
        error.Data["remotePeerAddressSource"] = AddressSource;
        error.Data["remotePeerInterfaceName"] = InterfaceName;
        error.Data["remotePeerDefaultInterfaceCandidateCount"] = DefaultInterfaceCandidateCount;
        error.Data["remotePeerAddressCandidateCount"] = AddressCandidateCount;
        error.Data["remotePeerErrorPhase"] = RemoteErrorPhase;
        error.Data["remotePeerExceptionType"] = RemoteExceptionType;
        error.Data["remotePeerErrno"] = RemoteErrno;
        error.Data["remotePeerScriptLine"] = RemoteScriptLine;
        error.Data["remotePeerClosedAcknowledged"] = _closedAcknowledged;
        error.Data["remotePeerCleanupConfirmed"] = _cleanupConfirmed;
        error.Data["remotePeerStderrBytes"] = StderrBytes;
        error.Data["remotePeerStderrSha256"] = StderrSha256;
        error.Data["remotePeerStderrFailureCode"] = StderrFailureCode;
        error.Data["remotePeerSshExitCode"] = _sshExitCode ?? (_started && !_disposed && _ssh.HasExited ? _ssh.ExitCode : null);
        if (_lastSnapshot is { } snapshot)
        {
            error.Data["remotePeerErrorCode"] = snapshot.ErrorCode;
            error.Data["remotePeerHealthy"] = snapshot.PeerHealthy;
            error.Data["remotePeerTcpAccepted"] = snapshot.TcpAccepted;
            error.Data["remotePeerTcpMatched"] = snapshot.TcpMatched;
            error.Data["remotePeerUdpReceived"] = snapshot.UdpReceived;
            error.Data["remotePeerUdpMatched"] = snapshot.UdpMatched;
            error.Data["remotePeerOtherTcpAccepted"] = snapshot.OtherTcpAccepted;
            error.Data["remotePeerOtherTcpMatched"] = snapshot.OtherTcpMatched;
        }
        return error;
    }

    private const string Script = """
import hashlib, ipaddress, json, os, selectors, socket, subprocess, sys, time
VERSION = 1
SOURCE_SHA256 = hashlib.sha256(AFV2_SCRIPT_SOURCE).hexdigest()
DEADLINE_SECONDS = 240
SENTINEL = b'AFV2_NET_SENTINEL\n'
counts = dict(tcpAccepted=0, tcpMatched=0, udpReceived=0, udpMatched=0, otherTcpAccepted=0, otherTcpMatched=0)
selector = selectors.DefaultSelector()
owned = []
clients = {}
error_code = None
stop = False
control_buffer = bytearray()
ADDRESS_SOURCE = 'default_route_assigned_global_ipv4'
interface_name = None
route_candidate_count = 0
address_candidate_count = 0
phase = 'setup_default_route'
error_phase = exception_type = native_errno = script_line = None

def emit(kind, **fields):
    value = dict(kind=kind, protocolVersion=VERSION, sourceSha256=SOURCE_SHA256,
                 addressSource=ADDRESS_SOURCE, interfaceName=interface_name,
                 defaultInterfaceCandidateCount=route_candidate_count, addressCandidateCount=address_candidate_count)
    value.update(fields)
    sys.stdout.write(json.dumps(value, separators=(',', ':')) + '\n')
    sys.stdout.flush()

def snapshot(kind, **fields):
    emit(kind, **counts, peerHealthy=error_code is None, errorCode=error_code, errorPhase=error_phase,
         exceptionType=exception_type, nativeErrno=native_errno, scriptLine=script_line, **fields)

def record_exception(issue):
    global error_phase, exception_type, native_errno, script_line
    for _ in range(4):
        if issue.__cause__ is None:
            break
        issue = issue.__cause__
    error_phase = phase
    exception_type = type(issue).__name__
    number = getattr(issue, 'errno', None)
    native_errno = number if isinstance(number, int) and -2147483648 <= number <= 2147483647 else None
    trace = issue.__traceback__
    script_line = None
    while trace is not None:
        if trace.tb_frame.f_code.co_filename == 'afv2-network-peer-v1':
            script_line = trace.tb_lineno
        trace = trace.tb_next

def close_client(connection):
    clients.pop(connection, None)
    try:
        selector.unregister(connection)
    except KeyError:
        pass
    connection.close()

def query_ip(arguments, phase):
    try:
        result = subprocess.run(['ip', '-j', '-4'] + arguments, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=False)
    except FileNotFoundError as issue:
        raise ValueError('iproute_unavailable') from issue
    except subprocess.TimeoutExpired as issue:
        raise ValueError(phase + '_query_timeout') from issue
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise ValueError(phase + '_query_failed')
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeError) as issue:
        raise ValueError(phase + '_json_invalid') from issue
    if not isinstance(value, list):
        raise ValueError(phase + '_json_invalid')
    return value

try:
    routes = query_ip(['route', 'show', 'default'], 'default_route')
    devices = {item.get('dev') for item in routes if isinstance(item, dict) and isinstance(item.get('dev'), str)}
    route_candidate_count = len(devices)
    if route_candidate_count != 1:
        raise ValueError('default_route_interface_not_unique')
    interface_name = next(iter(devices))
    if not 1 <= len(interface_name) <= 64 or not all(character.isascii() and (character.isalnum() or character in '-_.:@') for character in interface_name):
        raise ValueError('interface_name_invalid')
    phase = 'setup_interface_address'
    assigned = query_ip(['address', 'show', 'dev', interface_name, 'scope', 'global'], 'interface_address')
    phase = 'setup_address_selection'
    candidates = set()
    for item in assigned:
        if not isinstance(item, dict) or item.get('ifname') != interface_name:
            continue
        for entry in item.get('addr_info', []):
            if isinstance(entry, dict) and entry.get('family') == 'inet' and entry.get('scope') == 'global':
                try:
                    candidate = ipaddress.IPv4Address(entry.get('local', ''))
                except ipaddress.AddressValueError as issue:
                    raise ValueError('assigned_ipv4_invalid') from issue
                if candidate.is_loopback or candidate.is_unspecified or candidate.is_multicast:
                    raise ValueError('assigned_ipv4_invalid')
                candidates.add(str(candidate))
    address_candidate_count = len(candidates)
    if address_candidate_count != 1:
        raise ValueError('assigned_ipv4_not_unique')
    address = next(iter(candidates))
    phase = 'bind_tcp_udp'
    tcp = udp = None
    last_bind_error = None
    for attempt in range(8):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp.bind((address, 0))
            port = tcp.getsockname()[1]
            udp.bind((address, port))
            break
        except OSError as issue:
            last_bind_error = issue
            tcp.close()
            udp.close()
            tcp = udp = None
    if tcp is None:
        raise OSError('matching_ports_unavailable') from last_bind_error
    owned.extend((tcp, udp))
    other = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    owned.append(other)
    phase = 'bind_other_tcp'
    other.bind((address, 0))
    other_port = other.getsockname()[1]
    phase = 'register_io'
    for listener, role in ((tcp, 'tcp'), (other, 'other')):
        listener.listen(16)
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ, role)
    udp.setblocking(False)
    selector.register(udp, selectors.EVENT_READ, 'udp')
    os.set_blocking(0, False)
    selector.register(0, selectors.EVENT_READ, 'control')
    end = time.monotonic() + DEADLINE_SECONDS
    emit('ready', peerProcessId=os.getpid(), address=str(address), port=port, otherTcpPort=other_port, deadlineSeconds=DEADLINE_SECONDS)
    while not stop and time.monotonic() < end:
        phase = 'select_io'
        for key, mask in selector.select(min(0.25, max(0, end-time.monotonic()))):
            role = key.data
            if role == 'control':
                phase = 'control'
                incoming = os.read(0, 256)
                if not incoming:
                    stop = True
                    break
                control_buffer.extend(incoming)
                if len(control_buffer) > 256:
                    raise ValueError('control_bound_exceeded')
                while b'\n' in control_buffer:
                    command, _, rest = control_buffer.partition(b'\n')
                    control_buffer[:] = rest
                    if command == b'snapshot':
                        snapshot('snapshot')
                    elif command == b'close':
                        stop = True
                        break
                    else:
                        raise ValueError('unknown_control')
            elif role in ('tcp', 'other'):
                phase = 'accept_tcp'
                connection, _ = key.fileobj.accept()
                counts['tcpAccepted' if role == 'tcp' else 'otherTcpAccepted'] += 1
                if len(clients) >= 32:
                    connection.close()
                    continue
                connection.setblocking(False)
                clients[connection] = dict(role=role, data=bytearray(), reply=None, sent=0, end=time.monotonic()+3)
                selector.register(connection, selectors.EVENT_READ, 'client')
            elif role == 'udp':
                phase = 'receive_udp'
                data, remote = udp.recvfrom(len(SENTINEL)+1)
                counts['udpReceived'] += 1
                if data == SENTINEL:
                    counts['udpMatched'] += 1
                    udp.sendto(SENTINEL, remote)
            else:
                connection = key.fileobj
                state = clients[connection]
                try:
                    if mask & selectors.EVENT_READ:
                        phase = 'client_read'
                        data = connection.recv(len(SENTINEL)+1-len(state['data']))
                        if not data:
                            close_client(connection)
                            continue
                        state['data'].extend(data)
                        if bytes(state['data']) == SENTINEL:
                            counts['tcpMatched' if state['role'] == 'tcp' else 'otherTcpMatched'] += 1
                            state['reply'] = SENTINEL
                            selector.modify(connection, selectors.EVENT_WRITE, 'client')
                        elif len(state['data']) >= len(SENTINEL):
                            close_client(connection)
                    elif mask & selectors.EVENT_WRITE:
                        phase = 'client_write'
                        state['sent'] += connection.send(state['reply'][state['sent']:])
                        if state['sent'] == len(SENTINEL):
                            close_client(connection)
                except (ConnectionError, OSError):
                    close_client(connection)
        phase = 'expire_clients'
        for connection, state in list(clients.items()):
            if time.monotonic() >= state['end']:
                close_client(connection)
    if not stop:
        error_code = 'hard_deadline_elapsed'
        error_phase = 'hard_deadline'
except ValueError as issue:
    record_exception(issue)
    known = {'default_route_query_failed', 'default_route_query_timeout', 'default_route_json_invalid',
             'interface_address_query_failed', 'interface_address_query_timeout', 'interface_address_json_invalid',
             'iproute_unavailable', 'default_route_interface_not_unique', 'interface_name_invalid',
             'assigned_ipv4_not_unique', 'assigned_ipv4_invalid', 'control_bound_exceeded', 'unknown_control'}
    error_code = str(issue) if str(issue) in known else 'peer_protocol_failed'
except OSError as issue:
    record_exception(issue)
    error_code = 'peer_socket_failed'
except Exception as issue:
    record_exception(issue)
    error_code = 'peer_failed'
finally:
    for connection in list(clients):
        close_client(connection)
    for item in owned:
        item.close()
    selector.close()
    try:
        snapshot('closed', listenersClosed=True)
    except (BrokenPipeError, OSError):
        pass
""";
}
