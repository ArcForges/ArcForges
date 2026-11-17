// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.MxcProbe;

// This is one experimental Run owner, not the product Sandbox Core. Its
// process is launched independently of the client and holds the real handles.
internal sealed record ProbeOwnerRecord(string RunId, string OwnerEpoch, long Generation,
    string SnapshotDigest, string PipeName, int OwnerPid, DateTimeOffset OwnerCreatedUtc,
    uint? ExecutorPid, DateTimeOffset? ExecutorCreatedUtc, string State, bool StopRequested,
    bool CleanupConfirmed, uint? RawExitCode, string ExitSource, long OutputCursor,
    ConPtyJobObservation? Job, string? FailureCode, DateTimeOffset UpdatedUtc);

[SupportedOSPlatform("windows")]
internal sealed partial class WindowsProbeOwner : IDisposable
{
    private readonly ProbeOwnerConfig _config;
    private readonly string _recordPath;
    private readonly byte[] _controllerKey;
    private readonly byte[] _observerKey;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _shutdown = new();
    private readonly DateTimeOffset _createdUtc;
    private readonly Dictionary<long, (byte[] Digest, ProbeOwnerResponse Response)> _acks = [];
    private ConPtySession? _session;
    private long _generation;
    private string _state = "STARTING";
    private string? _failure;
    private bool _empty;
    private bool _stopRequested;
    private uint? _exitCode;
    private string? _lease;
    private long _leaseUntil;
    private long _lastSequence;

    private WindowsProbeOwner(ProbeOwnerConfig config)
    {
        _config = config;
        _recordPath = Path.Combine(config.Launch.ControlDirectory, "owner-record.json");
        _controllerKey = Convert.FromBase64String(config.ControllerKey);
        _observerKey = Convert.FromBase64String(config.ObserverKey);
        _generation = config.Generation;
        using var process = Process.GetCurrentProcess();
        _createdUtc = process.StartTime.ToUniversalTime();
    }

    public static async Task<int> RunAsync(string privateOwnerConfigPath)
    {
        var path = Path.GetFullPath(privateOwnerConfigPath);
        WindowsPolicy.VerifyPrivateFile(path);
        var config = JsonSerializer.Deserialize(await File.ReadAllBytesAsync(path).ConfigureAwait(false),
            OwnerJson.Default.ProbeOwnerConfig) ?? throw new InvalidDataException("Missing private owner configuration.");
        Validate(config, path);
        // Validation and native host sampling happen in the real background
        // owner, never in a foreground surrogate that later exits.
        Program.ValidateStage(Path.Combine(AppContext.BaseDirectory, "mxc-manifest.json"));
        WindowsPolicy.VerifyPrivateControl(config.Launch.ControlDirectory);
        using var owner = new WindowsProbeOwner(config);
        try { return await owner.RunCoreAsync().ConfigureAwait(false); }
        finally
        {
            CryptographicOperations.ZeroMemory(owner._controllerKey);
            CryptographicOperations.ZeroMemory(owner._observerKey);
        }
    }

    private static void Validate(ProbeOwnerConfig config, string path)
    {
        if (!Guid.TryParseExact(config.RunId, "N", out _) || !Guid.TryParseExact(config.OwnerEpoch, "N", out _)
            || config.Generation is < 1 or > long.MaxValue - 1
            || config.SnapshotDigest.Length != 64 || config.SnapshotDigest.Any(x => !char.IsAsciiHexDigit(x))
            || config.PipeName.Length is < 20 or > 100 || !config.PipeName.StartsWith("arcforges-mxc-owner-", StringComparison.Ordinal)
            || config.PipeName.Any(x => !char.IsAsciiLetterOrDigit(x) && x != '-')
            || Convert.FromBase64String(config.ControllerKey).Length != 32 || Convert.FromBase64String(config.ObserverKey).Length != 32
            || config.ControllerKey == config.ObserverKey)
            throw new InvalidDataException("Invalid owner identity or private capabilities.");
        if (config.PauseAtPhase is not null and not ("prepared" or "owner-ack" or "executor-created" or "active" or "cleaning" or "final"))
            throw new InvalidDataException("Unknown bounded owner experiment phase.");
        var control = Path.TrimEndingDirectorySeparator(Path.GetFullPath(config.Launch.ControlDirectory));
        if (!Path.GetDirectoryName(path)!.Equals(control, StringComparison.OrdinalIgnoreCase)
            || !Path.GetFullPath(config.Launch.ExecutorPath).Equals(Path.Combine(AppContext.BaseDirectory, "wxc-exec.exe"), StringComparison.OrdinalIgnoreCase)
            || !Path.GetDirectoryName(Path.GetFullPath(config.Launch.PrivateConfigPath))!.Equals(control, StringComparison.OrdinalIgnoreCase)
            || File.Exists(Path.Combine(control, "owner-record.json")))
            throw new InvalidDataException("Owner paths or an existing Run record forbid a new launch.");
        WindowsPolicy.VerifyPrivateFile(config.Launch.PrivateConfigPath);
    }

    private async Task<int> RunCoreAsync()
    {
        SaveRecord(); // No payload can exist yet; exact owner identity is durable.
        await WindowsPhaseClient.OwnerPhaseAsync(_config, "prepared").ConfigureAwait(false);
        using (var stream = NewDurableFile(Path.Combine(_config.Launch.ControlDirectory, "owner-host-context.json")))
        {
            using (var writer = new Utf8JsonWriter(stream)) WindowsHostContext.Write(writer);
            stream.Flush(true);
        }
        await WindowsPhaseClient.OwnerPhaseAsync(_config, "owner-ack").ConfigureAwait(false);
        try
        {
            _session = _config.PauseAtPhase == "executor-created"
                ? ConPtySession.StartForOwnerPhase(_config.Launch, suspended =>
                {
                    // The primitive has held the exact suspended process and
                    // verified Job/limits/argv, but has not resumed its thread.
                    SaveRecord(suspended);
                    WindowsPhaseClient.OwnerPhaseAsync(_config, "executor-created", suspended.ProcessId).GetAwaiter().GetResult();
                })
                : ConPtySession.Start(_config.Launch);
            _state = "RUNNING";
        }
        catch (ConPtyLaunchException error)
        {
            _session = error.CleanupOwner;
            _state = "RECOVERY_REQUIRED";
            _failure = "launch_cleanup_unresolved";
        }
        catch
        {
            // Start only returns a generic exception after proving its own
            // cleanup; unresolved handles are returned in ConPtyLaunchException.
            _state = "FAILED";
            _failure = "launch_rejected";
            _empty = true;
        }
        SaveRecord();
        if (_state == "RUNNING") await WindowsPhaseClient.OwnerPhaseAsync(_config, "active").ConfigureAwait(false);
        var monitor = MonitorAsync();
        try
        {
            while (!_shutdown.IsCancellationRequested)
            {
                await using var pipe = new NamedPipeServerStream(_config.PipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4_096, 4_096);
                try
                {
                    await pipe.WaitForConnectionAsync(_shutdown.Token).ConfigureAwait(false);
                    await ServeAsync(pipe).ConfigureAwait(false);
                }
                catch (Exception error) when (error is IOException or OperationCanceledException or UnauthorizedAccessException
                    or InvalidDataException or JsonException or FormatException)
                {
                    // A vanished/malformed/unauthenticated client cannot stop
                    // the independently owned terminal. Never log its bytes.
                }
            }
        }
        finally
        {
            await _shutdown.CancelAsync().ConfigureAwait(false);
            await monitor.ConfigureAwait(false);
        }
        if (!_empty) throw new InvalidOperationException("The owner cannot release unresolved native handles.");
        if (_session is not null) await _session.DisposeAsync().ConfigureAwait(false);
        return _state == "FAILED" ? 1 : 0;
    }

    private async Task ServeAsync(NamedPipeServerStream pipe)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(18));
        var hello = await OwnerProtocol.ReadAsync(pipe, OwnerJson.Default.ProbeOwnerHello, deadline.Token).ConfigureAwait(false);
        if (hello.RunId != _config.RunId || hello.OwnerEpoch != _config.OwnerEpoch || hello.SnapshotDigest != _config.SnapshotDigest
            || hello.Generation != _generation) throw new UnauthorizedAccessException("Owner identity or generation mismatch.");
        var key = hello.Observer ? _observerKey : _controllerKey;
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await OwnerProtocol.WriteAsync(pipe, new ProbeOwnerChallenge(nonce, OwnerProtocol.Mac(key, hello, nonce, "server")),
            OwnerJson.Default.ProbeOwnerChallenge, deadline.Token).ConfigureAwait(false);
        var proof = await OwnerProtocol.ReadAsync(pipe, OwnerJson.Default.ProbeOwnerProof, deadline.Token).ConfigureAwait(false);
        if (!OwnerProtocol.Verify(key, hello, nonce, "client", proof.Proof)) throw new UnauthorizedAccessException("Client authentication failed.");
        var request = await OwnerProtocol.ReadAsync(pipe, OwnerJson.Default.ProbeOwnerRequest, deadline.Token).ConfigureAwait(false);
        await _gate.WaitAsync(deadline.Token).ConfigureAwait(false);
        ProbeOwnerResponse response;
        try { response = await ExecuteAsync(request, hello.Observer).ConfigureAwait(false); }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
        {
            response = Response(false, "operation_refused");
        }
        finally { _gate.Release(); }
        await OwnerProtocol.WriteAsync(pipe, response, OwnerJson.Default.ProbeOwnerResponse, deadline.Token).ConfigureAwait(false);
    }

    private async Task<ProbeOwnerResponse> ExecuteAsync(ProbeOwnerRequest request, bool observer)
    {
        if (request.Generation != _generation) return Response(false, "stale_generation");
        if (observer && request.Operation is not "read" and not "status") return Response(false, "observer_read_only");
        switch (request.Operation)
        {
            case "status": return Response(true) with { Job = _session?.ObserveJob() };
            case "read":
                return _session is null ? Response(false, "terminal_unavailable")
                    : Response(true) with { Replay = _session.ReadReplay(request.Cursor, request.MaxBytes) };
            case "rebind":
                _generation = checked(_generation + 1);
                InvalidateLease();
                SaveRecord();
                return Response(true);
            case "acquire":
                if (_state != "RUNNING") return Response(false, "terminal_unavailable");
                if (_lease is not null && Stopwatch.GetTimestamp() < _leaseUntil) return Response(false, "writer_busy");
                InvalidateLease();
                _lease = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                RenewLease();
                return LeaseResponse();
            case "renew":
                if (!OwnsLease(request)) return Response(false, "writer_lease_unavailable");
                RenewLease();
                return LeaseResponse();
            case "detach":
                if (!OwnsLease(request)) return Response(false, "writer_lease_unavailable");
                InvalidateLease();
                return Response(true);
            case "write":
            case "resize":
                return await TerminalAsync(request).ConfigureAwait(false);
            case "limits":
                if (_state != "RUNNING" || _session is null || request.Limits is null) return Response(false, "limits_unavailable");
                var updated = _session.UpdateLimits(request.Limits);
                SaveRecord();
                return Response(true) with { Job = updated };
            case "stop":
                if (_empty) return Response(true);
                _stopRequested = true;
                _state = "STOPPING";
                InvalidateLease();
                SaveRecord(); // Durable safety intent precedes the native effect.
                try
                {
                    if (_session is null) return Response(false, "cleanup_owner_unavailable", "UNKNOWN");
                    if (_session.ProcessId == 0)
                    {
                        var job = _session.ObserveJob();
                        if (job.ActiveProcesses != 0 || job.ProcessIds.Length != 0)
                            throw new InvalidOperationException("Pre-launch owned Job is not empty.");
                        await _session.DisposeAsync().ConfigureAwait(false);
                        _session = null;
                        _state = "FAILED";
                        _failure = "launch_rejected";
                        _empty = true;
                    }
                    else SetFinal(await _session.ForceStopAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false));
                    SaveRecord();
                    return Response(true, effect: "CONFIRMED");
                }
                catch
                {
                    _state = "RECOVERY_REQUIRED";
                    _failure = "cleanup_unresolved";
                    _empty = false;
                    SaveRecord();
                    return Response(false, "cleanup_unresolved", "UNKNOWN");
                }
            case "shutdown":
                if (!_empty) return Response(false, "cleanup_unresolved", "UNKNOWN");
                SaveRecord();
                _shutdown.Cancel();
                return Response(true);
            default: return Response(false, "unknown_operation");
        }
    }

    private async Task<ProbeOwnerResponse> TerminalAsync(ProbeOwnerRequest request)
    {
        if (_state != "RUNNING" || _session is null || !OwnsLease(request)) return Response(false, "writer_lease_unavailable");
        // Authentication/ack fingerprints exist only in bounded owner memory.
        // Nothing in the control record stores terminal bytes or their hashes.
        var digest = HMACSHA256.HashData(_controllerKey, JsonSerializer.SerializeToUtf8Bytes(request, OwnerJson.Default.ProbeOwnerRequest));
        if (request.Sequence <= _lastSequence)
            return _acks.TryGetValue(request.Sequence, out var previous)
                ? CryptographicOperations.FixedTimeEquals(digest, previous.Digest) ? previous.Response : Response(false, "terminal_sequence_conflict")
                : Response(false, "terminal_ack_unavailable", "UNKNOWN");
        if (request.Sequence != _lastSequence + 1) return Response(false, "terminal_sequence_gap");
        if (request.Operation == "write" && (request.Input is null || request.Input.Length is < 1 or > 32_768))
            return Response(false, "invalid_terminal_input");
        if (request.Operation == "resize" && (request.Columns is < 1 or > short.MaxValue || request.Rows is < 1 or > short.MaxValue))
            return Response(false, "invalid_terminal_size");
        _lastSequence = request.Sequence;
        ProbeOwnerResponse response;
        try
        {
            if (request.Operation == "write") await _session.WriteInputAsync(request.Input!, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            else _session.Resize(request.Columns, request.Rows);
            response = Response(true, effect: "CONFIRMED");
        }
        catch { response = Response(false, "terminal_ack_unavailable", "UNKNOWN"); }
        _acks.Add(request.Sequence, (digest, response));
        if (_acks.Count > 32)
        {
            var oldest = _acks.Keys.Min();
            CryptographicOperations.ZeroMemory(_acks[oldest].Digest);
            _acks.Remove(oldest);
        }
        return response;
    }

    private async Task MonitorAsync()
    {
        try
        {
            while (true)
            {
                await Task.Delay(100, _shutdown.Token).ConfigureAwait(false);
                await _gate.WaitAsync(_shutdown.Token).ConfigureAwait(false);
                try
                {
                    if (_state != "RUNNING" || _session?.GetExecutorExitCode() is null) continue;
                    _state = "DRAINING";
                    InvalidateLease();
                    SaveRecord();
                    await WindowsPhaseClient.OwnerPhaseAsync(_config, "cleaning").ConfigureAwait(false);
                    try { SetFinal(await _session.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false)); }
                    catch { _state = "RECOVERY_REQUIRED"; _failure = "cleanup_unresolved"; }
                    SaveRecord();
                    if (_empty) await WindowsPhaseClient.OwnerPhaseAsync(_config, "final").ConfigureAwait(false);
                }
                catch
                {
                    _state = "RECOVERY_REQUIRED";
                    _failure = "observation_unresolved";
                    _empty = false;
                    // The exact handles stay held. A record-I/O failure cannot
                    // turn uncertain cleanup into a terminal success.
                    try { SaveRecord(); }
                    catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { }
                }
                finally { _gate.Release(); }
            }
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested) { }
    }

    private void SetFinal(ConPtyExit exit)
    {
        if (!exit.JobEmpty || exit.Job.ActiveProcesses != 0 || exit.Job.ProcessIds.Length != 0)
            throw new InvalidOperationException("Independent owned Job observation is not empty.");
        _empty = true;
        _exitCode = exit.RawExitCode;
        _state = "EXITED";
        _failure = null;
    }

    private bool OwnsLease(ProbeOwnerRequest request) => _lease is not null && request.LeaseId == _lease && Stopwatch.GetTimestamp() < _leaseUntil;
    private void RenewLease() => _leaseUntil = Stopwatch.GetTimestamp() + 30 * Stopwatch.Frequency;
    private ProbeOwnerResponse LeaseResponse() => Response(true) with { LeaseId = _lease, LeaseExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(30) };

    private void InvalidateLease()
    {
        _lease = null;
        _leaseUntil = 0;
        _lastSequence = 0;
        foreach (var ack in _acks.Values) CryptographicOperations.ZeroMemory(ack.Digest);
        _acks.Clear();
    }

    private ProbeOwnerResponse Response(bool ok, string? error = null, string effect = "NONE") => new()
    {
        Ok = ok, Error = error, Effect = effect, Generation = _generation, State = _state,
        CleanupConfirmed = _empty, DataDeletionAllowed = _empty,
        OwnerPid = Environment.ProcessId, OwnerCreatedUtc = _createdUtc,
        ExecutorPid = _session?.ProcessId, ExecutorCreatedUtc = _session?.ProcessStartTimeUtc,
        RawExitCode = _exitCode, ExitSource = _exitCode.HasValue ? "official_executor" : "unknown"
    };

    private void SaveRecord(ConPtySession? observationSession = null)
    {
        var observed = observationSession ?? _session;
        var record = new ProbeOwnerRecord(_config.RunId, _config.OwnerEpoch, _generation, _config.SnapshotDigest,
            _config.PipeName, Environment.ProcessId, _createdUtc, observed?.ProcessId, observed?.ProcessStartTimeUtc,
            _state, _stopRequested, _empty, _exitCode, _exitCode.HasValue ? "official_executor" : "unknown",
            observed?.ReadReplay(0, 1).AvailableUntil ?? 0, observed?.ObserveJob(), _failure, DateTimeOffset.UtcNow);
        var temporary = _recordPath + ".new-" + Guid.NewGuid().ToString("N");
        // The containing private directory was verified; every write is flushed
        // before atomic publication. Never treat a stale policy as a new launch.
        using (var stream = NewDurableFile(temporary))
        {
            JsonSerializer.Serialize(stream, record, OwnerJson.Default.ProbeOwnerRecord);
            stream.Flush(true);
        }
        if (!ReplaceRecord(temporary, _recordPath, 0x1 | 0x8))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Publish durable owner record failed.");
        WindowsPolicy.VerifyPrivateFile(_recordPath);
    }

    private static FileStream NewDurableFile(string path) => new(path, FileMode.CreateNew, FileAccess.Write,
        FileShare.None, 4_096, FileOptions.WriteThrough);

    // Session disposal occurs only after native emptiness in RunCoreAsync.
    // Disposing these coordination objects never releases an unresolved Job.
    public void Dispose()
    {
        _shutdown.Dispose();
        _gate.Dispose();
        GC.SuppressFinalize(this);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReplaceRecord(string existing, string destination, uint flags);
}
