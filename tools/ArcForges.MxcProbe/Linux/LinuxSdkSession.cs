// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.MxcProbe.Linux;

internal sealed record LinuxSdkOutputPage(long StartSequence, long NextSequence, long AvailableFrom, long AvailableUntil,
    long? GapFrom, long? GapUntil, byte[] Data, bool EndOfStream, string? FailureCode);
internal sealed record LinuxSdkExit(int ExitCode, bool TimedOut, string ExitSource, bool Drained, bool NativeProcessAbsent,
    long StdoutBytes, long StderrBytes);

internal sealed class LinuxSdkLaunchException(Exception primary, Exception cleanup, LinuxSdkSession cleanupOwner)
    : Exception("linux_sdk_launch_cleanup_unresolved", new AggregateException(primary, cleanup))
{
    internal LinuxSdkSession CleanupOwner { get; } = cleanupOwner;
}

// The calling supervisor must already be inside its configured resource scope.
// Native root absence below is an observation, never cgroup-empty authority.
[SupportedOSPlatform("linux")]
internal sealed class LinuxSdkSession : IAsyncDisposable
{
    private readonly LinuxEvidence _log;
    private readonly string _phase;
    private readonly Replay _stdout;
    private readonly Replay _stderr;
    private readonly SemaphoreSlim _inputGate = new(1, 1);
    private readonly CancellationTokenSource _closing = new();
    private MxcProcess? _process;
    private Stream? _input;
    private Stream? _output;
    private Stream? _error;
    private Task? _stdoutDrain;
    private Task? _stderrDrain;
    private Task<WaitResult>? _nativeWait;
    private Task<LinuxSdkExit>? _completion;
    private Task? _kill;
    private Task? _nativeDispose;
    private Task? _inputClose;
    private bool _inputClosed;
    private bool _disposed;
    private bool _inputCleanupHeld;

    private LinuxSdkSession(LinuxEvidence log, string phase, bool terminal, int replayBytes)
    {
        _log = log;
        _phase = phase;
        Terminal = terminal;
        _stdout = new(replayBytes);
        _stderr = new(replayBytes);
    }

    internal uint ProcessId { get; private set; }
    internal bool Terminal { get; }
    internal double SpawnMs { get; private set; }
    internal bool LifetimeCompleted => _completion?.IsCompleted == true;

    internal static LinuxSdkSession Start(ContainerRequest request, bool terminal, LinuxEvidence log, string phase = "sdk",
        int rows = 24, int columns = 80, int replayBytes = 262144)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(log);
        if (phase.Length is < 1 or > 64 || phase.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_')) throw new ArgumentException("linux_sdk_phase_invalid", nameof(phase));
        if (replayBytes is < 1024 or > 1_048_576) throw new ArgumentOutOfRangeException(nameof(replayBytes));
        if (request.Containment is not Containment.Bubblewrap || request.InheritDefaultEnvironment || request.TimeoutMs is not (> 0 and <= 180000))
            throw new LinuxProbeException("sdk_explicit_bubblewrap_bounded_request_required");
        ValidateSize(rows, columns);
        var session = new LinuxSdkSession(log, phase, terminal, replayBytes);
        try
        {
            session.Record("spawn", "begin", new() { ["mode"] = terminal ? "pty" : "pipes" });
            var clock = Stopwatch.StartNew();
            session._process = terminal
                ? MxcContainer.SpawnWithPty(request, new SpawnWithPtyOptions { Size = new((ushort)rows, (ushort)columns), Telemetry = new() { Enabled = false } })
                : MxcContainer.Spawn(request, new SpawnOptions { Telemetry = new() { Enabled = false } });
            session.ProcessId = session._process.Id;
            if (session.ProcessId == 0) throw new LinuxProbeException("sdk_native_process_identity_missing");
            session.SpawnMs = clock.Elapsed.TotalMilliseconds;
            session.Record("streams", "begin");
            // Every owned stream is taken before the SDK lifetime waiter can
            // claim untaken streams for its own discard drains.
            if (session._process is MxcPtyProcess pty)
            {
                session._input = pty.Input;
                session._output = pty.Output;
                session._error = pty.StandardError;
            }
            else
            {
                session._input = session._process.StandardInput;
                session._output = session._process.StandardOutput;
                session._error = session._process.StandardError;
            }
            if (session._input is null || session._output is null || (!terminal && session._error is null)) throw new LinuxProbeException("sdk_required_stream_missing");
            session.StartDrainsAndWait();
            session.Record("spawn", "ready", new() { ["pid"] = session.ProcessId.ToString(CultureInfo.InvariantCulture) });
            return session;
        }
        catch (Exception primary)
        {
            log.Failure(phase + "_spawn", primary);
            try { session.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
            catch (Exception cleanup) { throw new LinuxSdkLaunchException(primary, cleanup, session); }
            throw;
        }
    }

    private void StartDrainsAndWait()
    {
        _stdoutDrain ??= Task.Run(() => DrainAsync(_output, _stdout, "stdout"), CancellationToken.None);
        _stderrDrain ??= Task.Run(() => DrainAsync(_error, _stderr, "stderr"), CancellationToken.None);
        Record("lifetime_wait", "begin");
        _nativeWait ??= _process!.WaitAsync(CancellationToken.None);
        _completion ??= CompleteAsync();
    }

    private async Task DrainAsync(Stream? stream, Replay replay, string name)
    {
        Record(name + "_drain", "begin");
        try
        {
            if (stream is not null)
            {
                var buffer = new byte[8192];
                while (true)
                {
                    var count = await stream.ReadAsync(buffer, CancellationToken.None).ConfigureAwait(false);
                    if (count == 0) break;
                    replay.Append(buffer.AsSpan(0, count));
                }
            }
            Record(name + "_drain", "eof", new() { ["bytes"] = replay.Count.ToString(CultureInfo.InvariantCulture) });
        }
        catch (Exception error)
        {
            replay.Failure = "sdk_" + name + "_drain_failed";
            _log.Failure(_phase + "_" + name + "_drain", error);
        }
        finally { replay.Complete(); }
    }

    private async Task<LinuxSdkExit> CompleteAsync()
    {
        try
        {
            var result = await _nativeWait!.ConfigureAwait(false);
            Record("lifetime_wait", "native_complete", new() { ["exitCode"] = result.ExitCode.ToString(CultureInfo.InvariantCulture), ["timedOut"] = result.TimedOut.ToString() });
            await Task.WhenAll(_stdoutDrain!, _stderrDrain!).ConfigureAwait(false);
            if (_stdout.Failure is not null || _stderr.Failure is not null) throw new LinuxProbeException("sdk_output_drain_failed");
            return new(result.ExitCode, result.TimedOut, "official_sdk", true,
                !Directory.Exists("/proc/" + ProcessId.ToString(CultureInfo.InvariantCulture)), _stdout.Count, _stderr.Count);
        }
        catch (Exception error) { _log.Failure(_phase + "_lifetime_wait", error); throw; }
    }

    internal async Task<LinuxSdkExit> WaitAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ValidateTimeout(timeout);
        Record("client_wait", "begin");
        try { return await _completion!.WaitAsync(timeout, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Record("client_wait", "cancelled_owner_retained");
            throw;
        }
        catch (Exception error) { _log.Failure(_phase + "_client_wait", error); throw; }
    }

    internal async Task<LinuxSdkExit> StopAsync(TimeSpan timeout)
    {
        ValidateTimeout(timeout);
        Record("stop", "begin");
        try
        {
            _kill ??= Task.Run(() => _process!.Kill(), CancellationToken.None);
            await _kill.WaitAsync(timeout).ConfigureAwait(false);
            return await WaitAsync(timeout).ConfigureAwait(false);
        }
        catch (Exception error) { _log.Failure(_phase + "_stop", error); throw; }
    }

    internal void Resize(int rows, int columns)
    {
        Record("resize", "begin", new() { ["rows"] = rows.ToString(CultureInfo.InvariantCulture), ["columns"] = columns.ToString(CultureInfo.InvariantCulture) });
        try
        {
            ValidateSize(rows, columns);
            if (_process is not MxcPtyProcess pty) throw new LinuxProbeException("sdk_resize_requires_terminal");
            pty.Resize(new((ushort)rows, (ushort)columns));
            Record("resize", "complete");
        }
        catch (Exception error) { _log.Failure(_phase + "_resize", error); throw; }
    }

    internal async Task WriteInputAsync(ReadOnlyMemory<byte> data, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ValidateTimeout(timeout);
        if (data.Length is < 1 or > 32768) throw new ArgumentOutOfRangeException(nameof(data));
        ObjectDisposedException.ThrowIf(_disposed || _inputClosed, this);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _closing.Token);
        deadline.CancelAfter(timeout);
        Record("input", "begin", new() { ["bytes"] = data.Length.ToString(CultureInfo.InvariantCulture) });
        await _inputGate.WaitAsync(deadline.Token).ConfigureAwait(false);
        Task? write = null;
        try
        {
            // An observer cancellation may abandon the await. Its immutable
            // bytes and writer gate remain owned until the actual I/O finishes.
            write = _input!.WriteAsync(data.ToArray(), CancellationToken.None).AsTask();
            await write.WaitAsync(deadline.Token).ConfigureAwait(false);
            Record("input", "complete");
        }
        catch (Exception error) { _log.Failure(_phase + "_input", error); throw; }
        finally
        {
            if (write is null || write.IsCompleted) _inputGate.Release();
            else _ = ReleaseWriterAsync(write);
        }
    }

    private async Task ReleaseWriterAsync(Task write)
    {
        try { await write.ConfigureAwait(false); }
        catch (Exception error) { _log.Failure(_phase + "_pending_input", error); }
        finally { _inputGate.Release(); }
    }

    internal void CloseInput()
    {
        Record("input_close", "begin");
        _inputClosed = true;
        _inputClose ??= Task.Run(() => _input?.Dispose(), CancellationToken.None);
    }

    internal LinuxSdkOutputPage ReadOutput(long cursor, int maxBytes = 32768, bool stderr = false) => (stderr ? _stderr : _stdout).Read(cursor, maxBytes);

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        Record("dispose", "begin");
        try
        {
            await _closing.CancelAsync().ConfigureAwait(false);
            if (_process is not null)
            {
                StartDrainsAndWait();
                if (!_nativeWait!.IsCompletedSuccessfully)
                {
                    _kill ??= Task.Run(() => _process.Kill(), CancellationToken.None);
                    await _kill.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                }
                // Native finalization and the drains are required independently
                // of any client wait. A trace failure is retained in the ring.
                _ = await _nativeWait.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                await Task.WhenAll(_stdoutDrain!, _stderrDrain!).WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                if (!_inputCleanupHeld)
                {
                    if (!await _inputGate.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false)) throw new LinuxProbeException("sdk_input_cleanup_unresolved");
                    _inputCleanupHeld = true;
                }
                CloseInput();
                await _inputClose!.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                _nativeDispose ??= Task.Run(() => _process.Dispose(), CancellationToken.None);
                await _nativeDispose.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                _output?.Dispose();
                _error?.Dispose();
            }
            _disposed = true;
            _closing.Dispose();
            _inputGate.Dispose();
            Record("dispose", "complete");
        }
        catch (Exception error) { _log.Failure(_phase + "_dispose", error, cleanup: true); throw; }
    }

    private void Record(string operation, string outcome, Dictionary<string, string>? facts = null) => _log.Phase(_phase + "_" + operation, outcome, facts);
    private static void ValidateSize(int rows, int columns)
    {
        if (rows is < 1 or > 32767) throw new ArgumentOutOfRangeException(nameof(rows));
        if (columns is < 1 or > 32767) throw new ArgumentOutOfRangeException(nameof(columns));
    }
    private static void ValidateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(3)) throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    private sealed class Replay(int capacity)
    {
        private readonly byte[] _bytes = new byte[capacity];
        private readonly object _gate = new();
        private long _count;
        private bool _eof;
        internal string? Failure { get; set; }
        internal long Count { get { lock (_gate) return _count; } }
        internal void Append(ReadOnlySpan<byte> bytes)
        {
            lock (_gate)
            {
                foreach (var value in bytes) { _bytes[(int)(_count % _bytes.Length)] = value; _count = checked(_count + 1); }
            }
        }
        internal void Complete() { lock (_gate) _eof = true; }
        internal LinuxSdkOutputPage Read(long cursor, int maxBytes)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(cursor);
            ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(maxBytes, 32768);
            lock (_gate)
            {
                ArgumentOutOfRangeException.ThrowIfGreaterThan(cursor, _count);
                var first = Math.Max(0, _count - _bytes.Length);
                var start = Math.Max(first, cursor);
                var data = new byte[(int)Math.Min(maxBytes, _count - start)];
                for (var i = 0; i < data.Length; i++) data[i] = _bytes[(int)((start + i) % _bytes.Length)];
                return new(start, start + data.Length, first, _count, cursor < first ? cursor : null, cursor < first ? first : null,
                    data, _eof && start + data.Length == _count, Failure);
            }
        }
    }
}
