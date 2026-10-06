// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;

namespace ArcForges.Observability.Desktop;

/// <summary>A host adapter that observes the real dependency it owns; absence or failure must never return Available.</summary>
public interface IRequiredDependencyProbe
{
    string DependencyId { get; }
    ValueTask<DependencyReadinessStatus> ProbeAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Bounded, serialized readiness collection over actual dependency adapters. A timed-out adapter remains the only
/// outstanding call for that dependency until it finishes, preventing repeated checks from accumulating hung work.
/// Caller cancellation propagates, while dependency failures and deadlines fail readiness closed.
/// </summary>
public sealed class DependencyHealthMonitor : IAsyncDisposable
{
    private readonly SemaphoreSlim _refresh = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly ProbeState[] _probes;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private Task? _shutdown;
    private bool _stopping;

    public DependencyHealthMonitor(IEnumerable<IRequiredDependencyProbe> probes, TimeSpan timeout, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(probes);
        if (timeout < TimeSpan.FromMilliseconds(10) || timeout > TimeSpan.FromSeconds(30)) throw new ArgumentOutOfRangeException(nameof(timeout));
        IRequiredDependencyProbe[] supplied = probes.Take(33).ToArray();
        if (supplied.Length is 0 or > 32 || supplied.Any(probe => probe is null || !ValidId(probe.DependencyId))
            || supplied.Select(probe => probe.DependencyId).Distinct(StringComparer.Ordinal).Count() != supplied.Length)
            throw new ArgumentException("One to thirty-two uniquely identified dependency adapters are required.", nameof(probes));
        _probes = supplied.Select(probe => new ProbeState(probe, probe.DependencyId)).ToArray();
        _timeout = timeout;
        _time = time ?? TimeProvider.System;
    }

    public async ValueTask<HealthProbeResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate) ObjectDisposedException.ThrowIf(_stopping, this);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        await _refresh.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            linked.Token.ThrowIfCancellationRequested();
            RequiredDependencyObservation[] observations = await Task.WhenAll(_probes.Select(probe => CheckOneAsync(probe, linked.Token))).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            return HealthProbe.CheckReadiness(_probes.Select(probe => probe.Id), observations);
        }
        finally { _refresh.Release(); }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _stopping = true;
            return new ValueTask(_shutdown ??= ShutdownAsync());
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Dependency adapter errors are a typed Unavailable fact; exception messages or objects never leave the health boundary.")]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The linked source belongs to the actual adapter operation, not its bounded wait; its completion continuation disposes it even after a timeout.")]
    private async Task<RequiredDependencyObservation> CheckOneAsync(ProbeState state, CancellationToken cancellationToken)
    {
        if (state.Pending is { IsCompleted: false }) return new(state.Id, DependencyReadinessStatus.Unavailable);
        state.Deadline?.Dispose();
        state.Deadline = new CancellationTokenSource(_timeout, _time);
        var linked = CancellationTokenSource.CreateLinkedTokenSource(state.Deadline.Token, cancellationToken);
        Task<DependencyReadinessStatus>? pending = null;
        try
        {
            pending = Task.Run(async () => await state.Probe.ProbeAsync(linked.Token).ConfigureAwait(false), CancellationToken.None);
            state.Pending = pending;
            // Dispose this operation's linked source even if an uncooperative adapter outlives the timeout.
            _ = pending.ContinueWith(completed => { _ = completed.Exception; linked.Dispose(); }, CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            DependencyReadinessStatus status = await state.Pending.WaitAsync(_timeout, _time, cancellationToken).ConfigureAwait(false);
            return new(state.Id, Enum.IsDefined(status) ? status : DependencyReadinessStatus.Unavailable);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            if (pending is null) linked.Dispose();
            return new(state.Id, DependencyReadinessStatus.Unavailable);
        }
    }

    private async Task ShutdownAsync()
    {
        await Task.Yield();
        await _lifetime.CancelAsync().ConfigureAwait(false);
        await _refresh.WaitAsync().ConfigureAwait(false);
        foreach (ProbeState probe in _probes) probe.Deadline?.Dispose();
        _refresh.Release();
        _refresh.Dispose();
        _lifetime.Dispose();
    }

    private static bool ValidId(string value) => value is { Length: > 0 and <= 64 }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_');

    private sealed class ProbeState(IRequiredDependencyProbe probe, string id)
    {
        internal IRequiredDependencyProbe Probe { get; } = probe;
        internal string Id { get; } = id;
        internal Task<DependencyReadinessStatus>? Pending { get; set; }
        internal CancellationTokenSource? Deadline { get; set; }
    }
}

/// <summary>Real read/write/flush readiness of a host-owned diagnostic directory. Uses only a new, delete-on-close probe file.</summary>
public sealed class DiagnosticDirectoryProbe : IRequiredDependencyProbe
{
    private readonly string _directory;

    public DiagnosticDirectoryProbe(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        _directory = Path.GetFullPath(directory);
    }

    public string DependencyId => "diagnostics.storage";

    public async ValueTask<DependencyReadinessStatus> ProbeAsync(CancellationToken cancellationToken)
    {
        string path = Path.Combine(_directory, ".arcf-health-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                1, FileOptions.Asynchronous | FileOptions.DeleteOnClose);
            await using (file.ConfigureAwait(false))
            {
                byte[] expected = [0x41];
                await file.WriteAsync(expected, cancellationToken).ConfigureAwait(false);
                await file.FlushAsync(cancellationToken).ConfigureAwait(false);
                file.Position = 0;
                byte[] actual = new byte[1];
                int read = await file.ReadAsync(actual, cancellationToken).ConfigureAwait(false);
                return read == 1 && actual[0] == expected[0] ? DependencyReadinessStatus.Available : DependencyReadinessStatus.Unavailable;
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { return DependencyReadinessStatus.Unavailable; }
    }
}
