// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// A manually advanced clock (MOCKED time): the wall clock and the monotonic timestamp move only through <see cref="Advance"/>, and timers
/// (<c>Task.Delay</c>, <c>CancellationTokenSource</c> with this provider) fire when it passes their due time. <see cref="SetWall"/> moves the
/// wall clock alone (a skewed or corrected system clock).
/// </summary>
internal sealed class ManualClock(DateTimeOffset start) : TimeProvider
{
    private readonly Lock _gate = new();
    private readonly List<ManualTimer> _timers = [];
    private DateTimeOffset _wall = start;
    private long _ticks;
    private int _firing;

    public ManualClock()
        : this(new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero))
    {
    }

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    /// <summary>Timer callbacks that fired and have not finished yet (they run on the thread pool).</summary>
    public int Firing => Volatile.Read(ref _firing);

    /// <summary>The pending timers and when the next is due (test diagnostics).</summary>
    public string Describe()
    {
        lock (_gate)
        {
            var next = _timers.Count == 0 ? (long?)null : _timers.Min(timer => timer.Due) - _ticks;
            return $"{_timers.Count} timers, the next due in {(next is { } ticks ? TimeSpan.FromTicks(ticks).ToString() : "none")}, {Firing} firing";
        }
    }

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
        {
            return _wall;
        }
    }

    public override long GetTimestamp()
    {
        lock (_gate)
        {
            return _ticks;
        }
    }

    /// <summary>Moves both clocks forward and fires the due timers.</summary>
    public void Advance(TimeSpan by)
    {
        List<ManualTimer> due;
        lock (_gate)
        {
            _wall += by;
            _ticks += by.Ticks;
            due = [.. _timers.Where(timer => timer.Due <= _ticks)];
        }

        foreach (var timer in due)
        {
            timer.Fire();
        }
    }

    /// <summary>Sets the wall clock only (the monotonic clock keeps going as before).</summary>
    public void SetWall(DateTimeOffset wall)
    {
        lock (_gate)
        {
            _wall = wall;
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        timer.Change(dueTime, period);
        return timer;
    }

    private sealed class ManualTimer(ManualClock clock, TimerCallback callback, object? state) : ITimer
    {
        private TimeSpan _period;

        public long Due { get; private set; } = long.MaxValue;

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (clock._gate)
            {
                clock._timers.Remove(this);
                _period = period;
                if (dueTime == Timeout.InfiniteTimeSpan)
                {
                    Due = long.MaxValue;
                    return true;
                }

                Due = clock._ticks + dueTime.Ticks;
                clock._timers.Add(this);
            }

            if (dueTime == TimeSpan.Zero)
            {
                Fire();
            }

            return true;
        }

        public void Fire()
        {
            lock (clock._gate)
            {
                if (!clock._timers.Remove(this))
                {
                    return;
                }

                if (_period > TimeSpan.Zero && _period != Timeout.InfiniteTimeSpan)
                {
                    Due = clock._ticks + _period.Ticks;
                    clock._timers.Add(this);
                }
            }

            Interlocked.Increment(ref clock._firing);
            ThreadPool.UnsafeQueueUserWorkItem(_ =>
            {
                try
                {
                    callback(state);
                }
                finally
                {
                    Interlocked.Decrement(ref clock._firing);
                }
            }, null);
        }

        public void Dispose()
        {
            lock (clock._gate)
            {
                clock._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>
/// One cloud link in a temporary data root: a real node log, the isolated secret store (in memory; scripted faults available), the file-backed
/// node key store, FakeCenter as the center (MOCKED center) and a manual clock (MOCKED time). Publications are recorded.
/// </summary>
internal sealed class LinkFixture : IAsyncDisposable
{
    private CloudLinkService? _service;

    private LinkFixture(string root, FakeCenter center, ManualClock clock)
    {
        Root = root;
        Center = center;
        Clock = clock;
        DataRoot = Path.Combine(root, "data");
        Directory.CreateDirectory(Path.Combine(DataRoot, "run"));
        Log = new NodeLog(Path.Combine(root, "logs"), LogLevel.Debug, clock);
        Keys = NodeKeyStores.ForTestDataRoot(DataRoot);
        KeyFiles = (FileNodeKeyBackend)Keys.Backend;
        ConfiguredCenter = center.Endpoint;
    }

    public string Root { get; }

    public string DataRoot { get; }

    public FakeCenter Center { get; }

    public ManualClock Clock { get; }

    public NodeLog Log { get; }

    public NodeKeyStore Keys { get; set; }

    /// <summary>The file-backed key backend of the data root.</summary>
    public FileNodeKeyBackend KeyFiles { get; }

    /// <summary>When set, reading the configured center throws it (an invalid <c>node.json</c>).</summary>
    public Exception? CenterFailure { get; set; }

    public IsolatedSecretStore Secrets { get; set; } = new();

    public byte[] NodeId { get; } = RandomNumberGenerator.GetBytes(16);

    public CenterEndpoint? ConfiguredCenter { get; set; }

    public string NodeName { get; set; } = "buildbox";

    public TimeSpan? RefreshInterval { get; set; }

    /// <summary>The link's random draw in [0, 1] (<see langword="null"/>: random).</summary>
    public Func<double>? LinkRandom { get; set; }

    public string? ConnectLog { get; set; }

    /// <summary>The sign-in flows' browser (part N2): the allowed ScriptedBrowser.</summary>
    public ScriptedBrowser Browser { get; } = new();

    public List<CloudLinkPublication> Publications { get; } = [];

    /// <summary>Runs the node channel (AF-CTR-05 N1) with a real node store of the data root for <c>routed_call_log</c>.</summary>
    public bool Channel { get; set; }

    /// <summary>The routed dispatch of the channel (<see langword="null"/>: part N1's refusing dispatcher).</summary>
    public IRoutedDispatcher? Dispatcher { get; set; }

    /// <summary>The channel's step hook (AF-CTR-05 decisions B-3).</summary>
    public Func<string, Task>? StepHook { get; set; }

    /// <summary>The channel backoff's random draw.</summary>
    public Func<double>? ChannelRandom { get; set; }

    /// <summary>The node store while the link runs with <see cref="Channel"/> (closed at <see cref="StopAsync"/>, reopened at the next start).</summary>
    public NodeStore? Store { get; private set; }

    public CloudLinkService Service => _service ?? throw new InvalidOperationException("Start the link first.");

    public static async Task<LinkFixture> CreateAsync(string pathBase = "/api")
    {
        var root = Directory.CreateTempSubdirectory("arcforges-cloudlink-").FullName;
        var center = await FakeCenter.StartAsync(pathBase);
        var clock = new ManualClock();
        center.Clock = clock;
        return new LinkFixture(root, center, clock);
    }

    /// <summary>Builds and starts a link (again, after <see cref="StopAsync"/>: a node restart over the same files and secret store).</summary>
    public async Task<CloudLinkService> StartAsync()
    {
        if (Channel)
        {
            Store ??= NodeStore.Open(new NodeStoreOptions { DataRoot = DataRoot, BootIdentity = "boot-1", Clock = Clock });
        }

        var store = Store;
        _service = new CloudLinkService(new CloudLinkOptions
        {
            RoutedCalls = store is null ? null : new DirectRoutedCallStore(store),
            Dispatcher = Dispatcher,
            ChannelStepHook = StepHook,
            ChannelRandom = ChannelRandom,
            DataRoot = DataRoot,
            NodeId = NodeId,
            Secrets = Secrets.Selection,
            Keys = Keys,
            Center = () => CenterFailure is { } failure ? throw failure : ConfiguredCenter,
            Log = Log,
            Clock = Clock,
            NodeInfo = () => new EnrollingNodeInfo
            {
                NodeId = new Id { Value = ByteString.CopyFrom(NodeId) },
                Name = NodeName,
                Os = OsFamily.Linux,
                Arch = CpuArchitecture.X64,
                Version = "0.1.0-dev+0123456789abcdef0123456789abcdef01234567",
                Role = NodeRole.Host,
            },
            Publish = publication =>
            {
                lock (Publications)
                {
                    Publications.Add(publication);
                }

                return Task.CompletedTask;
            },
            RefreshInterval = RefreshInterval,
            LinkRandom = LinkRandom,
            ConnectLog = ConnectLog,
            Opener = Browser,
        });
        await _service.StartAsync();
        return _service;
    }

    /// <summary>Signs the link in with credentials FakeCenter issued (as a completed sign-in delivers them).</summary>
    public async Task<NodeCredentials> SignInAsync()
    {
        var credentials = Center.Issue(NodeId);
        await Service.AdoptAsync(credentials, Center.Endpoint);
        return credentials;
    }

    public async Task StopAsync()
    {
        if (_service is not null)
        {
            await _service.DisposeAsync();
            _service = null;
        }

        Store?.Dispose();
        Store = null;
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
    }

    /// <summary>
    /// Signs in for the channel: the node key of the center's origin first (as a sign-in creates it before its request), the peer's command key
    /// in the delivered key set, and the key registered for the credential's installation (as the center registers it at sign-in).
    /// </summary>
    public async Task<NodeCredentials> SignInWithChannelAsync()
    {
        using (var key = Keys.Load(NodeId, Center.Endpoint.Origin) ?? Keys.Create(NodeId, Center.Endpoint.Origin, Clock))
        {
            NodePublicKey = key.PublicKey;
        }

        if (!Center.CommandKeys.Any(key => key.Kid == FakeChannelPeer.Kid))
        {
            Center.CommandKeys.Add(Center.Channel.CommandPublicKey);
        }

        var credentials = Center.Issue(NodeId);
        Center.Channel.RegisterNodeKey(credentials.AccessToken, NodePublicKey);
        await Service.AdoptAsync(credentials, Center.Endpoint);
        return credentials;
    }

    /// <summary>The node key's public half (after <see cref="SignInWithChannelAsync"/>).</summary>
    public byte[] NodePublicKey { get; private set; } = [];

    /// <summary>The rows of <c>routed_call_log</c> (decision, refusal step, refusal code, call ID present).</summary>
    public List<(long Decision, string? Step, string? Code, bool CallId)> RoutedLog()
    {
        var store = Store ?? throw new InvalidOperationException("The link runs without its store.");
        return store.Read(reader =>
        {
            var rows = new List<(long, string?, string?, bool)>();
            using var command = reader.CreateCommand("SELECT decision, refusal_step, refusal_code, call_id IS NOT NULL FROM routed_call_log ORDER BY log_id;");
            using var result = command.ExecuteReader();
            while (result.Read())
            {
                rows.Add((result.GetInt64(0), result.IsDBNull(1) ? null : result.GetString(1), result.IsDBNull(2) ? null : result.GetString(2), result.GetInt64(3) == 1));
            }

            return rows;
        });
    }

    /// <summary>The stored credential record (test verification; the node reads it only through the link).</summary>
    public CloudCredentialRecord? StoredRecord()
    {
        // The test reads the files while the link may be ending them: on Windows a read of a file whose deletion is pending is refused
        // (UnauthorizedAccessException) for a moment. The test's read is retried for up to 2 s; the link's own reads run under its gate.
        var store = new CloudCredentialStore(DataRoot, Secrets.Selection);
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return store.ReadLink() is { } link ? store.ReadRecord(link.Target) : null;
            }
            catch (Exception exception) when (attempt < 40 && exception is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(50);
            }
        }
    }

    public CloudCredentialStore Storage => new(DataRoot, Secrets.Selection);

    public List<CloudNotice> Notices()
    {
        lock (Publications)
        {
            return [.. Publications.Select(publication => publication.Notice).OfType<CloudNotice>()];
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        Log.Dispose();
        await Center.DisposeAsync();
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}

internal static class Eventually
{
    /// <summary>Waits (real time, at most 15 s) until <paramref name="condition"/> holds; fails with <paramref name="what"/> otherwise.</summary>
    public static async Task TrueAsync(Func<bool> condition, string what)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(15))
            {
                Assert.Fail("Timed out waiting for: " + what);
            }

            await Task.Delay(20);
        }
    }

    /// <summary>
    /// Advances the link's clock by <paramref name="step"/> until <paramref name="condition"/> holds (at most <paramref name="limit"/>), each step
    /// only once the link's loop waits for its next due time, so no due time is passed before the loop scheduled it.
    /// </summary>
    public static async Task AdvanceUntilAsync(LinkFixture link, TimeSpan step, TimeSpan limit, Func<bool> condition, string what,
        Action<TimeSpan>? alsoAdvance = null)
    {
        var moved = TimeSpan.Zero;
        while (!condition())
        {
            await TrueAsync(() => condition() || link.Service.Idle, "the link's loop to wait (" + what + ")");
            if (condition())
            {
                return;
            }

            if (moved >= limit)
            {
                Assert.Fail("Not within " + limit + " of the link's clock: " + what);
            }

            link.Clock.Advance(step);
            alsoAdvance?.Invoke(step);
            moved += step;
            await Task.Delay(5);

            // The timers the step fired run on the thread pool: the loop is judged idle only once they have run.
            await TrueAsync(() => link.Clock.Firing == 0, "the fired timers (" + what + ")");
        }
    }

    /// <summary>Advances <paramref name="clock"/> by <paramref name="step"/> until <paramref name="condition"/> holds (at most <paramref name="limit"/>).</summary>
    public static async Task AdvanceUntilAsync(ManualClock clock, TimeSpan step, TimeSpan limit, Func<bool> condition, string what)
    {
        var moved = TimeSpan.Zero;
        while (!condition())
        {
            if (moved >= limit)
            {
                await TrueAsync(condition, what);
                return;
            }

            clock.Advance(step);
            moved += step;
            await Task.Delay(15);
        }
    }
}

/// <summary>The link tests' routed-call store: one write transaction of the node store (the host uses its command processor).</summary>
internal sealed class DirectRoutedCallStore(NodeStore store) : IRoutedCallStore
{
    /// <inheritdoc />
    public Task<long> WriteAsync(Func<StoreTransaction, long> write) => Task.FromResult(store.Write(write));
}
