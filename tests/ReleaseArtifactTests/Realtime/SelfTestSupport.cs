// SPDX-License-Identifier: AGPL-3.0-only
// Test code runs on a console without a synchronization context and holds each fixture for the whole check, so these
// library-oriented rules do not apply here; the production-shaped files of this project keep them enabled.
#pragma warning disable CA1849, CA2007, CA2000, CA1508
using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.PublicApi.V1;
using Google.Protobuf;

namespace RealtimeAotProbe;

internal sealed class SelfTestException : Exception
{
    public SelfTestException()
    {
    }

    public SelfTestException(string message)
        : base(message)
    {
    }

    public SelfTestException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Assertions and waiting that never depend on a wall clock.</summary>
internal static class Check
{
    public static void True(bool condition, string message)
    {
        if (!condition)
        {
            throw new SelfTestException(message);
        }
    }

    public static void Equal<T>(T expected, T actual, string what)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new SelfTestException(string.Create(CultureInfo.InvariantCulture, $"{what}: expected {expected}, got {actual}"));
        }
    }

    public static void Sequence<T>(IEnumerable<T> expected, IEnumerable<T> actual, string what)
    {
        T[] left = [.. expected];
        T[] right = [.. actual];
        if (!left.SequenceEqual(right))
        {
            throw new SelfTestException(what + ": expected [" + string.Join(", ", left) + "], got [" + string.Join(", ", right) + "]");
        }
    }

    public static async Task ThrowsAsync<TException>(Func<Task> action, string what)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new SelfTestException(what + ": expected " + typeof(TException).Name);
    }

    public static void Throws<TException>(Action action, string what)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new SelfTestException(what + ": expected " + typeof(TException).Name);
    }

    /// <summary>Yield until the condition holds. The bound is a count of yields, not a duration.</summary>
    public static async Task EventuallyAsync(Func<bool> condition, string what)
    {
        for (int attempt = 0; attempt < 400_000; attempt++)
        {
            if (condition())
            {
                return;
            }

            await Task.Yield();
        }

        throw new SelfTestException("never reached: " + what);
    }
}

/// <summary>A time provider that moves only when the test advances it.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<ManualTimer> _timers = [];
    private readonly DateTimeOffset _start = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
    private long _ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public TimeSpan Elapsed
    {
        get
        {
            lock (_gate)
            {
                return TimeSpan.FromTicks(_ticks);
            }
        }
    }

    public override long GetTimestamp() => Elapsed.Ticks;

    public override DateTimeOffset GetUtcNow() => _start + Elapsed;

    /// <summary>The remaining time of every armed timer, soonest first.</summary>
    public IReadOnlyList<TimeSpan> Pending()
    {
        lock (_gate)
        {
            return [.. _timers.Where(timer => timer.Armed).Select(timer => TimeSpan.FromTicks(timer.Due - _ticks)).Order()];
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        timer.Change(dueTime, period);
        lock (_gate)
        {
            _timers.Add(timer);
        }

        return timer;
    }

    /// <summary>Move forward, firing each timer due on the way at its own due time.</summary>
    public async Task AdvanceAsync(TimeSpan by)
    {
        long target;
        lock (_gate)
        {
            target = _ticks + by.Ticks;
        }

        while (true)
        {
            ManualTimer? next;
            lock (_gate)
            {
                next = _timers.Where(timer => timer.Armed && timer.Due <= target).MinBy(timer => timer.Due);
                if (next is null)
                {
                    _ticks = target;
                    return;
                }

                _ticks = Math.Max(_ticks, next.Due);
                next.Fire();
            }

            next.Invoke();
            for (int pass = 0; pass < 64; pass++)
            {
                await Task.Yield();
            }
        }
    }

    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state) : ITimer
    {
        private long _period;

        public bool Armed { get; private set; }

        public long Due { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (owner._gate)
            {
                Armed = dueTime != Timeout.InfiniteTimeSpan;
                Due = owner._ticks + (Armed ? dueTime.Ticks : 0);
                _period = period == Timeout.InfiniteTimeSpan ? 0 : period.Ticks;
            }

            return true;
        }

        public void Fire()
        {
            if (_period > 0)
            {
                Due += _period;
            }
            else
            {
                Armed = false;
            }
        }

        public void Invoke() => callback(state);

        public void Dispose()
        {
            lock (owner._gate)
            {
                Armed = false;
                owner._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>One step of a scripted stream.</summary>
internal abstract record Step
{
    public static Step Frame(StreamFrame frame) => new FrameStep(frame);

    public static Step Fail(Exception exception) => new FailStep(exception);

    public static Step After(TimeSpan delay) => new WaitStep(delay);

    public static readonly Step Hold = new HoldStep();

    public static readonly Step End = new EndStep();

    internal sealed record FrameStep(StreamFrame Value) : Step;

    internal sealed record FailStep(Exception Error) : Step;

    internal sealed record WaitStep(TimeSpan Delay) : Step;

    internal sealed record HoldStep : Step;

    internal sealed record EndStep : Step;
}

internal delegate IAsyncEnumerable<StreamFrame> StreamScript(string? cursor, CancellationToken cancellationToken);

/// <summary>A transport that replays scripts and records how it was called.</summary>
internal sealed class ScriptedTransport(TimeProvider time) : IRealtimeTransport
{
    private readonly ConcurrentQueue<StreamScript> _watch = new();
    private readonly ConcurrentQueue<StreamScript> _watchOutput = new();
    private readonly ConcurrentQueue<Func<string?, CancellationToken, Task<EventServicePollResponse>>> _poll = new();
    private readonly ConcurrentQueue<Func<string?, CancellationToken, Task<ExecutionServiceReadOutputResponse>>> _read = new();
    private int _active;
    private int _maxActive;

    public ConcurrentQueue<string?> WatchCursors { get; } = new();

    public ConcurrentQueue<string?> PollCursors { get; } = new();

    public ConcurrentQueue<string?> WatchOutputCursors { get; } = new();

    public ConcurrentQueue<string?> ReadOutputCursors { get; } = new();

    public int WatchCalls => WatchCursors.Count;

    public int PollCalls => PollCursors.Count;

    public int WatchOutputCalls => WatchOutputCursors.Count;

    public int ReadOutputCalls => ReadOutputCursors.Count;

    /// <summary>The largest number of unary calls that were in flight at the same time.</summary>
    public int MaximumConcurrentUnary => Volatile.Read(ref _maxActive);

    public void OnWatch(params Step[] steps) => _watch.Enqueue((cursor, token) => Run(steps, token));

    public void OnWatchOutput(params Step[] steps) => _watchOutput.Enqueue((cursor, token) => Run(steps, token));

    public void OnPoll(Func<string?, CancellationToken, Task<EventServicePollResponse>> script) => _poll.Enqueue(script);

    public void OnPoll(EventServicePollResponse response) => _poll.Enqueue((_, _) => Task.FromResult(response));

    public void OnReadOutput(Func<string?, CancellationToken, Task<ExecutionServiceReadOutputResponse>> script) => _read.Enqueue(script);

    public void OnReadOutput(ExecutionServiceReadOutputResponse response) => _read.Enqueue((_, _) => Task.FromResult(response));

    public IAsyncEnumerable<StreamFrame> WatchAsync(string subscriptionKey, string? cursor, CancellationToken cancellationToken)
    {
        WatchCursors.Enqueue(cursor);
        return _watch.TryDequeue(out StreamScript? script) ? script(cursor, cancellationToken) : Run([Step.Hold], cancellationToken);
    }

    public IAsyncEnumerable<StreamFrame> WatchOutputAsync(ExecutionOwner owner, string? cursor, CancellationToken cancellationToken)
    {
        WatchOutputCursors.Enqueue(cursor);
        return _watchOutput.TryDequeue(out StreamScript? script) ? script(cursor, cancellationToken) : Run([Step.Hold], cancellationToken);
    }

    public Task<EventServicePollResponse> PollAsync(string subscriptionKey, string? cursor, CancellationToken cancellationToken)
    {
        PollCursors.Enqueue(cursor);
        return Unary(_poll, cursor, cancellationToken);
    }

    public Task<ExecutionServiceReadOutputResponse> ReadOutputAsync(ExecutionOwner owner, string? cursor, CancellationToken cancellationToken)
    {
        ReadOutputCursors.Enqueue(cursor);
        return Unary(_read, cursor, cancellationToken);
    }

    private async Task<T> Unary<T>(ConcurrentQueue<Func<string?, CancellationToken, Task<T>>> queue, string? cursor, CancellationToken cancellationToken)
    {
        int now = Interlocked.Increment(ref _active);
        int seen;
        while (now > (seen = Volatile.Read(ref _maxActive)) && Interlocked.CompareExchange(ref _maxActive, now, seen) != seen)
        {
        }

        try
        {
            if (!queue.TryDequeue(out Func<string?, CancellationToken, Task<T>>? script))
            {
                throw new SelfTestException("an unscripted unary call");
            }

            return await script(cursor, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    private async IAsyncEnumerable<StreamFrame> Run(IReadOnlyList<Step> steps, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (Step step in steps)
        {
            switch (step)
            {
                case Step.FrameStep frame:
                    yield return frame.Value;
                    break;
                case Step.FailStep fail:
                    throw fail.Error;
                case Step.WaitStep wait:
                    await Task.Delay(wait.Delay, time, cancellationToken).ConfigureAwait(false);
                    break;
                case Step.HoldStep:
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    yield break;
            }
        }
    }
}

/// <summary>An observer that records everything and can be told to fail.</summary>
internal sealed class RecordingObserver : RealtimeObserver
{
    private readonly ConcurrentQueue<string> _log = new();

    public IReadOnlyList<string> Log => [.. _log];

    public List<Event> Hints { get; } = [];

    public List<SequenceGap> Gaps { get; } = [];

    public List<string> Snapshots { get; } = [];

    public List<ConnectionState> States { get; } = [];

    public List<OutputChunk> Chunks { get; } = [];

    public List<string> OutputResets { get; } = [];

    public List<ExecutionOutput> Terminals { get; } = [];

    public Func<Event, Exception?>? FailHint { get; set; }

    public override Task ConnectionChangedAsync(ConnectionState state, string detail, CancellationToken cancellationToken)
    {
        lock (States)
        {
            States.Add(state);
        }

        _log.Enqueue("state:" + state);
        return Task.CompletedTask;
    }

    public override Task HintAsync(Event hint, CancellationToken cancellationToken)
    {
        if (FailHint?.Invoke(hint) is { } error)
        {
            throw error;
        }

        lock (Hints)
        {
            Hints.Add(hint);
        }

        _log.Enqueue("hint:" + hint.Seq);
        return Task.CompletedTask;
    }

    public override Task GapAsync(SequenceGap gap, CancellationToken cancellationToken)
    {
        lock (Gaps)
        {
            Gaps.Add(gap);
        }

        _log.Enqueue($"gap:{gap.Expected}-{gap.Actual}");
        return Task.CompletedTask;
    }

    public override Task SnapshotRequiredAsync(string reason, CancellationToken cancellationToken)
    {
        lock (Snapshots)
        {
            Snapshots.Add(reason);
        }

        _log.Enqueue("snapshot:" + reason);
        return Task.CompletedTask;
    }

    public override Task OutputAsync(OutputChunk chunk, CancellationToken cancellationToken)
    {
        lock (Chunks)
        {
            Chunks.Add(chunk);
        }

        _log.Enqueue("output:" + chunk.Offset);
        return Task.CompletedTask;
    }

    public override Task OutputResetAsync(string reason, CancellationToken cancellationToken)
    {
        lock (OutputResets)
        {
            OutputResets.Add(reason);
        }

        _log.Enqueue("outputreset");
        return Task.CompletedTask;
    }

    public override Task TerminalAsync(ExecutionOutput terminal, CancellationToken cancellationToken)
    {
        lock (Terminals)
        {
            Terminals.Add(terminal);
        }

        _log.Enqueue("terminal");
        return Task.CompletedTask;
    }

    public int Count(Func<List<ConnectionState>, int> read)
    {
        lock (States)
        {
            return read(States);
        }
    }
}

/// <summary>Builders for generated records.</summary>
internal static class Make
{
    public const string Key = "workspace:11111111-1111-1111-1111-111111111111";

    public static Id NewId(byte seed) => new() { Value = ByteString.CopyFrom(Enumerable.Repeat(seed, 16).ToArray()) };

    public static ExecutionOwner Owner(byte seed = 7) => new() { TaskId = NewId(seed) };

    public static Event Hint(ulong sequence, string key = Key, bool payload = true)
    {
        var hint = new Event { SubscriptionKey = key, Seq = sequence };
        if (payload)
        {
            hint.SyncChanged = new SyncChanged();
        }

        return hint;
    }

    public static StreamFrame HintFrame(ulong sequence, string? cursor = null, string key = Key) =>
        new() { Position = Position(cursor ?? "c" + sequence.ToString(CultureInfo.InvariantCulture), sequence), Hint = Hint(sequence, key) };

    public static StreamFrame Heartbeat(string? cursor = null)
    {
        var frame = new StreamFrame { Heartbeat = new Instant { UnixSeconds = 1 } };
        if (cursor is not null)
        {
            frame.Position = Position(cursor, 0);
        }

        return frame;
    }

    public static StreamFrame Reset(string reason, bool snapshot, string? resumeFrom = null)
    {
        var reset = new StreamReset { Reason = reason, SnapshotRequired = snapshot };
        if (resumeFrom is not null)
        {
            reset.ResumeFrom = resumeFrom;
        }

        return new StreamFrame { Reset = reset };
    }

    public static StreamFrame ErrorFrame(ErrorCategory category, RetryMode? mode = null, Instant? retryAt = null, string code = "test.error")
    {
        var error = new ArcError { Code = code, Category = category };
        if (mode is { } value)
        {
            error.Retry = new RetryAdvice { Mode = value };
            if (retryAt is not null)
            {
                error.Retry.RetryAt = retryAt;
            }
        }

        return new StreamFrame { Error = error };
    }

    public static StreamPosition Position(string cursor, ulong sequence) => new() { Cursor = cursor, Sequence = sequence, Generation = 1 };

    public static OutputChunk Chunk(ulong offset, string text, byte owner = 7, string? hash = null, byte attempt = 1, byte stream = 2) => new()
    {
        Execution = Owner(owner),
        Offset = offset,
        Data = ByteString.CopyFromUtf8(text),
        ChunkHash = hash ?? "h:" + offset.ToString(CultureInfo.InvariantCulture),
        Kind = "text",
        AttemptId = NewId(attempt),
        StreamId = NewId(stream),
    };

    public static StreamFrame ChunkFrame(ulong offset, string text, string? cursor = null, byte owner = 7) =>
        new() { Position = Position(cursor ?? "o" + (offset + (ulong)text.Length).ToString(CultureInfo.InvariantCulture), offset), Output = Chunk(offset, text, owner) };

    public static ExecutionOutput Terminal(string hash = "final", string state = "completed", byte owner = 7) =>
        new() { Execution = Owner(owner), State = state, FinalHash = hash };

    public static StreamFrame TerminalFrame(string hash = "final", string state = "completed", byte owner = 7) =>
        new() { Terminal = Terminal(hash, state, owner) };

    public static EventServicePollResponse PollReset(string next) =>
        new() { Value = new EventServicePollValue { ResetRequired = true, NextCursor = next } };

    public static EventServicePollResponse PollPage(string next, params Event[] hints)
    {
        var value = new EventServicePollValue { NextCursor = next };
        value.Events.AddRange(hints);
        return new EventServicePollResponse { Value = value };
    }

    public static ExecutionServiceReadOutputResponse ReadPage(string? cursor, ExecutionOutput? terminal = null, params OutputChunk[] chunks)
    {
        var value = new ExecutionServiceReadOutputValue();
        value.Chunks.AddRange(chunks);
        if (cursor is not null)
        {
            value.Position = Position(cursor, 0);
        }

        if (terminal is not null)
        {
            value.Terminal = terminal;
        }

        return new ExecutionServiceReadOutputResponse { Value = value };
    }

    public static ExecutionServiceReadOutputResponse ReadReset() =>
        new() { Value = new ExecutionServiceReadOutputValue { ResetRequired = true } };

    public static Instant At(DateTimeOffset moment) => new() { UnixSeconds = moment.ToUnixTimeSeconds() };

    /// <summary>The parser exception a corrupt message raises (its constructors are not public).</summary>
    public static InvalidProtocolBufferException Malformed()
    {
        try
        {
            _ = Event.Parser.ParseFrom(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });
        }
        catch (InvalidProtocolBufferException ex)
        {
            return ex;
        }

        throw new SelfTestException("the corrupt bytes parsed");
    }
}

/// <summary>Binary gRPC-Web message framing for the replayed HTTP responses.</summary>
internal static class GrpcWebWire
{
    public static byte[] Message(IMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        return Frame(0x00, message.ToByteArray());
    }

    public static byte[] Frame(byte flag, byte[] payload)
    {
        byte[] bytes = new byte[5 + payload.Length];
        bytes[0] = flag;
        bytes[1] = (byte)(payload.Length >> 24);
        bytes[2] = (byte)(payload.Length >> 16);
        bytes[3] = (byte)(payload.Length >> 8);
        bytes[4] = (byte)payload.Length;
        payload.CopyTo(bytes, 5);
        return bytes;
    }

    public static byte[] Trailers(int status, string? message = null)
    {
        string text = "grpc-status: " + status.ToString(CultureInfo.InvariantCulture) + "\r\n" + (message is null ? string.Empty : "grpc-message: " + message + "\r\n");
        return Frame(0x80, System.Text.Encoding.ASCII.GetBytes(text));
    }
}

/// <summary>An HTTP handler that answers with a body the test feeds and completes.</summary>
internal sealed class ReplayHandler : HttpMessageHandler
{
    private readonly Channel<byte[]> _body = Channel.CreateUnbounded<byte[]>();
    private readonly TaskCompletionSource _sent = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public HttpRequestMessage? Request { get; private set; }

    public byte[] RequestBody { get; private set; } = [];

    public string? AuthorizationHeader { get; private set; }

    public Task Sent => _sent.Task;

    public bool BodyDisposed { get; private set; }

    public void Write(byte[] bytes) => _body.Writer.TryWrite(bytes);

    public void WriteByteByByte(byte[] bytes)
    {
        foreach (byte value in bytes)
        {
            _body.Writer.TryWrite([value]);
        }
    }

    public void Complete() => _body.Writer.TryComplete();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Request = request;
        AuthorizationHeader = request.Headers.TryGetValues("Authorization", out IEnumerable<string>? values) ? values.Single() : null;
        RequestBody = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var content = new StreamContent(new ChannelStream(_body.Reader, () => BodyDisposed = true));
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc-web");
        _sent.TrySetResult();
        return new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = content, Version = new Version(1, 1), RequestMessage = request };
    }

    private sealed class ChannelStream(ChannelReader<byte[]> reader, Action onDispose) : Stream
    {
        private byte[] _current = [];
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException("Length");

        public override long Position
        {
            get => throw new NotSupportedException("Position get");
            set => throw new NotSupportedException("Position set");
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("Read");

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException("Seek");

        public override void SetLength(long value) => throw new NotSupportedException("SetLength");

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("Write");

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (_position >= _current.Length)
            {
                if (!await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return 0;
                }

                if (reader.TryRead(out byte[]? next))
                {
                    _current = next;
                    _position = 0;
                }
            }

            int count = Math.Min(buffer.Length, _current.Length - _position);
            _current.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                onDispose();
            }

            base.Dispose(disposing);
        }
    }
}
