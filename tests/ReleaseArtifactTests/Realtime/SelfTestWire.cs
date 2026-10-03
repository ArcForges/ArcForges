// SPDX-License-Identifier: AGPL-3.0-only
// Test code runs on a console without a synchronization context and holds each fixture for the whole check, so these
// library-oriented rules do not apply here; the production-shaped files of this project keep them enabled.
#pragma warning disable CA1849, CA2007, CA2000, CA1508
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.PublicApi.V1;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;

namespace RealtimeAotProbe;

/// <summary>
/// The real generated clients and the real <c>GrpcWebHandler</c> over a handler that replays HTTP bytes.
/// Nothing here opens a socket or calls a service: it proves how this client encodes requests and decodes
/// responses, trailers, cancellation and malformed input under the executing runtime, not what any server does.
/// </summary>
internal static class SelfTestWire
{
    private const ulong BeyondSafe = (1UL << 53) + 1;

    public static void Register(SelfTestRunner runner)
    {
        ArgumentNullException.ThrowIfNull(runner);
        runner.Add("grpc-web: Watch is a binary gRPC-Web POST of the generated request at /api/arcforges.events.v1.EventService/Watch", WatchRequestIsBinaryGrpcWeb);
        runner.Add("grpc-web: frames delivered one byte at a time decode in order and the stream ends cleanly", FramesSplitAcrossReads);
        runner.Add("grpc-web: the trailer status ends the stream with a typed status", TrailerStatus);
        runner.Add("grpc-web: a stream that ends without trailers is an error, never a clean end", MissingTrailers);
        runner.Add("grpc-web: cancelling ends the call and releases the response body", Cancellation);
        runner.Add("grpc-web: bytes that are not the generated message are a protocol violation", MalformedMessage);
        runner.Add("grpc-web: a message over the receive bound is refused, one at the bound is read", ReceiveBound);
        runner.Add("grpc-web: the authorization header is sent only when configured", Authorization);
        runner.Add("grpc-web: Poll, WatchOutput and ReadOutput use the generated routes and bounded requests", UnaryAndOutputRoutes);
    }

    /// <summary>One replayed call: handler, channel, transport and the stream being read, released together.</summary>
    private sealed class Session : IAsyncDisposable
    {
        private readonly CancellationTokenSource _cancel = new();
        private IAsyncEnumerator<StreamFrame>? _frames;
        private Task? _pending;

        public Session(string? authorization = null)
        {
            Handler = new ReplayHandler();
            Channel = RealtimeChannel.Create(new Uri("https://replay.test/"), authorization, Handler);
            Transport = new GeneratedRealtimeTransport(Channel, new RealtimePolicy());
        }

        public ReplayHandler Handler { get; }

        public GrpcChannel Channel { get; }

        public GeneratedRealtimeTransport Transport { get; }

        public CancellationToken Token => _cancel.Token;

        public StreamFrame Current => _frames!.Current;

        public void StartWatch(string? cursor) => _frames = Transport.WatchAsync(Make.Key, cursor, _cancel.Token).GetAsyncEnumerator(_cancel.Token);

        public void StartWatchOutput(ExecutionOwner owner, string? cursor) =>
            _frames = Transport.WatchOutputAsync(owner, cursor, _cancel.Token).GetAsyncEnumerator(_cancel.Token);

        public Task<bool> Move()
        {
            Task<bool> move = _frames!.MoveNextAsync().AsTask();
            _pending = move;
            return move;
        }

        public Task CancelAsync() => _cancel.CancelAsync();

        public async Task SentAsync() =>
            await Check.EventuallyAsync(() => Handler.Sent.IsCompleted, "the request reaching the handler").ConfigureAwait(false);

        public async ValueTask DisposeAsync()
        {
            await _cancel.CancelAsync().ConfigureAwait(false);
            if (_pending is not null)
            {
                await Check.EventuallyAsync(() => _pending.IsCompleted, "the pending read to end after cancellation").ConfigureAwait(false);
                _ = _pending.Exception;
            }

            if (_frames is not null)
            {
                await _frames.DisposeAsync().ConfigureAwait(false);
            }

            Channel.Dispose();
            _cancel.Dispose();
        }
    }

    private static async Task<T> Done<T>(Task<T> task, string what)
    {
        await Check.EventuallyAsync(() => task.IsCompleted, what).ConfigureAwait(false);
        return await task.ConfigureAwait(false);
    }

    private static async Task<Exception> Failure(Task task, string what)
    {
        await Check.EventuallyAsync(() => task.IsCompleted, what).ConfigureAwait(false);
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is RpcException or OperationCanceledException)
        {
            return ex;
        }

        throw new SelfTestException(what + ": expected the call to fail");
    }

    private static async Task WatchRequestIsBinaryGrpcWeb()
    {
        await using var session = new Session();
        session.StartWatch("resume-cursor");
        Task<bool> first = session.Move();
        await session.SentAsync().ConfigureAwait(false);
        HttpRequestMessage request = session.Handler.Request!;
        Check.Equal("POST", request.Method.Method, "method");
        Check.Equal("/api/arcforges.events.v1.EventService/Watch", request.RequestUri!.AbsolutePath, "route");
        Check.Equal("application/grpc-web", request.Content!.Headers.ContentType!.MediaType ?? string.Empty, "binary content type, not grpc-web-text");
        Check.True(session.Handler.AuthorizationHeader is null, "no authorization header was configured");
        byte[] body = session.Handler.RequestBody;
        Check.Equal((byte)0, body[0], "an uncompressed data frame");
        int length = (body[1] << 24) | (body[2] << 16) | (body[3] << 8) | body[4];
        Check.Equal(body.Length - 5, length, "length prefix");
        var parsed = EventServiceWatchRequest.Parser.ParseFrom(body.AsSpan(5));
        Check.Equal(Make.Key, parsed.SubscriptionKey, "subscription key");
        Check.Equal("resume-cursor", parsed.Cursor, "cursor");
        Check.Equal(16, parsed.Meta.CorrelationId.Value.Length, "a 16 byte correlation id");
        Check.True(parsed.Meta.CommandId is null, "a read carries no command id");
        StreamFrame frame = Make.HintFrame(BeyondSafe, "c1");
        session.Handler.Write(GrpcWebWire.Message(frame));
        session.Handler.Write(GrpcWebWire.Trailers(0));
        session.Handler.Complete();
        Check.True(await Done(first, "the first frame").ConfigureAwait(false) && session.Current.Equals(frame), "the replayed frame");
        Check.True(!await Done(session.Move(), "the end of the stream").ConfigureAwait(false), "a clean end after the OK trailer");
    }

    private static async Task FramesSplitAcrossReads()
    {
        await using var session = new Session();
        session.StartWatch(null);
        Task<bool> first = session.Move();
        await session.SentAsync().ConfigureAwait(false);
        StreamFrame one = Make.HintFrame(1);
        StreamFrame two = Make.HintFrame(2);
        session.Handler.WriteByteByByte(GrpcWebWire.Message(one));
        session.Handler.WriteByteByByte(GrpcWebWire.Message(two));
        session.Handler.WriteByteByByte(GrpcWebWire.Trailers(0));
        session.Handler.Complete();
        Check.True(await Done(first, "the first frame").ConfigureAwait(false) && session.Current.Equals(one), "first frame");
        Check.True(await Done(session.Move(), "the second frame").ConfigureAwait(false) && session.Current.Equals(two), "second frame");
        Check.True(!await Done(session.Move(), "the end of the stream").ConfigureAwait(false), "clean end");
    }

    private static async Task TrailerStatus()
    {
        await using var session = new Session();
        session.StartWatch(null);
        Task<bool> first = session.Move();
        await session.SentAsync().ConfigureAwait(false);
        session.Handler.Write(GrpcWebWire.Message(Make.HintFrame(1)));
        session.Handler.Write(GrpcWebWire.Trailers((int)StatusCode.Unavailable, "overloaded"));
        session.Handler.Complete();
        Check.True(await Done(first, "the first frame").ConfigureAwait(false), "the frame before the failing trailer is delivered");
        Exception error = await Failure(session.Move(), "the failing read").ConfigureAwait(false);
        var rpc = error as RpcException ?? throw new SelfTestException("expected an RpcException, got " + error.GetType().Name);
        Check.Equal(StatusCode.Unavailable, rpc.StatusCode, "trailer status");
        Check.Equal(Disposition.Retry, ErrorClassifier.FromRpc(rpc).Disposition, "Unavailable retries");
    }

    private static async Task MissingTrailers()
    {
        await using var session = new Session();
        session.StartWatch(null);
        Task<bool> first = session.Move();
        await session.SentAsync().ConfigureAwait(false);
        session.Handler.Write(GrpcWebWire.Message(Make.HintFrame(1)));
        session.Handler.Complete();
        Check.True(await Done(first, "the first frame").ConfigureAwait(false), "the frame before the body ended");
        Exception error = await Failure(session.Move(), "the read after the body ended").ConfigureAwait(false);
        Check.True(FailureMapper.TryMap(error, CancellationToken.None, out ConnectionEnd end), "the failure is understood: " + error.GetType().Name);
        Check.Equal(EndKind.Retryable, end.Kind, "a body that ended without trailers retries, it never completes");
    }

    private static async Task Cancellation()
    {
        await using var session = new Session();
        session.StartWatch(null);
        Task<bool> pending = session.Move();
        await session.SentAsync().ConfigureAwait(false);
        await session.CancelAsync().ConfigureAwait(false);
        Exception error = await Failure(pending, "the cancelled read").ConfigureAwait(false);
        Check.True(error is OperationCanceledException, "a cancelled read raises OperationCanceledException: " + error.GetType().Name);
        await Check.EventuallyAsync(() => session.Handler.BodyDisposed, "the response body being released").ConfigureAwait(false);
        Check.True(FailureMapper.TryMap(error, session.Token, out ConnectionEnd end) && end.Kind == EndKind.Cancelled, "the caller's own cancellation maps to cancelled");
    }

    private static async Task MalformedMessage()
    {
        await using var session = new Session();
        session.StartWatch(null);
        Task<bool> first = session.Move();
        await session.SentAsync().ConfigureAwait(false);
        session.Handler.Write(GrpcWebWire.Frame(0x00, [0xFF, 0xFF, 0xFF, 0xFF]));
        session.Handler.Write(GrpcWebWire.Trailers(0));
        session.Handler.Complete();
        Exception error = await Failure(first, "the malformed frame").ConfigureAwait(false);
        var rpc = error as RpcException ?? throw new SelfTestException("expected an RpcException, got " + error.GetType().Name);
        Check.Equal(Disposition.StopProtocol, ErrorClassifier.FromRpc(rpc).Disposition, "a malformed message stops: " + rpc.StatusCode);
    }

    private static async Task ReceiveBound()
    {
        int limit = RealtimeChannel.MaximumReceiveBytes;
        int size = limit;
        StreamFrame Sized(int bytes) => new() { Output = new OutputChunk { Data = ByteString.CopyFrom(new byte[bytes]) } };
        while (Sized(size).CalculateSize() > limit)
        {
            size--;
        }

        Check.True(Sized(size).CalculateSize() <= limit && Sized(size + 1).CalculateSize() > limit, "the probe frame straddles the bound");
        foreach ((int bytes, bool accepted) in new[] { (size, true), (size + 1, false) })
        {
            await using var session = new Session();
            session.StartWatch(null);
            Task<bool> read = session.Move();
            await session.SentAsync().ConfigureAwait(false);
            session.Handler.Write(GrpcWebWire.Message(Sized(bytes)));
            session.Handler.Write(GrpcWebWire.Trailers(0));
            session.Handler.Complete();
            if (accepted)
            {
                Check.True(await Done(read, "the frame at the bound").ConfigureAwait(false) && session.Current.Output.Data.Length == bytes, "a frame at the bound is read");
            }
            else
            {
                Exception error = await Failure(read, "the frame over the bound").ConfigureAwait(false);
                var rpc = error as RpcException ?? throw new SelfTestException("expected an RpcException, got " + error.GetType().Name);
                Check.Equal(StatusCode.ResourceExhausted, rpc.StatusCode, "a frame over the bound is refused");
            }
        }
    }

    private static async Task Authorization()
    {
        await using var session = new Session("Bearer test-value");
        session.StartWatch(null);
        Task<bool> read = session.Move();
        await session.SentAsync().ConfigureAwait(false);
        Check.Equal("Bearer test-value", session.Handler.AuthorizationHeader ?? string.Empty, "the configured authorization header");
        session.Handler.Write(GrpcWebWire.Trailers(0));
        session.Handler.Complete();
        Check.True(!await Done(read, "the end of the stream").ConfigureAwait(false), "the stream ended cleanly after the OK trailer");
    }

    private static async Task UnaryAndOutputRoutes()
    {
        var policy = new RealtimePolicy();
        ExecutionOwner owner = Make.Owner();

        await using (var poll = new Session())
        {
            Task<EventServicePollResponse> call = poll.Transport.PollAsync(Make.Key, null, poll.Token);
            await poll.SentAsync().ConfigureAwait(false);
            Check.Equal("/api/arcforges.events.v1.EventService/Poll", poll.Handler.Request!.RequestUri!.AbsolutePath, "Poll route");
            var request = EventServicePollRequest.Parser.ParseFrom(poll.Handler.RequestBody.AsSpan(5));
            Check.True(!request.HasCursor, "the first Poll carries no cursor");
            poll.Handler.Write(GrpcWebWire.Message(Make.PollReset("n1")));
            poll.Handler.Write(GrpcWebWire.Trailers(0));
            poll.Handler.Complete();
            EventServicePollResponse response = await Done(call, "the Poll response").ConfigureAwait(false);
            Check.True(response.Value.ResetRequired && response.Value.NextCursor == "n1", "the Poll response");
        }

        await using (var output = new Session())
        {
            output.StartWatchOutput(owner, "o1");
            Task<bool> read = output.Move();
            await output.SentAsync().ConfigureAwait(false);
            Check.Equal("/api/arcforges.events.v1.ExecutionService/WatchOutput", output.Handler.Request!.RequestUri!.AbsolutePath, "WatchOutput route");
            var request = ExecutionServiceWatchOutputRequest.Parser.ParseFrom(output.Handler.RequestBody.AsSpan(5));
            Check.True(request.Owner.Equals(owner) && request.Cursor == "o1", "WatchOutput request");
            output.Handler.Write(GrpcWebWire.Trailers(0));
            output.Handler.Complete();
            Check.True(!await Done(read, "the empty output stream").ConfigureAwait(false), "an empty output stream ends cleanly");
        }

        await using (var reads = new Session())
        {
            Task<ExecutionServiceReadOutputResponse> call = reads.Transport.ReadOutputAsync(owner, "o9", reads.Token);
            await reads.SentAsync().ConfigureAwait(false);
            Check.Equal("/api/arcforges.events.v1.ExecutionService/ReadOutput", reads.Handler.Request!.RequestUri!.AbsolutePath, "ReadOutput route");
            var request = ExecutionServiceReadOutputRequest.Parser.ParseFrom(reads.Handler.RequestBody.AsSpan(5));
            Check.Equal((uint)policy.MaximumPageChunks, request.Limit, "ReadOutput asks for the page bound");
            Check.True(request.Owner.Equals(owner) && request.Cursor == "o9", "ReadOutput request");
            reads.Handler.Write(GrpcWebWire.Message(Make.ReadPage("o10", Make.Terminal(), Make.Chunk(0, "a"))));
            reads.Handler.Write(GrpcWebWire.Trailers(0));
            reads.Handler.Complete();
            ExecutionServiceReadOutputResponse response = await Done(call, "the ReadOutput response").ConfigureAwait(false);
            Check.True(response.Value.Terminal.FinalHash == "final" && response.Value.Chunks.Count == 1, "the ReadOutput response");
        }
    }
}
