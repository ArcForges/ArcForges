// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Net;
using System.Text;
using ArcForges.Contracts.Hello.V1;
using Google.Protobuf;

namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

/// <summary>
/// One deliberate misbehavior of the fixture ingress. The self-test runs the verifier against each of them and
/// requires the named check to fail, so the verifier is shown to discriminate rather than to accept anything.
/// </summary>
internal enum FixtureFault
{
    None,
    OmitTrailerFrame,
    EmptyNameSucceeds,
    TooLongSucceeds,
    CountUtf8BytesNotUtf16Units,
    RewriteUnicode,
    ApplicationErrorAsHttp400,
    NoWorkerRevisionHeader,
    WorkerRevisionMismatch,
    UnknownMethodSucceeds,
    HealthReportsJit,
    HttpFailureAsSuccess,
    EmptyNameWrongCode,
    EmptyNameNoMessage,
    HealthServerError,
    UnknownMethodForbidden,
    WrongResponseMediaType,
    BrokenAfterCancel,
}

/// <summary>Shared by every handler instance of one fixture so counters survive channel disposal.</summary>
internal sealed class FixtureState
{
    private int _dropNext;
    private int _cancelled;
    private int _failNextStatus;

    public FixtureState(FixtureFault fault) => Fault = fault;

    public FixtureFault Fault { get; }

    public string Revision { get; } = new('c', 40);

    public TimeSpan Latency { get; } = TimeSpan.FromMilliseconds(100);

    /// <summary>Fails the next transport attempts as a lost connection.</summary>
    public void DropNext(int count) => Volatile.Write(ref _dropNext, count);

    /// <summary>Answers the next request with a boundary HTTP failure (413, 415, 429 or 503) and a plain-text body.</summary>
    public void FailNextWith(int status) => Volatile.Write(ref _failNextStatus, status);

    public bool TryTakeDrop()
    {
        while (true)
        {
            int current = Volatile.Read(ref _dropNext);
            if (current <= 0)
            {
                return false;
            }

            if (Interlocked.CompareExchange(ref _dropNext, current - 1, current) == current)
            {
                return true;
            }
        }
    }

    public void MarkCancelled() => Volatile.Write(ref _cancelled, 1);

    public bool TakeCancelled() => Interlocked.Exchange(ref _cancelled, 0) == 1;

    public int TakeFailStatus() => Interlocked.Exchange(ref _failNextStatus, 0);
}

/// <summary>
/// A test-only stand-in for the deployed Worker/Container Hello ingress that follows the contract written in the
/// Cloud repository (docs/development.md, worker/router.ts): binary gRPC-Web in, HTTP 200 with a terminal status
/// frame for application results, plain boundary HTTP failures, caller deadline honored. It proves the probe's own
/// verification logic only; it is never evidence about a real ingress.
/// </summary>
internal sealed class IngressFixtureHandler(FixtureState state) : HttpMessageHandler
{
    private const string HelloPath = "/arcforges.hello.v1.HelloService/SayHello";
    private const string HealthPath = "/healthz";
    private const int MaximumNameUtf16Units = 256;
    private const int GrpcOk = 0;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (state.TryTakeDrop())
        {
            throw new HttpRequestException("Fixture: connection lost.", new IOException("Fixture: connection reset."));
        }

        if (state.Fault == FixtureFault.BrokenAfterCancel && state.TakeCancelled())
        {
            return PlainFailure(HttpStatusCode.ServiceUnavailable);
        }

        try
        {
            await Task.Delay(state.Latency, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            state.MarkCancelled();
            throw;
        }

        string path = request.RequestUri?.AbsolutePath ?? string.Empty;
        int failure = state.TakeFailStatus();
        if (failure != 0)
        {
            return state.Fault == FixtureFault.HttpFailureAsSuccess
                ? Grpc(new SayHelloResponse { Message = "Hello, boundary!" }, GrpcOk, state.Revision)
                : PlainFailure((HttpStatusCode)failure);
        }

        if (request.Method == HttpMethod.Get && path.EndsWith(HealthPath, StringComparison.Ordinal))
        {
            bool aot = state.Fault != FixtureFault.HealthReportsJit;
            string json = "{\"service\":\"fixture\",\"revision\":\"" + state.Revision + "\",\"nativeAot\":" +
                (aot ? "true" : "false") + ",\"artifact\":{},\"build\":{}}";
            var health = new HttpResponseMessage(state.Fault == FixtureFault.HealthServerError ? HttpStatusCode.InternalServerError : HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            health.Headers.Add("x-arcforges-worker-revision", state.Revision);
            return health;
        }

        if (request.Method != HttpMethod.Post || !path.EndsWith(HelloPath, StringComparison.Ordinal))
        {
            return state.Fault switch
            {
                FixtureFault.UnknownMethodSucceeds => Grpc(new SayHelloResponse(), GrpcOk, state.Revision),
                FixtureFault.UnknownMethodForbidden => PlainFailure(HttpStatusCode.Forbidden),
                _ => PlainFailure(HttpStatusCode.NotFound),
            };
        }

        string? mediaType = request.Content?.Headers.ContentType?.MediaType;
        if (mediaType is not ("application/grpc-web" or "application/grpc-web+proto"))
        {
            return PlainFailure(HttpStatusCode.UnsupportedMediaType);
        }

        byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (body.Length < 5 || body[0] != 0 || BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(1, 4)) != body.Length - 5)
        {
            return RpcError(13, "Fixture: malformed frame.");
        }

        var parsed = SayHelloRequest.Parser.ParseFrom(body.AsSpan(5));
        string name = parsed.Name;
        if (state.Fault == FixtureFault.RewriteUnicode)
        {
            name = name.Replace(Exactness.Precomposed, Exactness.Decomposed, StringComparison.Ordinal);
        }

        int length = state.Fault == FixtureFault.CountUtf8BytesNotUtf16Units ? Encoding.UTF8.GetByteCount(name) : name.Length;
        if (name.Length == 0 && state.Fault != FixtureFault.EmptyNameSucceeds)
        {
            return ApplicationError(state.Fault == FixtureFault.EmptyNameWrongCode ? 2 : 3,
                state.Fault == FixtureFault.EmptyNameNoMessage ? null : "Name must not be empty.");
        }

        if (length > MaximumNameUtf16Units && state.Fault != FixtureFault.TooLongSucceeds)
        {
            return ApplicationError(8, "Name exceeds 256 UTF-16 code units.");
        }

        return Grpc(new SayHelloResponse { Message = "Hello, " + name + "!" }, GrpcOk,
            state.Fault == FixtureFault.WorkerRevisionMismatch ? new string('d', 40) : state.Revision);
    }

    private HttpResponseMessage ApplicationError(int code, string? message)
    {
        if (state.Fault == FixtureFault.ApplicationErrorAsHttp400)
        {
            return PlainFailure(HttpStatusCode.BadRequest);
        }

        return RpcError(code, message);
    }

    private HttpResponseMessage RpcError(int code, string? message)
    {
        byte[] trailer = Trailers(code, message);
        return Respond(Frame(0x80, trailer), state.Revision);
    }

    private HttpResponseMessage Grpc(SayHelloResponse message, int status, string revision)
    {
        byte[] data = Frame(0, message.ToByteArray());
        if (state.Fault == FixtureFault.OmitTrailerFrame)
        {
            return Respond(data, revision);
        }

        return Respond([.. data, .. Frame(0x80, Trailers(status, null))], revision);
    }

    private HttpResponseMessage Respond(byte[] content, string revision)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(content) };
        response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
            state.Fault == FixtureFault.WrongResponseMediaType ? "text/plain" : "application/grpc-web");
        response.Headers.TryAddWithoutValidation("cache-control", "no-store");
        response.Headers.TryAddWithoutValidation("x-content-type-options", "nosniff");
        if (state.Fault != FixtureFault.NoWorkerRevisionHeader)
        {
            response.Headers.TryAddWithoutValidation("x-arcforges-worker-revision", revision);
        }

        return response;
    }

    private static HttpResponseMessage PlainFailure(HttpStatusCode status) =>
        new(status) { Content = new StringContent("Fixture boundary failure.", Encoding.UTF8, "text/plain") };

    private static byte[] Trailers(int code, string? message)
    {
        string text = "grpc-status: " + code.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\r\n";
        if (message is not null)
        {
            text += "grpc-message: " + Uri.EscapeDataString(message) + "\r\n";
        }

        return Encoding.ASCII.GetBytes(text);
    }

    private static byte[] Frame(byte flag, byte[] payload)
    {
        byte[] frame = new byte[5 + payload.Length];
        frame[0] = flag;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1, 4), (uint)payload.Length);
        payload.CopyTo(frame, 5);
        return frame;
    }
}
