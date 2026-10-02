// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using ArcForges.Contracts.Hello.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

/// <summary>Where the scenarios send their calls. A live target is a real ingress; a fixture target is the in-process stand-in.</summary>
internal sealed class ScenarioTarget
{
    public required Uri BaseAddress { get; init; }

    public required Func<HttpMessageHandler> CreateTransport { get; init; }

    public bool Live { get; init; }

    public string? ExpectedRevision { get; init; }

    public FixtureState? Fixture { get; init; }

    /// <summary>Self-test seam that damages each request before it reaches the transport.</summary>
    public Action<HttpRequestMessage>? MutateRequest { get; init; }

    public ProbeChannel Open() => new(BaseAddress, CreateTransport(), MutateRequest);
}

/// <summary>What a call looked like to the caller, whether it succeeded or failed.</summary>
internal sealed record CallOutcome(StatusCode Code, string Detail, SayHelloResponse? Response, StatusCode? StatusAfterResponse);

/// <summary>
/// The generated HelloService client driven through binary gRPC-Web. The same checks run against a live ingress
/// and against the fixture; the fixture run is how the verifier itself is tested.
/// </summary>
internal static partial class HelloScenarios
{
    private const string ServiceName = "arcforges.hello.v1.HelloService";
    private const string HelloMethodPath = ServiceName + "/SayHello";

    public static async Task RunCommonAsync(ScenarioTarget target, CheckRecorder checks)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(checks);
        string? revision = await CheckIdentityAsync(target, checks).ConfigureAwait(false);
        await CheckUnaryAsync(target, checks, revision).ConfigureAwait(false);
        await CheckExactValuesAsync(target, checks).ConfigureAwait(false);
        await CheckScopedErrorsAsync(target, checks).ConfigureAwait(false);
        await CheckCancellationAsync(target, checks).ConfigureAwait(false);
        await CheckDeadlineAsync(target, checks).ConfigureAwait(false);
        await CheckWrongTargetAsync(target, checks).ConfigureAwait(false);
    }

    /// <summary>Failure injection only the fixture can perform: a lost connection and boundary HTTP failures.</summary>
    public static async Task RunFixtureOnlyAsync(ScenarioTarget target, CheckRecorder checks)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(checks);
        var state = target.Fixture ?? throw new InvalidOperationException("Failure injection needs the fixture.");

        using (var channel = target.Open())
        {
            var client = new HelloService.HelloServiceClient(channel.Channel);
            state.DropNext(1);
            var lost = await CallAsync(client, "ArcForges", Deadline(15)).ConfigureAwait(false);
            int attemptsAfterLoss = channel.Tap.Entries.Count;
            checks.Expect("loss.single-attempt",
                lost.Code == StatusCode.Unavailable && lost.Response is null && attemptsAfterLoss == 1,
                $"A lost connection surfaced as {lost.Code} after {attemptsAfterLoss} transport attempt(s); the client retried nothing.");
            var again = await CallAsync(client, "ArcForges", Deadline(15)).ConfigureAwait(false);
            checks.Expect("loss.explicit-retry-succeeds",
                again.Code == StatusCode.OK && again.Response?.Message == "Hello, ArcForges!" && channel.Tap.Entries.Count == 2,
                "The caller's own second call succeeded as the second and last transport attempt.");
        }

        foreach ((int status, StatusCode expected) in new[]
        {
            (413, StatusCode.Unknown), (415, StatusCode.Unknown), (429, StatusCode.Unavailable), (503, StatusCode.Unavailable),
        })
        {
            using var channel = target.Open();
            var client = new HelloService.HelloServiceClient(channel.Channel);
            state.FailNextWith(status);
            var outcome = await CallAsync(client, "ArcForges", Deadline(15)).ConfigureAwait(false);
            checks.Expect("boundary.http-" + status.ToString(CultureInfo.InvariantCulture),
                outcome.Response is null && outcome.Code == expected,
                $"A boundary HTTP {status} surfaced as {outcome.Code} and never as a protobuf success.");
        }
    }

    private static DateTime Deadline(int seconds) => DateTime.UtcNow.AddSeconds(seconds);

    private static async Task<CallOutcome> CallAsync(HelloService.HelloServiceClient client, string name, DateTime? deadline,
        CancellationToken cancellation = default)
    {
        using var call = client.SayHelloAsync(new SayHelloRequest { Name = name }, deadline: deadline, cancellationToken: cancellation);
        try
        {
            var response = await call.ResponseAsync.ConfigureAwait(false);
            return new CallOutcome(StatusCode.OK, string.Empty, response, call.GetStatus().StatusCode);
        }
        catch (RpcException error)
        {
            return new CallOutcome(error.StatusCode, error.Status.Detail, null, null);
        }
    }

    internal static async Task<string?> CheckIdentityAsync(ScenarioTarget target, CheckRecorder checks)
    {
        string? revision = null;
        bool nativeAot = false;
        int status = 0;
        using var tap = new RequestTap(target.CreateTransport());
        using var http = new HttpClient(tap, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(20) };
        try
        {
            using var response = await http.GetAsync(new Uri(target.BaseAddress, "healthz")).ConfigureAwait(false);
            status = (int)response.StatusCode;
            string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.TryGetProperty("revision", out var found) && found.ValueKind == JsonValueKind.String)
            {
                revision = found.GetString();
            }

            nativeAot = document.RootElement.TryGetProperty("nativeAot", out var aot) && aot.ValueKind == JsonValueKind.True;
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException or JsonException)
        {
            checks.Expect("identity.health", false, "The health endpoint was not readable: " + error.GetType().Name);
            return null;
        }

        bool shaped = revision is not null && RevisionPattern().IsMatch(revision);
        checks.Expect("identity.health", status == 200 && shaped && nativeAot,
            $"Health answered {status}; revision {(shaped ? revision : "(invalid)")}; nativeAot {nativeAot}.");
        if (target.ExpectedRevision is not null)
        {
            checks.Expect("identity.expected-revision", string.Equals(revision, target.ExpectedRevision, StringComparison.Ordinal),
                "The deployed revision equals the revision the caller expected; a stale target would differ.");
        }

        return shaped ? revision : null;
    }

    private static async Task CheckUnaryAsync(ScenarioTarget target, CheckRecorder checks, string? healthRevision)
    {
        using var channel = target.Open();
        var client = new HelloService.HelloServiceClient(channel.Channel);
        var outcome = await CallAsync(client, "ArcForges", Deadline(15)).ConfigureAwait(false);
        checks.Expect("unary.success.message", outcome.Code == StatusCode.OK && outcome.Response?.Message == "Hello, ArcForges!",
            "The generated unary call returned the exact greeting.");
        checks.Expect("unary.success.trailers", outcome.StatusAfterResponse == StatusCode.OK,
            "The terminal gRPC status arrived in the gRPC-Web trailer frame and was OK.");
        var entry = channel.Tap.Last;
        string expectedPath = target.BaseAddress.AbsolutePath + HelloMethodPath;
        bool shaped = entry is not null && entry.Method == "POST" && entry.Uri.AbsolutePath == expectedPath &&
            (entry.RequestMediaType is "application/grpc-web" or "application/grpc-web+proto") && string.IsNullOrEmpty(entry.Uri.Query);
        checks.Expect("unary.success.request-shape", shaped,
            $"The request was {entry?.Method} {entry?.Uri.AbsolutePath} as {entry?.RequestMediaType}; expected a POST of binary gRPC-Web to {expectedPath}.");
        string? workerRevision = null;
        entry?.ResponseHeaders.TryGetValue("x-arcforges-worker-revision", out workerRevision);
        bool mediaType = entry?.ResponseMediaType?.StartsWith("application/grpc-web", StringComparison.Ordinal) == true;
        bool revisionBound = workerRevision is not null && RevisionPattern().IsMatch(workerRevision) &&
            (healthRevision is null || string.Equals(workerRevision, healthRevision, StringComparison.Ordinal));
        checks.Expect("unary.success.response-headers", entry?.Status == 200 && mediaType && revisionBound,
            "The response was HTTP 200 gRPC-Web and carried the Worker revision header matching the health revision.");
    }

    private static async Task CheckExactValuesAsync(ScenarioTarget target, CheckRecorder checks)
    {
        using var channel = target.Open();
        var client = new HelloService.HelloServiceClient(channel.Channel);
        int exact = 0;
        foreach (string name in Exactness.Names)
        {
            var outcome = await CallAsync(client, name, Deadline(15)).ConfigureAwait(false);
            if (outcome.Code == StatusCode.OK && string.Equals(outcome.Response?.Message, "Hello, " + name + "!", StringComparison.Ordinal))
            {
                exact++;
            }
        }

        checks.Expect("exact.unicode", exact == Exactness.Names.Count,
            $"{exact} of {Exactness.Names.Count} names (surrogate pair, whitespace, precomposed and decomposed forms, controls) came back byte-exact.");
        var ascii = await CallAsync(client, new string('a', Exactness.MaximumNameUtf16Units), Deadline(15)).ConfigureAwait(false);
        checks.Expect("exact.boundary-256",
            ascii.Code == StatusCode.OK && ascii.Response?.Message == "Hello, " + new string('a', Exactness.MaximumNameUtf16Units) + "!",
            "A name of exactly 256 UTF-16 code units is accepted and returned exactly.");
        var pairs = await CallAsync(client, Exactness.MaximumPairs, Deadline(15)).ConfigureAwait(false);
        checks.Expect("exact.boundary-256-utf16-pairs",
            pairs.Code == StatusCode.OK && pairs.Response?.Message == "Hello, " + Exactness.MaximumPairs + "!",
            "128 surrogate pairs (256 UTF-16 units, 512 UTF-8 bytes) are measured in UTF-16 units and returned exactly.");
    }

    private static async Task CheckScopedErrorsAsync(ScenarioTarget target, CheckRecorder checks)
    {
        using var channel = target.Open();
        var client = new HelloService.HelloServiceClient(channel.Channel);
        var empty = await CallAsync(client, string.Empty, Deadline(15)).ConfigureAwait(false);
        var emptyEntry = channel.Tap.Last;
        checks.Expect("error.empty-name", empty.Code == StatusCode.InvalidArgument && empty.Detail.Length > 0 && empty.Response is null,
            "An empty name is INVALID_ARGUMENT with a status message, not a success.");
        checks.Expect("error.application-status-in-http-200", emptyEntry?.Status == 200,
            "The application error travelled as HTTP 200 with a terminal status frame, not as an HTTP error.");
        var tooLong = await CallAsync(client, new string('a', Exactness.MaximumNameUtf16Units + 1), Deadline(15)).ConfigureAwait(false);
        checks.Expect("error.too-long", tooLong.Code == StatusCode.ResourceExhausted && tooLong.Response is null,
            "A 257 code unit name is RESOURCE_EXHAUSTED.");
        var tooLongPairs = await CallAsync(client, Exactness.MaximumPairs + "a", Deadline(15)).ConfigureAwait(false);
        checks.Expect("error.too-long-utf16-pairs", tooLongPairs.Code == StatusCode.ResourceExhausted && tooLongPairs.Response is null,
            "128 surrogate pairs plus one unit (257 UTF-16 units) is RESOURCE_EXHAUSTED.");
    }

    private static async Task CheckCancellationAsync(ScenarioTarget target, CheckRecorder checks)
    {
        using var channel = target.Open();
        var client = new HelloService.HelloServiceClient(channel.Channel);
        using var cancellation = new CancellationTokenSource();
        channel.Tap.BeforeSend = () => cancellation.Cancel();
        var cancelled = await CallAsync(client, "ArcForges", Deadline(15), cancellation.Token).ConfigureAwait(false);
        channel.Tap.BeforeSend = null;
        checks.Expect("cancel.in-flight", cancelled.Code == StatusCode.Cancelled && cancelled.Response is null,
            "A cancellation requested while the request was handed to the transport surfaced as CANCELLED.");
        checks.Expect("cancel.reached-transport", channel.Tap.Entries.Count == 1,
            "The cancelled request had reached the transport, so it was cancelled in flight and not before dispatch.");
        var recovered = await CallAsync(client, "ArcForges", Deadline(15)).ConfigureAwait(false);
        checks.Expect("cancel.channel-recovers", recovered.Code == StatusCode.OK && recovered.Response?.Message == "Hello, ArcForges!",
            "The same channel served the next call after the cancellation.");
    }

    private static async Task CheckDeadlineAsync(ScenarioTarget target, CheckRecorder checks)
    {
        using var channel = target.Open();
        var client = new HelloService.HelloServiceClient(channel.Channel);
        var expired = await CallAsync(client, "ArcForges", DateTime.UtcNow.AddMilliseconds(1)).ConfigureAwait(false);
        checks.Expect("deadline.expired", expired.Code == StatusCode.DeadlineExceeded && expired.Response is null,
            "A one millisecond deadline surfaced as DEADLINE_EXCEEDED.");
        var timed = await CallAsync(client, "ArcForges", Deadline(5)).ConfigureAwait(false);
        string? header = channel.Tap.Last?.GrpcTimeout;
        double? milliseconds = ParseGrpcTimeout(header);
        checks.Expect("deadline.header-format", timed.Code == StatusCode.OK && milliseconds is > 0 and <= 5000,
            "The emitted grpc-timeout header is a valid gRPC timeout of at most the five second deadline.");
    }

    private static async Task CheckWrongTargetAsync(ScenarioTarget target, CheckRecorder checks)
    {
        using (var channel = target.Open())
        {
            var method = new Method<SayHelloRequest, SayHelloResponse>(MethodType.Unary, ServiceName, "NoSuchMethod",
                Marshallers.Create<SayHelloRequest>(message => message.ToByteArray(), bytes => SayHelloRequest.Parser.ParseFrom(bytes)),
                Marshallers.Create<SayHelloResponse>(message => message.ToByteArray(), bytes => SayHelloResponse.Parser.ParseFrom(bytes)));
            StatusCode code;
            try
            {
                using var call = channel.Channel.CreateCallInvoker().AsyncUnaryCall(method, null,
                    new CallOptions(deadline: Deadline(15)), new SayHelloRequest { Name = "ArcForges" });
                await call.ResponseAsync.ConfigureAwait(false);
                code = StatusCode.OK;
            }
            catch (RpcException error)
            {
                code = error.StatusCode;
            }

            checks.Expect("target.unknown-method", code == StatusCode.Unimplemented && channel.Tap.Last?.Status == 404,
                "A method the ingress does not own surfaced as UNIMPLEMENTED from an HTTP 404, never as success.");
        }

        int port = ClosedLoopbackPort();
        using var closed = ProbeChannel.CreateReal(new Uri("http://127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture) + "/api/"), useSystemProxy: false);
        var unreachable = await CallAsync(new HelloService.HelloServiceClient(closed.Channel), "ArcForges", Deadline(15)).ConfigureAwait(false);
        checks.Expect("target.unreachable", unreachable.Code == StatusCode.Unavailable && unreachable.Response is null,
            "A target nobody listens on surfaced as UNAVAILABLE over the real transport.");
    }

    internal static double? ParseGrpcTimeout(string? header)
    {
        if (header is null)
        {
            return null;
        }

        var match = GrpcTimeoutPattern().Match(header);
        if (!match.Success)
        {
            return null;
        }

        double value = double.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
        return match.Groups[2].Value switch
        {
            "H" => value * 3_600_000,
            "M" => value * 60_000,
            "S" => value * 1_000,
            "m" => value,
            "u" => value / 1_000,
            "n" => value / 1_000_000,
            _ => null,
        };
    }

    private static int ClosedLoopbackPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex RevisionPattern();

    [GeneratedRegex("^([1-9][0-9]{0,7})([HMSmun])$", RegexOptions.CultureInvariant)]
    private static partial Regex GrpcTimeoutPattern();
}
