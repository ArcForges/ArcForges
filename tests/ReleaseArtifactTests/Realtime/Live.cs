// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.PublicApi.V1;
using Google.Protobuf;
using Grpc.Net.Client;

namespace RealtimeAotProbe;

/// <summary>The parsed command line of the explicit local live run.</summary>
internal sealed record LiveOptions(Uri BaseAddress, string SubscriptionKey, Guid? OutputTask, bool Poll, int Seconds, string? Authorization)
{
    internal const string AuthorizationVariable = "RTPROBE_AUTHORIZATION";
    internal const int DefaultSeconds = 60;
    internal const int MaximumSeconds = 3600;

    /// <summary>Parse <c>--live &lt;base-url&gt; --subscription &lt;key&gt; [--output-task &lt;uuid&gt;] [--mode watch|poll] [--seconds n]</c>.</summary>
    /// <remarks>The authorization value is read only from the environment so it never appears in a command line.</remarks>
    public static LiveOptions Parse(IReadOnlyList<string> args, Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(environment);
        if (args.Count < 2 || args[0] != "--live")
        {
            throw new ArgumentException("Usage: --live <base-url> --subscription <key> [--output-task <uuid>] [--mode watch|poll] [--seconds n]");
        }

        if (!Uri.TryCreate(args[1], UriKind.Absolute, out Uri? address))
        {
            throw new ArgumentException("The base address is not an absolute URI.");
        }

        string? subscription = null;
        Guid? task = null;
        bool poll = false;
        int seconds = DefaultSeconds;
        for (int index = 2; index < args.Count; index += 2)
        {
            if (index + 1 >= args.Count)
            {
                throw new ArgumentException("The option " + args[index] + " needs a value.");
            }

            string value = args[index + 1];
            switch (args[index])
            {
                case "--subscription":
                    subscription = value;
                    break;
                case "--output-task":
                    task = Guid.TryParse(value, out Guid parsed) ? parsed : throw new ArgumentException("The output task is not a UUID.");
                    break;
                case "--mode":
                    poll = value switch
                    {
                        "watch" => false,
                        "poll" => true,
                        _ => throw new ArgumentException("The mode is watch or poll."),
                    };
                    break;
                case "--seconds":
                    if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) || seconds < 1 || seconds > MaximumSeconds)
                    {
                        throw new ArgumentException("The seconds value is 1 to " + MaximumSeconds.ToString(CultureInfo.InvariantCulture) + ".");
                    }

                    break;
                default:
                    throw new ArgumentException("Unknown option " + args[index] + "; credentials are read from " + AuthorizationVariable + " only.");
            }
        }

        if (string.IsNullOrEmpty(subscription))
        {
            throw new ArgumentException("--subscription is required.");
        }

        string? authorization = environment(AuthorizationVariable);
        RealtimeChannel.NormalizeAddress(address);
        return new LiveOptions(address, subscription, task, poll, seconds, string.IsNullOrEmpty(authorization) ? null : authorization);
    }
}

/// <summary>Prints what a live run observed. It never prints a hint body, a chunk body or the authorization value.</summary>
internal sealed class ConsoleObserver(TextWriter output) : RealtimeObserver
{
    private readonly TextWriter _output = output;

    public long Hints { get; private set; }

    public long Chunks { get; private set; }

    public long Gaps { get; private set; }

    public long Snapshots { get; private set; }

    public override async Task ConnectionChangedAsync(ConnectionState state, string detail, CancellationToken cancellationToken)
    {
        await _output.WriteLineAsync($"state: {state} ({detail})").ConfigureAwait(false);
    }

    public override async Task HintAsync(Event hint, CancellationToken cancellationToken)
    {
        Hints++;
        await _output.WriteLineAsync($"hint: seq={hint.Seq} payload={hint.PayloadCase}").ConfigureAwait(false);
    }

    public override async Task GapAsync(SequenceGap gap, CancellationToken cancellationToken)
    {
        Gaps++;
        await _output.WriteLineAsync($"gap: expected={gap.Expected} actual={gap.Actual}; the owner RPC must be re-read").ConfigureAwait(false);
    }

    public override async Task SnapshotRequiredAsync(string reason, CancellationToken cancellationToken)
    {
        Snapshots++;
        await _output.WriteLineAsync($"snapshot required: {reason}; the probe has no owner RPC to read, so this only records the obligation").ConfigureAwait(false);
    }

    public override async Task OutputAsync(OutputChunk chunk, CancellationToken cancellationToken)
    {
        Chunks++;
        await _output.WriteLineAsync($"output: offset={chunk.Offset} bytes={chunk.Data.Length}").ConfigureAwait(false);
    }

    public override async Task OutputResetAsync(string reason, CancellationToken cancellationToken)
    {
        await _output.WriteLineAsync($"output reset: {reason}").ConfigureAwait(false);
    }

    public override async Task TerminalAsync(ExecutionOutput terminal, CancellationToken cancellationToken)
    {
        await _output.WriteLineAsync("terminal outcome confirmed by an authoritative read").ConfigureAwait(false);
    }
}

/// <summary>The explicit local live run against a deployed ingress. It is never run by CI and never claimed as passed.</summary>
internal static class LiveRun
{
    public static async Task<int> RunAsync(LiveOptions options, TextWriter output, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(output);
        var policy = new RealtimePolicy();
        using GrpcChannel channel = RealtimeChannel.Create(options.BaseAddress, options.Authorization);
        var transport = new GeneratedRealtimeTransport(channel, policy);
        var observer = new ConsoleObserver(output);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(options.Seconds));
        var events = new EventSession(options.SubscriptionKey);
        Task<WatchResult> eventRun = options.Poll
            ? new EventPoller(events, transport, observer, TimeProvider.System, Jitter.Next, policy).RunAsync(deadline.Token)
            : new EventWatcher(events, transport, observer, TimeProvider.System, Jitter.Next, policy).RunAsync(deadline.Token);
        Task<WatchResult>? outputRun = null;
        if (options.OutputTask is { } taskId)
        {
            var owner = new ExecutionOwner { TaskId = new Id { Value = ByteString.CopyFrom(ToBytes(taskId)) } };
            var session = new OutputSession(owner, policy);
            outputRun = options.Poll
                ? new OutputReader(session, transport, observer, TimeProvider.System, Jitter.Next, policy).RunAsync(deadline.Token)
                : new OutputWatcher(session, transport, observer, TimeProvider.System, Jitter.Next, policy).RunAsync(deadline.Token);
        }

        WatchResult events1 = await eventRun.ConfigureAwait(false);
        await output.WriteLineAsync($"events run ended: {events1.Reason} ({events1.Detail}); hints={observer.Hints} gaps={observer.Gaps} snapshots={observer.Snapshots}").ConfigureAwait(false);
        int exit = events1.Reason == StopReason.Cancelled ? 0 : 1;
        if (outputRun is not null)
        {
            WatchResult output1 = await outputRun.ConfigureAwait(false);
            await output.WriteLineAsync($"output run ended: {output1.Reason} ({output1.Detail}); chunks={observer.Chunks}").ConfigureAwait(false);
            exit = output1.Reason is StopReason.Cancelled or StopReason.Completed ? exit : 1;
        }

        return exit;
    }

    internal static byte[] ToBytes(Guid id)
    {
        byte[] bytes = new byte[16];
        id.TryWriteBytes(bytes, bigEndian: true, out _);
        return bytes;
    }
}
