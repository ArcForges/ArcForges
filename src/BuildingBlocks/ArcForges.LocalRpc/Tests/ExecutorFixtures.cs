// SPDX-License-Identifier: AGPL-3.0-only
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

/// <summary>A manual clock, an executor on it and a scripted send delegate, so the state machine is exercised without a network.</summary>
internal sealed class ExecutorRig
{
    internal const string Operation = "pkg.Service/Method";

    internal static readonly LocalRpcPeerGeneration Gen = new(Guid.Parse("11111111-1111-1111-1111-111111111111"), 1);

    internal static readonly LocalRpcPeerGeneration OtherGen = new(Guid.Parse("22222222-2222-2222-2222-222222222222"), 2);

    internal static readonly TimeSpan FirstWait = TimeSpan.FromMilliseconds(100);

    internal static readonly TimeSpan MaxWait = TimeSpan.FromMilliseconds(400);

    private int _sends;

    internal ExecutorRig(
        int maxAttempts = 3,
        TimeSpan? replayWindow = null,
        int capacity = 4096,
        TimeSpan? retention = null)
    {
        Time = new ManualTimeProvider();
        Executor = new LocalRpcCommandExecutor(
            new LocalRpcCommandExecutorOptions
            {
                MaxAttempts = maxAttempts,

                // Every wait is its full ceiling: 100 ms, 200 ms, then 400 ms.
                Backoff = new LocalRpcBackoff(FirstWait, MaxWait, () => 1.0),
                ReplayWindow = replayWindow ?? TimeSpan.FromMinutes(5),
                JournalCapacity = capacity,
                SettledRetention = retention ?? TimeSpan.FromMinutes(10),
            },
            Time);
    }

    internal ManualTimeProvider Time { get; }

    internal LocalRpcCommandExecutor Executor { get; }

    internal int Sends => Volatile.Read(ref _sends);

    internal static byte[] Digest(byte fill = 1) => Enumerable.Repeat(fill, LocalRpcCommand.DigestBytes).ToArray();

    internal static LocalRpcCommand Command(
        Guid? id = null,
        LocalRpcIdempotency idempotency = LocalRpcIdempotency.NonIdempotent,
        bool replay = false,
        byte digest = 1,
        string operation = Operation) =>
        new(id ?? Guid.NewGuid(), operation, Digest(digest), idempotency, replay);

    /// <summary>A send delegate that plays one step per call (the last step repeats) and counts its calls.</summary>
    internal Func<int, CancellationToken, Task<string>> Script(params Func<int, CancellationToken, Task<string>>[] steps) =>
        (attempt, token) =>
        {
            var index = Interlocked.Increment(ref _sends) - 1;
            return steps[Math.Min(index, steps.Length - 1)](attempt, token);
        };

    internal static Func<int, CancellationToken, Task<string>> Ok(string value = "ok") => (_, _) => Task.FromResult(value);

    internal static Func<int, CancellationToken, Task<string>> Fail(Exception exception) => (_, _) => Task.FromException<string>(exception);

    internal static Func<int, CancellationToken, Task<string>> Throw(Exception exception) => (_, _) => throw exception;

    /// <summary>A step that waits for its token and then fails like a cancelled call.</summary>
    internal static Func<int, CancellationToken, Task<string>> UntilCancelled() => async (_, token) =>
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, token).ConfigureAwait(false);
        return "never";
    };

    /// <summary>A step that waits for a gate and then answers.</summary>
    internal static Func<int, CancellationToken, Task<string>> Gated(TaskCompletionSource gate, string value = "ok") => async (_, token) =>
    {
        await gate.Task.WaitAsync(token).ConfigureAwait(false);
        return value;
    };

    internal static RpcException Unavailable() => Failures.Unavailable();

    internal static RpcException DataQueueFull() => Failures.Refusal(LocalRpcRefusalReason.DataQueueFull);

    internal static RpcException ConnectFailure() => Failures.Connect();

    /// <summary>Waits until the executor is sleeping in a backoff wait.</summary>
    internal async Task WaitingAsync(CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(BoundsHarness.Patience);
        while (Time.ArmedTimers == 0)
        {
            await Task.Delay(1, bounded.Token).ConfigureAwait(false);
        }
    }

    /// <summary>Waits until the executor is sleeping, then lets exactly <paramref name="by"/> pass.</summary>
    internal async Task AfterWaitingAdvanceAsync(TimeSpan by, CancellationToken cancellationToken)
    {
        await WaitingAsync(cancellationToken).ConfigureAwait(false);
        Time.Advance(by);
    }

    internal Task<LocalRpcCommandOutcome<string>> RunAsync(
        LocalRpcCommand command,
        Func<int, CancellationToken, Task<string>> send,
        LocalRpcPeerGeneration? generation = null,
        Func<string, LocalRpcEffect>? interpret = null,
        CancellationToken cancellationToken = default) =>
        Executor.ExecuteAsync(command, generation ?? Gen, send, interpret, cancellationToken);
}
