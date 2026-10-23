// SPDX-License-Identifier: AGPL-3.0-only
using System.Threading.Channels;

namespace ArcForges.Node.Core.Execution;

/// <summary>
/// A queue of platform calls run one at a time on a background task: the pressure hooks run on the resource monitor's thread and must
/// never block it (a D-Bus call to the user manager can take its full timeout), so they post their freeze, thaw, limit and root-limit
/// calls here. A failed call is logged and the queue goes on.
/// </summary>
internal sealed class SerialWork : IAsyncDisposable
{
    private readonly Channel<(string Name, Action Work)> _queue = Channel.CreateUnbounded<(string, Action)>(new UnboundedChannelOptions { SingleReader = true });
    private readonly NodeLog _log;
    private readonly Task _runner;
    private int _pending;

    public SerialWork(NodeLog log)
    {
        _log = log;
        _runner = Task.Run(RunAsync);
    }

    /// <summary>Calls posted and not yet finished.</summary>
    public int Pending => Volatile.Read(ref _pending);

    /// <summary>Posts a call; never blocks.</summary>
    public void Post(string name, Action work)
    {
        Interlocked.Increment(ref _pending);
        if (!_queue.Writer.TryWrite((name, work)))
        {
            Interlocked.Decrement(ref _pending);
        }
    }

    /// <summary>Completes once every call posted so far ran (tests and shutdown).</summary>
    public async Task DrainAsync(TimeSpan bound)
    {
        var deadline = DateTime.UtcNow + bound;
        while (Pending > 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _queue.Writer.TryComplete();
        await Task.WhenAny(_runner, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
    }

    private async Task RunAsync()
    {
        await foreach (var (name, work) in _queue.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            try
            {
                work();
            }
#pragma warning disable CA1031 // A failed platform call is logged by type; it must not end the queue that later calls depend on.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                _log.Warning("execution.platform_call.failed", new LogField("call", name), new LogField("errorType", exception.GetType().Name),
                    new LogField("error", NodeLog.OneLine(exception.Message)));
            }
            finally
            {
                Interlocked.Decrement(ref _pending);
            }
        }
    }
}
