// SPDX-License-Identifier: AGPL-3.0-only
using System.Threading.Channels;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core;

/// <summary>The command queue is full (4,096 waiting commands): <c>RESOURCE/overloaded</c>.</summary>
public sealed class CommandQueueFullException : InvalidOperationException
{
    /// <summary>Creates the exception.</summary>
    public CommandQueueFullException()
        : base("The node's command queue is full.")
    {
    }

    /// <summary>Creates the exception.</summary>
    public CommandQueueFullException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public CommandQueueFullException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>The store transaction of one command and the journal events it appends.</summary>
public sealed class CommandContext
{
    private readonly EventJournal _journal;
    private readonly List<NodeEvent> _events = [];

    internal CommandContext(StoreTransaction transaction, EventJournal journal)
    {
        Transaction = transaction;
        _journal = journal;
    }

    /// <summary>The command's transaction.</summary>
    public StoreTransaction Transaction { get; }

    /// <summary>The events appended so far.</summary>
    public IReadOnlyList<NodeEvent> Events => _events;

    /// <summary>Appends an event to the journal in this transaction; it is published after the commit.</summary>
    public NodeEvent Emit(EventTopic topic, NodeEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        var appended = _journal.Append(Transaction, topic, item);
        _events.Add(appended);
        return appended;
    }
}

/// <summary>The outcome of an idempotent command (contracts README section 6).</summary>
/// <param name="Replayed">The command ID was seen with the same payload; the stored outcome is returned and nothing executed again.</param>
/// <param name="Outcome">The serialized response, new or stored.</param>
/// <param name="Error"><c>CONFLICT/command_id_reused</c> when the same ID came with another payload.</param>
public sealed record IdempotentOutcome(bool Replayed, byte[]? Outcome, ArcError? Error);

/// <summary>
/// The command processor (architecture 02 section 1): every state mutation runs through one writer loop fed by a bounded queue of
/// 4,096 commands. A command executes in one store transaction, appends its journal events in that transaction, and its events are
/// published to the stream hub after the commit, in sequence order. Idempotent commands record their outcome in
/// <c>command_dedup</c> in the same transaction (<c>synchronous=FULL</c>).
/// </summary>
public sealed class CommandProcessor : IAsyncDisposable
{
    /// <summary>The queue bound.</summary>
    public const int Capacity = 4096;

    private readonly NodeStore _store;
    private readonly EventJournal _journal;
    private readonly StreamHub _hub;
    private readonly Channel<WorkItem> _queue = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(Capacity)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.Wait,
    });

    private readonly Task _loop;
    private long _executed;

    /// <summary>Starts the writer loop.</summary>
    public CommandProcessor(NodeStore store, EventJournal journal, StreamHub hub)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _hub = hub ?? throw new ArgumentNullException(nameof(hub));
        _loop = Task.Factory.StartNew(RunAsync, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap();
    }

    /// <summary>Commands executed since start.</summary>
    public long Executed => Interlocked.Read(ref _executed);

    /// <summary>Commands waiting in the queue.</summary>
    public int Queued => _queue.Reader.Count;

    /// <summary>Runs <paramref name="command"/> in the writer loop and returns its result after the commit.</summary>
    /// <exception cref="CommandQueueFullException">The queue is full.</exception>
    public Task<T> ExecuteAsync<T>(Func<CommandContext, T> command, CommitDurability durability = CommitDurability.Normal)
    {
        ArgumentNullException.ThrowIfNull(command);
        var item = new WorkItem<T>(command, durability);
        if (!_queue.Writer.TryWrite(item))
        {
            throw new CommandQueueFullException();
        }

        return item.Completion.Task;
    }

    /// <summary>
    /// Runs a mutation at most once per command ID (24-hour window): a repeated ID with the same payload digest returns the stored
    /// response; with another digest, <c>CONFLICT/command_id_reused</c>. The response bytes are stored with the effects.
    /// </summary>
    public Task<IdempotentOutcome> ExecuteIdempotentAsync(ReadOnlyMemory<byte> commandId, string method, ReadOnlyMemory<byte> payloadDigest, Origin origin,
        Func<CommandContext, byte[]> command)
    {
        ArgumentNullException.ThrowIfNull(command);
        return ExecuteAsync(context =>
        {
            var decision = CommandDeduplication.Begin(context.Transaction, commandId.Span, method, payloadDigest.Span, origin);
            switch (decision.Status)
            {
                case DedupStatus.Replay:
                    return new IdempotentOutcome(true, decision.Outcome!.Value.ToArray(), null);
                case DedupStatus.Conflict:
                    return new IdempotentOutcome(false, null, decision.Error);
                case DedupStatus.InProgress:
                    throw new InvalidOperationException("The command is still executing.");
                default:
                    var outcome = command(context);
                    CommandDeduplication.Complete(context.Transaction, commandId.Span, outcome);
                    return new IdempotentOutcome(false, outcome, null);
            }
        }, CommitDurability.Full);
    }

    /// <summary>Stops accepting commands and waits until the queued ones ran.</summary>
    public async ValueTask DisposeAsync()
    {
        _queue.Writer.TryComplete();
        await _loop.ConfigureAwait(false);
    }

    private async Task RunAsync()
    {
        await foreach (var item in _queue.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            var next = _journal.NextSequence;
            IReadOnlyList<NodeEvent> events = [];
            try
            {
                events = item.Run(_store, _journal);
                if (events.Count > 0)
                {
                    _journal.Committed(events[^1].Seq);
                }
            }
            catch (Exception exception)
            {
                _journal.NextSequence = next;
                item.Fail(exception);
                continue;
            }

            Interlocked.Increment(ref _executed);
            _hub.Publish(events);
            item.Succeed();
        }
    }

    private abstract class WorkItem
    {
        public abstract IReadOnlyList<NodeEvent> Run(NodeStore store, EventJournal journal);

        public abstract void Succeed();

        public abstract void Fail(Exception exception);
    }

    private sealed class WorkItem<T>(Func<CommandContext, T> command, CommitDurability durability) : WorkItem
    {
        private T _result = default!;

        public TaskCompletionSource<T> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override IReadOnlyList<NodeEvent> Run(NodeStore store, EventJournal journal)
        {
            IReadOnlyList<NodeEvent> events = [];
            _result = store.Write(transaction =>
            {
                var context = new CommandContext(transaction, journal);
                var result = command(context);
                events = context.Events;
                return result;
            }, durability);
            return events;
        }

        public override void Succeed() => Completion.TrySetResult(_result);

        public override void Fail(Exception exception) => Completion.TrySetException(exception);
    }
}
