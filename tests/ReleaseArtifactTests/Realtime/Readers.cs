// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.PublicApi.V1;

namespace RealtimeAotProbe;

internal enum StepKind
{
    /// <summary>The page was handled; the next read waits one jittered cadence interval.</summary>
    Idle,

    /// <summary>A retryable failure; the next read waits the larger of the backoff and the server retry time.</summary>
    Retry,

    /// <summary>Stop with <see cref="PageStep.Stop"/>.</summary>
    Stop,
}

internal readonly record struct PageStep(StepKind Kind, WatchResult Stop = default, Classified Retry = default);

/// <summary>The periodic unary fallback loop shared by Poll and ReadOutput.</summary>
/// <remarks>
/// Calls never overlap (the next read starts only after the previous one finished and the interval elapsed), the
/// cadence carries plus or minus 20 percent jitter, and a transient failure backs off from the same ladder as the
/// stream. Permission failures stop the loop. All waiting uses the injected time provider.
/// </remarks>
internal abstract class PagedReader(RealtimeObserver observer, TimeProvider time, Func<double> random, RealtimePolicy policy)
{
    private readonly Func<double> _random = random ?? throw new ArgumentNullException(nameof(random));

    protected RealtimeObserver Observer { get; } = observer ?? throw new ArgumentNullException(nameof(observer));

    protected TimeProvider Time { get; } = time ?? throw new ArgumentNullException(nameof(time));

    protected RealtimePolicy Policy { get; } = policy ?? throw new ArgumentNullException(nameof(policy));

    public ReconnectBackoff Backoff { get; } = new(policy);

    public long Reads { get; private set; }

    protected abstract TimeSpan Interval { get; }

    /// <summary>Perform one unary read and apply its page.</summary>
    protected abstract Task<PageStep> ReadPageAsync(CancellationToken cancellationToken);

    public async Task<WatchResult> RunAsync(CancellationToken cancellationToken)
    {
        bool live = false;
        while (true)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return await StopAsync(new WatchResult(StopReason.Cancelled, "cancelled")).ConfigureAwait(false);
            }

            PageStep step;
            Reads++;
            try
            {
                step = await ReadPageAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (FailureMapper.TryMap(ex, cancellationToken, out ConnectionEnd mapped))
            {
                if (mapped.Kind == EndKind.Cancelled)
                {
                    return await StopAsync(new WatchResult(StopReason.Cancelled, "cancelled")).ConfigureAwait(false);
                }

                step = mapped.Kind == EndKind.Stopped
                    ? new PageStep(StepKind.Stop, new WatchResult(mapped.Stop, mapped.Detail))
                    : new PageStep(StepKind.Retry, Retry: new Classified(Disposition.Retry, mapped.RetryAfter, mapped.Detail));
            }

            TimeSpan delay;
            switch (step.Kind)
            {
                case StepKind.Stop:
                    return await StopAsync(step.Stop).ConfigureAwait(false);
                case StepKind.Retry:
                    delay = Backoff.NextDelay(_random);
                    if (step.Retry.RetryAfter > delay)
                    {
                        delay = step.Retry.RetryAfter;
                    }

                    await Observer.ConnectionChangedAsync(ConnectionState.Reconnecting, step.Retry.Detail, cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    Backoff.Succeeded();
                    if (!live)
                    {
                        live = true;
                        await Observer.ConnectionChangedAsync(ConnectionState.Live, "first page received", cancellationToken).ConfigureAwait(false);
                    }

                    delay = Pacing.Next(Interval, Policy.CadenceJitter, _random);
                    break;
            }

            try
            {
                await Task.Delay(delay, Time, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return await StopAsync(new WatchResult(StopReason.Cancelled, "cancelled")).ConfigureAwait(false);
            }
        }
    }

    private async Task<WatchResult> StopAsync(WatchResult result)
    {
        await Observer.ConnectionChangedAsync(ConnectionState.Stopped, result.Detail, CancellationToken.None).ConfigureAwait(false);
        return result;
    }
}

/// <summary>The <c>EventService.Poll</c> fallback: first Poll establishes scope, later Polls carry bounded hints.</summary>
/// <remarks>
/// The first Poll (no cursor) must return a cursor and <c>resetRequired</c>; the authoritative snapshot is then read
/// before the cursor is used. The cursor advances only after every hint of a page was handled, so a failing
/// observer leaves the cursor where it was and the replayed hints are deduplicated by sequence.
/// </remarks>
internal sealed class EventPoller(
    EventSession session,
    IRealtimeTransport transport,
    RealtimeObserver observer,
    TimeProvider time,
    Func<double> random,
    RealtimePolicy policy) : PagedReader(observer, time, random, policy)
{
    private readonly EventSession _session = session ?? throw new ArgumentNullException(nameof(session));
    private readonly IRealtimeTransport _transport = transport ?? throw new ArgumentNullException(nameof(transport));

    protected override TimeSpan Interval => Policy.PollInterval;

    protected override async Task<PageStep> ReadPageAsync(CancellationToken cancellationToken)
    {
        string? cursor = _session.Cursor;
        EventServicePollResponse response = await _transport.PollAsync(_session.Key, cursor, cancellationToken).ConfigureAwait(false);
        switch (response.OutcomeCase)
        {
            case EventServicePollResponse.OutcomeOneofCase.Error:
                return Classify(ErrorClassifier.FromArcError(response.Error, Time.GetUtcNow(), Policy));
            case EventServicePollResponse.OutcomeOneofCase.Value:
                break;
            default:
                return Stop(StopReason.ProtocolViolation, "a Poll response without a value or an error");
        }

        EventServicePollValue value = response.Value;
        bool reset = value.HasResetRequired && value.ResetRequired;
        if (!value.HasNextCursor || value.NextCursor.Length == 0)
        {
            return Stop(StopReason.ProtocolViolation, "a Poll page without a next cursor");
        }

        if (cursor is null && !reset)
        {
            return Stop(StopReason.ProtocolViolation, "the first Poll did not require a reset");
        }

        if (reset)
        {
            if (value.Events.Count > 0)
            {
                return Stop(StopReason.ProtocolViolation, "a reset Poll page carried hints");
            }

            _session.Tracker.Reset();
            _session.Snapshots++;
            await Observer.SnapshotRequiredAsync(cursor is null ? "first Poll" : "Poll reset", cancellationToken).ConfigureAwait(false);
            _session.Cursor = value.NextCursor;
            return new PageStep(StepKind.Idle);
        }

        foreach (Event hint in value.Events)
        {
            WatchResult? stop = await EventDelivery.DeliverAsync(_session, Observer, hint, cancellationToken).ConfigureAwait(false);
            if (stop is { } failure)
            {
                return new PageStep(StepKind.Stop, failure);
            }
        }

        _session.Cursor = value.NextCursor;
        return new PageStep(StepKind.Idle);
    }

    private static PageStep Stop(StopReason reason, string detail) => new(StepKind.Stop, new WatchResult(reason, detail));

    private static PageStep Classify(Classified classified)
    {
        ConnectionEnd end = ConnectionEnd.From(classified);
        return end.Kind == EndKind.Stopped
            ? new PageStep(StepKind.Stop, new WatchResult(end.Stop, end.Detail))
            : new PageStep(StepKind.Retry, Retry: classified);
    }
}

/// <summary>The <c>ExecutionService.ReadOutput</c> fallback, read every five seconds until the terminal outcome is read.</summary>
internal sealed class OutputReader(
    OutputSession session,
    IRealtimeTransport transport,
    RealtimeObserver observer,
    TimeProvider time,
    Func<double> random,
    RealtimePolicy policy) : PagedReader(observer, time, random, policy)
{
    private readonly OutputSession _session = session ?? throw new ArgumentNullException(nameof(session));
    private readonly IRealtimeTransport _transport = transport ?? throw new ArgumentNullException(nameof(transport));

    protected override TimeSpan Interval => Policy.ReadOutputInterval;

    protected override async Task<PageStep> ReadPageAsync(CancellationToken cancellationToken)
    {
        ExecutionServiceReadOutputResponse response = await _transport.ReadOutputAsync(_session.Owner, _session.Cursor, cancellationToken).ConfigureAwait(false);
        PageResult page = await OutputDelivery.ApplyPageAsync(_session, Observer, Policy, Time, response, cancellationToken).ConfigureAwait(false);
        switch (page.Kind)
        {
            case PageKind.Completed:
                await Observer.TerminalAsync(_session.AuthoritativeTerminal!, cancellationToken).ConfigureAwait(false);
                return new PageStep(StepKind.Stop, new WatchResult(StopReason.Completed, "the authoritative read returned the terminal outcome"));
            case PageKind.Stop:
                return new PageStep(StepKind.Stop, page.Stop);
            case PageKind.Retry:
                ConnectionEnd end = ConnectionEnd.From(page.Retry);
                return end.Kind == EndKind.Stopped
                    ? new PageStep(StepKind.Stop, new WatchResult(end.Stop, end.Detail))
                    : new PageStep(StepKind.Retry, Retry: page.Retry);
            default:
                return new PageStep(StepKind.Idle);
        }
    }
}
