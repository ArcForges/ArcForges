// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;

namespace ArcForges.ContentSandbox.Broker;

/// <summary>One bounded teardown owner. Unconfirmed exit retains the identity until the actual exit signal arrives.</summary>
internal sealed class HelperResourceLifetime(
    Action terminate,
    Action closeBoundary,
    Task confirmedExit,
    Func<ValueTask> drainDiagnostics,
    IReadOnlyList<Func<ValueTask>> releaseResources,
    Action releaseIdentity,
    TimeSpan exitBudget,
    TimeSpan diagnosticBudget) : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? _disposal;

    /// <summary>Completes only after actual exit and identity cleanup, including a quarantined continuation.</summary>
    internal Task Released => _released.Task;

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            return new ValueTask(_disposal ??= CleanupAsync());
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "The lifetime owner must attempt all remaining resource releases after any teardown fault.")]
    private async Task CleanupAsync()
    {
        // Publish the single cleanup task before callbacks can reenter or compete with disposal.
        await Task.Yield();
        var failures = new List<Exception>();
        foreach (var action in new[] { terminate, closeBoundary })
        {
            try
            {
                action();
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        foreach (var release in releaseResources)
        {
            try
            {
                var pending = release().AsTask();
                _ = ObserveCompletionAsync(pending);
                await pending.WaitAsync(diagnosticBudget).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        try
        {
            var pending = drainDiagnostics().AsTask();
            _ = ObserveCompletionAsync(pending);
            await pending.WaitAsync(diagnosticBudget).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        try
        {
            await confirmedExit.WaitAsync(exitBudget).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failures.Add(exception);
            // This owned continuation never releases on an erroneous or canceled exit task.
            // The Windows producer supplies an actual wait on its retained kernel process handle.
            _ = ReleaseAfterExitAsync();
            throw Failure(failures, "The helper exit is unconfirmed; its identity remains quarantined.");
        }

        Release(failures);
        if (failures.Count != 0)
        {
            throw Failure(failures, "The helper ended, but one or more teardown operations failed.");
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "The quarantine continuation owns and records its eventual cleanup failure without an unobserved background exception.")]
    private async Task ReleaseAfterExitAsync()
    {
        try
        {
            await confirmedExit.ConfigureAwait(false);
            Release([]);
        }
        catch (Exception exception)
        {
            _ = _released.TrySetException(exception);
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "The owner reports identity cleanup failure after every other resource has been attempted.")]
    private void Release(List<Exception> failures)
    {
        try
        {
            releaseIdentity();
            _ = _released.TrySetResult();
        }
        catch (Exception exception)
        {
            failures.Add(exception);
            _ = _released.TrySetException(exception);
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "A bounded teardown attempt retains and observes a late asynchronous release, including failure after the caller has received a timeout.")]
    private static async Task ObserveCompletionAsync(Task pending)
    {
        try
        {
            await pending.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // CleanupAsync reports faults within the deadline. Later faults are still observed by this owned continuation.
        }
    }

    private static ContentSandboxLaunchException Failure(List<Exception> failures, string message) =>
        new("resource.unavailable", message, new AggregateException(failures));
}
