// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// Holds synchronous private stage handles and their in-process byte/slot reservation. This does not cover named
/// approval staging or its durable post-restart quota, and does not grant caller authority or perform a target effect.
/// Closing these node-owned handles is not proof that an externally held metadata reference disappeared.
/// </summary>
internal sealed class WorkspaceStagePair : IDisposable
{
    private readonly object _gate = new();
    private readonly FileStageBudget.Lease _reservation;
    private bool _disposed;
    private bool _dispositionFailed;

    private WorkspaceStagePair(FileStageBudget.Lease reservation, WorkspaceAnonymousStage? original, WorkspaceAnonymousStage intended)
    {
        _reservation = reservation;
        Original = original;
        Intended = intended;
    }

    internal WorkspaceAnonymousStage? Original { get; }

    internal WorkspaceAnonymousStage Intended { get; }

    /// <summary>Reserves both sizes before creating either native stage. Null means the current in-process budget is exhausted.</summary>
    internal static WorkspaceStagePair? TryCreate(WorkspacePath root, FileStageBudget budget, ReadOnlyMemory<byte>? original,
        ReadOnlyMemory<byte> intended, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(budget);
        cancellationToken.ThrowIfCancellationRequested();
        var reservation = budget.TryReserve(original?.Length ?? 0, intended.Length);
        if (reservation is null) return null;
        WorkspaceAnonymousStage? before = null;
        WorkspaceAnonymousStage? after = null;
        try
        {
            if (original is { } bytes) before = root.CreateAnonymousStage(bytes.Span, cancellationToken);
            after = root.CreateAnonymousStage(intended.Span, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return new WorkspaceStagePair(reservation, before, after);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            var cleanup = CloseStages(before, after);
            if (cleanup is not null)
            {
                // Keep the budget charged when actual handle disposition could not be established.
                throw new AggregateException("Failed to dispose a private stage after creation failure.", exception, cleanup);
            }
            reservation.Dispose();
            throw;
        }
    }

    /// <summary>Releases this node's stage handles before releasing their capacity reservation.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            if (_dispositionFailed) throw new IOException("A previous stage disposition could not be established.");
            var cleanup = CloseStages(Original, Intended);
            if (cleanup is not null)
            {
                _dispositionFailed = true;
                throw new IOException("Failed to dispose private stages.", cleanup);
            }
            _reservation.Dispose();
            _disposed = true;
        }
    }

    private static Exception? CloseStages(WorkspaceAnonymousStage? original, WorkspaceAnonymousStage? intended)
    {
        Exception? failure = null;
        try
        {
            intended?.Dispose();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            failure = exception;
        }
        try
        {
            original?.Dispose();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            failure = failure is null ? exception : new AggregateException(failure, exception);
        }
        return failure;
    }
}
