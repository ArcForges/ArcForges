// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Observability;

/// <summary>Async-flowing ambient context used by the unified signal emitter.</summary>
public static class ObservabilityScope
{
    private static readonly AsyncLocal<Frame?> CurrentFrame = new();

    public static ObservabilityContext? Current => CurrentFrame.Value?.Context;

    /// <summary>Installs a complete immutable context for this async flow and restores the prior one on disposal.</summary>
    public static IDisposable Push(ObservabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        _ = context.MaterializeDimensions();
        var frame = new Frame(context, CurrentFrame.Value);
        CurrentFrame.Value = frame;
        return new Scope(frame);
    }

    private sealed record Frame(ObservabilityContext Context, Frame? Parent);

    private sealed class Scope(Frame frame) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            if (!ReferenceEquals(CurrentFrame.Value, frame))
            {
                Interlocked.Exchange(ref _disposed, 0);
                throw new InvalidOperationException("Observability scopes must be disposed in last-in, first-out order on the creating async flow.");
            }

            CurrentFrame.Value = frame.Parent;
        }
    }
}
