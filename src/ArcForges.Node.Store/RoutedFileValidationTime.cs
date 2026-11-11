// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.Node.Store;

/// <summary>A file/workspace validation time derived from both the persisted floor and native monotonic elapsed time.</summary>
public readonly record struct RoutedFileTimeSample(bool Healthy, long BoundaryMicroseconds);

/// <summary>
/// A nondecreasing, FULL-committed validation floor. A material wall/monotonic disagreement is explicitly unhealthy;
/// callers must not execute an effect or claim a verified result from such a sample.
/// </summary>
public static class RoutedFileValidationTime
{
    private const long ToleranceMicroseconds = 120L * 1_000_000;

    /// <summary>Samples the floor and the real process-local monotonic clock without modifying the store.</summary>
    public static RoutedFileTimeSample Sample(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if (reader.FileRetention is not { } process ||
            reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;") is not long persisted)
        {
            return new RoutedFileTimeSample(false, 0);
        }

        try
        {
            var now = StoreTime.NowMicroseconds(reader.Clock);
            var tick = Stopwatch.GetTimestamp();
            if (tick < process.StartedAt)
            {
                return new RoutedFileTimeSample(false, Math.Max(persisted, now));
            }

            var expected = checked(process.StartedWall + Stopwatch.GetElapsedTime(process.StartedAt, tick).Ticks / 10);
            var boundary = Math.Max(persisted, Math.Max(now, expected));
            var healthy = Math.Abs((double)now - expected) <= ToleranceMicroseconds &&
                (double)persisted - now <= ToleranceMicroseconds;
            return new RoutedFileTimeSample(healthy, boundary);
        }
        catch (Exception exception) when (exception is ArgumentOutOfRangeException or OverflowException)
        {
            return new RoutedFileTimeSample(false, persisted);
        }
    }

    /// <summary>Advances the durable floor in a caller-owned FULL transaction, including an unhealthy observed forward jump.</summary>
    public static RoutedFileTimeSample Advance(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.Durability != CommitDurability.Full)
        {
            throw new InvalidOperationException("The file validation-time boundary requires a FULL transaction.");
        }

        var sample = Sample(transaction);
        if (transaction.FileRetention is null)
        {
            return sample;
        }

        if (transaction.Execute("""
            UPDATE routed_file_validation_time SET highwater = max(highwater, $boundary)
            WHERE singleton = 1 AND highwater IS NOT NULL;
            """, ("$boundary", sample.BoundaryMicroseconds)) != 1)
        {
            throw new InvalidOperationException("The durable file validation-time boundary is unavailable.");
        }

        return sample;
    }
}
