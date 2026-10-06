// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Observability.Desktop;

/// <summary>Bounded OTLP/HTTP JSON delivery to an explicitly configured HTTPS collector.</summary>
public sealed class OtlpExporterOptions
{
    /// <summary>Collector base URI. No credentials, query or fragment; /v1/traces, logs and metrics are appended.</summary>
    public required Uri Collector { get; init; }
    /// <summary>Optional owner-approved collector authentication. No credential is retained in options or telemetry.</summary>
    public IOtlpCollectorCredentials? Credentials { get; init; }
    public int MaximumRetainedRecords { get; init; } = 256;
    public int MaximumRetainedBytes { get; init; } = 2 * 1024 * 1024;
    public int MaximumRecordBytes { get; init; } = 64 * 1024;
    public int MaximumAttempts { get; init; } = 3;
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(10);
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromMilliseconds(250);
    public TimeSpan MaximumRetryDelay { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan MetricCollectionInterval { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan HealthFreshness { get; init; } = TimeSpan.FromMinutes(1);

    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(Collector);
        if (!Collector.IsAbsoluteUri || Collector.Scheme != Uri.UriSchemeHttps || Collector.UserInfo.Length != 0
            || Collector.Query.Length != 0 || Collector.Fragment.Length != 0 || Collector.Host.Length == 0)
            throw new ArgumentException("An explicit credential-free HTTPS collector is required.", nameof(Collector));
        Range(MaximumRetainedRecords, 1, 4096, nameof(MaximumRetainedRecords));
        Range(MaximumRetainedBytes, 4096, 16 * 1024 * 1024, nameof(MaximumRetainedBytes));
        Range(MaximumRecordBytes, 1024, Math.Min(MaximumRetainedBytes, 256 * 1024), nameof(MaximumRecordBytes));
        Range(MaximumAttempts, 1, 5, nameof(MaximumAttempts));
        Duration(RequestTimeout, TimeSpan.FromMilliseconds(10), TimeSpan.FromMinutes(1), nameof(RequestTimeout));
        Duration(RetryDelay, TimeSpan.Zero, TimeSpan.FromSeconds(5), nameof(RetryDelay));
        Duration(MaximumRetryDelay, RetryDelay, TimeSpan.FromSeconds(30), nameof(MaximumRetryDelay));
        Duration(ShutdownTimeout, TimeSpan.FromMilliseconds(10), TimeSpan.FromSeconds(30), nameof(ShutdownTimeout));
        Duration(MetricCollectionInterval, TimeSpan.FromMilliseconds(100), TimeSpan.FromMinutes(5), nameof(MetricCollectionInterval));
        Duration(HealthFreshness, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5), nameof(HealthFreshness));
    }

    private static void Range(int value, int minimum, int maximum, string name)
    {
        if (value < minimum || value > maximum) throw new ArgumentOutOfRangeException(name);
    }

    private static void Duration(TimeSpan value, TimeSpan minimum, TimeSpan maximum, string name)
    {
        if (value < minimum || value > maximum) throw new ArgumentOutOfRangeException(name);
    }
}

/// <summary>Local delivery facts; never exports endpoint names, payloads or exception text.</summary>
public readonly record struct OtlpExportStatistics(long Accepted, long Delivered, long Rejected, long Overflow,
    long Purged, long Failures, long Retries, int RetainedRecords, long RetainedBytes, bool Stopped);
