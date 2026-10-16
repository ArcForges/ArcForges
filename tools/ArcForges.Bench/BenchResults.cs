// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;

namespace ArcForges.Bench;

/// <summary>Where a benchmark ran. Contains no user or machine names.</summary>
internal sealed class BenchEnvironment
{
    public required string Os { get; init; }

    public required string Architecture { get; init; }

    public required string RuntimeIdentifier { get; init; }

    public required int ProcessorCount { get; init; }

    public required string Framework { get; init; }

    public static BenchEnvironment Current() => new()
    {
        Os = RuntimeInformation.OSDescription,
        Architecture = RuntimeInformation.OSArchitecture.ToString(),
        RuntimeIdentifier = RuntimeInformation.RuntimeIdentifier,
        ProcessorCount = Environment.ProcessorCount,
        Framework = RuntimeInformation.FrameworkDescription,
    };
}

internal sealed class SizeResult
{
    public string Tool { get; init; } = "arcforges-bench";

    public int SchemaVersion { get; init; } = 1;

    public string Benchmark { get; init; } = "size";

    public required string Name { get; init; }

    public required string Measurement { get; init; }

    public required long Bytes { get; init; }

    public required long LimitBytes { get; init; }

    public required IReadOnlyList<string> Excluded { get; init; }

    public required bool Pass { get; init; }

    public required BenchEnvironment Environment { get; init; }
}

internal sealed class StartupResult
{
    public string Tool { get; init; } = "arcforges-bench";

    public int SchemaVersion { get; init; } = 1;

    public string Benchmark { get; init; } = "startup";

    public required string Name { get; init; }

    public required IReadOnlyList<string> Command { get; init; }

    public required int Runs { get; init; }

    public required int Warmup { get; init; }

    public required IReadOnlyList<double> SamplesMs { get; init; }

    public required double P50Ms { get; init; }

    public required double P95Ms { get; init; }

    public required double MinMs { get; init; }

    public required double MaxMs { get; init; }

    public required double MeanMs { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? LimitP50Ms { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? LimitP95Ms { get; init; }

    public required bool Pass { get; init; }

    public required BenchEnvironment Environment { get; init; }
}

internal sealed record StartupComparisonResult
{
    public string Tool { get; init; } = "arcforges-bench";

    public int SchemaVersion { get; init; } = 1;

    public string Benchmark { get; init; } = "startup-comparison";

    public required string Name { get; init; }

    /// <summary><c>pass</c>, <c>regression</c> or <c>no-baseline</c>.</summary>
    public required string Status { get; init; }

    /// <summary>
    /// <c>interleaved-same-runner</c>: both executables measured here, alternating; <c>recorded-results</c>: two saved startup results
    /// compared (only meaningful when both were measured on the same machine).
    /// </summary>
    public string Method { get; init; } = "recorded-results";

    public required string Reason { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BaselineSource { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? BaselineP50Ms { get; init; }

    public required double CurrentP50Ms { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? BaselineP95Ms { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? CurrentP95Ms { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? DeltaMs { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? DeltaPercent { get; init; }

    public required double MaxRegressionPercent { get; init; }

    public required double NoiseFloorMs { get; init; }

    public required bool Pass { get; init; }

    /// <summary>The baseline's startup result (samples, percentiles, environment).</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public StartupResult? Baseline { get; init; }

    /// <summary>The current startup result.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public StartupResult? Current { get; init; }
}

internal sealed class TableSize
{
    public required string Table { get; init; }

    public required long Rows { get; init; }

    /// <summary>Pages of the table and its indexes (SQLite dbstat); absent when the SQLite build has no dbstat.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required long? Bytes { get; init; }
}

internal sealed class StoreGrowthResult
{
    public string Tool { get; init; } = "arcforges-bench";

    public int SchemaVersion { get; init; } = 1;

    public string Benchmark { get; init; } = "store-growth";

    public required string Name { get; init; }

    public required int Attempts { get; init; }

    public required int Tasks { get; init; }

    public required int Sessions { get; init; }

    public required int SealedTasks { get; init; }

    public required long DistinctEnvironments { get; init; }

    public required IReadOnlyList<string> EnvironmentSources { get; init; }

    /// <summary>The new, empty store (schema and default policy) after a checkpoint.</summary>
    public required long BaselineBytes { get; init; }

    /// <summary>The database file after a final checkpoint (logs are files outside the store and never counted).</summary>
    public required long DatabaseBytes { get; init; }

    public required long WalBytes { get; init; }

    /// <summary>The measured growth: database plus WAL minus the baseline; the gated value.</summary>
    public required long GrowthBytes { get; init; }

    public required double BytesPerAttempt { get; init; }

    public required long LimitBytes { get; init; }

    public required long LimitBytesPer10000Attempts { get; init; }

    public required bool Pass { get; init; }

    public required long DurationMs { get; init; }

    public required string Profile { get; init; }

    public required IReadOnlyList<TableSize> Tables { get; init; }

    public required BenchEnvironment Environment { get; init; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(SizeResult))]
[JsonSerializable(typeof(StartupResult))]
[JsonSerializable(typeof(StartupComparisonResult))]
[JsonSerializable(typeof(StoreGrowthResult))]
internal sealed partial class BenchJsonContext : JsonSerializerContext;
