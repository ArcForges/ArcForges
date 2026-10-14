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

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(SizeResult))]
[JsonSerializable(typeof(StartupResult))]
internal sealed partial class BenchJsonContext : JsonSerializerContext;
