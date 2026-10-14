// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Serialization;

namespace ArcForges.TestLoad;

/// <summary>
/// The JSON report of one scenario run. <see cref="Parameters"/>, <see cref="Digest"/>,
/// <see cref="Results"/> and <see cref="StreamDigests"/> are reproducible; <see cref="Measured"/>
/// holds observations of this run (time, memory, process IDs) that legitimately vary.
/// </summary>
internal sealed class ScenarioReport
{
    public string Tool { get; init; } = "arcforges-testload";

    public int SchemaVersion { get; init; } = 1;

    public required string Scenario { get; init; }

    public required IReadOnlyDictionary<string, string> Parameters { get; init; }

    public required string Digest { get; init; }

    public required IReadOnlyDictionary<string, long> Results { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? StreamDigests { get; init; }

    public required IReadOnlyDictionary<string, long> Measured { get; init; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ScenarioReport))]
internal sealed partial class TestLoadJsonContext : JsonSerializerContext;
