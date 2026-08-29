// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using ArcForges.Contracts.Foundation;

namespace ArcForges.Tests.ContractCompatibilityTests;

/// <summary>Every Foundation wire type round-trips through its committed canonical JSON.</summary>
public sealed class FoundationGoldenTests
{
    public static Xunit.TheoryData<string> GoldenNames()
    {
        var names = new Xunit.TheoryData<string>();
        foreach (var (name, _, _) in FoundationGolden.All())
        {
            names.Add(name);
        }

        return names;
    }

    [Xunit.Theory]
    [Xunit.MemberData(nameof(GoldenNames))]
    [Xunit.Trait("Category", "Contract")]
    public void SerialisingTheFixtureProducesTheCommittedBytes(string name)
    {
        var (_, value, typeInfo) = FoundationGolden.All().Single(entry => entry.Name == name);

        Xunit.Assert.True(FoundationGolden.Exists(name), $"Golden sample '{name}.json' is missing.");
        Xunit.Assert.Equal(FoundationGolden.Read(name), FoundationGolden.Serialize(value, typeInfo));
    }

    [Xunit.Theory]
    [Xunit.MemberData(nameof(GoldenNames))]
    [Xunit.Trait("Category", "Contract")]
    public void SerialisationIsRepeatable(string name)
    {
        // Member order is not a compatibility promise, but the generator must not reorder between runs or
        // the goldens would be untrustworthy as a diff surface.
        var (_, value, typeInfo) = FoundationGolden.All().Single(entry => entry.Name == name);

        Xunit.Assert.Equal(
            FoundationGolden.Serialize(value, typeInfo),
            FoundationGolden.Serialize(value, typeInfo));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void EveryGoldenFileBelongsToASample()
    {
        // A stale file left behind after a type is renamed would otherwise sit unnoticed and unverified.
        var declared = FoundationGolden.All().Select(entry => entry.Name).ToHashSet(StringComparer.Ordinal);
        var onDisk = Directory
            .EnumerateFiles(Path.GetDirectoryName(FoundationGolden.Path("any"))!, "*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .ToArray();

        var orphans = onDisk.Where(name => name is not null && !declared.Contains(name)).ToArray();
        Xunit.Assert.True(orphans.Length == 0, $"Golden files with no sample: {string.Join(", ", orphans)}");
        Xunit.Assert.Equal(declared.Count, onDisk.Length);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void ResourceRefRoundTripsStructurally()
    {
        var original = FoundationFixtures.LocalResource();
        var json = FoundationGolden.Serialize(original, FoundationGolden.Strict<ResourceRef>());
        var restored = JsonSerializer.Deserialize(json, FoundationGolden.Strict<ResourceRef>());

        Xunit.Assert.Equal(original, restored);
        Xunit.Assert.Equal(json, FoundationGolden.Serialize(restored!, FoundationGolden.Strict<ResourceRef>()));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void ArtifactRefRoundTripsStructurallyIncludingItsProvenanceBranch()
    {
        var original = FoundationFixtures.Artifact();
        var json = FoundationGolden.Serialize(original, FoundationGolden.Strict<ArtifactRef>());
        var restored = JsonSerializer.Deserialize(json, FoundationGolden.Strict<ArtifactRef>());

        Xunit.Assert.Equal(original, restored);
        Xunit.Assert.IsType<CloudTaskProvenance>(restored!.Provenance);
    }

    [Xunit.Theory]
    [Xunit.InlineData(0L)]
    [Xunit.InlineData(1L)]
    [Xunit.InlineData(long.MaxValue)]
    [Xunit.Trait("Category", "Contract")]
    public void RevisionBoundariesSurviveTheWire(long value)
    {
        // 0 means "no committed version", 1 is the first, and long.MaxValue is where Next() must refuse.
        var result = ArcResult<ResourceRef>.Success(FoundationFixtures.LocalResource(), new Revision(value));
        var json = FoundationGolden.Serialize(result, FoundationGolden.Strict<ArcResult<ResourceRef>>());
        var restored = JsonSerializer.Deserialize(json, FoundationGolden.Strict<ArcResult<ResourceRef>>());

        Xunit.Assert.Equal(new Revision(value), restored!.NewRevision);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void RevisionAndSequenceRefuseToAdvancePastTheirCeiling()
    {
        Xunit.Assert.Throws<OverflowException>(() => new Revision(long.MaxValue).Next());
        Xunit.Assert.Throws<OverflowException>(() => new Sequence(long.MaxValue).Next());
    }
}
