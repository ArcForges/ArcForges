// SPDX-License-Identifier: AGPL-3.0-only

using System.IO;
using System.Linq;
using System.Text.Json;
using ArcForges.Contracts.Foundation;
using ArcForges.Contracts.LocalRpc;
using ArcForges.Contracts.LocalRpc.Notes;
using ArcForges.Contracts.LocalRpc.Scope;
using ArcForges.Contracts.LocalRpc.Slate;
using Xunit;

namespace ArcForges.Tests.ContractCompatibilityTests;

public sealed class LocalRpcGoldenTests
{
    public static TheoryData<string> GoldenNames()
    {
        var names = new TheoryData<string>();
        foreach (var (name, _, _) in LocalRpcGolden.All())
        {
            names.Add(name);
        }

        return names;
    }

    [Theory]
    [MemberData(nameof(GoldenNames))]
    [Trait("Category", "Contract")]
    public void SerialisingTheFixtureProducesTheCommittedBytes(string name)
    {
        var (_, value, typeInfo) = LocalRpcGolden.All().Single(entry => entry.Name == name);

        Assert.True(LocalRpcGolden.Exists(name), $"Golden sample '{name}.json' is missing.");
        Assert.Equal(LocalRpcGolden.Read(name), LocalRpcGolden.Serialize(value, typeInfo));
    }

    [Theory]
    [MemberData(nameof(GoldenNames))]
    [Trait("Category", "Contract")]
    public void SerialisationIsRepeatable(string name)
    {
        var (_, value, typeInfo) = LocalRpcGolden.All().Single(entry => entry.Name == name);

        Assert.Equal(
            LocalRpcGolden.Serialize(value, typeInfo),
            LocalRpcGolden.Serialize(value, typeInfo));
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void EveryGoldenFileBelongsToASample()
    {
        var declared = LocalRpcGolden.All().Select(entry => entry.Name).ToHashSet();
        var directory = Path.GetDirectoryName(LocalRpcGolden.Path("any"))!;
        if (!Directory.Exists(directory))
        {
            return;
        }

        var onDisk = Directory
            .EnumerateFiles(directory, "*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .ToArray();

        var orphans = onDisk.Where(name => name is not null && !declared.Contains(name)).ToArray();
        Assert.True(orphans.Length == 0, $"Golden files with no sample: {string.Join(", ", orphans)}");
        Assert.Equal(declared.Count, onDisk.Length);
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void RegisterInstanceRequestRoundTripsStructurally()
    {
        var original = LocalRpcFixtures.RegisterRequest();
        var json = LocalRpcGolden.Serialize(original, LocalRpcGolden.Strict<RegisterInstanceRequest>());
        var restored = JsonSerializer.Deserialize(json, LocalRpcGolden.Strict<RegisterInstanceRequest>());

        Assert.NotNull(restored);
        Assert.Equal(original.Product, restored.Product);
        Assert.Equal(original.Instance, restored.Instance);
        Assert.Equal(original.Capabilities.Count, restored.Capabilities.Count);
        Assert.Equal(original.Capabilities[0].CapabilityId, restored.Capabilities[0].CapabilityId);
        Assert.Equal(json, LocalRpcGolden.Serialize(restored, LocalRpcGolden.Strict<RegisterInstanceRequest>()));
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void InsertBlocksMutationRequestRoundTripsStructurally()
    {
        var original = LocalRpcFixtures.InsertBlocksReq();
        var json = LocalRpcGolden.Serialize(original, LocalRpcGolden.Strict<InsertBlocksRequest>());
        var restored = JsonSerializer.Deserialize(json, LocalRpcGolden.Strict<InsertBlocksRequest>());

        Assert.NotNull(restored);
        Assert.Equal(original.CommandId, restored.CommandId);
        Assert.Equal(original.TargetResource.ResourceId, restored.TargetResource.ResourceId);
        Assert.Equal(original.ExpectedRevision, restored.ExpectedRevision);
        Assert.Equal(original.Blocks.Count, restored.Blocks.Count);
        Assert.Equal(json, LocalRpcGolden.Serialize(restored, LocalRpcGolden.Strict<InsertBlocksRequest>()));
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void ArcResultInsertBlocksResponseRoundTripsStructurally()
    {
        var original = LocalRpcFixtures.ArcResultInsertBlocks();
        var json = LocalRpcGolden.Serialize(original, LocalRpcGolden.Strict<ArcResult<InsertBlocksResponse>>());
        var restored = JsonSerializer.Deserialize(json, LocalRpcGolden.Strict<ArcResult<InsertBlocksResponse>>());

        Assert.True(original.Ok);
        Assert.True(restored!.Ok);
        Assert.Equal(original.NewRevision, restored.NewRevision);
        Assert.Equal(original.Value!.CommandId, restored.Value!.CommandId);
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void EnsureGoldensExist()
    {
        var directory = Path.GetDirectoryName(LocalRpcGolden.Path("any"))!;
        Directory.CreateDirectory(directory);
        foreach (var (name, value, typeInfo) in LocalRpcGolden.All())
        {
            if (!LocalRpcGolden.Exists(name))
            {
                var json = LocalRpcGolden.Serialize(value, typeInfo);
                LocalRpcGolden.Write(name, json);
            }
        }
    }
}
