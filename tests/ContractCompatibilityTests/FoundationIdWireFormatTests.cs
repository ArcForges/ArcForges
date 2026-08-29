// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using ArcForges.Contracts.Foundation;

namespace ArcForges.Tests.ContractCompatibilityTests;

/// <summary>
/// Identities travel as bare scalars, never as wrapper objects.
/// </summary>
/// <remarks>
/// The whole point of a strongly typed identity is that it costs nothing on the wire. If a wrapper ever
/// leaked — <c>{"value":"..."}</c> instead of <c>"..."</c> — every consumer's parser would break and the
/// goldens would move, so the shape is asserted directly rather than only through a round-trip.
/// </remarks>
public sealed class FoundationIdWireFormatTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AGuidIdentityIsABareCanonicalGuidString()
    {
        var json = FoundationGolden.Serialize(
            FoundationFixtures.Locator(), FoundationGolden.Strict<LocalResourceLocator>());

        using var document = JsonDocument.Parse(json);
        var deviceId = document.RootElement.GetProperty("deviceId");

        Xunit.Assert.Equal(JsonValueKind.String, deviceId.ValueKind);
        Xunit.Assert.Equal(FoundationFixtures.DeviceGuid, deviceId.GetString());
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AProductIdentityIsOneOfTheSevenFrozenStrings()
    {
        var json = FoundationGolden.Serialize(
            FoundationFixtures.LocalResource(), FoundationGolden.Strict<ResourceRef>());

        using var document = JsonDocument.Parse(json);
        var owner = document.RootElement.GetProperty("ownerProduct");

        Xunit.Assert.Equal(JsonValueKind.String, owner.ValueKind);
        Xunit.Assert.Contains(owner.GetString(), WellKnownProducts.All);
        Xunit.Assert.Equal("arcnotes", owner.GetString());
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AProductIdentityOutsideTheClosedSetCannotBeConstructed()
    {
        // The counter-evidence for the frozen set: if an unknown value were constructible, the wire value
        // would no longer be closed and a third party could impersonate a product.
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new ProductId("arcforges-evil"));
        Xunit.Assert.False(ProductId.TryParse("arcforges-evil", out _));
        Xunit.Assert.False(ProductId.TryParse(null, out _));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AProductIdentityOutsideTheClosedSetIsRejectedOnRead()
    {
        var json = """{"deviceId":"0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e12","locatorId":"x"}""";

        // A wrapped identity object must not deserialise into a bare-scalar identity.
        var wrapped = """{"deviceId":{"value":"0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e12"},"locatorId":"x"}""";

        Xunit.Assert.NotNull(JsonSerializer.Deserialize(json, FoundationGolden.Strict<LocalResourceLocator>()));
        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(wrapped, FoundationGolden.Strict<LocalResourceLocator>()));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void EveryGuidIdentityAgreesOnTheSameTextForm()
    {
        var value = Guid.Parse(FoundationFixtures.ResourceGuid);

        Xunit.Assert.Equal(FoundationFixtures.ResourceGuid, new ResourceId(value).ToString());
        Xunit.Assert.Equal(FoundationFixtures.ResourceGuid, new DocumentId(value).ToString());
        Xunit.Assert.Equal(FoundationFixtures.ResourceGuid, new CommandId(value).ToString());
        Xunit.Assert.Equal(FoundationFixtures.ResourceGuid, new AttemptId(value).ToString());
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void DistinctIdentityTypesDoNotInterchange()
    {
        // The reason these are nominal types at all: a CommandId and an AttemptId are both GUIDs and mean
        // entirely different things, so the compiler has to keep them apart.
        var value = Guid.Parse(FoundationFixtures.TaskGuid);

        Xunit.Assert.False(typeof(CommandId).IsAssignableFrom(typeof(AttemptId)));
        Xunit.Assert.False(typeof(TaskId).IsAssignableFrom(typeof(RunId)));
        Xunit.Assert.Equal(new TaskId(value), new TaskId(value));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnIdentityIsNewEachTimeAndIsVersion7()
    {
        var first = DocumentId.New();
        var second = DocumentId.New();

        Xunit.Assert.NotEqual(first, second);
        Xunit.Assert.False(first.IsEmpty);
        Xunit.Assert.True(default(DocumentId).IsEmpty);

        // Version 7 puts the timestamp in the high bits, which is what gives these identities index locality.
        // The version nibble is the assertion; ordering is deliberately not asserted, because two values
        // minted inside the same millisecond differ only in their random tail and may order either way.
        Xunit.Assert.Equal(7, first.Value.Version);
        Xunit.Assert.Equal(7, second.Value.Version);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void ParsingRejectsTextThatIsNotAnIdentity()
    {
        Xunit.Assert.Throws<FormatException>(() => DocumentId.Parse("not-a-guid"));
        Xunit.Assert.False(DocumentId.TryParse("not-a-guid", out _));
    }
}
