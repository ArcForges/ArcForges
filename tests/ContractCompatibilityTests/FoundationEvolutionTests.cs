// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using ArcForges.Contracts.Foundation;

namespace ArcForges.Tests.ContractCompatibilityTests;

/// <summary>
/// How the two contexts differ, and where tolerance stops.
/// </summary>
/// <remarks>
/// Contract evolution is additive-only, which only works if a reader ignores fields it does not yet know.
/// That tolerance is deliberately narrow: an unknown *field* is forward compatibility, but a duplicate key,
/// a missing required member or an unknown enum value is a document this build cannot act on safely.
/// </remarks>
public sealed class FoundationEvolutionTests
{
    /// <summary>A future build has added a field the current one has never heard of.</summary>
    private static string FutureResourceRef() =>
        FoundationGolden.Read("resource-ref-local")
            .Insert(1, "\"retentionClass\":\"long-term\",");

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void TheInboundContextIgnoresAFieldItDoesNotKnow()
    {
        var restored = JsonSerializer.Deserialize(FutureResourceRef(), FoundationGolden.Inbound<ResourceRef>());

        Xunit.Assert.NotNull(restored);
        Xunit.Assert.Equal(FoundationFixtures.LocalResource(), restored);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void TheStrictContextRefusesAFieldItDoesNotKnow()
    {
        // Counter-evidence for the pair: if both contexts behaved the same, one of them would be pointless.
        // Strict is what this assembly holds itself to; tolerant is what it reads a newer peer with.
        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(FutureResourceRef(), FoundationGolden.Strict<ResourceRef>()));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void BothContextsRefuseADuplicateProperty()
    {
        var duplicated = FoundationGolden.Read("local-page-query").Insert(1, "\"limit\":99,");

        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(duplicated, FoundationGolden.Strict<LocalPageQuery>()));
        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(duplicated, FoundationGolden.Inbound<LocalPageQuery>()));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void BothContextsRefuseAMisCasedPropertyName()
    {
        // Case-insensitive matching would quietly accept "ContentHash" for "contentHash" and make the wire
        // name ambiguous. Strict fails on the unmapped member; tolerant skips it and then fails because the
        // required member never arrived. Both refuse, for different and correct reasons.
        var misCased = FoundationGolden.Read("resource-ref-local")
            .Replace("\"contentHash\"", "\"ContentHash\"", StringComparison.Ordinal);

        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(misCased, FoundationGolden.Strict<ResourceRef>()));
        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(misCased, FoundationGolden.Inbound<ResourceRef>()));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void BothContextsRefuseAMissingRequiredMember()
    {
        var withoutHash = RemoveProperty(FoundationGolden.Read("resource-ref-local"), "contentHash");

        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(withoutHash, FoundationGolden.Strict<ResourceRef>()));
        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(withoutHash, FoundationGolden.Inbound<ResourceRef>()));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void BothContextsRefuseAnExplicitNullForANonNullableMember()
    {
        var nulledHash = FoundationGolden.Read("resource-ref-local")
            .Replace($"\"contentHash\":\"{FoundationFixtures.ContentHash}\"", "\"contentHash\":null", StringComparison.Ordinal);

        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(nulledHash, FoundationGolden.Strict<ResourceRef>()));
        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(nulledHash, FoundationGolden.Inbound<ResourceRef>()));
    }

    [Xunit.Theory]
    [Xunit.InlineData("\"availability\":\"local_online\"", "\"availability\":\"quantum\"")]
    [Xunit.InlineData("\"sensitivity\":\"internal\"", "\"sensitivity\":\"top_secret\"")]
    [Xunit.Trait("Category", "Contract")]
    public void AnUnknownEnumValueIsRefusedByBothContexts(string original, string replacement)
    {
        // This is the "unsupported contract" boundary. An unknown state must never resolve to a known one:
        // mapping an unrecognised availability onto local_online, or an unrecognised sensitivity onto public,
        // would turn a message this build cannot understand into one it acts on confidently.
        var unknown = FoundationGolden.Read("resource-ref-local")
            .Replace(original, replacement, StringComparison.Ordinal);

        var strict = Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(unknown, FoundationGolden.Strict<ResourceRef>()));
        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(unknown, FoundationGolden.Inbound<ResourceRef>()));

        Xunit.Assert.Contains("Unsupported contract", strict.ToString(), StringComparison.Ordinal);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnEnumSentAsANumberIsRefused()
    {
        // The wire form is the frozen string. A number would bind to ordinal position, which is exactly the
        // coupling the frozen strings exist to remove.
        var numeric = FoundationGolden.Read("resource-ref-local")
            .Replace("\"availability\":\"local_online\"", "\"availability\":0", StringComparison.Ordinal);

        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(numeric, FoundationGolden.Inbound<ResourceRef>()));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnUnknownProvenanceDiscriminatorIsRefused()
    {
        // The union is closed. An artifact whose origin this build cannot name must not silently present as
        // one of the four known origins.
        var unknown = FoundationGolden.Read("provenance-cloud-task")
            .Replace("\"kind\":\"cloud_task\"", "\"kind\":\"imported_from_elsewhere\"", StringComparison.Ordinal);

        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(unknown, FoundationGolden.Strict<ArtifactProvenance>()));
        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(unknown, FoundationGolden.Inbound<ArtifactProvenance>()));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnUnknownProductIdentityIsRefusedOnTheWire()
    {
        var unknown = FoundationGolden.Read("resource-ref-local")
            .Replace("\"ownerProduct\":\"arcnotes\"", "\"ownerProduct\":\"arcforges-evil\"", StringComparison.Ordinal);

        Xunit.Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize(unknown, FoundationGolden.Inbound<ResourceRef>()));
    }

    private static string RemoveProperty(string json, string name)
    {
        using var document = JsonDocument.Parse(json);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!string.Equals(property.Name, name, StringComparison.Ordinal))
                {
                    property.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }
}
