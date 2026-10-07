// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.ContentSandbox.Host;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

public sealed class ProductionContainmentHarnessTests
{
    private static byte[] Configuration()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var directory = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "arcforges-operator-test"));
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("helperPath", Path.Combine(directory, "ArcForges.ContentSandbox.exe"));
            writer.WriteString("helperSha256", new string('a', 64));
            writer.WriteString("nativeDirectory", directory);
            writer.WriteString("runtimeRoot", Path.Combine(directory, "runtime"));
            writer.WriteString("rid", "win-x64");
            writer.WriteString("packageVersion", "1.0.0-ci.120.1");
            writer.WriteString("sourceCommit", new string('b', 40));
            writer.WriteStartArray("approvedPublisherKeys");
            writer.WriteStartObject();
            writer.WriteString("keyId", "operator-test");
            writer.WriteString("spki", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
            writer.WriteEndObject(); writer.WriteEndArray();
            writer.WriteStartArray("libraries");
            writer.WriteStartObject(); writer.WriteString("library", "ArcImageNative");
            writer.WriteString("profileSha256", new string('c', 64)); writer.WriteString("manifestSha256", new string('d', 64)); writer.WriteEndObject();
            writer.WriteStartObject(); writer.WriteString("library", "ArcPdfNative");
            writer.WriteString("profileSha256", new string('e', 64)); writer.WriteString("manifestSha256", new string('f', 64)); writer.WriteEndObject();
            writer.WriteEndArray(); writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    [Fact]
    public void ExplicitOperatorPinsComposeTheProductionLauncherWithoutFixtureTrust()
    {
        var bytes = Configuration();
        var harness = ProductionContainmentHarness.FromOperatorConfiguration(bytes);
        Assert.False(harness.Options.LocalUnsignedFixture);
        Assert.NotNull(harness.Options.ReleaseTrust);
        Assert.Equal(ProductionParserProfile.ProfileId, harness.Options.ParserProfile);
        Assert.Equal(new string('b', 40), harness.SourceCommit);
        Assert.Equal("win-x64", harness.Rid);
        var trustBefore = harness.Options.ReleaseTrust.Encode();
        Array.Fill(bytes, (byte)0);
        Assert.Equal(trustBefore, harness.Options.ReleaseTrust.Encode());
        Assert.Equal(new string('a', 64), Convert.ToHexStringLower(harness.Options.HelperSha256.Span));
        // This checks configuration composition only; the generated key approves no installed artifact.
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("unknown")]
    [InlineData("missing")]
    [InlineData("schema")]
    [InlineData("hash")]
    [InlineData("source")]
    [InlineData("rid")]
    [InlineData("relative")]
    [InlineData("foreign-library")]
    [InlineData("duplicate-library")]
    [InlineData("unapproved-keys")]
    [InlineData("duplicate-key")]
    [InlineData("too-many-keys")]
    [InlineData("nested-extra")]
    [InlineData("missing-peer")]
    public void MissingAmbiguousForeignOrUnboundedAuthorityNeverCreatesLaunchOptions(string mutation)
    {
        var input = Encoding.UTF8.GetString(Configuration());
        if (mutation is "relative" or "unapproved-keys" or "duplicate-key" or "too-many-keys" or "nested-extra" or "missing-peer")
        {
            var value = JsonNode.Parse(input)!.AsObject();
            if (mutation == "relative") { value["nativeDirectory"] = "relative"; }
            else if (mutation == "unapproved-keys") { value["approvedPublisherKeys"] = new JsonArray(); }
            else if (mutation == "missing-peer") { value["libraries"]!.AsArray().RemoveAt(1); }
            else if (mutation == "nested-extra") { value["libraries"]![0]!["extra"] = true; }
            else
            {
                var keys = value["approvedPublisherKeys"]!.AsArray();
                var original = keys[0]!.DeepClone();
                for (var i = 0; i < (mutation == "duplicate-key" ? 1 : 4); i++) { keys.Add(original.DeepClone()); }
            }
            input = value.ToJsonString();
        }

        input = mutation switch
        {
            "duplicate" => input.Insert(1, "\"schemaVersion\":1,"),
            "unknown" => input.Insert(1, "\"fixture\":true,"),
            "missing" => input.Replace("\"schemaVersion\":1,", string.Empty, StringComparison.Ordinal),
            "schema" => input.Replace("\"schemaVersion\":1", "\"schemaVersion\":2", StringComparison.Ordinal),
            "hash" => input.Replace(new string('a', 64), "not-a-hash", StringComparison.Ordinal),
            "source" => input.Replace(new string('b', 40), "not-a-source", StringComparison.Ordinal),
            "rid" => input.Replace("win-x64", "win-x86", StringComparison.Ordinal),
            "relative" => input,
            "foreign-library" => input.Replace("ArcPdfNative", "ForeignNative", StringComparison.Ordinal),
            "duplicate-library" => input.Replace("ArcPdfNative", "ArcImageNative", StringComparison.Ordinal),
            "unapproved-keys" => input,
            "duplicate-key" or "too-many-keys" or "nested-extra" or "missing-peer" => input,
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };
        _ = Assert.ThrowsAny<Exception>(() => ProductionContainmentHarness.FromOperatorConfiguration(Encoding.UTF8.GetBytes(input)));
    }

    [Fact]
    public void ConfigurationAcquisitionBoundsAreAppliedBeforeParsing()
    {
        _ = Assert.Throws<InvalidDataException>(() => ProductionContainmentHarness.FromOperatorConfiguration(ReadOnlyMemory<byte>.Empty));
        _ = Assert.Throws<InvalidDataException>(() => ProductionContainmentHarness.FromOperatorConfiguration(new byte[8193]));
        var path = Path.Combine(Path.GetTempPath(), "arcforges-operator-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllBytes(path, Configuration());
            Assert.NotNull(ProductionContainmentHarness.ReadOperatorConfiguration(path).Options.ReleaseTrust);
            File.WriteAllBytes(path, new byte[8193]);
            _ = Assert.Throws<InvalidDataException>(() => ProductionContainmentHarness.ReadOperatorConfiguration(path));
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("png")]
    [InlineData("tiff")]
    [InlineData("exr")]
    public void AuthoredFormatInputsAreFiniteIndependentSnapshots(string codec)
    {
        var first = FirstPartyImageFixtures.Create(codec);
        var original = first.ToArray();
        Assert.InRange(first.Length, 32, 4096);
        first[0] ^= 255;
        Assert.Equal(original, FirstPartyImageFixtures.Create(codec));
        Assert.NotEqual(first, FirstPartyImageFixtures.Create(codec));
        // Structural test-data check only. Actual decode/pixels are asserted by the child scenarios.
    }
}
