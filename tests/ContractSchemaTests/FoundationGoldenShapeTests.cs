// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;

namespace ArcForges.Tests.ContractSchemaTests;

/// <summary>
/// Validates the committed Foundation golden files as documents, independently of the C# types.
/// </summary>
/// <remarks>
/// <para>
/// This project deliberately holds no <c>InternalsVisibleTo</c> grant for the contract assemblies, so it
/// cannot reach the source-generated contexts and cannot round-trip anything. That is the point: these
/// assertions read the golden files with <see cref="JsonDocument"/> and describe the wire the way a consumer
/// in another language would see it. A refactor that changed the shape and updated the C# round-trip in the
/// same breath would still be caught here.
/// </para>
/// <para>
/// The round-trip, source-generation coverage and evolution behaviour live in
/// <c>ArcForges.Tests.ContractCompatibilityTests</c>, which is one of the four granted assemblies.
/// </para>
/// </remarks>
public sealed class FoundationGoldenShapeTests
{
    private static readonly Lazy<string> GoldenRoot = new(Locate);

    /// <summary>The frozen availability values, as the plan spells them.</summary>
    private static readonly string[] Availability =
        ["local_online", "local_offline", "cloud", "preparing", "unavailable"];

    private static readonly string[] Sensitivity = ["public", "internal", "confidential", "restricted"];

    private static readonly string[] PreviewAvailability = ["none", "metadata", "thin", "rich"];

    private static readonly string[] ProvenanceKinds =
        ["user_created", "product_activity", "cloud_task", "automation"];

    private static readonly string[] Products =
    [
        "arcchat", "arcnotes", "arcscope", "arcslate", "arcchat-mobile", "arcforges-cloud", "arcforges-web",
    ];

    /// <summary>The frozen resource-reference field set from architecture §5.2, required members first.</summary>
    private static readonly string[] RequiredResourceFields =
    [
        "resourceId", "ownerProduct", "kind", "availability", "revision", "contentHash", "sizeBytes",
        "sensitivity", "displayName",
    ];

    private static readonly string[] AllResourceFields =
    [
        "resourceId", "ownerProduct", "kind", "availability", "revision", "contentHash", "sizeBytes",
        "sensitivity", "displayName", "contentType", "localLocator", "cloudObjectId",
    ];

    private static readonly string[] RequiredArtifactFields =
    [
        "artifactId", "ownerProduct", "kind", "displayName", "resourceRef", "mediaType", "provenance",
        "previewAvailability", "revision", "createdAtUtc", "updatedAtUtc",
    ];

    public static Xunit.TheoryData<string> GoldenFiles()
    {
        var files = new Xunit.TheoryData<string>();
        foreach (var path in Directory.EnumerateFiles(GoldenRoot.Value, "*.json").OrderBy(p => p, StringComparer.Ordinal))
        {
            files.Add(Path.GetFileName(path));
        }

        return files;
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void TheGoldenSetIsPresent()
    {
        // Guards every theory below: an empty directory would make them all pass vacuously.
        var count = Directory.EnumerateFiles(GoldenRoot.Value, "*.json").Count();
        Xunit.Assert.True(count >= 14, $"Only {count} golden files were found at {GoldenRoot.Value}.");
    }

    [Xunit.Theory]
    [Xunit.MemberData(nameof(GoldenFiles))]
    [Xunit.Trait("Category", "Contract")]
    public void EveryGoldenFileIsCompactSingleLineUtf8Json(string fileName)
    {
        var text = File.ReadAllText(Path.Combine(GoldenRoot.Value, fileName)).TrimEnd('\r', '\n');

        Xunit.Assert.False(text.Contains('\n', StringComparison.Ordinal), "A golden sample must be one line.");
        using var document = JsonDocument.Parse(text);
        Xunit.Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
    }

    [Xunit.Theory]
    [Xunit.InlineData("resource-ref-local.json")]
    [Xunit.InlineData("resource-ref-cloud.json")]
    [Xunit.Trait("Category", "Contract")]
    public void AResourceReferenceCarriesTheFrozenFieldSet(string fileName)
    {
        using var document = Parse(fileName);
        var root = document.RootElement;

        // architecture §5.2 fixes this field list exactly.
        foreach (var required in RequiredResourceFields)
        {
            Xunit.Assert.True(root.TryGetProperty(required, out _), $"{fileName} is missing '{required}'.");
        }

        foreach (var name in root.EnumerateObject().Select(property => property.Name))
        {
            Xunit.Assert.Contains(name, AllResourceFields);
        }

        Xunit.Assert.Contains(root.GetProperty("ownerProduct").GetString(), Products);
        Xunit.Assert.Contains(root.GetProperty("availability").GetString(), Availability);
        Xunit.Assert.Contains(root.GetProperty("sensitivity").GetString(), Sensitivity);
    }

    [Xunit.Theory]
    [Xunit.InlineData("resource-ref-local.json")]
    [Xunit.InlineData("resource-ref-cloud.json")]
    [Xunit.Trait("Category", "Contract")]
    public void AResourceReferenceCarriesARealSha256(string fileName)
    {
        using var document = Parse(fileName);
        var hash = document.RootElement.GetProperty("contentHash").GetString();

        Xunit.Assert.NotNull(hash);
        Xunit.Assert.Equal(64, hash!.Length);
        Xunit.Assert.All(hash, character =>
            Xunit.Assert.True(character is >= '0' and <= '9' or >= 'a' and <= 'f', $"'{character}' is not lower-case hex."));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void LocatorConstraintsHoldInTheCommittedSamples()
    {
        using var local = Parse("resource-ref-local.json");
        Xunit.Assert.True(local.RootElement.TryGetProperty("localLocator", out _));
        Xunit.Assert.False(local.RootElement.TryGetProperty("cloudObjectId", out _));

        using var cloud = Parse("resource-ref-cloud.json");
        Xunit.Assert.True(cloud.RootElement.TryGetProperty("cloudObjectId", out _));
        Xunit.Assert.False(cloud.RootElement.TryGetProperty("localLocator", out _));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnArtifactReferenceCarriesTheFrozenFieldSetAndSharesItsResourceOwner()
    {
        using var document = Parse("artifact-ref.json");
        var root = document.RootElement;

        foreach (var required in RequiredArtifactFields)
        {
            Xunit.Assert.True(root.TryGetProperty(required, out _), $"artifact-ref.json is missing '{required}'.");
        }

        Xunit.Assert.Contains(root.GetProperty("previewAvailability").GetString(), PreviewAvailability);
        Xunit.Assert.Equal(
            root.GetProperty("ownerProduct").GetString(),
            root.GetProperty("resourceRef").GetProperty("ownerProduct").GetString());
    }

    [Xunit.Theory]
    [Xunit.InlineData("provenance-user-created.json", "user_created")]
    [Xunit.InlineData("provenance-product-activity.json", "product_activity")]
    [Xunit.InlineData("provenance-cloud-task.json", "cloud_task")]
    [Xunit.InlineData("provenance-automation.json", "automation")]
    [Xunit.Trait("Category", "Contract")]
    public void EachProvenanceBranchDeclaresItsKindAndOnlyItsOwnFields(string fileName, string kind)
    {
        using var document = Parse(fileName);
        var root = document.RootElement;

        Xunit.Assert.Equal(kind, root.GetProperty("kind").GetString());
        Xunit.Assert.Contains(kind, ProvenanceKinds);

        string[] allowed = kind switch
        {
            "user_created" => ["kind"],
            "product_activity" => ["kind", "activityId"],
            "cloud_task" => ["kind", "taskId", "runId", "stepId"],
            "automation" => ["kind", "automationId", "automationRunId"],
            _ => throw new Xunit.Sdk.XunitException($"Unexpected provenance kind '{kind}'."),
        };

        foreach (var name in root.EnumerateObject().Select(property => property.Name))
        {
            Xunit.Assert.Contains(name, allowed);
        }
    }

    [Xunit.Theory]
    [Xunit.MemberData(nameof(GoldenFiles))]
    [Xunit.Trait("Category", "Contract")]
    public void EveryIdentityIsABareScalarNeverAWrapperObject(string fileName)
    {
        // The single most damaging shape regression available here: a strongly typed identity leaking its
        // wrapper. Every property whose name ends in "Id" is checked wherever it appears in the document.
        using var document = Parse(fileName);
        Assert(document.RootElement);

        static void Assert(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        if (property.Name.EndsWith("Id", StringComparison.Ordinal))
                        {
                            Xunit.Assert.True(
                                property.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number,
                                $"'{property.Name}' is {property.Value.ValueKind}; identities are bare scalars.");
                        }

                        Assert(property.Value);
                    }

                    break;

                case JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray())
                    {
                        Assert(item);
                    }

                    break;

                default:
                    break;
            }
        }
    }

    [Xunit.Theory]
    [Xunit.MemberData(nameof(GoldenFiles))]
    [Xunit.Trait("Category", "Contract")]
    public void EveryRevisionAndSequenceIsABareNumber(string fileName)
    {
        using var document = Parse(fileName);
        Assert(document.RootElement);

        static void Assert(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        if (property.Name is "revision" or "newRevision" or "projectionWatermark")
                        {
                            Xunit.Assert.Equal(JsonValueKind.Number, property.Value.ValueKind);
                        }

                        Assert(property.Value);
                    }

                    break;

                case JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray())
                    {
                        Assert(item);
                    }

                    break;

                default:
                    break;
            }
        }
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void PublicPagingDoesNotExposeAHasMoreFlag()
    {
        // Two ways of stating "there is more" drift apart, so the public page carries only the cursor.
        using var cursorPage = Parse("cursor-page.json");
        Xunit.Assert.False(cursorPage.RootElement.TryGetProperty("hasMore", out _));
        Xunit.Assert.True(cursorPage.RootElement.TryGetProperty("serverTimeUtc", out _));

        // The local page is the LocalRpc-only shape and does carry it.
        using var localPage = Parse("local-page.json");
        Xunit.Assert.True(localPage.RootElement.TryGetProperty("hasMore", out _));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnErrorCarriesAStableCodeAndALocalisationKeyRatherThanProse()
    {
        using var document = Parse("arc-error.json");
        var root = document.RootElement;

        Xunit.Assert.True(root.TryGetProperty("code", out var code));
        Xunit.Assert.True(root.TryGetProperty("messageKey", out var messageKey));
        Xunit.Assert.True(root.TryGetProperty("correlationId", out _));

        // A machine code is dotted and lower-case; a message key is a key, not a sentence.
        Xunit.Assert.Matches("^[a-z0-9_]+(\\.[a-z0-9_]+)+$", code.GetString()!);
        Xunit.Assert.Matches("^[a-z0-9_]+(\\.[a-z0-9_]+)+$", messageKey.GetString()!);
    }

    [Xunit.Theory]
    [Xunit.MemberData(nameof(GoldenFiles))]
    [Xunit.Trait("Category", "Contract")]
    public void NoGoldenSampleCarriesAnAbsolutePathOrABareByteArray(string fileName)
    {
        // A reference exists so that paths and bytes never cross a boundary. This is the negative check.
        var text = File.ReadAllText(Path.Combine(GoldenRoot.Value, fileName));

        Xunit.Assert.DoesNotContain("C:\\\\", text, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("file://", text, StringComparison.OrdinalIgnoreCase);
        Xunit.Assert.DoesNotContain("\"bytes\"", text, StringComparison.OrdinalIgnoreCase);
        Xunit.Assert.DoesNotContain("\"base64\"", text, StringComparison.OrdinalIgnoreCase);
    }

    private static JsonDocument Parse(string fileName) =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(GoldenRoot.Value, fileName)));

    private static string Locate()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ArcForges.slnx")))
        {
            directory = directory.Parent;
        }

        var root = directory?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
        return Path.Combine(root, "tests", "ContractCompatibilityTests", "golden", "foundation", "v1");
    }
}
