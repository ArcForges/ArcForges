// SPDX-License-Identifier: AGPL-3.0-only

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using ArcForges.Contracts.Foundation;

namespace ArcForges.Tests.ContractCompatibilityTests;

/// <summary>
/// The committed canonical JSON samples for Foundation wire types, and how they are located.
/// </summary>
/// <remarks>
/// <para>
/// A golden sample is the contract stated as bytes. The C# type can be refactored freely as long as the
/// bytes do not move; when they do move, the diff on these files is the wire change, visible in review.
/// </para>
/// <para>
/// The files live under this test project rather than in <c>contracts/</c> so they sit beside the baseline
/// contract packages Step 02.05 introduces at <c>tests/ContractCompatibilityTests/baselines/</c>.
/// <c>ArcForges.Tests.ContractSchemaTests</c> reads the same files to assert their shape independently of
/// the C# types.
/// </para>
/// </remarks>
internal static class FoundationGolden
{
    private static readonly Lazy<string> Root = new(Locate);

    /// <summary>Every golden sample: file name without extension, and the value it must serialise to.</summary>
    internal static IEnumerable<(string Name, object Value, JsonTypeInfo TypeInfo)> All()
    {
        yield return ("arc-error", FoundationFixtures.Error(), Strict<ArcError>());
        yield return ("resource-ref-local", FoundationFixtures.LocalResource(), Strict<ResourceRef>());
        yield return ("resource-ref-cloud", FoundationFixtures.CloudResource(), Strict<ResourceRef>());
        yield return ("local-resource-locator", FoundationFixtures.Locator(), Strict<LocalResourceLocator>());
        yield return ("artifact-ref", FoundationFixtures.Artifact(), Strict<ArtifactRef>());
        yield return ("provenance-user-created", FoundationFixtures.UserCreated(), Strict<ArtifactProvenance>());
        yield return ("provenance-product-activity", FoundationFixtures.ProductActivity(), Strict<ArtifactProvenance>());
        yield return ("provenance-cloud-task", FoundationFixtures.CloudTask(), Strict<ArtifactProvenance>());
        yield return ("provenance-automation", FoundationFixtures.Automation(), Strict<ArtifactProvenance>());
        yield return ("arc-result-ok", FoundationFixtures.SuccessResult(), Strict<ArcResult<ResourceRef>>());
        yield return ("arc-result-failure", FoundationFixtures.FailureResult(), Strict<ArcResult<ResourceRef>>());
        yield return ("local-page-query", FoundationFixtures.PageQuery(), Strict<LocalPageQuery>());
        yield return ("local-page", FoundationFixtures.LocalPage(), Strict<LocalPage<ResourceRef>>());
        yield return ("cursor-page", FoundationFixtures.CursorPage(), Strict<CursorPageDto<ResourceRef>>());
    }

    internal static JsonTypeInfo<T> Strict<T>() =>
        (JsonTypeInfo<T>)FoundationJsonContext.Default.GetTypeInfo(typeof(T))!;

    internal static JsonTypeInfo<T> Inbound<T>() =>
        (JsonTypeInfo<T>)FoundationInboundJsonContext.Default.GetTypeInfo(typeof(T))!;

    internal static string Path(string name) =>
        System.IO.Path.Combine(Root.Value, name + ".json");

    /// <summary>
    /// The committed bytes, with any trailing newline removed.
    /// </summary>
    /// <remarks>
    /// The repository normalises text to LF on checkout, and an editor may add a final newline. Trimming the
    /// trailing whitespace keeps the assertion about the JSON itself rather than about file conventions; the
    /// JSON is emitted un-indented so there is no interior whitespace to lose.
    /// </remarks>
    internal static string Read(string name) =>
        File.ReadAllText(Path(name), Encoding.UTF8).TrimEnd('\r', '\n');

    internal static void Write(string name, string json) =>
        File.WriteAllText(Path(name), json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

    internal static bool Exists(string name) => File.Exists(Path(name));

    internal static string Serialize(object value, JsonTypeInfo typeInfo) =>
        JsonSerializer.Serialize(value, typeInfo);

    private static string Locate()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(System.IO.Path.Combine(directory.FullName, "ArcForges.slnx")))
        {
            directory = directory.Parent;
        }

        var root = directory?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
        return System.IO.Path.Combine(root, "tests", "ContractCompatibilityTests", "golden", "foundation", "v1");
    }
}
