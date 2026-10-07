// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using System.Text.Json;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Host;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>
/// Local diagnostic composition over the production launcher. Approval keys and exact pins come from an explicit
/// operator/application configuration, never from the downloaded helper or its native manifests. No launch bypass exists here.
/// </summary>
internal sealed class ProductionContainmentHarness
{
    internal ContentSandboxLaunchOptions Options { get; }

    internal string SourceCommit { get; }

    internal string Rid { get; }

    internal string PackageVersion { get; }

    private ProductionContainmentHarness(ContentSandboxLaunchOptions options, string source, string rid, string version)
    {
        Options = options;
        SourceCommit = source;
        Rid = rid;
        PackageVersion = version;
    }

    internal static ProductionContainmentHarness FromOperatorConfiguration(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is 0 or > 8192) { throw new InvalidDataException("The operator configuration exceeds its bound."); }
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        Fields(root, "schemaVersion", "helperPath", "helperSha256", "nativeDirectory", "runtimeRoot", "rid", "packageVersion", "sourceCommit", "approvedPublisherKeys", "libraries");
        if (root.GetProperty("schemaVersion").GetInt32() != 1) { throw new InvalidDataException("Unknown operator configuration schema."); }
        var helper = CanonicalPath(root, "helperPath");
        var native = CanonicalPath(root, "nativeDirectory");
        var runtime = CanonicalPath(root, "runtimeRoot");
        var source = String(root, "sourceCommit");
        var rid = String(root, "rid");
        var version = String(root, "packageVersion");
        var digest = String(root, "helperSha256");
        if (digest.Length != 64 || digest.Any(value => !char.IsAsciiHexDigitLower(value)))
        {
            throw new InvalidDataException("The operator must select an exact helper digest.");
        }

        var keys = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal);
        var keyArray = root.GetProperty("approvedPublisherKeys");
        if (keyArray.ValueKind != JsonValueKind.Array || keyArray.GetArrayLength() is < 1 or > 4)
        {
            throw new InvalidDataException("The operator must supply a bounded approved publisher key set.");
        }

        foreach (var row in keyArray.EnumerateArray())
        {
            Fields(row, "keyId", "spki");
            var spki = Convert.FromBase64String(String(row, "spki"));
            if (spki.Length > 512 || !keys.TryAdd(String(row, "keyId"), spki)) { throw new InvalidDataException("Duplicate or oversized publisher key."); }
        }

        var libraries = new List<ContentSandboxNativeRelease>();
        var libraryArray = root.GetProperty("libraries");
        if (libraryArray.ValueKind != JsonValueKind.Array || libraryArray.GetArrayLength() != 2)
        {
            throw new InvalidDataException("Exactly two production native families are required.");
        }

        foreach (var row in libraryArray.EnumerateArray())
        {
            Fields(row, "library", "profileSha256", "manifestSha256");
            libraries.Add(new ContentSandboxNativeRelease(String(row, "library"), String(row, "profileSha256"), String(row, "manifestSha256")));
        }

        var trust = new ContentSandboxReleaseTrust(native, rid, version, source, keys, libraries);
        return new ProductionContainmentHarness(new ContentSandboxLaunchOptions
        {
            HelperPath = helper,
            HelperSha256 = Convert.FromHexString(digest),
            ParserProfile = ProductionParserProfile.ProfileId,
            ReleaseTrust = trust,
            RuntimeRoot = runtime,
            Limits = new Contracts.ContentSandboxLimits { TimeoutMs = 10000, MaxWidth = 4096, MaxHeight = 4096 },
            SlotCapacityBytes = 1024 * 1024,
            LaunchTimeout = TimeSpan.FromSeconds(60),
        }, source, rid, version);
    }

    internal static ProductionContainmentHarness ReadOperatorConfiguration(string path)
    {
        // Read exactly a bounded snapshot, with writes refused for its whole acquisition.
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is 0 or > 8192) { throw new InvalidDataException("The operator configuration exceeds its bound."); }
        var bytes = new byte[checked((int)file.Length)];
        file.ReadExactly(bytes);
        if (file.ReadByte() != -1) { throw new InvalidDataException("The operator configuration changed during acquisition."); }
        return FromOperatorConfiguration(bytes);
    }

    internal void Evidence(string scenario, ContentSandboxInvocation invocation)
    {
        if (scenario.Length > 256 || scenario.Any(value => value is < ' ' or > '~'))
        {
            throw new ArgumentException("Scenario evidence must be bounded ASCII.", nameof(scenario));
        }

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("scenario", scenario);
            writer.WriteString("sourceCommit", SourceCommit);
            writer.WriteString("rid", Rid);
            writer.WriteString("packageVersion", PackageVersion);
            writer.WriteString("helperSha256", Convert.ToHexStringLower(Options.HelperSha256.Span));
            writer.WriteNumber("helperPid", invocation.HelperProcess.ProcessId);
            writer.WriteNumber("parentPid", Environment.ProcessId);
            var os = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
            writer.WriteString("os", os.Length > 512 ? os[..512] : os);
            writer.WriteString("evidenceClass", "actual-authenticated-helper-operation");
            writer.WriteString("limitation", "Only the reported operation on this installed cohort; no unexecuted RID or whole-series acceptance.");
            writer.WriteEndObject();
        }

        Console.Error.WriteLine("[production-containment] " + Encoding.UTF8.GetString(stream.ToArray()));
    }

    private static void Fields(JsonElement value, params string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object) { throw new InvalidDataException("An operator configuration object is required."); }
        var fields = value.EnumerateObject().Select(property => property.Name).ToArray();
        if (fields.Length != expected.Length || fields.Distinct(StringComparer.Ordinal).Count() != fields.Length
            || !fields.ToHashSet(StringComparer.Ordinal).SetEquals(expected))
        {
            throw new InvalidDataException("Operator configuration fields are missing, duplicate or unknown.");
        }
    }

    private static string String(JsonElement value, string name) => value.GetProperty(name).GetString()
        ?? throw new InvalidDataException("An operator configuration string is required.");

    private static string CanonicalPath(JsonElement value, string name)
    {
        var path = String(value, name);
        if (!Path.IsPathFullyQualified(path) || Path.GetFullPath(path) != path)
        {
            throw new InvalidDataException("Installation paths must be explicit and canonical.");
        }

        return path;
    }
}
