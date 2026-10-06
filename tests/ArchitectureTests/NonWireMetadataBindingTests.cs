// SPDX-License-Identifier: AGPL-3.0-only

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>Actual shared engine enforcement of source identity, immutable shape and non-transport use.</summary>
public sealed class NonWireMetadataBindingTests
{
    private const string Policy = """
        using System;
        using System.Collections.Generic;
        using System.Linq;
        namespace Metadata;
        public sealed class Policy
        {
            public Policy(IEnumerable<string> actors)
            {
                var snapshot = actors.ToArray();
                ActorKinds = Array.AsReadOnly(snapshot);
                PatScopes = Array.AsReadOnly(new[] { "read" });
            }
            public string OperationId { get; } = "read";
            public string Binding { get; } = "public/Read";
            public string Surface => "public";
            public string Scope { get; } = "assistant";
            public string Idempotency { get; } = "Q";
            public string Profile { get; } = "human-owner";
            public string SourceRule { get; } = "owned#rule";
            public string? Capability { get; }
            public string? Risk { get; } = "R1";
            public string? RiskSource { get; }
            public string Approval { get; } = "none";
            public bool? StepUp { get; } = false;
            public string? StepUpSource { get; }
            public bool? LocalPresence { get; } = false;
            public string? LocalPresenceSource { get; }
            public string Egress { get; } = "none";
            public bool PatEligible { get; } = true;
            public IReadOnlyList<string> PatScopes { get; }
            public IReadOnlyList<string> ActorKinds { get; }
        }
        """;
    private const string Catalog = """
        using System;
        using System.Collections.Generic;
        using System.Collections.Frozen;
        namespace Metadata;
        public static class Catalog
        {
            public static IReadOnlyList<Policy> All { get; } = Array.AsReadOnly<Policy>([new(new[] { "human" })]);
            private static readonly FrozenDictionary<string, Policy> ById = All.ToFrozenDictionary(operation => operation.OperationId, StringComparer.Ordinal);
            public static bool TryGet(string operationId, out Policy? policy)
            {
                ArgumentNullException.ThrowIfNull(operationId);
                return ById.TryGetValue(operationId, out policy);
            }
        }
        """;

    [Xunit.Fact]
    public void OnlyExactReviewedImmutablePolicyAndCatalogAreAdmitted()
    {
        using var fixture = new Fixture();
        Xunit.Assert.Empty(fixture.Check());
        Xunit.Assert.Equal(2, fixture.Bindings.Count);
    }

    [Xunit.Fact]
    public void MissingBindingsPreserveDefaultGeneratedWireEnforcement()
    {
        using var fixture = new Fixture();
        fixture.Bindings.Clear();
        Xunit.Assert.Equal(2, fixture.Check().Length);
    }

    [Xunit.Theory]
    [Xunit.InlineData("hash")]
    [Xunit.InlineData("symbol")]
    [Xunit.InlineData("project")]
    [Xunit.InlineData("path")]
    [Xunit.InlineData("traversal")]
    [Xunit.InlineData("kind")]
    [Xunit.InlineData("duplicate")]
    [Xunit.InlineData("wire-binding")]
    public void WrongOrAmbiguousBindingNeverCreatesAnExemption(string mutation)
    {
        using var fixture = new Fixture();
        var original = fixture.Bindings[0];
        fixture.Bindings[0] = mutation switch
        {
            "hash" => original with { SourceSha256 = new string('0', 64) },
            "symbol" => original with { TypeSymbol = "Metadata.Absent" },
            "project" => original with { ProjectPath = "elsewhere/subject.csproj" },
            "path" => original with { SourcePath = "subject/Catalog.cs" },
            "traversal" => original with { SourcePath = "subject/../subject/Policy.cs" },
            "kind" => original with { Kind = (NonWireMetadataKind)99 },
            _ => original,
        };
        if (mutation == "duplicate") fixture.Bindings.Add(original);
        if (mutation == "wire-binding") fixture.WireBindings.Add(new("Metadata.Policy", "message.proto", fixture.SchemaHash));
        Xunit.Assert.NotEmpty(fixture.Check());
    }

    [Xunit.Fact]
    public void DiskAndCompilerSnapshotMustBothMatchReviewedSource()
    {
        using var fixture = new Fixture();
        File.AppendAllText(fixture.PolicyPath, "\n// changed after compilation\n");
        fixture.Bindings[0] = fixture.Bindings[0] with { SourceSha256 = Hash(File.ReadAllText(fixture.PolicyPath)) };
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("source binding", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void CompilationSourceMustBeOwnedAndQualifiedSymbolMustBeUnambiguous()
    {
        using (var foreign = new Fixture())
        {
            foreign.RemovePolicyOwnership();
            Xunit.Assert.Contains(foreign.Check(), finding => finding.Message.Contains("source binding", StringComparison.Ordinal));
        }
        using var duplicate = new Fixture();
        duplicate.AddDuplicate();
        Xunit.Assert.Contains(duplicate.Check(), finding => finding.Message.Contains("ambiguous", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void Utf8BomAndCrLfNormalizeWithoutIgnoringOtherContent()
    {
        using var fixture = new Fixture();
        File.WriteAllText(fixture.PolicyPath, "\uFEFF" + Policy.Replace("\n", "\r\n", StringComparison.Ordinal), new UTF8Encoding(false));
        Xunit.Assert.Empty(fixture.Check());
    }

    [Xunit.Theory]
    [Xunit.InlineData("setter")]
    [Xunit.InlineData("extra")]
    [Xunit.InlineData("field")]
    [Xunit.InlineData("borrowed")]
    [Xunit.InlineData("partial")]
    [Xunit.InlineData("interface")]
    [Xunit.InlineData("serializer")]
    [Xunit.InlineData("wrong-surface")]
    [Xunit.InlineData("mutable-actor")]
    [Xunit.InlineData("escaped-snapshot")]
    [Xunit.InlineData("stored-snapshot")]
    public void ReviewedHashDoesNotAdmitMutableArbitraryOrSerializedShapes(string mutation)
    {
        string source = mutation switch
        {
            "setter" => Policy.Replace("OperationId { get; }", "OperationId { get; set; }", StringComparison.Ordinal),
            "extra" => Policy.Replace("public sealed class Policy\n{", "public sealed class Policy\n{\n public object Extra { get; } = new();", StringComparison.Ordinal),
            "field" => Policy.Replace("public sealed class Policy\n{", "public sealed class Policy\n{\n private readonly string[] retained = [];", StringComparison.Ordinal),
            "borrowed" => Policy.Replace("var snapshot = actors.ToArray();", "var snapshot = (string[])actors;", StringComparison.Ordinal),
            "partial" => Policy.Replace("sealed class", "sealed partial class", StringComparison.Ordinal),
            "interface" => Policy.Replace("public sealed class Policy", "public sealed class Policy : ICloneable", StringComparison.Ordinal)
                .Replace("public string OperationId", "public object Clone() => this;\npublic string OperationId", StringComparison.Ordinal),
            "serializer" => Policy.Replace("public string OperationId", "[System.Text.Json.Serialization.JsonPropertyName(\"operation\")] public string OperationId", StringComparison.Ordinal),
            "wrong-surface" => Policy.Replace("Surface => \"public\"", "Surface => \"operator\"", StringComparison.Ordinal),
            "mutable-actor" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "ActorKinds = snapshot;", StringComparison.Ordinal),
            "escaped-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "ActorKinds = Array.AsReadOnly(snapshot);\n Escape(snapshot);", StringComparison.Ordinal)
                .Replace("public string OperationId", "private static void Escape(string[] value) {}\npublic string OperationId", StringComparison.Ordinal),
            "stored-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "ActorKinds = Array.AsReadOnly(snapshot);\n External.Value = snapshot;", StringComparison.Ordinal)
                + "\ninternal static class External { public static object? Value; }",
            _ => throw new ArgumentException("Unknown fixture mutation.", nameof(mutation)),
        };
        using var fixture = new Fixture(source);
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains(mutation == "partial" ? "source binding" : "closed immutable", StringComparison.Ordinal));
    }

    [Xunit.Theory]
    [Xunit.InlineData("mutable-list")]
    [Xunit.InlineData("comparer")]
    [Xunit.InlineData("stub")]
    [Xunit.InlineData("extra-method")]
    public void CatalogRequiresImmutableStorageOrdinalKeysAndActualLookup(string mutation)
    {
        string source = mutation switch
        {
            "mutable-list" => Catalog.Replace("Array.AsReadOnly<Policy>([new(new[] { \"human\" })])", "new Policy[] { new(new[] { \"human\" }) }", StringComparison.Ordinal),
            "comparer" => Catalog.Replace("StringComparer.Ordinal", "StringComparer.OrdinalIgnoreCase", StringComparison.Ordinal),
            "stub" => Catalog.Replace("return ById.TryGetValue(operationId, out policy);", "policy = All[0]; return true;", StringComparison.Ordinal),
            "extra-method" => Catalog.Replace("public static bool TryGet", "public static void Register(Policy value) {}\npublic static bool TryGet", StringComparison.Ordinal),
            _ => throw new ArgumentException("Unknown fixture mutation.", nameof(mutation)),
        };
        using var fixture = new Fixture(catalog: source);
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("canonical immutable", StringComparison.Ordinal));
    }

    [Xunit.Theory]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize<object>(Catalog.All[0]);")]
    [Xunit.InlineData("object value = Catalog.All[0]; return System.Text.Json.JsonSerializer.Serialize(value);")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize((object)Catalog.All[0]);")]
    [Xunit.InlineData("var values = Catalog.All.Select(policy => (object)policy).ToArray(); return System.Text.Json.JsonSerializer.Serialize(values);")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(System.Threading.Tasks.Task.FromResult<object>(Catalog.All[0]));")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(new Wrapper(Catalog.All[0]));")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(Box(Catalog.All[0]));")]
    [Xunit.InlineData("object[] values = [Catalog.All[0]]; return System.Text.Json.JsonSerializer.Serialize(values);")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(new { Value = (object)Catalog.All[0] });")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(Iterate());")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(AsyncBox());")]
    public void ErasedScalarCollectionFactoryAndWrapperMetadataCannotBeSerialized(string body)
    {
        string extra = """
            using System;
            using System.Linq;
            using Metadata;
            internal static class Sender
            {
                private static object Box(object value) => value;
                private static System.Collections.Generic.IEnumerable<object> Iterate() { yield return Catalog.All[0]; }
                private static async System.Threading.Tasks.Task<object> AsyncBox() { await System.Threading.Tasks.Task.Yield(); return Catalog.All[0]; }
                private static string Send() { BODY }
            }
            internal sealed class Wrapper
            {
                public Wrapper(object value) { Value = value; }
                public object Value { get; }
            }
            """.Replace("BODY", body, StringComparison.Ordinal);
        using var fixture = new Fixture(extra: extra);
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void CanonicalScalarProjectionRemainsAllowed()
    {
        using var fixture = new Fixture(extra: "using System.Linq; using Metadata; internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize(Catalog.All.Select(policy => policy.OperationId).ToArray()); }");
        Xunit.Assert.Empty(fixture.Check());
    }

    [Xunit.Fact]
    public void SerializerTypeRegistrationAndGeneratedWirePropertyAreRejected()
    {
        using (var registration = new Fixture(extra: "[System.Text.Json.Serialization.JsonSerializable(typeof(Metadata.Policy))] internal class Context {}"))
            Xunit.Assert.Contains(registration.Check(), finding => finding.Message.Contains("serializer payload", StringComparison.Ordinal));
        using var wire = new Fixture(extra: "// <auto-generated/>\npublic sealed class Wire { public Metadata.Policy? Value { get; set; } }");
        wire.WireBindings.Add(new("Wire", "message.proto", wire.SchemaHash));
        Xunit.Assert.Contains(wire.Check(), finding => finding.Message.Contains("wire/RPC", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void RpcObjectArgumentDoesNotHideMetadata()
    {
        using var fixture = new Fixture(rpc: "using Metadata; public sealed class Rpc { public void Send(object value) {} private void Invoke() { object value = Catalog.All[0]; Send(value); } }");
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Path.StartsWith("rpc/", StringComparison.Ordinal) && finding.Message.Contains("escapes through", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void ErasedCollectionCannotEnterActualHttpJsonTransport()
    {
        using var fixture = new Fixture(extra: "using System.Linq; using System.Net.Http.Json; using Metadata; internal static class Sender { private static object Send() => new System.Net.Http.HttpClient().PostAsJsonAsync(\"https://invalid.example\", Catalog.All.Select(policy => (object)policy).ToArray()); }");
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void FakeSameNameSerializerIsNotAFrameworkSink()
    {
        using var fixture = new Fixture(extra: "using Metadata; internal static class JsonSerializer { public static string Serialize<T>(T value) => \"fixture\"; } internal static class Sender { private static string Send() => JsonSerializer.Serialize<object>(Catalog.All[0]); }");
        Xunit.Assert.Empty(fixture.Check());
    }

    [Xunit.Fact]
    public void AliasAnalysisExhaustionFailsClosedInsteadOfAcceptingTransport()
    {
        var body = new StringBuilder("using Metadata; internal static class Sender { private static string Send() { object value0 = Catalog.All[0];");
        for (int index = 1; index <= 140; index++) body.Append("object value").Append(index).Append(" = value").Append(index - 1).Append(';');
        body.Append("return System.Text.Json.JsonSerializer.Serialize(value140); } }");
        using var fixture = new Fixture(extra: body.ToString());
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
    }

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text.TrimStart('\uFEFF').Replace("\r\n", "\n", StringComparison.Ordinal))));

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "arcforges-metadata-" + Guid.NewGuid().ToString("N"));
        private readonly List<ProjectFacts> _projects = [];
        private readonly Dictionary<string, CSharpCompilation> _compilations = new(StringComparer.Ordinal);
        public List<NonWireMetadataBinding> Bindings { get; } = [];
        public List<WireTypeBinding> WireBindings { get; } = [];
        public string PolicyPath => Path.Combine(_root, "subject", "Policy.cs");
        public string SchemaHash { get; }
        public void RemovePolicyOwnership() => _projects[0] = _projects[0] with
        {
            Sources = _projects[0].Sources.Where(path => path != PolicyPath).ToArray(),
        };
        public void AddDuplicate() => _ = Add("duplicate", ProjectRole.Contracts,
            new Dictionary<string, string>(StringComparer.Ordinal) { ["Policy.cs"] = Policy, ["Catalog.cs"] = Catalog });
        public Fixture(string policy = Policy, string catalog = Catalog, string? extra = null, string? rpc = null)
        {
            Directory.CreateDirectory(_root);
            File.WriteAllText(Path.Combine(_root, "global.json"), "{}");
            File.WriteAllText(Path.Combine(_root, "message.proto"), "syntax = \"proto3\"; message Wire { string value = 1; }");
            SchemaHash = Hash(File.ReadAllText(Path.Combine(_root, "message.proto")));
            var sources = new Dictionary<string, string>(StringComparer.Ordinal) { ["Policy.cs"] = policy, ["Catalog.cs"] = catalog };
            if (extra is not null) sources.Add("Extra.cs", extra);
            var subject = Add("subject", ProjectRole.Contracts, sources);
            Bindings.Add(new("Metadata.Policy", "subject/subject.csproj", "subject/Policy.cs", Hash(policy), NonWireMetadataKind.OperationAuthorizationPolicy));
            Bindings.Add(new("Metadata.Catalog", "subject/subject.csproj", "subject/Catalog.cs", Hash(catalog), NonWireMetadataKind.OperationAuthorizationCatalog));
            if (rpc is not null) _ = Add("rpc", ProjectRole.PublicApiAdapter, new Dictionary<string, string>(StringComparer.Ordinal) { ["Rpc.cs"] = rpc }, subject);
        }
        private CSharpCompilation Add(string name, ProjectRole role, Dictionary<string, string> files, CSharpCompilation? reference = null)
        {
            string directory = Path.Combine(_root, name);
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, name + ".csproj"), "<Project />");
            File.WriteAllText(Path.Combine(directory, "packages.lock.json"), JsonSerializer.Serialize(new { version = 1, dependencies = new Dictionary<string, object> { ["net10.0"] = new { } } }));
            var sourcePaths = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var file in files)
            {
                string path = Path.Combine(directory, file.Key);
                File.WriteAllText(path, file.Value);
                sourcePaths.Add(path, file.Value);
            }
            var compilation = FixtureCompiler.Create(name, sourcePaths);
            if (reference is not null) compilation = compilation.AddReferences(reference.ToMetadataReference());
            using var image = new MemoryStream();
            var emit = compilation.Emit(image);
            if (!emit.Success) throw new InvalidOperationException(string.Join("\n", emit.Diagnostics.Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error)));
            string projectPath = name + "/" + name + ".csproj";
            _compilations.Add(projectPath, compilation);
            _projects.Add(new ProjectFacts(new ProjectClassification(projectPath, role, "DesktopPlatform"), "net10.0", "Library", "AGPL-3.0-only", "AGPL", [], sourcePaths.Keys.ToArray(), [],
                new Dictionary<string, string>(StringComparer.Ordinal) { ["ManagePackageVersionsCentrally"] = "true", ["RestorePackagesWithLockFile"] = "true" },
                new Dictionary<string, string>(StringComparer.Ordinal)));
            return compilation;
        }
        public PolicyFinding[] Check() => PolicyEngine.Check(new RepositoryFacts(_root, "DesktopPlatform", _projects, [], []),
            new RepositoryPolicyConfiguration(new string('a', 40), new Dictionary<string, string>(StringComparer.Ordinal) { ["global.json"] = Hash("{}") },
                new Dictionary<string, string>(StringComparer.Ordinal), new HashSet<string>(StringComparer.Ordinal), [], WireBindings, [], NonWireMetadataBindings: Bindings),
            _compilations, new DateOnly(2026, 10, 6)).Where(finding => finding.Rule == "AT-12").ToArray();
        public void Dispose() => Directory.Delete(_root, recursive: true);
    }
}
