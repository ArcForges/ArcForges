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
    [Xunit.InlineData("cast-snapshot")]
    [Xunit.InlineData("parenthesized-snapshot")]
    [Xunit.InlineData("collection-snapshot")]
    [Xunit.InlineData("cast-alias")]
    [Xunit.InlineData("arrow-snapshot")]
    [Xunit.InlineData("return-snapshot")]
    [Xunit.InlineData("tuple-snapshot")]
    [Xunit.InlineData("struct-snapshot")]
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
            "cast-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "Escape((object)snapshot); ActorKinds = Array.AsReadOnly(snapshot);", StringComparison.Ordinal)
                .Replace("public string OperationId", "private static void Escape(object value) {}\npublic string OperationId", StringComparison.Ordinal),
            "parenthesized-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "Escape(((snapshot))); ActorKinds = Array.AsReadOnly(snapshot);", StringComparison.Ordinal)
                .Replace("public string OperationId", "private static void Escape(object value) {}\npublic string OperationId", StringComparison.Ordinal),
            "collection-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "Escape(new object[] { snapshot }); ActorKinds = Array.AsReadOnly(snapshot);", StringComparison.Ordinal)
                .Replace("public string OperationId", "private static void Escape(object value) {}\npublic string OperationId", StringComparison.Ordinal),
            "cast-alias" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "var alias = (string[])snapshot; ActorKinds = Array.AsReadOnly(snapshot);", StringComparison.Ordinal),
            "arrow-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "object Borrow() => (object)snapshot; External.Value = Borrow(); ActorKinds = Array.AsReadOnly(snapshot);", StringComparison.Ordinal)
                + "\ninternal static class External { public static object? Value; }",
            "return-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "object Borrow() { return (object)snapshot; } External.Value = Borrow(); ActorKinds = Array.AsReadOnly(snapshot);", StringComparison.Ordinal)
                + "\ninternal static class External { public static object? Value; }",
            "tuple-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "Escape((snapshot, 0)); ActorKinds = Array.AsReadOnly(snapshot);", StringComparison.Ordinal)
                .Replace("public string OperationId", "private static void Escape(object value) {}\npublic string OperationId", StringComparison.Ordinal),
            "struct-snapshot" => Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "Escape(new Carrier { Value = snapshot }); ActorKinds = Array.AsReadOnly(snapshot);", StringComparison.Ordinal)
                .Replace("public string OperationId", "private static void Escape(object value) {}\npublic string OperationId", StringComparison.Ordinal)
                + "\ninternal struct Carrier { public object Value; }",
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
    [Xunit.InlineData("static-constructor")]
    [Xunit.InlineData("static-all")]
    public void CatalogRequiresImmutableStorageOrdinalKeysAndActualLookup(string mutation)
    {
        string source = mutation switch
        {
            "mutable-list" => Catalog.Replace("Array.AsReadOnly<Policy>([new(new[] { \"human\" })])", "new Policy[] { new(new[] { \"human\" }) }", StringComparison.Ordinal),
            "comparer" => Catalog.Replace("StringComparer.Ordinal", "StringComparer.OrdinalIgnoreCase", StringComparison.Ordinal),
            "stub" => Catalog.Replace("return ById.TryGetValue(operationId, out policy);", "policy = All[0]; return true;", StringComparison.Ordinal),
            "extra-method" => Catalog.Replace("public static bool TryGet", "public static void Register(Policy value) {}\npublic static bool TryGet", StringComparison.Ordinal),
            "static-constructor" => Catalog.Replace("public static bool TryGet", "static Catalog() { ById = All.ToFrozenDictionary(operation => operation.OperationId, StringComparer.OrdinalIgnoreCase); }\npublic static bool TryGet", StringComparison.Ordinal),
            "static-all" => Catalog.Replace("public static bool TryGet", "static Catalog() { All = Array.AsReadOnly<Policy>([]); }\npublic static bool TryGet", StringComparison.Ordinal),
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
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(new InitializedWrapper());")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(new GetterWrapper());")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(new ArrowGetterWrapper());")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(new GetterWrapper().Value);")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(new ArrowGetterWrapper().Value);")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(Catalog.All.Cast<object>().Select(value => value).ToArray());")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(System.Linq.Enumerable.Select(Catalog.All.Cast<object>(), value => value).ToArray());")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(Catalog.All.Cast<object>().Select(Identity).ToArray());")]
    [Xunit.InlineData("return System.Text.Json.JsonSerializer.Serialize(((object)Catalog.All[0], 0));")]
    public void ErasedScalarCollectionFactoryAndWrapperMetadataCannotBeSerialized(string body)
    {
        string extra = """
            using System;
            using System.Linq;
            using Metadata;
            internal static class Sender
            {
                private static object Box(object value) => value;
                private static object Identity(object value) => value;
                private static System.Collections.Generic.IEnumerable<object> Iterate() { yield return Catalog.All[0]; }
                private static async System.Threading.Tasks.Task<object> AsyncBox() { await System.Threading.Tasks.Task.Yield(); return Catalog.All[0]; }
                private static string Send() { BODY }
            }
            internal sealed class Wrapper
            {
                public Wrapper(object value) { Value = value; }
                public object Value { get; }
            }
            internal sealed class InitializedWrapper { public object Value { get; } = Catalog.All[0]; }
            internal sealed class GetterWrapper { public object Value { get { return Catalog.All[0]; } } }
            internal sealed class ArrowGetterWrapper { public object Value { get => Catalog.All[0]; } }
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

    [Xunit.Theory]
    [Xunit.InlineData("(object)Catalog.All[0].StepUp")]
    [Xunit.InlineData("Catalog.All.Select(policy => policy.StepUp).ToArray()")]
    [Xunit.InlineData("(object)Catalog.All[0].ActorKinds")]
    [Xunit.InlineData("Catalog.All.Select(policy => policy.ActorKinds.ToArray()).ToArray()")]
    [Xunit.InlineData("Catalog.All.Select(policy => policy.PatScopes).ToArray()")]
    public void ExactNullablePrimitiveAndApprovedStringListFactsRemainUsable(string value)
    {
        using var fixture = new Fixture(extra: "using System.Linq; using Metadata; internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize(" + value + "); }");
        Xunit.Assert.Empty(fixture.Check());
    }

    [Xunit.Fact]
    public void ScalarGetterProjectionRemainsAllowed()
    {
        using var fixture = new Fixture(extra: "using Metadata; internal sealed class Wrapper { public object Value { get { return Catalog.All[0].OperationId; } } } internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize(new Wrapper()); }");
        Xunit.Assert.Empty(fixture.Check());
    }

    [Xunit.Fact]
    public void ErasedScalarProjectionAndReadonlySnapshotResultsRemainAllowed()
    {
        using var fixture = new Fixture(Policy.Replace("ActorKinds = Array.AsReadOnly(snapshot);", "var count = snapshot.Length; var copy = snapshot.ToArray(); ActorKinds = Array.AsReadOnly(copy);", StringComparison.Ordinal),
            extra: "using System.Linq; using Metadata; internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize(Catalog.All.Cast<object>().Select(value => ((Policy)value).OperationId).ToArray()); }");
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

    [Xunit.Theory]
    [Xunit.InlineData("using var stream = new System.IO.MemoryStream(); new System.Xml.Serialization.XmlSerializer(typeof(object)).Serialize(stream, VALUE); return string.Empty;")]
    [Xunit.InlineData("using var stream = new System.IO.MemoryStream(); new System.Runtime.Serialization.DataContractSerializer(typeof(object)).WriteObject(stream, VALUE); return string.Empty;")]
    [Xunit.InlineData("using var stream = new System.IO.MemoryStream(); new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(object)).WriteObject(stream, VALUE); return string.Empty;")]
    [Xunit.InlineData("using var stream = new System.IO.MemoryStream(); using var writer = System.Xml.XmlDictionaryWriter.CreateTextWriter(stream); new System.Runtime.Serialization.DataContractSerializer(typeof(object)).WriteObjectContent(writer, VALUE); return string.Empty;")]
    public void ActualBclXmlAndDataContractSinksRejectMetadataButAllowScalarProjection(string body)
    {
        ArgumentNullException.ThrowIfNull(body);
        string Source(string value) => "using Metadata; internal static class Sender { private static string Send() { "
            + body.Replace("VALUE", value, StringComparison.Ordinal) + " } }";
        using (var negative = new Fixture(extra: Source("(object)Catalog.All[0]")))
            Xunit.Assert.Contains(negative.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
        using var positive = new Fixture(extra: Source("(object)Catalog.All[0].OperationId"));
        Xunit.Assert.Empty(positive.Check());
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

    [Xunit.Theory]
    [Xunit.InlineData("public static Wire Parser { get; } = new Wire(); public Wire Clone() => this;")]
    [Xunit.InlineData("private Link? Next { get; } internal sealed class Link { public Wire? Next { get; } }")]
    public void CompletedOwnedWireCyclesDoNotConsumeFreshTraversalBudget(string members)
    {
        using var fixture = new Fixture(extra: "// <auto-generated/>\npublic sealed class Wire { " + members + " }");
        fixture.WireBindings.Add(new("Wire", "message.proto", fixture.SchemaHash));
        Xunit.Assert.Empty(fixture.Check());
    }

    [Xunit.Theory]
    [Xunit.InlineData("public Wire? Next { get; } public object Value => Metadata.Catalog.All[0];")]
    [Xunit.InlineData("private Link? Next { get; } public object Value => Next!.Value; internal sealed class Link { public Wire? Next { get; } public object Value => Metadata.Catalog.All[0]; }")]
    public void ACompletedSafeCycleNeverHidesAnotherMetadataOrigin(string members)
    {
        using var fixture = new Fixture(extra: "// <auto-generated/>\npublic sealed class Wire { " + members + " }");
        fixture.WireBindings.Add(new("Wire", "message.proto", fixture.SchemaHash));
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("wire/RPC/serializer", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void FreshIndependentSemanticStatesStillExhaustTheTotalBudget()
    {
        var source = new StringBuilder("// <auto-generated/>\npublic sealed class Wire {");
        for (int index = 0; index < 66000; index++)
            source.Append("private readonly object value").Append(index).Append(" = new object();");
        source.Append('}');
        using var fixture = new Fixture(extra: source.ToString());
        fixture.WireBindings.Add(new("Wire", "message.proto", fixture.SchemaHash));
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("wire/RPC/serializer", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void DeepUnresolvedSourceAliasesStillFailClosed()
    {
        var source = new StringBuilder("internal static class Sender { private static string Send() { object value0 = new object();");
        for (int index = 1; index <= 300; index++) source.Append("object value").Append(index).Append(" = value").Append(index - 1).Append(';');
        source.Append("return System.Text.Json.JsonSerializer.Serialize(value300); } }");
        using var fixture = new Fixture(extra: source.ToString());
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
    }

    [Xunit.Theory]
    [Xunit.InlineData("(Identity(Metadata.Catalog.All[0]))", true)]
    [Xunit.InlineData("((object)Metadata.Catalog.All[0])", true)]
    [Xunit.InlineData("(Identity(new object()))", false)]
    [Xunit.InlineData("((object)new object())", false)]
    public void ParenthesizedErasedOriginsAreTraversedBeforeSemanticReuse(string payload, bool denied)
    {
        using var fixture = new Fixture(extra: "internal static class Sender { private static object Identity(object value) => value; private static string Send() => System.Text.Json.JsonSerializer.Serialize(" + payload + "); }");
        Xunit.Assert.Equal(denied, fixture.Check().Any(finding => finding.Message.Contains("escapes through", StringComparison.Ordinal)));
    }

    [Xunit.Theory]
    [Xunit.InlineData("System.Func<Metadata.Policy, object> selector = value => value;", "Metadata.Catalog.All", true)]
    [Xunit.InlineData("System.Func<object, object> selector = value => value;", "Metadata.Catalog.All.Cast<object>()", true)]
    [Xunit.InlineData("System.Func<Metadata.Policy, string> selector = value => value.OperationId;", "Metadata.Catalog.All", false)]
    public void DelegateSelectorsRequireAProvedScalarResultOrFailClosed(string declaration, string source, bool denied)
    {
        using var fixture = new Fixture(extra: "using System.Linq; internal static class Sender { private static string Send() { " + declaration + " return System.Text.Json.JsonSerializer.Serialize(" + source + ".Select(selector)); } }");
        Xunit.Assert.Equal(denied, fixture.Check().Any(finding => finding.Message.Contains("escapes through", StringComparison.Ordinal)));
    }

    [Xunit.Theory]
    [Xunit.InlineData("Metadata.Catalog.All[0]", true)]
    [Xunit.InlineData("\"safe\"", false)]
    public void ConstructedOwnedGenericWrappersRetainTheirOriginalGetterSources(string value, bool denied)
    {
        using var fixture = new Fixture(extra: "internal sealed class Wrapper<T> { public object Value => " + value + "; } internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize<object>(new Wrapper<object>()); }");
        Xunit.Assert.Equal(denied, fixture.Check().Any(finding => finding.Message.Contains("escapes through", StringComparison.Ordinal)));
    }

    [Xunit.Theory]
    [Xunit.InlineData("object", false)]
    [Xunit.InlineData("Metadata.Policy", true)]
    public void ConstructedNestedGenericWrappersRetainActualOuterArguments(string argument, bool denied)
    {
        using var fixture = new Fixture(extra: "internal sealed class Outer<T> { internal sealed class Nested { public T? Value { get; } } } internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize<object>(new Outer<" + argument + ">.Nested()); }");
        Xunit.Assert.Equal(denied, fixture.Check().Any(finding => finding.Message.Contains("escapes through", StringComparison.Ordinal)));
    }

    [Xunit.Theory]
    [Xunit.InlineData(100, false)]
    [Xunit.InlineData(300, true)]
    public void ExpressionDepthIsFiniteAndRefusesAnUnresolvedDeepPayload(int depth, bool denied)
    {
        string payload = new string('(', depth) + "new object()" + new string(')', depth);
        using var fixture = new Fixture(extra: "internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize(" + payload + "); }");
        Xunit.Assert.Equal(denied, fixture.Check().Any(finding => finding.Message.Contains("escapes through", StringComparison.Ordinal)));
    }

    [Xunit.Theory]
    [Xunit.InlineData("object", false)]
    [Xunit.InlineData("Metadata.Policy", true)]
    public void DeepArrayTypesUseTheChargedIterativeProofWithoutDroppingTheirElementOrigin(string element, bool denied)
    {
        string arrays = string.Concat(Enumerable.Repeat("[]", 400));
        using var fixture = new Fixture(extra: "// <auto-generated/>\npublic sealed class Wire { private " + element + arrays + "? value; }");
        fixture.WireBindings.Add(new("Wire", "message.proto", fixture.SchemaHash));
        Xunit.Assert.Equal(denied, fixture.Check().Any(finding => finding.Message.Contains("wire/RPC/serializer", StringComparison.Ordinal)));
    }

    [Xunit.Fact]
    public void ActualGenericReceiverAndDistinctArgumentOriginsRemainMetadataBearing()
    {
        using var fixture = new Fixture(extra: "using Metadata; internal static class Wrapper<T> { public static object Value => new object(); } internal static class Sender { private static object Identity(object value) => value; private static string Send() { _ = Identity(new object()); return System.Text.Json.JsonSerializer.Serialize(Identity(Wrapper<Policy>.Value)); } }");
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
    }

    [Xunit.Theory]
    [Xunit.InlineData("new string[] { \"hello\" }")]
    [Xunit.InlineData("new int[2, 2]")]
    [Xunit.InlineData("new string[][] { new[] { \"hello\" } }")]
    public void ActualPrimitiveElementArraysRemainSafeAfterObjectErasure(string value)
    {
        using var fixture = new Fixture(extra: "internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize<object>(" + value + "); }");
        Xunit.Assert.Empty(fixture.Check());
    }

    [Xunit.Theory]
    [Xunit.InlineData("new object[] { new string[] { \"hello\" }, Metadata.Catalog.All[0] }")]
    [Xunit.InlineData("((object)new string[] { \"hello\" }, (object)Metadata.Catalog.All[0])")]
    public void ScalarArrayProofDoesNotEraseMetadataInAnotherOrigin(string value)
    {
        using var fixture = new Fixture(extra: "internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize<object>(" + value + "); }");
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
    }

    [Xunit.Theory]
    [Xunit.InlineData("System.Linq.Enumerable.Select(selector: value => (object)Metadata.Catalog.All[0], source: System.Array.Empty<object>())")]
    [Xunit.InlineData("System.Linq.Enumerable.Select(selector: value => value, source: Metadata.Catalog.All.Cast<object>())")]
    public void ActualNamedReorderedSelectArgumentsPreserveMetadataOrigins(string value)
    {
        using var fixture = new Fixture(extra: "using System.Linq; internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize(" + value + ".ToArray()); }");
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
    }

    [Xunit.Fact]
    public void ActualNamedReorderedScalarSelectorRemainsAllowed()
    {
        using var fixture = new Fixture(extra: "using System.Linq; internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize(System.Linq.Enumerable.Select(selector: value => value.OperationId, source: Metadata.Catalog.All).ToArray()); }");
        Xunit.Assert.Empty(fixture.Check());
    }

    [Xunit.Fact]
    public void ErasedThisRetainsTheCompleteOwnedTypeProof()
    {
        using (var negative = new Fixture(extra: "internal sealed class Wrapper { public object Value => Metadata.Catalog.All[0]; private string Send() => System.Text.Json.JsonSerializer.Serialize((object)this); }"))
            Xunit.Assert.Contains(negative.Check(), finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
        using var positive = new Fixture(extra: "internal sealed class Wrapper { public string Value => \"safe\"; private string Send() => System.Text.Json.JsonSerializer.Serialize((object)this); }");
        Xunit.Assert.Empty(positive.Check());
    }

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text.TrimStart('\uFEFF').Replace("\r\n", "\n", StringComparison.Ordinal))));

    [Xunit.Fact]
    public void OwnerIndexPreservesFirstOwnerAndEveryMatchingAdapterRole()
    {
        var first = FixtureCompiler.Create("SameOwner", new Dictionary<string, string> { ["first.cs"] = "namespace Shared; public class Payload {}" }).GetTypeByMetadataName("Shared.Payload")!;
        var second = FixtureCompiler.Create("SameOwner", new Dictionary<string, string> { ["second.cs"] = "namespace Shared; public class Payload {}" }).GetTypeByMetadataName("Shared.Payload")!;
        var foreign = FixtureCompiler.Create("ForeignOwner", new Dictionary<string, string> { ["foreign.cs"] = "namespace Shared; public class Payload {}" }).GetTypeByMetadataName("Shared.Payload")!;
        var missing = FixtureCompiler.Create("MissingOwner", new Dictionary<string, string> { ["missing.cs"] = "namespace Shared; public class Payload {}" }).GetTypeByMetadataName("Shared.Payload")!;
        var projects = new Dictionary<INamedTypeSymbol, ProjectFacts>(SymbolEqualityComparer.Default)
        {
            [foreign] = IndexProject("foreign", ProjectRole.LocalRpcAdapter),
            [first] = IndexProject("first", ProjectRole.Contracts),
            [second] = IndexProject("second", ProjectRole.PublicApiAdapter),
        };
        Xunit.Assert.Equal(3, projects.Count);
        var index = new NonWireMetadataPolicy.OwnerIndex(projects);
        Xunit.Assert.Same(first, index.First(second));
        Xunit.Assert.True(index.HasAdapter(first));
        Xunit.Assert.Same(foreign, index.First(foreign));
        Xunit.Assert.True(index.HasAdapter(foreign));
        Xunit.Assert.Null(index.First(missing));
        Xunit.Assert.False(index.HasAdapter(missing));
        var reverse = new NonWireMetadataPolicy.OwnerIndex(new Dictionary<INamedTypeSymbol, ProjectFacts>(SymbolEqualityComparer.Default)
        {
            [second] = projects[second],
            [first] = projects[first],
        });
        Xunit.Assert.Same(second, reverse.First(first));
        Xunit.Assert.True(reverse.HasAdapter(first));
    }

    [Xunit.Fact]
    public void ThousandsOfRealOwnersResolveExactSymbolsWithoutForeignNameAliasing()
    {
        var source = new StringBuilder("namespace Large;");
        const int count = 4096;
        for (int i = 0; i < count; i++) source.Append(" public sealed class T").Append(i).Append(" {}");
        var compilation = FixtureCompiler.Create("LargeOwner", new Dictionary<string, string> { ["large.cs"] = source.ToString() });
        var projects = new Dictionary<INamedTypeSymbol, ProjectFacts>(SymbolEqualityComparer.Default);
        var expected = new INamedTypeSymbol[count];
        for (int i = 0; i < count; i++)
        {
            expected[i] = compilation.GetTypeByMetadataName("Large.T" + i)!;
            projects.Add(expected[i], IndexProject("owner-" + i, i % 2 == 0 ? ProjectRole.Contracts : ProjectRole.LocalRpcAdapter));
        }
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var index = new NonWireMetadataPolicy.OwnerIndex(projects);
        for (int i = count - 1; i >= 0; i--)
        {
            Xunit.Assert.Same(expected[i], index.First(expected[i]));
            Xunit.Assert.Equal(i % 2 != 0, index.HasAdapter(expected[i]));
        }
        var foreign = FixtureCompiler.Create("Foreign", new Dictionary<string, string> { ["foreign.cs"] = "namespace Large; public class T4095 {}" }).GetTypeByMetadataName("Large.T4095")!;
        Xunit.Assert.Null(index.First(foreign));
        Xunit.Assert.False(index.HasAdapter(foreign));
        Console.WriteLine($"GOV25: indexed {count} actual owner symbols and resolved all first-owner/adapter vectors in {timer.ElapsedMilliseconds} ms.");
    }

    [Xunit.Fact]
    public void CompletePolicyRetainsMetadataRefusalWithThousandsOfUnrelatedTypes()
    {
        var source = new StringBuilder("using Metadata;");
        for (int i = 0; i < 2048; i++) source.Append(" public sealed class Unrelated").Append(i).Append(" { public string Name => string.Empty; }");
        source.Append(" internal static class Sender { private static string Send() => System.Text.Json.JsonSerializer.Serialize<object>(Catalog.All[0]); }");
        using var fixture = new Fixture(extra: source.ToString());
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var findings = fixture.Check();
        Xunit.Assert.Equal(2049, findings.Length);
        Xunit.Assert.Single(findings, finding => finding.Message.Contains("escapes through", StringComparison.Ordinal));
        Xunit.Assert.Equal(2048, findings.Count(finding => finding.Message.StartsWith("Wire type is not bound to generated owned schema: Unrelated", StringComparison.Ordinal)));
        Console.WriteLine($"GOV25: complete policy evaluated 2048 unrelated real types, preserving every generated-wire refusal and the metadata refusal in {timer.ElapsedMilliseconds} ms.");
    }

    private static ProjectFacts IndexProject(string name, ProjectRole role) => new(
        new ProjectClassification(name + "/" + name + ".csproj", role, "DesktopPlatform"),
        "net10.0", "Library", "AGPL-3.0-only", "AGPL", [], [], [],
        new Dictionary<string, string>(StringComparer.Ordinal), new Dictionary<string, string>(StringComparer.Ordinal));

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
