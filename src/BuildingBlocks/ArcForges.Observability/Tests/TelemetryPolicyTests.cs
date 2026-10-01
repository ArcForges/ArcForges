// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using Xunit;

namespace ArcForges.Observability.Tests;

/// <summary>
/// <c>eng/policy/telemetry-policy.json</c> is the reviewed record of the dimension allowlist, the metric label
/// allowlist, the redaction name lists and the sampling and retention configuration. These tests keep it identical to
/// what the library actually enforces, so neither can drift from the other.
/// </summary>
public sealed class TelemetryPolicyTests
{
    private const string Invalid = "zzmarker";

    [Fact]
    public void PolicyFileHasExactlyTheReviewedSections()
    {
        using JsonDocument policy = Load();
        JsonElement root = policy.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(
            ["authority", "dimensions", "metricLabels", "notFixedByDesign", "owners", "redaction", "retention", "routeParameters", "sampling", "schemaVersion"],
            root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void DimensionAllowlistEqualsTheVocabularyTheLibraryEnforces()
    {
        using JsonDocument policy = Load();
        var fromPolicy = policy.RootElement.GetProperty("dimensions").EnumerateArray()
            .Select(entry => (
                Name: entry.GetProperty("name").GetString()!,
                Kind: entry.GetProperty("kind").GetString()!,
                Members: entry.TryGetProperty("members", out JsonElement members)
                    ? members.EnumerateArray().Select(member => member.GetString()!).Order(StringComparer.Ordinal).ToArray()
                    : []))
            .ToArray();
        var fromCode = TelemetryFields.Rules
            .Select(rule => (rule.Name, Kind: TelemetryFields.KindName(rule.Kind),
                Members: rule.Members is null ? [] : rule.Members.Order(StringComparer.Ordinal).ToArray()))
            .ToArray();

        Assert.Equal(fromPolicy.Length, fromPolicy.Select(entry => entry.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(fromCode.Select(entry => entry.Name).Order(StringComparer.Ordinal), fromPolicy.Select(entry => entry.Name).Order(StringComparer.Ordinal));
        foreach (var entry in fromPolicy)
        {
            var code = Assert.Single(fromCode, candidate => candidate.Name == entry.Name);
            Assert.Equal(code.Kind, entry.Kind);
            Assert.Equal(code.Members, entry.Members);
        }

        JsonElement route = policy.RootElement.GetProperty("routeParameters");
        Assert.Equal(TelemetryFields.RouteParameterPrefix, route.GetProperty("namePrefix").GetString());
        Assert.Equal("guid-32", route.GetProperty("kind").GetString());
    }

    [Fact]
    public void EveryPolicyDimensionAcceptsItsOwnKindAndRefusesAnythingElse()
    {
        using JsonDocument policy = Load();
        string template = RouteTemplateSet.Create(["/policy/probe"]).Record("/policy/probe").Template;
        foreach (JsonElement entry in policy.RootElement.GetProperty("dimensions").EnumerateArray())
        {
            string name = entry.GetProperty("name").GetString()!;
            string kind = entry.GetProperty("kind").GetString()!;
            string[] members = entry.TryGetProperty("members", out JsonElement list)
                ? list.EnumerateArray().Select(member => member.GetString()!).ToArray()
                : [];
            object valid = kind switch
            {
                "application-id" or "enum" or "http-method" => members[0],
                "guid-32" => "0123456789abcdef0123456789abcdef",
                "build-id" => "local.local",
                "sha256-reference" => "sha256:" + new string('a', 64),
                "unsigned-integer" => 5UL,
                "duration-ms" => 1.5d,
                "reason-code" => "state.gone",
                "native-abi-version" => "1.2",
                "count" => 3,
                "route-template" => template,
                "http-status-code" => 200,
                _ => throw new InvalidOperationException("Unreviewed kind " + kind),
            };

            Assert.Equal(valid, Assert.Single(RedactionProcessor.ScrubFields([new(name, valid)])).Value);
            Assert.Empty(RedactionProcessor.ScrubFields([new(name, Invalid)]));
            foreach (string member in members)
            {
                Assert.Single(RedactionProcessor.ScrubFields([new(name, member)]));
            }
        }
    }

    [Fact]
    public void MetricLabelAllowlistIsTheOnlyPointLabelSetTheEmitterEverUses()
    {
        using JsonDocument policy = Load();
        JsonElement labels = policy.RootElement.GetProperty("metricLabels");
        string[] points = labels.GetProperty("pointLabels").EnumerateArray().Select(label => label.GetString()!).ToArray();
        string[] scope = labels.GetProperty("scopeAttributes").EnumerateArray().Select(label => label.GetString()!).ToArray();
        string[] dimensions = policy.RootElement.GetProperty("dimensions").EnumerateArray().Select(entry => entry.GetProperty("name").GetString()!).ToArray();

        Assert.Equal(["service.name"], points);
        Assert.Equal(["application.id", "instance.id", "build.id", "deployment.environment"], scope);
        Assert.All(points.Concat(scope), name => Assert.Contains(name, dimensions));
        Assert.True(labels.GetProperty("unboundedIdentifiersAreNeverLabels").GetBoolean());

        ObservabilityContext full = RedactionProcessorTests.FullContext();
        using var exporter = new LocalTestExporter(full.InstanceId);
        using var emitter = new SignalEmitter(exporter);
        using (ObservabilityScope.Push(full))
        {
            emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
        }

        string[] metricLines = exporter.ExportedText().Split('\n').Where(line => line.StartsWith("metric ", StringComparison.Ordinal)).ToArray();
        Assert.NotEmpty(metricLines);
        foreach (string line in metricLines)
        {
            string[] observedScope = line.Split(' ').Where(part => part.StartsWith("scope:", StringComparison.Ordinal))
                .Select(part => part["scope:".Length..part.IndexOf('=', StringComparison.Ordinal)]).ToArray();
            string[] observedLabels = line.Split(' ').Where(part => part.StartsWith("label:", StringComparison.Ordinal))
                .Select(part => part["label:".Length..part.IndexOf('=', StringComparison.Ordinal)]).ToArray();
            Assert.Equal(scope.Order(StringComparer.Ordinal), observedScope.Order(StringComparer.Ordinal));
            Assert.Equal(points, observedLabels);
        }
    }

    [Fact]
    public void SensitiveNameListsInThePolicyEqualTheOnesTheProcessorUses()
    {
        using JsonDocument policy = Load();
        JsonElement names = policy.RootElement.GetProperty("redaction").GetProperty("sensitiveFieldNames");

        Assert.Equal(SensitiveFieldNames.ExactNames, Strings(names.GetProperty("exact")));
        Assert.Equal(SensitiveFieldNames.Segments, Strings(names.GetProperty("words")));
        Assert.Equal(SensitiveFieldNames.Sequences.Select(sequence => sequence.ToArray()),
            names.GetProperty("wordSequences").EnumerateArray().Select(Strings));
        foreach (string word in Strings(names.GetProperty("words")))
        {
            Assert.True(RedactionProcessor.IsSensitiveFieldName(word), word);
            Assert.True(RedactionProcessor.IsSensitiveFieldName("a." + word + ".b"), word);
        }

        foreach (string exact in Strings(names.GetProperty("exact")))
        {
            Assert.True(RedactionProcessor.IsSensitiveFieldName(exact), exact);
            Assert.True(RedactionProcessor.IsSensitiveFieldName(exact.ToUpperInvariant()), exact);
        }

        foreach (IReadOnlyList<string> sequence in SensitiveFieldNames.Sequences)
        {
            Assert.True(RedactionProcessor.IsSensitiveFieldName(string.Join('.', sequence)), string.Join(' ', sequence));
        }
    }

    [Fact]
    public void SamplingAndRetentionRecordOnlyWhatDesignFixesAndNameWhatItLeavesOpen()
    {
        using JsonDocument policy = Load();
        JsonElement sampling = policy.RootElement.GetProperty("sampling");
        JsonElement buffer = sampling.GetProperty("diagnosticBuffer");

        Assert.Equal(8L * 1024 * 1024, buffer.GetProperty("defaultBytes").GetInt64());
        Assert.Equal(16L * 1024 * 1024, buffer.GetProperty("hardLimitBytes").GetInt64());
        Assert.Equal(30, buffer.GetProperty("perTraceRetentionSeconds").GetInt32());
        Assert.Equal("spans-still-recorded-only", sampling.GetProperty("promotion").GetProperty("errorAndSlow").GetString());
        Assert.False(sampling.GetProperty("promotion").GetProperty("everyErrorTraceRetained").GetBoolean());
        Assert.True(sampling.GetProperty("lossIsCountedAndVisible").GetBoolean());
        Assert.Equal(["signal", "route"], Strings(sampling.GetProperty("head").GetProperty("configurablePer")));

        JsonElement retention = policy.RootElement.GetProperty("retention");
        Assert.Equal(["metrics", "traces", "logs"], retention.GetProperty("signalClassPosture").EnumerateObject().Select(property => property.Name));
        Assert.True(retention.GetProperty("auditRetentionIsIndependent").GetBoolean());

        string[] open = Strings(policy.RootElement.GetProperty("notFixedByDesign"));
        Assert.Equal(["sampling.head.defaultRatio", "retention.durationsByClassAndEnvironment"], open);
        foreach (string path in open)
        {
            JsonElement value = policy.RootElement;
            foreach (string part in path.Split('.'))
            {
                value = value.GetProperty(part);
            }

            Assert.Equal(JsonValueKind.Null, value.ValueKind);
        }
    }

    [Fact]
    public void TheRedactionSectionStatesTheExportRule()
    {
        using JsonDocument policy = Load();
        JsonElement redaction = policy.RootElement.GetProperty("redaction");

        Assert.Contains("exported only if", redaction.GetProperty("exportRule").GetString(), StringComparison.Ordinal);
        Assert.Contains("redacted", redaction.GetProperty("operationNameRule").GetString(), StringComparison.Ordinal);
    }

    private static string[] Strings(JsonElement array) => array.EnumerateArray().Select(item => item.GetString()!).ToArray();

    private static JsonDocument Load()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null)
        {
            string candidate = Path.Combine(directory, "eng", "policy", "telemetry-policy.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate), new JsonDocumentOptions { AllowTrailingCommas = false });
            }

            directory = Path.GetDirectoryName(directory);
        }

        throw new FileNotFoundException("eng/policy/telemetry-policy.json was not found above the test output directory.");
    }
}
