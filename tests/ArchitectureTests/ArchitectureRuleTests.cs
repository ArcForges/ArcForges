// SPDX-License-Identifier: AGPL-3.0-only

using System.Xml.Linq;

namespace ArcForges.Tests.ArchitectureTests;

internal static class ArchitectureRules
{
    private static readonly string[] ProductPrefixes = ["ArcChat", "ArcNotes", "ArcScope", "ArcSlate"];
    private static readonly Lazy<string> RepositoryRoot = new(FindRepositoryRoot);

    internal static void AssertRule(string id)
    {
        var violations = ValidateProduction(id).ToArray();
        Xunit.Assert.True(violations.Length == 0, $"[{id}] {string.Join(Environment.NewLine, violations)}");
    }

    internal static void AssertFixtures(string id)
    {
        var fixtureRoot = Path.Combine(RepositoryRoot.Value, "tests", "ArchitectureTests", "Fixtures");
        var valid = File.ReadAllText(Path.Combine(fixtureRoot, $"{id.Replace("-", string.Empty, StringComparison.Ordinal)}Valid.cs"));
        var invalid = File.ReadAllText(Path.Combine(fixtureRoot, $"{id.Replace("-", string.Empty, StringComparison.Ordinal)}Violation.cs.txt"));
        Xunit.Assert.Empty(ValidateFixture(id, valid));
        Xunit.Assert.NotEmpty(ValidateFixture(id, invalid));
    }

    private static string[] ValidateFixture(string id, string content)
    {
        string root = Path.Combine(Path.GetTempPath(), "arcforges-architecture-fixture", Guid.NewGuid().ToString("N"));
        try
        {
            string relativePath = FixtureRelativePath(id);
            string path = Path.Combine(root, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, id == "ARC-012" ? CloudModuleFixture(content) : content);
            return ValidateProduction(id, root).ToArray();
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static string FixtureRelativePath(string id) => id switch
    {
        "ARC-001" => Path.Combine("src", "ArcChat", "ArcChat.Domain", "ArcChat.Domain.csproj"),
        "ARC-002" => Path.Combine("src", "ArcChat", "ArcChat.Presentation", "FixtureViewModel.cs"),
        "ARC-003" => Path.Combine("src", "ArcChat", "ArcChat.LocalRpc", "ArcChat.LocalRpc.csproj"),
        "ARC-004" => Path.Combine("src", "ArcChat", "ArcChat.Domain", "ArcChat.Domain.csproj"),
        "ARC-005" => Path.Combine("src", "Contracts", "ArcForges.Contracts.Foundation", "Fixture.cs"),
        "ARC-006" => Path.Combine("src", "Cloud", "Fixture.csproj"),
        "ARC-007" or "ARC-009" => Path.Combine("src", "Contracts", "ArcForges.Contracts.LocalRpc", "Fixture.cs"),
        "ARC-008" or "ARC-011" => Path.Combine("src", "Fixture.cs"),
        "ARC-010" => Path.Combine("src", "BuildingBlocks", "ArcForges.Foundation", "Fixture.cs"),
        "ARC-012" => Path.Combine("src", "Cloud", "ArcForges.Cloud.Modules.Chat", "ArcForges.Cloud.Modules.Chat.csproj"),
        "ARC-013" => Path.Combine("src", "ArcChat", "ArcChat.Desktop", "Fixture.cs"),
        _ => throw new ArgumentOutOfRangeException(nameof(id), id, "Unknown architecture fixture."),
    };

    private static string CloudModuleFixture(string content)
    {
        bool violates = content.Contains("ArcForges.Cloud.Modules.Notes", StringComparison.Ordinal);
        string reference = violates
            ? "<ProjectReference Include=\"../ArcForges.Cloud.Modules.Notes/ArcForges.Cloud.Modules.Notes.csproj\" />"
            : string.Empty;
        return $"<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup>{reference}</ItemGroup></Project>";
    }

    private static IEnumerable<string> ValidateProduction(string id, string? repositoryRoot = null)
    {
        var root = repositoryRoot ?? RepositoryRoot.Value;
        var sourceRoot = Path.Combine(root, "src");
        var projects = Directory.EnumerateFiles(sourceRoot, "*.csproj", SearchOption.AllDirectories).ToArray();
        var sources = Directory.EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToArray();

        return id switch
        {
            "ARC-001" => FindTokens(projects.Where(path => Path.GetFileNameWithoutExtension(path).EndsWith(".Domain", StringComparison.Ordinal)),
                ["Application", "Infrastructure", "Desktop", "Contracts.", "Avalonia", "Microsoft.Maui", "StreamJsonRpc", "Refit", "SignalR.Client", "Npgsql", "Microsoft.Data.Sqlite", "ArcForges.NativeInterop"]),
            "ARC-002" => FindTokens(sources.Where(path => Path.GetFileName(path).Contains("ViewModel", StringComparison.Ordinal)),
                ["DbContext", "Npgsql", "Sqlite", "StreamJsonRpc", "Refit", "SignalR", "IntPtr", "nint", "SafeHandle"]),
            "ARC-003" => FindTokens(projects.Where(IsAdapterProject), ["Avalonia", "Microsoft.Maui", ".Desktop", "ViewModel", "DbContext"]),
            "ARC-004" => ValidateProductIsolation(projects),
            "ARC-005" => FindTokens(ProjectAndSourceFiles(root, "src", "Contracts"),
                ["Avalonia", "Microsoft.Maui", "Npgsql", "Microsoft.Data.Sqlite", "ArcForges.NativeInterop", "Android.", "UIKit.", "Windows.", "AppKit.", "record struct AppId", "class AppId"]),
            "ARC-006" => ValidatePublicClients(projects),
            "ARC-007" => FindTokens(ProjectAndSourceFiles(root, "src", "Contracts", "ArcForges.Contracts.LocalRpc"),
                ["object ", "dynamic ", "System.Type", "Dictionary<string, object>", "JsonElement"]),
            "ARC-008" => FindTokens(projects.Concat(sources), ["Refit.Reflection", "RestService.For<"]),
            "ARC-009" => ValidateGeneratedRpc(ProjectAndSourceFiles(root, "src", "Contracts", "ArcForges.Contracts.LocalRpc")),
            "ARC-010" => FindTokens(ProjectAndSourceFiles(root, "src", "BuildingBlocks", "ArcForges.Foundation"),
                ["class Document", "record Document", "class VideoTimeline", "record VideoTimeline", "class Conversation", "record Conversation", "class Capture", "record Capture"]),
            "ARC-011" => FindTokens(sources, ["AVFrame", "AVPacket", "AVCodec", "AVFormatContext", "ma_device", "ma_context", "std::"]),
            "ARC-012" => ValidateCloudModuleIsolation(projects),
            "ARC-013" => ValidateDesktopNativeOnly(root),
            _ => [$"Unknown architecture rule {id}."],
        };
    }

    private static IEnumerable<string> ValidateProductIsolation(IEnumerable<string> projects)
    {
        foreach (var project in projects.Where(path => path.EndsWith(".Domain.csproj", StringComparison.Ordinal) || path.EndsWith(".Application.csproj", StringComparison.Ordinal)))
        {
            var owner = ProductPrefixes.FirstOrDefault(prefix => Path.GetFileName(project).StartsWith(prefix, StringComparison.Ordinal));
            if (owner is null)
            {
                continue;
            }

            foreach (var other in ProductPrefixes.Where(prefix => !string.Equals(prefix, owner, StringComparison.Ordinal)))
            {
                if (File.ReadAllText(project).Contains($"{other}.", StringComparison.Ordinal))
                {
                    yield return $"{Path.GetFileName(project)} -> {other}";
                }
            }
        }
    }

    private static IEnumerable<string> ValidatePublicClients(IEnumerable<string> projects)
    {
        var targets = projects.Where(path => path.Contains($"{Path.DirectorySeparatorChar}Cloud{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || path.Contains($"{Path.DirectorySeparatorChar}Mobile{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || path.Contains($"{Path.DirectorySeparatorChar}Web{Path.DirectorySeparatorChar}", StringComparison.Ordinal));
        var banned = new[] { "ArcForges.Contracts.LocalRpc", "ArcForges.NativeInterop" };
        foreach (var violation in FindTokens(targets, banned))
        {
            yield return violation;
        }

        var webProjects = projects.Where(path => path.Contains($"{Path.DirectorySeparatorChar}Web{Path.DirectorySeparatorChar}", StringComparison.Ordinal));
        foreach (var violation in FindTokens(webProjects, ["ArcForges.Cloud.", ".Desktop", "ArcChat.Mobile", "Mcp", "Npgsql", "Microsoft.Data.Sqlite"]))
        {
            yield return violation;
        }
    }

    private static List<string> ValidateGeneratedRpc(IEnumerable<string> files)
    {
        var content = string.Join(Environment.NewLine, files.Select(File.ReadAllText));
        if (!content.Contains("JsonRpcContract", StringComparison.Ordinal))
        {
            return [];
        }

        var failures = new List<string>();
        if (!content.Contains("GenerateShape", StringComparison.Ordinal)) failures.Add("JsonRpcContract -> missing GenerateShape");
        if (!content.Contains("ExportRpcContractProxies", StringComparison.Ordinal)) failures.Add("JsonRpcContract -> missing ExportRpcContractProxies");
        return failures;
    }

    private static IEnumerable<string> ValidateCloudModuleIsolation(IEnumerable<string> projects)
    {
        foreach (var project in projects.Where(path => Path.GetFileName(path).StartsWith("ArcForges.Cloud.Modules.", StringComparison.Ordinal)))
        {
            var ownName = Path.GetFileNameWithoutExtension(project);
            foreach (var reference in ProjectReferences(project).Where(reference => reference.StartsWith("ArcForges.Cloud.Modules.", StringComparison.Ordinal) && !string.Equals(reference, ownName, StringComparison.Ordinal)))
            {
                yield return $"{ownName} -> {reference}";
            }
        }
    }

    private static IEnumerable<string> ValidateDesktopNativeOnly(string root)
    {
        var directories = new[]
        {
            Path.Combine(root, "src", "ArcChat", "ArcChat.Desktop"),
            Path.Combine(root, "src", "ArcNotes", "ArcNotes.Desktop"),
            Path.Combine(root, "src", "ArcScope", "ArcScope.Desktop"),
            Path.Combine(root, "src", "ArcSlate", "ArcSlate.Desktop"),
            Path.Combine(root, "src", "DesktopHelpers", "ArcForges.ContentSandbox"),
        };
        var files = directories.Where(Directory.Exists)
            .SelectMany(directory => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));
        return FindTokens(files, ["WebView", "WebView2", "CEF", "Chromium", "Electron", "WKWebView", "HybridWebView", "BlazorWebView", "JavaScript", "iframe", "localhost", "src\\Web", "src/Web"]);
    }

    private static IEnumerable<string> FindTokens(IEnumerable<string> files, IEnumerable<string> tokens)
    {
        foreach (var file in files)
        {
            var content = File.ReadAllText(file);
            foreach (var token in tokens.Where(token => content.Contains(token, StringComparison.OrdinalIgnoreCase)))
            {
                yield return $"{Path.GetRelativePath(RepositoryRoot.Value, file)} -> {token}";
            }
        }
    }

    private static bool IsAdapterProject(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path);
        return name.EndsWith(".LocalRpc", StringComparison.Ordinal)
            || name is "ArcForges.Cloud.PublicApi" or "ArcForges.Cloud.Realtime";
    }

    private static IEnumerable<string> ProjectReferences(string project)
    {
        var document = XDocument.Load(project);
        return document.Descendants("ProjectReference")
            .Select(element => element.Attribute("Include")?.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar))
            .Select(value => Path.GetFileNameWithoutExtension(value)!);
    }

    private static IEnumerable<string> ProjectAndSourceFiles(string root, params string[] parts)
    {
        var directory = parts.Aggregate(root, Path.Combine);
        return Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Where(path => (path.EndsWith(".cs", StringComparison.Ordinal) || path.EndsWith(".csproj", StringComparison.Ordinal))
                && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ArcForges.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("ArcForges repository root was not found.");
    }
}

public abstract class ArchitectureRuleTestBase(string ruleId)
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionGraphPasses() => ArchitectureRules.AssertRule(ruleId);

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void FixturesProveBothDirections() => ArchitectureRules.AssertFixtures(ruleId);
}

public sealed class ARC001DomainTests() : ArchitectureRuleTestBase("ARC-001");
public sealed class ARC002UiLayerTests() : ArchitectureRuleTestBase("ARC-002");
public sealed class ARC003AdapterTests() : ArchitectureRuleTestBase("ARC-003");
public sealed class ARC004ProductIsolationTests() : ArchitectureRuleTestBase("ARC-004");
public sealed class ARC005ContractPurityTests() : ArchitectureRuleTestBase("ARC-005");
public sealed class ARC006PublicBoundaryTests() : ArchitectureRuleTestBase("ARC-006");
public sealed class ARC007TypedRpcTests() : ArchitectureRuleTestBase("ARC-007");
public sealed class ARC008GeneratedRefitTests() : ArchitectureRuleTestBase("ARC-008");
public sealed class ARC009GeneratedRpcTests() : ArchitectureRuleTestBase("ARC-009");
public sealed class ARC010FoundationTests() : ArchitectureRuleTestBase("ARC-010");
public sealed class ARC011NativeBoundaryTests() : ArchitectureRuleTestBase("ARC-011");
public sealed class ARC012CloudModuleTests() : ArchitectureRuleTestBase("ARC-012");
public sealed class ARC013DesktopNativeTests() : ArchitectureRuleTestBase("ARC-013");
