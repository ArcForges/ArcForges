// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using ArcForges.Build.Policy.Architecture;

namespace ArcForges.Tests.ArchitectureTests;

public sealed class EvaluatedPolicyTests
{
    private const string LocalAcceptanceProject = "eng/acceptance/foundation/Foundation.Acceptance.csproj";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    [Xunit.Fact]
    public void ActualDesktopProjectsSatisfyTheSharedArchitecturePolicy()
    {
        string root = FindRoot();
        var classifications = Read<ProjectClassification[]>(root, "eng/policy/architecture-projects.json");
        var solution = XDocument.Load(Path.Combine(root, "DesktopPlatform.slnx"));
        var solutionProjects = solution.Descendants("Project").Select(project => project.Attribute("Path")!.Value).Order(StringComparer.Ordinal);
        using var ownership = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "eng/policy/runtime-ownership.json")));
        var ownedProjects = ownership.RootElement.GetProperty("owners").EnumerateArray()
            .Single(owner => owner.GetProperty("repository").GetString() == "DesktopPlatform")
            .GetProperty("projects").EnumerateArray().Select(project => project.GetProperty("path").GetString()!)
            .Where(path => path.EndsWith(".csproj", StringComparison.Ordinal)).Order(StringComparer.Ordinal);
        var defaultProjects = DefaultProjects(classifications, solutionProjects.ToArray(), ownedProjects.ToArray());
        ValidateLocalAcceptance(path => File.ReadAllBytes(Path.Combine(root, path)));

        string? driver = Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_SDK_DRIVER");
        string? compatibility = Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_COMPATIBILITY_TARGETS");
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true")
        {
            Xunit.Assert.Null(driver);
            Xunit.Assert.Null(compatibility);
        }

        var projects = defaultProjects.Select(project => ProjectGraph.Evaluate(root, project,
            sdkDriver: driver, compatibilityTargets: compatibility)).ToArray();
        foreach (var project in projects.Where(project => project.Classification.Aot))
        {
            Xunit.Assert.Equal("true", project.Properties["IsAotCompatible"]);
        }

        var compilations = projects.ToDictionary(project => project.Classification.Path, ProjectGraph.ReadCompilation, StringComparer.Ordinal);
        using var dependency = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "eng/policy/dependency-policy.json")));
        var dependencyLicenses = dependency.RootElement.GetProperty("nugetClosure").EnumerateObject()
            .GroupBy(package => package.Name[..package.Name.LastIndexOf('/')], StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Select(package => package.Value.GetProperty("licence").GetString()!)
                .Distinct(StringComparer.Ordinal).Single(), StringComparer.OrdinalIgnoreCase);
        var hashes = dependency.RootElement.GetProperty("inputHashes").EnumerateObject()
            .ToDictionary(input => input.Name, input => input.Value.GetString()!, StringComparer.Ordinal);
        var bindings = Read<ContractTestBinding[]>(root, "eng/policy/architecture-contract-tests.json");
        var exceptions = Read<PolicyException[]>(root, "eng/policy/exceptions.json");
        string evidencePath = Path.Combine(root, "artifacts/evidence/architecture-gates.json");
        ExternalPolicyEvidence[] evidence = [];
        if (File.Exists(evidencePath))
        {
            using var report = JsonDocument.Parse(File.ReadAllText(evidencePath));
            evidence = report.RootElement.GetProperty("evidence").Deserialize<ExternalPolicyEvidence[]>(JsonOptions)!;
        }

        string sourceCommit = Head(root);
        string nativeEvidence = Path.Combine(root, "artifacts/evidence/native-architecture");
        var nativeReports = Directory.Exists(nativeEvidence)
            ? Directory.GetFiles(nativeEvidence, "licence-boundary.json", SearchOption.AllDirectories) : [];
        var nativeProjects = nativeReports.SelectMany(path => NativeProjectGraph.Read(path, sourceCommit, "DesktopPlatform"))
            .GroupBy(project => project.Classification.Path, StringComparer.Ordinal).Select(group =>
            {
                Xunit.Assert.Single(group.Select(project => project.Classification.Role).Distinct());
                return group.First() with { ProjectReferences = group.SelectMany(project => project.ProjectReferences).Distinct(StringComparer.Ordinal).ToArray() };
            });
        var allProjects = projects.Concat(nativeProjects).ToArray();
        var repository = new RepositoryFacts(root, "DesktopPlatform", allProjects, exceptions, bindings);
        var configuration = new RepositoryPolicyConfiguration(Head(root), hashes, dependencyLicenses,
            new HashSet<string>(StringComparer.Ordinal), [], [], evidence);
        var findings = PolicyEngine.Check(repository, configuration, compilations, DateOnly.FromDateTime(DateTime.UtcNow));
        if (nativeReports.Length == 0)
        {
            findings = findings.Append(new PolicyFinding("AT-09", "artifacts/evidence/native-architecture",
                "Missing existing same-source native configure receipt; native release graph remains unverified.")).ToArray();
        }
        string reportDirectory = Path.Combine(root, "artifacts/evidence");
        Directory.CreateDirectory(reportDirectory);
        File.WriteAllText(Path.Combine(reportDirectory, "architecture-findings.json"), JsonSerializer.Serialize(findings, JsonOptions));
        Xunit.Assert.True(findings.Count == 0, string.Join(Environment.NewLine,
            findings.Select(finding => $"{finding.Rule} {finding.Path}: {finding.Message}")));
    }

    // The owned local published-package consumer is admitted statically. It must never be
    // restored, evaluated, compiled or executed by this hosted default-solution gate.
    private static ProjectClassification[] DefaultProjects(ProjectClassification[] classifications, string[] solutionProjects, string[] ownedProjects)
    {
        Xunit.Assert.Equal(classifications.Length, classifications.Select(project => project.Path).Distinct(StringComparer.Ordinal).Count());
        Xunit.Assert.Equal(ownedProjects.Order(StringComparer.Ordinal), classifications.Select(project => project.Path).Order(StringComparer.Ordinal));
        var local = Xunit.Assert.Single(classifications, project => project.Path == LocalAcceptanceProject);
        Xunit.Assert.Equal(new ProjectClassification(LocalAcceptanceProject, ProjectRole.BuildTool, "DesktopPlatform", "", false, false), local);
        var defaults = classifications.Where(project => project.Path != LocalAcceptanceProject).ToArray();
        Xunit.Assert.Equal(solutionProjects.Order(StringComparer.Ordinal), defaults.Select(project => project.Path).Order(StringComparer.Ordinal));
        return defaults;
    }

    private static void ValidateLocalAcceptance(Func<string, byte[]> read)
    {
        using var dependency = JsonDocument.Parse(read("eng/policy/dependency-policy.json"));
        using var receipt = JsonDocument.Parse(read("eng/policy/dependency-reviews/fnd-07-r1.json"));
        string[] inputs = [LocalAcceptanceProject, "eng/acceptance/foundation/Directory.Packages.props",
            "eng/acceptance/foundation/packages.lock.json", "eng/acceptance/foundation/package.json",
            "eng/acceptance/foundation/package-lock.json"];
        foreach (string path in inputs)
        {
            byte[] canonical = System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(read(path)).Replace("\r\n", "\n", StringComparison.Ordinal));
            string hash = Convert.ToHexStringLower(SHA256.HashData(canonical));
            Xunit.Assert.Equal(hash, dependency.RootElement.GetProperty("inputHashes").GetProperty(path).GetString());
            Xunit.Assert.Equal(hash, receipt.RootElement.GetProperty("review").GetProperty("inputHashes").GetProperty(path).GetString());
        }

        var project = XDocument.Parse(System.Text.Encoding.UTF8.GetString(read(LocalAcceptanceProject)));
        Xunit.Assert.Equal("Microsoft.NET.Sdk", project.Root!.Attribute("Sdk")?.Value);
        Xunit.Assert.Equal("Exe", Xunit.Assert.Single(project.Descendants("OutputType")).Value);
        Xunit.Assert.Equal("false", Xunit.Assert.Single(project.Descendants("IsPackable")).Value);
        Xunit.Assert.Equal("net10.0", Xunit.Assert.Single(project.Descendants("TargetFramework")).Value);
        using var manifest = JsonDocument.Parse(read("eng/acceptance/foundation/package.json"));
        Xunit.Assert.True(manifest.RootElement.GetProperty("private").GetBoolean());
        Xunit.Assert.Equal("foundation-acceptance", manifest.RootElement.GetProperty("name").GetString());
        using var packages = JsonDocument.Parse(read("eng/packaging/packages.json"));
        Xunit.Assert.DoesNotContain(packages.RootElement.GetProperty("packages").EnumerateArray(),
            package => package.GetProperty("project").GetString() == LocalAcceptanceProject);
    }

    [Xunit.Fact]
    public void LocalAcceptanceSelectionRetainsDefaultBuildTools()
    {
        var local = new ProjectClassification(LocalAcceptanceProject, ProjectRole.BuildTool, "DesktopPlatform", "", false, false);
        var tool = new ProjectClassification("src/Build/tool.csproj", ProjectRole.BuildTool, "DesktopPlatform", "", false, false);
        Xunit.Assert.Equal([tool], DefaultProjects([local, tool], [tool.Path], [local.Path, tool.Path]));
    }

    [Xunit.Theory]
    [Xunit.InlineData("missing")]
    [Xunit.InlineData("duplicate")]
    [Xunit.InlineData("unknown")]
    [Xunit.InlineData("owner")]
    [Xunit.InlineData("role")]
    [Xunit.InlineData("module")]
    [Xunit.InlineData("production")]
    [Xunit.InlineData("aot")]
    [Xunit.InlineData("solution")]
    [Xunit.InlineData("missing-owner")]
    [Xunit.InlineData("duplicate-owner")]
    public void LocalAcceptanceInventoryRejectsScopeDrift(string mutation)
    {
        var local = new ProjectClassification(LocalAcceptanceProject, ProjectRole.BuildTool, "DesktopPlatform", "", false, false);
        ProjectClassification[] classifications = mutation switch
        {
            "missing" => [],
            "duplicate" => [local, local],
            "unknown" => [local, local with { Path = "eng/other.csproj" }],
            "owner" => [local with { Owner = "Other" }],
            "role" => [local with { Role = ProjectRole.Infrastructure }],
            "module" => [local with { Module = "Other" }],
            "production" => [local with { Production = true }],
            "aot" => [local with { Aot = true }],
            _ => [local],
        };
        string[] owned = mutation switch
        {
            "missing-owner" => [],
            "duplicate-owner" => [LocalAcceptanceProject, LocalAcceptanceProject],
            _ => classifications.Select(project => project.Path).ToArray(),
        };
        Xunit.Assert.ThrowsAny<Exception>(() => DefaultProjects(classifications, mutation == "solution" ? [LocalAcceptanceProject] : [], owned));
    }

    [Xunit.Theory]
    [Xunit.InlineData(LocalAcceptanceProject)]
    [Xunit.InlineData("eng/acceptance/foundation/Directory.Packages.props")]
    [Xunit.InlineData("eng/acceptance/foundation/packages.lock.json")]
    [Xunit.InlineData("eng/acceptance/foundation/package.json")]
    [Xunit.InlineData("eng/acceptance/foundation/package-lock.json")]
    public void LocalAcceptanceRejectsInputDrift(string changed)
    {
        string root = FindRoot();
        byte[] ReadInput(string path) => File.ReadAllBytes(Path.Combine(root, path));
        ValidateLocalAcceptance(ReadInput);
        Xunit.Assert.ThrowsAny<Exception>(() => ValidateLocalAcceptance(path => path == changed ? [.. ReadInput(path), 32] : ReadInput(path)));
    }

    private static T Read<T>(string root, string path) =>
        JsonSerializer.Deserialize<T>(File.ReadAllText(Path.Combine(root, path)), JsonOptions)
        ?? throw new InvalidOperationException("Missing policy input: " + path);

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DesktopPlatform.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Owning repository not found.");
    }

    private static string Head(string root)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = root, RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("rev-parse");
        start.ArgumentList.Add("HEAD");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Git did not start.");
        string value = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        return process.ExitCode == 0 ? value : throw new InvalidOperationException("Cannot bind policy evidence to HEAD.");
    }
}
