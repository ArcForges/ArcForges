// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using ArcForges.Build.Policy.Architecture;

namespace ArcForges.Tests.ArchitectureTests;

public sealed class EvaluatedPolicyTests
{
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
        Xunit.Assert.Equal(solutionProjects, classifications.Select(project => project.Path).Order(StringComparer.Ordinal));
        using var ownership = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "eng/policy/runtime-ownership.json")));
        var ownedProjects = ownership.RootElement.GetProperty("owners").EnumerateArray()
            .Single(owner => owner.GetProperty("repository").GetString() == "DesktopPlatform")
            .GetProperty("projects").EnumerateArray().Select(project => project.GetProperty("path").GetString()!)
            .Where(path => path.EndsWith(".csproj", StringComparison.Ordinal)).Order(StringComparer.Ordinal);
        Xunit.Assert.Equal(ownedProjects, classifications.Select(project => project.Path).Order(StringComparer.Ordinal));

        string? driver = Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_SDK_DRIVER");
        string? compatibility = Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_COMPATIBILITY_TARGETS");
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true")
        {
            Xunit.Assert.Null(driver);
            Xunit.Assert.Null(compatibility);
        }

        var projects = classifications.Select(project => ProjectGraph.Evaluate(root, project,
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
