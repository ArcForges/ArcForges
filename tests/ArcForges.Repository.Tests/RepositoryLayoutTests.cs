// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Repository.Tests;

/// <summary>Project layout, executable names (AD-0003) and the trait-suite definitions (16 section 4).</summary>
public sealed class RepositoryLayoutTests
{
    [Theory]
    [InlineData("src/ArcForges.Host/ArcForges.Host.csproj", "arcforges")]
    [InlineData("src/ArcForges.Desktop/ArcForges.Desktop.csproj", "arcforges-desktop")]
    [InlineData("tools/ArcForges.TestLoad/ArcForges.TestLoad.csproj", "arcforges-testload")]
    [InlineData("tools/ArcForges.Bench/ArcForges.Bench.csproj", "arcforges-bench")]
    public void ExecutablesHaveTheirDesignedNamesAndPublishNativeAot(string project, string assemblyName)
    {
        Assert.Equal(assemblyName, RepositoryFiles.Property(project, "AssemblyName"));
        Assert.Equal("true", RepositoryFiles.Property(project, "PublishAot"));
    }

    [Fact]
    public void ExecutableNamesAreDistinctOnCaseInsensitiveFileSystems()
    {
        var names = RepositoryFiles.Projects("src", "tools")
            .Where(project => RepositoryFiles.Property(project, "OutputType") is "Exe" or "WinExe")
            .Select(project => RepositoryFiles.Property(project, "AssemblyName") ?? Path.GetFileNameWithoutExtension(project))
            .ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains("arcforges", names);
    }

    [Fact]
    public void EveryProjectIsInTheSolutionWithItsLockFile()
    {
        var solution = RepositoryFiles.Xml("ArcForges.slnx").Descendants("Project")
            .Select(element => (string)element.Attribute("Path")!)
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.Equal(RepositoryFiles.Projects("src", "tools", "tests"), solution);
        Assert.All(solution, project => Assert.True(
            File.Exists(RepositoryFiles.PathOf(Path.Combine(Path.GetDirectoryName(project)!, "packages.lock.json"))),
            $"{project} needs a committed packages.lock.json."));
    }

    [Fact]
    public void TestSuitesReferenceExistingProjectsAndSuites()
    {
        var suites = new Dictionary<string, string>(StringComparer.Ordinal);
        var kinds = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (var line in File.ReadAllLines(RepositoryFiles.PathOf("eng/test-suites.conf")))
        {
            var fields = line.Split('#')[0].Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length == 0)
            {
                continue;
            }

            Assert.Contains(fields[0], (string[])["suite", "kind"]);
            if (fields[0] == "suite")
            {
                suites.Add(fields[1], fields[2]);
                Assert.All(fields.Skip(3).Where((_, index) => index % 2 == 0), option =>
                    Assert.Contains(option, (string[])["--filter-trait", "--filter-not-trait"]));
            }
            else
            {
                kinds.Add(fields[1], fields[2..]);
            }
        }

        var testProjects = RepositoryFiles.Projects("tests").Select(Path.GetFileNameWithoutExtension).ToHashSet(StringComparer.Ordinal);
        foreach (var projects in suites.Values.Where(projects => projects != "*"))
        {
            Assert.All(projects.Split(','), project => Assert.Contains(project, testProjects));
        }

        Assert.All(kinds.Values.SelectMany(names => names), suite => Assert.Contains(suite, suites.Keys));
        Assert.Equal("*", suites["unit"]);
        Assert.Equal("*", suites["ci"]);
    }

    [Fact]
    public void AvaloniaBuildTelemetryIsReplacedForEveryProject()
    {
        // Avalonia.BuildServices defines AvaloniaStats; the later Directory.Build.targets definition wins.
        var target = RepositoryFiles.Xml("Directory.Build.targets").Descendants("Target")
            .Single(element => (string?)element.Attribute("Name") == "AvaloniaStats");

        Assert.Null(target.Attribute("Condition"));
        Assert.DoesNotContain(target.Elements(), element => element.Name.LocalName != "Message");
    }

    [Fact]
    public void TestProjectsDoNotPublishNativeAot()
    {
        foreach (var project in RepositoryFiles.Projects("tests"))
        {
            Assert.NotEqual("true", RepositoryFiles.Property(project, "PublishAot"));
        }
    }
}
