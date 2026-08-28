// SPDX-License-Identifier: AGPL-3.0-only

using System.Reflection;
using System.Runtime.Loader;

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>Shared inputs for the thirteen rules: the real project graph and the built assemblies.</summary>
internal static class ArchitectureContext
{
    internal static readonly Lazy<string> RepositoryRoot = new(FindRepositoryRoot);

    internal static readonly Lazy<ProjectGraph> Graph =
        new(() => ProjectGraph.Load(Path.Combine(RepositoryRoot.Value, "src")));

    /// <summary>
    /// Every production assembly this test project references, resolved from its own output directory.
    /// A build that produced nothing would otherwise let the type rules pass vacuously, so the count is
    /// asserted by <see cref="ArchitectureSurfaceTests"/>.
    /// </summary>
    internal static readonly Lazy<IReadOnlyList<string>> ProductionAssemblyPaths = new(() =>
    {
        var names = Graph.Value.Nodes.Select(node => node.Name).ToHashSet(StringComparer.Ordinal);
        return Directory.EnumerateFiles(AppContext.BaseDirectory, "*.dll")
            .Where(path => names.Contains(Path.GetFileNameWithoutExtension(path)))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
    });

    internal static readonly Lazy<IReadOnlyList<Assembly>> ProductionAssemblies = new(() =>
        ProductionAssemblyPaths.Value.Select(Assembly.LoadFrom).ToArray());

    internal static Assembly LoadProduction(string name) => Assembly.Load(name);

    /// <summary>
    /// Compiles a fixture and loads it into the default context so NetArchTest can resolve its types.
    /// Fixture assembly names are chosen not to collide with a real one.
    /// </summary>
    internal static Assembly LoadFixtureAssembly(string id, string assemblyName)
    {
        var path = FixtureCompiler.Compile(RepositoryRoot.Value, id, assemblyName);
        return Assembly.LoadFrom(path);
    }

    /// <summary>
    /// Loads a fixture that deliberately reuses a real assembly identity, which only a separate load
    /// context can host alongside the real one.
    /// </summary>
    internal static Assembly LoadIsolatedFixtureAssembly(string id, string assemblyName)
    {
        var path = FixtureCompiler.Compile(RepositoryRoot.Value, id, assemblyName);
        var context = new AssemblyLoadContext($"{id}-fixture-{Guid.NewGuid():N}");
        return context.LoadFromAssemblyPath(path);
    }

    internal static string FixtureAssemblyPath(string id, string assemblyName) =>
        FixtureCompiler.Compile(RepositoryRoot.Value, id, assemblyName);

    /// <summary>
    /// Materialises a synthetic <c>src</c> tree from a graph fixture and returns a graph over it.
    /// A fixture may declare several projects, separated by <c>&lt;!-- file: Name.csproj --&gt;</c>, which is
    /// what lets a fixture reproduce an <em>indirect</em> forbidden edge rather than only a direct one.
    /// </summary>
    internal static ProjectGraph LoadGraphFixture(string id)
    {
        var source = Path.Combine(
            RepositoryRoot.Value, "tests", "ArchitectureTests", "Fixtures",
            $"{id.Replace("-", string.Empty, StringComparison.Ordinal)}Violation.cs.txt");
        var root = Path.Combine(Path.GetTempPath(), "arcforges-graph-fixtures", $"{id}-{Guid.NewGuid():N}", "src");
        Directory.CreateDirectory(root);

        string? current = null;
        var buffer = new List<string>();

        void Flush()
        {
            if (current is null)
            {
                return;
            }

            var directory = Path.Combine(root, Path.GetFileNameWithoutExtension(current));
            Directory.CreateDirectory(directory);
            File.WriteAllLines(Path.Combine(directory, current), buffer);
            buffer.Clear();
        }

        foreach (var line in File.ReadAllLines(source))
        {
            var marker = line.TrimStart();
            if (marker.StartsWith("<!-- file:", StringComparison.OrdinalIgnoreCase))
            {
                Flush();
                current = marker["<!-- file:".Length..].Replace("-->", string.Empty, StringComparison.Ordinal).Trim();
                continue;
            }

            buffer.Add(line);
        }

        Flush();
        return ProjectGraph.Load(root);
    }

    internal static void AssertClean(IEnumerable<RuleViolation> violations)
    {
        var found = violations.ToArray();
        Xunit.Assert.True(found.Length == 0, string.Join(Environment.NewLine, found.Select(violation => violation.ToString())));
    }

    internal static void AssertViolates(string ruleId, IEnumerable<RuleViolation> violations)
    {
        var found = violations.ToArray();
        Xunit.Assert.NotEmpty(found);

        // The message format Step 01.04 fixes: "[ARC-0XX <rule name>] <source> -> <target>".
        var rendered = found[0].ToString();
        Xunit.Assert.StartsWith($"[{ruleId} {ArchitectureRules.Names[ruleId]}] ", rendered, StringComparison.Ordinal);
        Xunit.Assert.Contains(" -> ", rendered, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ArcForges.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
    }
}

/// <summary>Guards against every rule passing because nothing was analysed.</summary>
public sealed class ArchitectureSurfaceTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void TheAnalysedSurfaceIsNotEmpty()
    {
        var projects = ArchitectureContext.Graph.Value.Nodes.Count;
        var assemblies = ArchitectureContext.ProductionAssemblyPaths.Value.Count;

        Xunit.Assert.True(projects >= 130, $"Only {projects} projects were discovered under src/.");
        Xunit.Assert.True(
            assemblies >= 100,
            $"Only {assemblies} production assemblies were found next to the test host; build the solution first.");
    }
}

public sealed class ARC001DomainHasNoExternalDependenciesTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc001(ArchitectureContext.Graph.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates("ARC-001", ArchitectureRules.Arc001(ArchitectureContext.LoadGraphFixture("ARC-001")));

    /// <summary>
    /// The regression for the defect the Step 01 review recorded as finding A: source-text scanning could
    /// only see a direct edge, so a Domain project reaching a database provider through an intermediate
    /// project passed. The fixture declares exactly that shape and the failure must name the whole path.
    /// </summary>
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void AnIndirectForbiddenEdgeAlsoFailsAndNamesThePath()
    {
        var violations = ArchitectureRules.Arc001(ArchitectureContext.LoadGraphFixture("ARC-001-Transitive")).ToArray();

        Xunit.Assert.NotEmpty(violations);
        var rendered = string.Join(Environment.NewLine, violations.Select(violation => violation.ToString()));
        Xunit.Assert.Contains("ArcChat.Domain -> ArcChat.Indirection -> Microsoft.Data.Sqlite", rendered, StringComparison.Ordinal);
    }
}

public sealed class ARC002UiDoesNotCrossLayersTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc002(ArchitectureContext.ProductionAssemblies.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates(
            "ARC-002",
            ArchitectureRules.Arc002([ArchitectureContext.LoadFixtureAssembly("ARC-002", "ArcChat.Presentation.Fixture")]));
}

public sealed class ARC003AdaptersCarryNoViewModelOrUiTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc003(ArchitectureContext.Graph.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates("ARC-003", ArchitectureRules.Arc003(ArchitectureContext.LoadGraphFixture("ARC-003")));
}

public sealed class ARC004ProductsStayIsolatedTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc004(ArchitectureContext.Graph.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates("ARC-004", ArchitectureRules.Arc004(ArchitectureContext.LoadGraphFixture("ARC-004")));
}

public sealed class ARC005ContractsStayPureTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule()
    {
        ArchitectureContext.AssertClean(ArchitectureRules.Arc005(ArchitectureContext.Graph.Value));
        ArchitectureContext.AssertClean(ArchitectureRules.Arc005Types(ArchitectureContext.ProductionAssemblies.Value));
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates(
            "ARC-005",
            ArchitectureRules.Arc005Types([ArchitectureContext.LoadFixtureAssembly("ARC-005", "ArcForges.Contracts.Fixture")]));
}

public sealed class ARC006PublicClientsStayOffTheLocalBoundaryTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc006(ArchitectureContext.Graph.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates("ARC-006", ArchitectureRules.Arc006(ArchitectureContext.LoadGraphFixture("ARC-006")));
}

public sealed class ARC007NoStringObjectRpcTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(
            ArchitectureRules.Arc007([ArchitectureContext.LoadProduction("ArcForges.Contracts.LocalRpc")]));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates(
            "ARC-007",
            ArchitectureRules.Arc007([ArchitectureContext.LoadIsolatedFixtureAssembly("ARC-007", "ArcForges.Contracts.LocalRpc")]));
}

public sealed class ARC008RefitIsGeneratedOnlyTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule()
    {
        ArchitectureContext.AssertClean(ArchitectureRules.Arc008(ArchitectureContext.Graph.Value));

        // The call-shape half. Step 02.02/02.05 replace this with the published-IL and generated-manifest
        // gates; until Refit contracts exist there is no call site to inspect at IL level.
        var offenders = Directory
            .EnumerateFiles(Path.Combine(ArchitectureContext.RepositoryRoot.Value, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => File.ReadAllText(path).Contains("RestService.For<", StringComparison.Ordinal))
            .ToArray();

        Xunit.Assert.True(offenders.Length == 0, $"Non-generated Refit factory: {string.Join(", ", offenders)}");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates("ARC-008", ArchitectureRules.Arc008(ArchitectureContext.LoadGraphFixture("ARC-008")));
}

public sealed class ARC009StreamJsonRpcProxyMarkersAreCompleteTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(
            ArchitectureRules.Arc009([ArchitectureContext.LoadProduction("ArcForges.Contracts.LocalRpc")]));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates(
            "ARC-009",
            ArchitectureRules.Arc009([ArchitectureContext.LoadIsolatedFixtureAssembly("ARC-009", "ArcForges.Contracts.LocalRpc")]));
}

public sealed class ARC010FoundationCarriesNoProductDomainTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc010(ArchitectureContext.ProductionAssemblyPaths.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates(
            "ARC-010",
            ArchitectureRules.Arc010([ArchitectureContext.FixtureAssemblyPath("ARC-010", "ArcForges.Foundation.Fixture")]));
}

public sealed class ARC011UpstreamNativeTypesDoNotCrossTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc011(ArchitectureContext.ProductionAssemblyPaths.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates(
            "ARC-011",
            ArchitectureRules.Arc011([ArchitectureContext.FixtureAssemblyPath("ARC-011", "ArcForges.NativeInterop.Fixture")]));
}

public sealed class ARC012CloudModulesDoNotCrossPersistTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc012(ArchitectureContext.Graph.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates("ARC-012", ArchitectureRules.Arc012(ArchitectureContext.LoadGraphFixture("ARC-012")));
}

public sealed class ARC013DesktopClosureStaysNativeTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ProductionSatisfiesTheRule() =>
        ArchitectureContext.AssertClean(ArchitectureRules.Arc013(ArchitectureContext.Graph.Value));

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ViolationFixtureFailsTheRule() =>
        ArchitectureContext.AssertViolates("ARC-013", ArchitectureRules.Arc013(ArchitectureContext.LoadGraphFixture("ARC-013")));
}
