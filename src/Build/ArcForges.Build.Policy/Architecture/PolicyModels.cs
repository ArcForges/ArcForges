// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Build.Policy.Architecture;

/// <summary>Stable classifications supplied by the owning repository, never inferred from a package name.</summary>
public enum ProjectRole
{
    Domain,
    Application,
    Abstractions,
    Infrastructure,
    UserInterface,
    LocalRpcAdapter,
    PublicApiAdapter,
    Contracts,
    NativeAdapter,
    Persistence,
    Foundation,
    DesignSystem,
    Shell,
    BuildTool,
    Test,
    NativeLibrary,
    NativeWorker,
}

/// <summary>A finding is a failing rule, not a warning or a coverage declaration.</summary>
public sealed record PolicyFinding(string Rule, string Path, string Message, int Line = 0);

/// <summary>Repository-owned classification of one evaluated project.</summary>
public sealed record ProjectClassification(
    string Path,
    ProjectRole Role,
    string Owner,
    string Module = "",
    bool Production = true,
    bool Aot = false);

/// <summary>Effective project data captured from MSBuild evaluation and locked dependency inputs.</summary>
public sealed record ProjectFacts(
    ProjectClassification Classification,
    string TargetFramework,
    string OutputType,
    string License,
    string Boundary,
    IReadOnlyList<string> ProjectReferences,
    IReadOnlyList<string> Sources,
    IReadOnlyList<string> AssemblyReferences,
    IReadOnlyDictionary<string, string> Properties,
    IReadOnlyDictionary<string, string> Packages);

/// <summary>A precise, owned and expiring exception. Wildcard rules and paths are not supported.</summary>
public sealed record PolicyException(
    string Rule,
    string Path,
    string Owner,
    string Reason,
    DateOnly Expires);

/// <summary>Explicit correspondence between a production API symbol and a real contract-test method.</summary>
public sealed record ContractTestBinding(string ApiSymbol, string TestProject, string TestMethod);

/// <summary>Structured inputs for non-managed consumers and canonical producer results.</summary>
public sealed record RepositoryFacts(
    string Root,
    string Owner,
    IReadOnlyList<ProjectFacts> Projects,
    IReadOnlyList<PolicyException> Exceptions,
    IReadOnlyList<ContractTestBinding> ContractTests);
