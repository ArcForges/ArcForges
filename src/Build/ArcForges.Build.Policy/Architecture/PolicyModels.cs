// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Build.Policy.Architecture;

/// <summary>Stable classifications supplied by the owning repository, never inferred from a package name.</summary>
internal enum ProjectRole
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
internal sealed record PolicyFinding(string Rule, string Path, string Message, int Line = 0);

/// <summary>Repository-owned classification of one evaluated project.</summary>
internal sealed record ProjectClassification(
    string Path,
    ProjectRole Role,
    string Owner,
    string Module = "",
    bool Production = true,
    bool Aot = false);

/// <summary>Effective project data captured from MSBuild evaluation and locked dependency inputs.</summary>
internal sealed record ProjectFacts(
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
internal sealed record PolicyException(
    string Rule,
    string Path,
    string Owner,
    string Reason,
    DateOnly Expires);

/// <summary>Explicit correspondence between a production API symbol and a real contract-test method.</summary>
internal sealed record ContractTestBinding(string ApiSymbol, string TestProject, string TestMethod);

/// <summary>Canonical generated-interface to application-port association for an owned local service.</summary>
internal sealed record LocalServiceBinding(string ServiceSymbol, string ContractSymbol, string PortSymbol);

/// <summary>Generated wire-type source and its immutable owned schema evidence.</summary>
internal sealed record WireTypeBinding(string TypeSymbol, string SchemaPath, string SchemaSha256);

/// <summary>Evidence from an existing required gate, bound to the exact source commit.</summary>
internal sealed record ExternalPolicyEvidence(string Rule, string SourceCommit, bool Passed, IReadOnlyList<PolicyFinding> Findings);

/// <summary>Exact lock inputs and licence classifications supplied by the owning repository.</summary>
internal sealed record RepositoryPolicyConfiguration(
    string SourceCommit,
    IReadOnlyDictionary<string, string> ToolchainHashes,
    IReadOnlyDictionary<string, string> DependencyLicenses,
    IReadOnlySet<string> AllowedMobileLicenses,
    IReadOnlyList<LocalServiceBinding> LocalServices,
    IReadOnlyList<WireTypeBinding> WireTypes,
    IReadOnlyList<ExternalPolicyEvidence> ExternalEvidence,
    string? WebRoot = null,
    bool MobileDistributable = false);

/// <summary>Structured inputs for non-managed consumers and canonical producer results.</summary>
internal sealed record RepositoryFacts(
    string Root,
    string Owner,
    IReadOnlyList<ProjectFacts> Projects,
    IReadOnlyList<PolicyException> Exceptions,
    IReadOnlyList<ContractTestBinding> ContractTests);
