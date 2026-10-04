// SPDX-License-Identifier: AGPL-3.0-only

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Build.Policy.Architecture;

/// <summary>Shared AT/RP enforcement. Repository inputs are explicit, complete and fail closed.</summary>
internal static class PolicyEngine
{
    private static readonly string[] BannedRules = BannedSymbolScanner.CategoryCatalog.Select(category => category.Id).ToArray();
    public static IReadOnlyList<string> Rules { get; } = Enumerable.Range(1, 14).Select(value => $"AT-{value:00}")
        .Concat(Enumerable.Range(1, 10).Select(value => $"RP-{value:00}")).ToArray();

    public static IReadOnlyList<PolicyFinding> Check(RepositoryFacts repository,
        RepositoryPolicyConfiguration configuration, IReadOnlyDictionary<string, CSharpCompilation> compilations,
        DateOnly today)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(compilations);
        var graph = new ProjectGraph(repository.Projects);
        var findings = new List<PolicyFinding>();
        var methods = new Dictionary<string, IMethodSymbol>(StringComparer.Ordinal);
        var types = new Dictionary<string, INamedTypeSymbol>(StringComparer.Ordinal);
        var typeProjects = new Dictionary<INamedTypeSymbol, ProjectFacts>(SymbolEqualityComparer.Default);
        foreach (var project in graph.Projects)
        {
            if (!compilations.TryGetValue(project.Classification.Path, out var compilation))
            {
                if (project.Classification.Role is not (ProjectRole.NativeLibrary or ProjectRole.NativeWorker or ProjectRole.BuildTool))
                {
                    throw new InvalidOperationException("Missing source compilation: " + project.Classification.Path);
                }

                continue;
            }

            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var declaration in tree.GetRoot().DescendantNodes().Where(node => node is BaseTypeDeclarationSyntax or DelegateDeclarationSyntax))
                {
                    if (model.GetDeclaredSymbol(declaration) is INamedTypeSymbol type)
                    {
                        string name = type.ToDisplayString();
                        types.TryAdd(project.Classification.Path + "\0" + name, type);
                        typeProjects.TryAdd(type, project);
                        foreach (var method in type.GetMembers().OfType<IMethodSymbol>())
                        {
                            methods.TryAdd(project.Classification.Path + "\0" + MethodIdentity(method), method);
                        }
                    }
                }
            }

            if (project.Classification.Production && project.Classification.Role != ProjectRole.BuildTool)
            {
                findings.AddRange(BannedSymbolScanner.Scan(compilation, project.Classification));
            }
        }

        foreach (var project in graph.Projects)
        {
            var classification = project.Classification;
            string path = classification.Path;
            var closure = graph.Closure(path).ToArray();
            if (classification.Role == ProjectRole.Domain)
            {
                Forbid("AT-01", closure.Any(dependency => dependency.Classification.Role is not (ProjectRole.Domain or ProjectRole.Abstractions or ProjectRole.Foundation))
                    || project.Packages.Keys.Any(package => configuration.DependencyRoles is null
                        || !configuration.DependencyRoles.TryGetValue(package, out var role)
                        || role is not (ProjectRole.Domain or ProjectRole.Abstractions or ProjectRole.Foundation)),
                    "Domain dependencies cross the domain/abstraction boundary.");
            }

            if (classification.Role == ProjectRole.Application)
            {
                Forbid("AT-01", closure.Any(dependency => dependency.Classification.Role is not (ProjectRole.Domain or ProjectRole.Abstractions or ProjectRole.Foundation))
                    || project.Packages.Keys.Any(package => configuration.DependencyRoles is null
                        || !configuration.DependencyRoles.TryGetValue(package, out var role)
                        || role is not (ProjectRole.Domain or ProjectRole.Abstractions or ProjectRole.Foundation)),
                    "Application depends on infrastructure, transport or UI rather than domain and ports.");
            }

            if (classification.Role is ProjectRole.LocalRpcAdapter or ProjectRole.PublicApiAdapter)
            {
                Forbid(classification.Role == ProjectRole.LocalRpcAdapter ? "AT-02" : "AT-03",
                    closure.Any(dependency => dependency.Classification.Role is ProjectRole.UserInterface or ProjectRole.DesignSystem or ProjectRole.Shell)
                        || project.Packages.Keys.Any(IsPlatformPackage),
                    "An RPC/API adapter references a UI project.");
            }

            if (classification.Role == ProjectRole.Contracts)
            {
                Forbid("AT-04", closure.Any(dependency => dependency.Classification.Role is not (ProjectRole.Contracts or ProjectRole.Foundation or ProjectRole.Abstractions))
                    || project.Packages.Keys.Any(IsPlatformPackage), "Contracts reference a platform implementation.");
            }

            Forbid("AT-05", classification.Production && closure.Any(dependency =>
                dependency.Classification.Owner != classification.Owner
                && dependency.Classification.Role is ProjectRole.Domain or ProjectRole.Application or ProjectRole.Infrastructure),
                "A product reaches another product's internal layer.");
            Forbid("AT-07", classification.Module.Length > 0 && closure.Any(dependency =>
                dependency.Classification.Role == ProjectRole.Persistence
                && dependency.Classification.Module != classification.Module), "A module reaches another module's persistence.");
            Forbid("AT-09", classification.Production && (classification.Role == ProjectRole.NativeWorker
                || closure.Any(dependency => !dependency.Classification.Production)),
                "A long-lived native executable entered the release graph.");
            Forbid("AT-10", classification.Production && project.Packages.Keys.Any(package =>
                package is "Refit" or "Refit.HttpClientFactory" or "RestEase" or "RestEase.HttpClientFactory"),
                "A reflection-based typed HTTP client is in the production dependency graph.");
            Forbid("AT-13", classification.Module.Length > 0 && closure.Any(dependency =>
                dependency.Classification.Module.Length > 0 && dependency.Classification.Module != classification.Module
                && dependency.Classification.Role is not (ProjectRole.Abstractions or ProjectRole.Contracts)),
                "A module bypasses another module's declared API.");
            if (classification.Role is ProjectRole.DesignSystem or ProjectRole.Shell or ProjectRole.Foundation)
            {
                Forbid("AT-14", closure.Any(dependency => dependency.Classification.Role is ProjectRole.Domain
                    or ProjectRole.Application or ProjectRole.Infrastructure), "Shared foundation, design system or shell references product internals.");
            }

            Forbid("RP-02", !ValidLicense(project.License, project.Boundary), "Missing or inconsistent SPDX licence/boundary declaration.");
            Forbid("RP-03", project.Boundary == "Apache" && closure.Any(dependency => dependency.Boundary != "Apache"),
                "Apache project reaches a non-Apache project directly or transitively.");
            foreach (string package in project.Packages.Keys)
            {
                if (!configuration.DependencyLicenses.TryGetValue(package, out string? license))
                {
                    Add("RP-02", path, "Dependency licence is unclassified: " + package);
                    continue;
                }

                Forbid("RP-03", project.Boundary == "Apache" && license.StartsWith("AGPL", StringComparison.Ordinal),
                    "Apache dependency closure contains an AGPL package: " + package);
                Forbid("RP-04", configuration.MobileDistributable && classification.Production
                    && !configuration.AllowedMobileLicenses.Contains(license), "Mobile dependency licence is not admitted: " + package);
            }

            if (path.EndsWith(".csproj", StringComparison.Ordinal))
            {
                Forbid("RP-05", project.Properties.GetValueOrDefault("ManagePackageVersionsCentrally") != "true"
                    || project.Packages.Any(package => package.Value.Length == 0 || package.Value.Contains('*', StringComparison.Ordinal)),
                    "Managed dependency versions are not centrally and exactly pinned.");
                string full = ProjectGraph.ContainedPath(repository.Root, path);
                if (File.Exists(full))
                {
                    var xml = XDocument.Load(full);
                    Forbid("RP-05", xml.Descendants("PackageReference").Any(reference => reference.Attribute("Version") is not null
                        || reference.Attribute("VersionOverride") is not null || reference.Element("Version") is not null
                        || reference.Element("VersionOverride") is not null), "Inline NuGet version overrides bypass central management.");
                }

                Forbid("RP-06", project.Properties.GetValueOrDefault("RestorePackagesWithLockFile") != "true"
                    || !LockMatches(Path.Combine(Path.GetDirectoryName(full)!, "packages.lock.json"), project.Packages),
                    "Managed lock file is missing, disabled or inconsistent with the resolved dependency closure.");
            }

            Forbid("RP-07", classification.Production && (project.Properties.GetValueOrDefault("SuppressTrimAnalysisWarnings") == "true"
                || project.Properties.GetValueOrDefault("EnableTrimAnalyzer") == "false"
                || project.Properties.GetValueOrDefault("EnableAotAnalyzer") == "false"
                || SuppressesAot(project.Properties.GetValueOrDefault("NoWarn", ""))),
                "Blanket trimming/AOT diagnostics are suppressed.");
            if (classification.Aot)
            {
                Forbid("RP-07", closure.Any(dependency => dependency.Classification.Production && !dependency.Classification.Aot
                    && dependency.Classification.Role is not (ProjectRole.NativeLibrary or ProjectRole.BuildTool)),
                    "An AOT deliverable reaches a fenced managed project.");
            }

            void Forbid(string rule, bool violation, string message)
            {
                if (violation)
                {
                    Add(rule, path, message);
                }
            }
        }

        foreach (var pair in types)
        {
            var type = pair.Value;
            var project = typeProjects[type];
            if (!project.Classification.Production || project.Classification.Role == ProjectRole.BuildTool || !PublicType(type))
            {
                continue;
            }

            foreach (var member in type.GetMembers().Where(member => member.DeclaredAccessibility == Accessibility.Public
                && (type.TypeKind != TypeKind.Delegate || SymbolEqualityComparer.Default.Equals(member, type.DelegateInvokeMethod))))
            {
                var exposed = member switch
                {
                    IMethodSymbol method => method.Parameters.Select(parameter => parameter.Type).Append(method.ReturnType),
                    IPropertySymbol property => [property.Type],
                    IFieldSymbol field => [field.Type],
                    IEventSymbol eventSymbol => [eventSymbol.Type],
                    _ => Enumerable.Empty<ITypeSymbol>(),
                };
                if (exposed.Any(ContainsNativeType))
                {
                    Add("AT-06", project.Classification.Path, "Native pointer/handle crosses a public boundary: " + member);
                }

                if (project.Classification.Role is ProjectRole.LocalRpcAdapter or ProjectRole.PublicApiAdapter
                    && member is IMethodSymbol rpcMethod && rpcMethod.MethodKind == MethodKind.Ordinary
                    && rpcMethod.Parameters.Any(parameter => parameter.Type.SpecialType is SpecialType.System_Object or SpecialType.System_String))
                {
                    Add("AT-08", project.Classification.Path, "Untyped string/object RPC entry point: " + member);
                }
            }
        }

        foreach (var project in graph.Projects.Where(project => project.Classification.Role == ProjectRole.LocalRpcAdapter))
        {
            foreach (var type in types.Values.Where(type => typeProjects[type] == project
                && type.TypeKind == TypeKind.Class && !type.IsAbstract && type.GetMembers().OfType<IMethodSymbol>()
                    .Any(method => method.DeclaredAccessibility == Accessibility.Public && method.MethodKind == MethodKind.Ordinary && !method.IsImplicitlyDeclared)))
            {
                var binding = configuration.LocalServices.SingleOrDefault(binding => binding.ServiceSymbol == type.ToDisplayString());
                var contractType = binding is null ? null : Contracts(type).FirstOrDefault(contract => contract.ToDisplayString() == binding.ContractSymbol);
                if (binding is null || contractType is null
                    || !type.GetMembers().OfType<IFieldSymbol>().Any(field => field.Type.ToDisplayString() == binding.PortSymbol)
                    || !Generated(contractType))
                {
                    Add("AT-11", project.Classification.Path, "Local service lacks its canonical generated interface and explicit application-port mapping: " + type);
                }
            }
        }

        foreach (var project in graph.Projects.Where(project => project.Classification.Role == ProjectRole.Contracts))
        {
            foreach (var type in types.Values.Where(type => typeProjects[type] == project
                && type.DeclaredAccessibility == Accessibility.Public && type.TypeKind is TypeKind.Class or TypeKind.Struct or TypeKind.Enum))
            {
                var binding = configuration.WireTypes.SingleOrDefault(binding => binding.TypeSymbol == type.ToDisplayString());
                if (binding is null || !Generated(type) || !HashMatches(repository.Root, binding.SchemaPath, binding.SchemaSha256))
                {
                    Add("AT-12", project.Classification.Path, "Wire type is not bound to generated owned schema: " + type);
                }
            }
        }

        foreach (var pair in methods.Where(pair => pair.Value.DeclaredAccessibility == Accessibility.Public
            && pair.Value.MethodKind == MethodKind.Ordinary && !pair.Value.IsImplicitlyDeclared && PublicType(pair.Value.ContainingType)))
        {
            var project = typeProjects[pair.Value.ContainingType];
            if (!project.Classification.Production || project.Classification.Role is ProjectRole.BuildTool or ProjectRole.Test)
            {
                continue;
            }

            var bindings = repository.ContractTests.Where(binding => binding.ApiSymbol == MethodIdentity(pair.Value)).ToArray();
            if (bindings.Length == 0 || bindings.Any(binding => !methods.TryGetValue(binding.TestProject + "\0" + binding.TestMethod, out var test)
                || typeProjects[test.ContainingType].Classification.Path != binding.TestProject
                || typeProjects[test.ContainingType].Classification.Role != ProjectRole.Test
                || !test.GetAttributes().Any(attribute => TestAttribute(attribute.AttributeClass))))
            {
                Add("RP-10", project.Classification.Path, "Public API lacks correspondence to an actual contract-test method: " + pair.Key);
            }
        }

        foreach (var pin in configuration.ToolchainHashes)
        {
            if (!HashMatches(repository.Root, pin.Key, pin.Value))
            {
                Add("RP-06", pin.Key, "Toolchain lock differs from the admitted exact input.");
            }
        }

        if (configuration.ToolchainHashes.Count == 0)
        {
            Add("RP-06", "", "No toolchain input identity was supplied.");
        }

        CheckWeb(repository.Root, configuration.WebRoot, findings);
        foreach (string rule in new[] { "RP-01", "RP-08", "RP-09" })
        {
            var evidence = configuration.ExternalEvidence.Where(evidence => evidence.Rule == rule).ToArray();
            if (evidence.Length != 1 || evidence[0].SourceCommit != configuration.SourceCommit
                || configuration.SourceCommit.Length != 40 || !evidence[0].Passed || evidence[0].Findings.Count != 0)
            {
                Add(rule, "", "Missing, stale or failing canonical naming/secret gate evidence.");
            }
        }

        var allowedRules = Rules.Concat(BannedRules).ToHashSet(StringComparer.Ordinal);
        foreach (var exception in repository.Exceptions)
        {
            if (!allowedRules.Contains(exception.Rule) || exception.Path.Length == 0 || exception.Path.Contains('*', StringComparison.Ordinal)
                || exception.Owner != repository.Owner || string.IsNullOrWhiteSpace(exception.Reason) || exception.Expires <= today)
            {
                throw new InvalidOperationException("Invalid, unowned or expired policy exception: " + exception);
            }
        }

        return findings.Where(finding => !repository.Exceptions.Any(exception =>
            exception.Rule == finding.Rule && exception.Path == finding.Path)).Distinct().ToArray();

        void Add(string rule, string path, string message) => findings.Add(new PolicyFinding(rule, path, message));
    }

    public static string MethodIdentity(IMethodSymbol method) => method.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat);

    private static bool TestAttribute(INamedTypeSymbol? type)
    {
        for (var current = type; current is not null; current = current.BaseType)
        {
            if (current.ToDisplayString() is "Xunit.FactAttribute" or "Xunit.TheoryAttribute")
            {
                return true;
            }
        }

        return false;
    }

    private static bool PublicType(INamedTypeSymbol type) => type.DeclaredAccessibility == Accessibility.Public
        && (type.ContainingType is null || PublicType(type.ContainingType));

    private static bool ContainsNativeType(ITypeSymbol type) =>
        ContainsNativeType(type, new HashSet<ITypeSymbol>(SymbolEqualityComparer.Default));

    private static bool ContainsNativeType(ITypeSymbol type, HashSet<ITypeSymbol> visited)
    {
        if (!visited.Add(type)) return false;
        if (BannedSymbolScanner.IsNativePointer(type)) return true;
        if (type is IArrayTypeSymbol array) return ContainsNativeType(array.ElementType, visited);
        if (type is not INamedTypeSymbol named) return false;
        if (named.TypeArguments.Any(argument => ContainsNativeType(argument, visited))) return true;
        return named.DelegateInvokeMethod is { } invoke
            && (ContainsNativeType(invoke.ReturnType, visited)
                || invoke.Parameters.Any(parameter => ContainsNativeType(parameter.Type, visited)));
    }

    // Generated code is recognised by exactly two shapes, never by name or location: a GeneratedCode attribute from a known
    // generator on the type, or a type declared only in syntax trees whose leading header comment carries the Roslyn
    // "<auto-generated" marker (the shape of protoc, gRPC and schema-generated output). A nested type follows its container.
    private static bool Generated(INamedTypeSymbol type) => type.GetAttributes().Any(attribute =>
        attribute.AttributeClass?.ToDisplayString() == "System.CodeDom.Compiler.GeneratedCodeAttribute"
        && attribute.ConstructorArguments.Length > 0 && attribute.ConstructorArguments[0].Value is string generator
        && generator is "protoc" or "Google.Protobuf" or "grpc_csharp_plugin" or "ArcForges.SchemaGenerator")
        || (type.DeclaringSyntaxReferences.Length > 0 && type.DeclaringSyntaxReferences.All(reference => LeadingAutoGeneratedHeader(reference.SyntaxTree)))
        || (type.ContainingType is not null && Generated(type.ContainingType));

    // Only comments before the first token of the file count; a marker after code, in a string or in a documentation comment does not.
    private static bool LeadingAutoGeneratedHeader(SyntaxTree tree) => tree.GetRoot().GetFirstToken(includeZeroWidth: true).LeadingTrivia
        .Any(trivia => trivia.Kind() is SyntaxKind.SingleLineCommentTrivia or SyntaxKind.MultiLineCommentTrivia
            && trivia.ToString().Contains("<auto-generated", StringComparison.Ordinal));

    private static IEnumerable<INamedTypeSymbol> Contracts(INamedTypeSymbol type)
    {
        foreach (var contract in type.AllInterfaces)
        {
            yield return contract;
        }

        for (var current = type.BaseType; current is not null; current = current.BaseType)
        {
            yield return current;
        }
    }

    private static bool ValidLicense(string license, string boundary) =>
        (boundary == "Apache" && license == "Apache-2.0") || (boundary == "AGPL" && license == "AGPL-3.0-only");

    private static bool IsPlatformPackage(string package) => package.StartsWith("Avalonia", StringComparison.Ordinal)
        || package.StartsWith("Microsoft.Windows", StringComparison.Ordinal) || package.StartsWith("Microsoft.Maui", StringComparison.Ordinal)
        || package.StartsWith("ArcForges.Native.", StringComparison.Ordinal);

    private static bool SuppressesAot(string codes) => codes.Split([';', ',', ' '], StringSplitOptions.RemoveEmptyEntries)
        .Any(code => code is "IL2026" or "IL3050" or "IL2*" or "IL3*" or "IL*" or "trim" or "AOT");

    private static bool HashMatches(string root, string path, string hash)
    {
        string full = ProjectGraph.ContainedPath(root, path);
        return hash.Length == 64 && File.Exists(full)
            && Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(File.ReadAllText(full)
                .Replace("\r\n", "\n", StringComparison.Ordinal)))) == hash;
    }

    private static bool LockMatches(string path, IReadOnlyDictionary<string, string> packages)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        using var document = JsonDocument.Parse(File.ReadAllText(path));
        if (!document.RootElement.TryGetProperty("dependencies", out var frameworks))
        {
            return false;
        }

        var resolved = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var framework in frameworks.EnumerateObject())
        {
            foreach (var dependency in framework.Value.EnumerateObject())
            {
                if (dependency.Value.TryGetProperty("resolved", out var version))
                {
                    if (!resolved.TryGetValue(dependency.Name, out var versions))
                    {
                        versions = new HashSet<string>(StringComparer.Ordinal);
                        resolved.Add(dependency.Name, versions);
                    }

                    versions.Add(version.GetString() ?? "");
                }
            }
        }

        return packages.All(package => resolved.TryGetValue(package.Key, out var versions)
            && versions.Contains(package.Value));
    }

    private static void CheckWeb(string root, string? webRoot, List<PolicyFinding> findings)
    {
        if (webRoot is null)
        {
            return;
        }

        string directory = ProjectGraph.ContainedPath(root, webRoot);
        var locks = Directory.EnumerateFiles(directory, "package-lock.json", SearchOption.AllDirectories)
            .Where(path => !ProjectGraph.Normalize(path).Contains("/node_modules/", StringComparison.Ordinal)).ToArray();
        if (locks.Length != 1 || Path.GetDirectoryName(locks[0]) != directory.TrimEnd(Path.DirectorySeparatorChar))
        {
            findings.Add(new PolicyFinding("RP-06", webRoot, "Exactly one npm root lock is required; nested lock files are forbidden."));
        }

        string manifest = Path.Combine(directory, "package.json");
        if (!File.Exists(manifest))
        {
            findings.Add(new PolicyFinding("RP-05", webRoot, "Web package manifest is missing."));
            return;
        }

        using var document = JsonDocument.Parse(File.ReadAllText(manifest));
        foreach (string section in new[] { "dependencies", "devDependencies" })
        {
            if (!document.RootElement.TryGetProperty(section, out var dependencies))
            {
                continue;
            }

            foreach (var dependency in dependencies.EnumerateObject())
            {
                string version = dependency.Value.GetString() ?? "";
                if (!System.Text.RegularExpressions.Regex.IsMatch(version, @"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$", System.Text.RegularExpressions.RegexOptions.CultureInvariant))
                {
                    findings.Add(new PolicyFinding("RP-05", webRoot, "Web dependency is not exactly pinned: " + dependency.Name));
                }
            }
        }
    }
}
