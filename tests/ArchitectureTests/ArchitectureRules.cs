// SPDX-License-Identifier: AGPL-3.0-only

using System.Reflection;
using System.Reflection.Metadata;
using NetArchTest.Rules;

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>One violated edge, rendered in the format Step 01.04 fixes for rule failures.</summary>
internal sealed record RuleViolation(string RuleId, string RuleName, string Source, string Target)
{
    public override string ToString() => $"[{RuleId} {RuleName}] {Source} -> {Target}";
}

/// <summary>
/// The thirteen layout §11 / architecture §14 rules, evaluated over two engines.
/// </summary>
/// <remarks>
/// <para>
/// <b>Graph engine.</b> Reference-direction rules run over <see cref="ProjectGraph"/>'s transitive closure
/// of the declared ProjectReference/PackageReference edges. This is what makes an <em>indirect</em>
/// forbidden edge fail: a Domain project that reaches a database provider through an intermediate project
/// is reported with the full path that carries it.
/// </para>
/// <para>
/// <b>Type engine.</b> Rules about what a type may touch run over the compiled assemblies with
/// <c>NetArchTest.Rules</c>, which <c>implementation-repository-layout.md</c> §12 pins as the only
/// architecture-test framework for V1. Two rules — ARC-007 (RPC method shape) and ARC-009 (proxy
/// attributes) — are about member signatures and assembly attributes, which NetArchTest's type-dependency
/// model cannot express; those use in-box reflection over the same assemblies.
/// </para>
/// <para>
/// ARC-008's "generated-only" half is split deliberately. The package edge (<c>Refit.Reflection</c>) is a
/// graph rule. The call shape <c>RestService.For&lt;T&gt;</c> versus <c>RestService.ForGenerated&lt;T&gt;</c>
/// is a method-call distinction below the granularity of a type-dependency model, so it stays a source
/// assertion here; Step 02.02/02.05 own the published-IL and generated-manifest versions of that gate.
/// </para>
/// </remarks>
internal static class ArchitectureRules
{
    internal static readonly string[] Products = ["ArcChat", "ArcNotes", "ArcScope", "ArcSlate"];

    internal static readonly IReadOnlyDictionary<string, string> Names = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["ARC-001"] = "Domain has no external dependencies",
        ["ARC-002"] = "UI does not cross layers",
        ["ARC-003"] = "Adapters carry no ViewModel or UI",
        ["ARC-004"] = "Products stay isolated",
        ["ARC-005"] = "Contracts stay pure",
        ["ARC-006"] = "Public clients stay off the local boundary",
        ["ARC-007"] = "No string-object RPC",
        ["ARC-008"] = "Refit is generated-only",
        ["ARC-009"] = "StreamJsonRpc proxy markers are complete",
        ["ARC-010"] = "Foundation carries no product domain",
        ["ARC-011"] = "Upstream native types do not cross",
        ["ARC-012"] = "Cloud modules do not cross-persist",
        ["ARC-013"] = "Desktop closure stays native",
    };

    private static readonly string[] UiPackages = ["Avalonia", "Microsoft.Maui", "Dock.Avalonia", "CommunityToolkit.Mvvm"];
    private static readonly string[] DataPackages = ["Npgsql", "Microsoft.Data.Sqlite", "SQLitePCLRaw"];
    private static readonly string[] TransportPackages = ["StreamJsonRpc", "Refit", "Microsoft.AspNetCore.SignalR.Client"];

    // ---------------------------------------------------------------- graph rules

    internal static IEnumerable<RuleViolation> Arc001(ProjectGraph graph)
    {
        foreach (var node in graph.Where(node => node.Name.EndsWith(".Domain", StringComparison.Ordinal)))
        {
            foreach (var violation in Forbid("ARC-001", graph, node.Name,
                projectPredicate: reference =>
                    reference.EndsWith(".Application", StringComparison.Ordinal)
                    || reference.EndsWith(".Infrastructure", StringComparison.Ordinal)
                    || reference.EndsWith(".Desktop", StringComparison.Ordinal)
                    || reference.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal)
                    || string.Equals(reference, "ArcForges.NativeInterop", StringComparison.Ordinal),
                packagePredicate: package =>
                    StartsWithAny(package, UiPackages) || StartsWithAny(package, DataPackages) || StartsWithAny(package, TransportPackages)))
            {
                yield return violation;
            }
        }
    }

    internal static IEnumerable<RuleViolation> Arc003(ProjectGraph graph)
    {
        bool IsAdapter(string name) =>
            name.EndsWith(".LocalRpc", StringComparison.Ordinal)
            || string.Equals(name, "ArcForges.Cloud.PublicApi", StringComparison.Ordinal)
            || string.Equals(name, "ArcForges.Cloud.Realtime", StringComparison.Ordinal);

        foreach (var node in graph.Where(node => IsAdapter(node.Name)))
        {
            foreach (var violation in Forbid("ARC-003", graph, node.Name,
                projectPredicate: reference =>
                    reference.EndsWith(".Desktop", StringComparison.Ordinal)
                    || reference.EndsWith(".Presentation", StringComparison.Ordinal),
                packagePredicate: package => StartsWithAny(package, UiPackages)))
            {
                yield return violation;
            }
        }
    }

    internal static IEnumerable<RuleViolation> Arc004(ProjectGraph graph)
    {
        foreach (var node in graph.Where(node =>
            node.Name.EndsWith(".Domain", StringComparison.Ordinal) || node.Name.EndsWith(".Application", StringComparison.Ordinal)))
        {
            var owner = Products.FirstOrDefault(product => node.Name.StartsWith(product + ".", StringComparison.Ordinal));
            if (owner is null)
            {
                continue;
            }

            foreach (var reference in graph.TransitiveProjects(node.Name))
            {
                var other = Products.FirstOrDefault(product =>
                    !string.Equals(product, owner, StringComparison.Ordinal)
                    && reference.StartsWith(product + ".", StringComparison.Ordinal));
                if (other is not null)
                {
                    yield return new RuleViolation("ARC-004", Names["ARC-004"], node.Name, graph.DescribePath(node.Name, reference));
                }
            }
        }
    }

    internal static IEnumerable<RuleViolation> Arc005(ProjectGraph graph)
    {
        foreach (var node in graph.Where(node => node.Name.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal)))
        {
            foreach (var violation in Forbid("ARC-005", graph, node.Name,
                projectPredicate: reference => !reference.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal),
                packagePredicate: package =>
                    StartsWithAny(package, UiPackages)
                    || StartsWithAny(package, DataPackages)
                    || package.StartsWith("Microsoft.AspNetCore.SignalR", StringComparison.Ordinal)
                    || package.StartsWith("ModelContextProtocol", StringComparison.Ordinal)
                    || package.StartsWith("Silk.NET", StringComparison.Ordinal)
                    || package.StartsWith("SkiaSharp", StringComparison.Ordinal)
                    || package.StartsWith("AngleSharp", StringComparison.Ordinal)))
            {
                yield return violation;
            }
        }
    }

    internal static IEnumerable<RuleViolation> Arc006(ProjectGraph graph)
    {
        bool IsCloud(string name) => name.StartsWith("ArcForges.Cloud.", StringComparison.Ordinal) || string.Equals(name, "ArcForges.ServiceDefaults", StringComparison.Ordinal);
        bool IsMobile(string name) => name.StartsWith("ArcChat.Mobile", StringComparison.Ordinal);
        bool IsWeb(string name) => name.StartsWith("ArcForges.Web.", StringComparison.Ordinal);

        foreach (var node in graph.Where(node => IsCloud(node.Name) || IsMobile(node.Name) || IsWeb(node.Name)))
        {
            var web = IsWeb(node.Name);
            foreach (var violation in Forbid("ARC-006", graph, node.Name,
                projectPredicate: reference =>
                    string.Equals(reference, "ArcForges.Contracts.LocalRpc", StringComparison.Ordinal)
                    || (web && (reference.StartsWith("ArcForges.Cloud.", StringComparison.Ordinal)
                        || string.Equals(reference, "ArcForges.NativeInterop", StringComparison.Ordinal)
                        || reference.EndsWith(".Desktop", StringComparison.Ordinal)
                        || Products.Any(product => reference.StartsWith(product + ".", StringComparison.Ordinal)))),
                packagePredicate: package =>
                    web && (StartsWithAny(package, DataPackages) || package.StartsWith("ModelContextProtocol", StringComparison.Ordinal))))
            {
                yield return violation;
            }
        }
    }

    internal static IEnumerable<RuleViolation> Arc008(ProjectGraph graph)
    {
        foreach (var node in graph.Nodes)
        {
            foreach (var package in graph.TransitivePackages(node.Name).Where(package =>
                package.StartsWith("Refit.Reflection", StringComparison.Ordinal)))
            {
                yield return new RuleViolation("ARC-008", Names["ARC-008"], node.Name, graph.DescribePath(node.Name, package));
            }
        }
    }

    internal static IEnumerable<RuleViolation> Arc012(ProjectGraph graph)
    {
        const string prefix = "ArcForges.Cloud.Modules.";
        foreach (var node in graph.Where(node => node.Name.StartsWith(prefix, StringComparison.Ordinal)))
        {
            // Direct edges only: modules are allowed to share ArcForges.Cloud.Infrastructure, so the
            // transitive closure legitimately joins them. A module naming another module is the violation.
            foreach (var reference in node.ProjectReferences.Where(reference =>
                reference.StartsWith(prefix, StringComparison.Ordinal)
                && !string.Equals(reference, node.Name, StringComparison.Ordinal)))
            {
                yield return new RuleViolation("ARC-012", Names["ARC-012"], node.Name, reference);
            }
        }
    }

    internal static IEnumerable<RuleViolation> Arc013(ProjectGraph graph)
    {
        string[] browserRuntimePackages =
        [
            "Microsoft.Web.WebView2", "CefSharp", "Chromium", "Electron", "Jint", "MoonSharp",
            "Microsoft.AspNetCore.Components.WebView", "Microsoft.AspNetCore.Components.WebAssembly",
        ];

        var heads = graph.Where(node => node.Name.EndsWith(".Desktop", StringComparison.Ordinal))
            .Concat(graph.Where(node => string.Equals(node.Name, "ArcForges.ContentSandbox", StringComparison.Ordinal)));

        foreach (var node in heads)
        {
            // AngleSharp is the single documented parser exception and belongs to ContentSandbox only.
            var sandbox = string.Equals(node.Name, "ArcForges.ContentSandbox", StringComparison.Ordinal);
            foreach (var violation in Forbid("ARC-013", graph, node.Name,
                projectPredicate: reference => reference.StartsWith("ArcForges.Web.", StringComparison.Ordinal),
                packagePredicate: package =>
                    StartsWithAny(package, browserRuntimePackages)
                    || (!sandbox && package.StartsWith("AngleSharp", StringComparison.Ordinal))))
            {
                yield return violation;
            }
        }
    }

    // ---------------------------------------------------------------- type rules

    internal static IEnumerable<RuleViolation> Arc002(IEnumerable<Assembly> assemblies) =>
        ForbidTypeDependencies("ARC-002", assemblies,
            selector: types => types.That().HaveNameEndingWith("ViewModel", StringComparison.Ordinal).ShouldNot(),
            banned: ["Microsoft.Data.Sqlite", "Npgsql", "StreamJsonRpc", "Refit", "Microsoft.AspNetCore.SignalR", "System.Runtime.InteropServices.SafeHandle"]);

    internal static IEnumerable<RuleViolation> Arc005Types(IEnumerable<Assembly> assemblies) =>
        ForbidTypeDependencies("ARC-005", assemblies.Where(IsContractAssembly),
            selector: types => types.ShouldNot(),
            banned: ["Avalonia", "Microsoft.Maui", "Npgsql", "Microsoft.Data.Sqlite", "Android", "UIKit", "AppKit", "ArcForges.NativeInterop"]);

    internal static IEnumerable<RuleViolation> Arc010(IEnumerable<string> assemblies)
    {
        // Read type names straight out of the metadata tables. NetArchTest materialises Cecil definitions
        // into System.Type, which resolves through the CLR and therefore cannot inspect a fixture assembly
        // that deliberately shares a simple name with a real one.
        string[] productDomainNames = ["Document", "VideoTimeline", "Session", "Conversation", "Capture", "Timeline", "Project"];

        foreach (var path in assemblies.Where(path =>
            Path.GetFileNameWithoutExtension(path).StartsWith("ArcForges.Foundation", StringComparison.Ordinal)))
        {
            using var stream = File.OpenRead(path);
            using var reader = new System.Reflection.PortableExecutable.PEReader(stream);
            var metadata = reader.GetMetadataReader();

            foreach (var handle in metadata.TypeDefinitions)
            {
                var definition = metadata.GetTypeDefinition(handle);
                var name = metadata.GetString(definition.Name);
                if (productDomainNames.Contains(name, StringComparer.Ordinal))
                {
                    var ns = metadata.GetString(definition.Namespace);
                    yield return new RuleViolation(
                        "ARC-010", Names["ARC-010"], Path.GetFileNameWithoutExtension(path),
                        string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}");
                }
            }
        }
    }

    /// <summary>
    /// ARC-011 is a type-identity rule: no upstream media type may exist in, or be referenced by, managed
    /// code. It reads the metadata tables directly because a violation can appear either as a declared type
    /// or as a reference to one, and because such a type is typically emitted into the global namespace,
    /// which NetArchTest's namespace-oriented dependency search does not reach.
    /// </summary>
    internal static IEnumerable<RuleViolation> Arc011(IEnumerable<string> assemblies)
    {
        string[] upstream =
        [
            "AVFrame", "AVPacket", "AVCodecContext", "AVFormatContext", "AVCodec", "AVStream",
            "ma_device", "ma_context", "ma_engine", "ma_decoder",
        ];

        foreach (var path in assemblies)
        {
            using var stream = File.OpenRead(path);
            using var reader = new System.Reflection.PortableExecutable.PEReader(stream);
            if (!reader.HasMetadata)
            {
                continue;
            }

            var metadata = reader.GetMetadataReader();
            var assemblyName = Path.GetFileNameWithoutExtension(path);

            foreach (var handle in metadata.TypeDefinitions)
            {
                var name = metadata.GetString(metadata.GetTypeDefinition(handle).Name);
                if (upstream.Contains(name, StringComparer.Ordinal))
                {
                    yield return new RuleViolation("ARC-011", Names["ARC-011"], assemblyName, $"declares {name}");
                }
            }

            foreach (var handle in metadata.TypeReferences)
            {
                var name = metadata.GetString(metadata.GetTypeReference(handle).Name);
                if (upstream.Contains(name, StringComparer.Ordinal))
                {
                    yield return new RuleViolation("ARC-011", Names["ARC-011"], assemblyName, $"references {name}");
                }
            }
        }
    }

    /// <summary>
    /// ARC-007 is a signature rule: a contract method may not take or return an untyped payload.
    /// NetArchTest models type-to-type dependencies, not member signatures, so this reflects.
    /// </summary>
    internal static IEnumerable<RuleViolation> Arc007(IEnumerable<Assembly> assemblies)
    {
        Type[] banned = [typeof(object), typeof(Type), typeof(System.Text.Json.JsonElement)];

        foreach (var assembly in assemblies.Where(assembly =>
            string.Equals(assembly.GetName().Name, "ArcForges.Contracts.LocalRpc", StringComparison.Ordinal)))
        {
            foreach (var contract in assembly.GetTypes().Where(type => type.IsInterface))
            {
                foreach (var method in contract.GetMethods())
                {
                    var offenders = method.GetParameters().Select(parameter => parameter.ParameterType)
                        .Append(method.ReturnType)
                        .Where(type => banned.Contains(type)
                            || (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Dictionary<,>)
                                && type.GetGenericArguments()[1] == typeof(object)));

                    foreach (var offender in offenders)
                    {
                        yield return new RuleViolation(
                            "ARC-007", Names["ARC-007"], $"{contract.FullName}.{method.Name}", offender.Name);
                    }
                }
            }
        }
    }

    /// <summary>
    /// ARC-009 is an attribute rule: every <c>[JsonRpcContract]</c> interface must also carry
    /// <c>[GenerateShape]</c>, and the assembly must export its proxies. Attribute types belong to Step 02's
    /// package set, so they are matched by name and the rule is vacuously satisfied until they exist.
    /// </summary>
    internal static IEnumerable<RuleViolation> Arc009(IEnumerable<Assembly> assemblies)
    {
        foreach (var assembly in assemblies.Where(assembly =>
            string.Equals(assembly.GetName().Name, "ArcForges.Contracts.LocalRpc", StringComparison.Ordinal)))
        {
            var contracts = assembly.GetTypes()
                .Where(type => type.IsInterface && HasAttribute(type, "JsonRpcContractAttribute"))
                .ToArray();

            foreach (var contract in contracts.Where(type => !HasAttribute(type, "GenerateShapeAttribute")))
            {
                yield return new RuleViolation("ARC-009", Names["ARC-009"], contract.FullName!, "missing [GenerateShape]");
            }

            if (contracts.Length > 0
                && !assembly.GetCustomAttributes().Any(attribute =>
                    string.Equals(attribute.GetType().Name, "ExportRpcContractProxiesAttribute", StringComparison.Ordinal)))
            {
                yield return new RuleViolation(
                    "ARC-009", Names["ARC-009"], assembly.GetName().Name!, "missing [assembly: ExportRpcContractProxies]");
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    private static bool HasAttribute(MemberInfo member, string attributeTypeName) =>
        member.GetCustomAttributes(inherit: false)
            .Any(attribute => string.Equals(attribute.GetType().Name, attributeTypeName, StringComparison.Ordinal));

    private static bool IsContractAssembly(Assembly assembly) =>
        (assembly.GetName().Name ?? string.Empty).StartsWith("ArcForges.Contracts.", StringComparison.Ordinal);

    private static bool StartsWithAny(string value, IEnumerable<string> prefixes) =>
        prefixes.Any(prefix => value.StartsWith(prefix, StringComparison.Ordinal));

    private static IEnumerable<RuleViolation> Forbid(
        string ruleId,
        ProjectGraph graph,
        string source,
        Func<string, bool> projectPredicate,
        Func<string, bool> packagePredicate)
    {
        foreach (var reference in graph.TransitiveProjects(source).Where(projectPredicate).OrderBy(value => value, StringComparer.Ordinal))
        {
            yield return new RuleViolation(ruleId, Names[ruleId], source, graph.DescribePath(source, reference));
        }

        foreach (var package in graph.TransitivePackages(source).Where(packagePredicate).OrderBy(value => value, StringComparer.Ordinal))
        {
            yield return new RuleViolation(ruleId, Names[ruleId], source, graph.DescribePath(source, package));
        }
    }

    /// <remarks>
    /// The assemblies must be loaded, not merely present on disk. NetArchTest materialises every Cecil type
    /// definition into a runtime <see cref="Type"/> and silently drops the ones the CLR cannot resolve, so a
    /// rule run over an unloaded file reports success having analysed nothing. Passing loaded assemblies plus
    /// their directory as a search path is what makes the result meaningful.
    /// </remarks>
    private static IEnumerable<RuleViolation> ForbidTypeDependencies(
        string ruleId,
        IEnumerable<Assembly> assemblies,
        Func<Types, Conditions> selector,
        string[] banned)
    {
        foreach (var assembly in assemblies)
        {
            var searchDirectories = new List<string>();
            if (!string.IsNullOrEmpty(assembly.Location) && Path.GetDirectoryName(assembly.Location) is { } directory)
            {
                searchDirectories.Add(directory);
            }

            var result = selector(Types.InAssembly(assembly, searchDirectories)).HaveDependencyOnAny(banned).GetResult();
            if (result.IsSuccessful)
            {
                continue;
            }

            foreach (var failing in result.FailingTypeNames ?? [])
            {
                yield return new RuleViolation(
                    ruleId, Names[ruleId], assembly.GetName().Name ?? "<unnamed assembly>", failing ?? "<unnamed type>");
            }
        }
    }
}
